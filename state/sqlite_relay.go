package state

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Relay platform persistence (relay.go holds the types and the contract).

const relayColumns = `id, name, hostname, region_code, region_name, node_key, version,
	derp_port, stun_port, visibility, desired_state, config_version, bandwidth_limit,
	healthy, uptime_seconds, connected_clients, bytes_in, bytes_out, last_seen, created, created_by, region_id, cert_name`

const relayEnrollmentColumns = `id, name, secret_hash, visibility, expiry, used_at, created, created_by`

const relaySelectColumns = relayColumns + `, execution_report, execution_reported_at`

// CreateRelayEnrollmentToken implements [RelayStore].
func (s *SQLiteStore) CreateRelayEnrollmentToken(tok RelayEnrollmentToken, secret string) error {
	if tok.ID == "" {
		return fmt.Errorf("state: relay enrollment token id is required")
	}
	if !ValidRelayEnrollmentSecret(secret) {
		return fmt.Errorf("state: refusing to store a malformed enrollment secret")
	}
	if tok.Created.IsZero() {
		tok.Created = time.Now().UTC()
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.ExecContext(context.Background(), `
		INSERT INTO relay_enrollment_tokens (`+relayEnrollmentColumns+`)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		tok.ID, tok.Name, RelaySecretHash(secret), relayVisibilityOrPrivate(tok.Visibility),
		nullableTimePtr(tok.Expiry), nullableTimePtr(tok.UsedAt), tok.Created.UnixNano(), tok.CreatedBy)
	if err != nil {
		return fmt.Errorf("state: storing relay enrollment token %s: %w", tok.ID, err)
	}
	return nil
}

// RelayEnrollmentTokenBySecret implements [RelayStore].
func (s *SQLiteStore) RelayEnrollmentTokenBySecret(secret string) (RelayEnrollmentToken, bool) {
	record, err := s.LookupRelayEnrollmentToken(context.Background(), secret)
	return record, err == nil
}

func (store *SQLiteStore) LookupRelayEnrollmentToken(ctx context.Context, secret string) (RelayEnrollmentToken, error) {
	if !ValidRelayEnrollmentSecret(secret) {
		return RelayEnrollmentToken{}, ErrRelayNotFound
	}
	row := store.db.QueryRowContext(ctx,
		`SELECT `+relayEnrollmentColumns+` FROM relay_enrollment_tokens WHERE secret_hash = ?`,
		RelaySecretHash(secret))
	record, err := scanRelayEnrollmentToken(row)
	if errors.Is(err, sql.ErrNoRows) {
		return RelayEnrollmentToken{}, ErrRelayNotFound
	}
	if err != nil {
		return RelayEnrollmentToken{}, fmt.Errorf("state: reading relay enrollment credential: %w", err)
	}
	return record, nil
}

// RelayEnrollmentTokenByID implements [RelayStore].
func (s *SQLiteStore) RelayEnrollmentTokenByID(id string) (RelayEnrollmentToken, bool) {
	row := s.db.QueryRowContext(context.Background(),
		`SELECT `+relayEnrollmentColumns+` FROM relay_enrollment_tokens WHERE id = ?`, id)
	tok, err := scanRelayEnrollmentToken(row)
	if err != nil {
		return RelayEnrollmentToken{}, false
	}
	return tok, true
}

// ListRelayEnrollmentTokens implements [RelayStore].
func (s *SQLiteStore) ListRelayEnrollmentTokens() []RelayEnrollmentToken {
	tokens, _ := s.ListRelayEnrollmentTokensContext(context.Background())
	return tokens
}

func (s *SQLiteStore) ListRelayEnrollmentTokensContext(ctx context.Context) ([]RelayEnrollmentToken, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+relayEnrollmentColumns+` FROM relay_enrollment_tokens ORDER BY created DESC, id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]RelayEnrollmentToken, 0)
	for rows.Next() {
		tok, err := scanRelayEnrollmentToken(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, tok)
	}
	return out, rows.Err()
}

// EnrollRelay 把令牌、配额和身份绑定在一个写事务内；跨连接竞争由 BEGIN IMMEDIATE 串行化。
func (store *SQLiteStore) EnrollRelay(ctx context.Context, enrollmentSecret string, relay Relay, token string, maxRelays int) (Relay, error) {
	return store.EnrollRelayChecked(ctx, enrollmentSecret, relay, token, maxRelays, nil)
}

// EnrollRelayChecked 的平台检查与身份、一次性令牌消费共用事务；核心不依赖外部地图业务。
func (store *SQLiteStore) EnrollRelayChecked(ctx context.Context, enrollmentSecret string, relay Relay, token string, maxRelays int, check func(context.Context, *sql.Tx) error) (Relay, error) {
	prepared, err := prepareRelayForCreation(relay, token)
	if err != nil {
		return Relay{}, err
	}
	if maxRelays < -1 {
		return Relay{}, fmt.Errorf("state: invalid relay quota")
	}
	if !ValidRelayEnrollmentSecret(enrollmentSecret) {
		return Relay{}, ErrRelayNotFound
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	transaction, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return Relay{}, fmt.Errorf("state: beginning relay enrollment: %w", err)
	}
	defer transaction.Rollback()
	if check != nil {
		if err := check(ctx, transaction); err != nil {
			return Relay{}, err
		}
	}

	record, err := scanRelayEnrollmentToken(transaction.QueryRowContext(ctx,
		`SELECT `+relayEnrollmentColumns+` FROM relay_enrollment_tokens WHERE secret_hash = ?`, RelaySecretHash(enrollmentSecret)))
	if errors.Is(err, sql.ErrNoRows) {
		return Relay{}, ErrRelayNotFound
	}
	if err != nil {
		return Relay{}, fmt.Errorf("state: reading relay enrollment credential: %w", err)
	}
	if record.Used() {
		return Relay{}, ErrRelayEnrollmentConsumed
	}
	now := time.Now().UTC()
	if record.Expired(now) {
		return Relay{}, ErrRelayEnrollmentExpired
	}
	var used int
	if err := transaction.QueryRowContext(ctx, `SELECT COUNT(*) FROM relays`).Scan(&used); err != nil {
		return Relay{}, fmt.Errorf("state: reading relay quota usage: %w", err)
	}
	if maxRelays != -1 && used >= maxRelays {
		return Relay{}, ErrRelayLimitReached
	}
	var duplicate bool
	if err := transaction.QueryRowContext(ctx,
		`SELECT EXISTS(SELECT 1 FROM relays WHERE id = ? OR (node_key <> '' AND node_key = ?))`,
		prepared.ID, prepared.NodeKey).Scan(&duplicate); err != nil {
		return Relay{}, fmt.Errorf("state: checking relay identity: %w", err)
	}
	if duplicate {
		return Relay{}, ErrRelayAlreadyEnrolled
	}
	if err := insertRelay(ctx, transaction, prepared, token); err != nil {
		return Relay{}, err
	}
	// 更新失败、取消请求或提交失败均回滚刚创建的身份，令牌不会成为半完成状态。
	result, err := transaction.ExecContext(ctx,
		`UPDATE relay_enrollment_tokens SET used_at = ? WHERE id = ? AND used_at IS NULL`,
		now.UnixNano(), record.ID)
	if err != nil {
		return Relay{}, fmt.Errorf("state: consuming relay enrollment token: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return Relay{}, fmt.Errorf("state: checking enrollment token consumption: %w", err)
	}
	if affected != 1 {
		return Relay{}, ErrRelayEnrollmentConsumed
	}
	if err := transaction.Commit(); err != nil {
		return Relay{}, fmt.Errorf("state: committing relay enrollment: %w", err)
	}
	return prepared, nil
}

// DeleteRelayEnrollmentToken implements [RelayStore].
func (s *SQLiteStore) DeleteRelayEnrollmentToken(id string) error {
	if _, err := s.db.ExecContext(context.Background(),
		"DELETE FROM relay_enrollment_tokens WHERE id = ?", id); err != nil {
		return fmt.Errorf("state: deleting relay enrollment token %s: %w", id, err)
	}
	return nil
}

// CreateRelay implements [RelayStore].
func (s *SQLiteStore) CreateRelay(relay Relay, token string) error {
	prepared, err := prepareRelayForCreation(relay, token)
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if prepared.NodeKey != "" {
		if _, dup := s.relayByNodeKeyLocked(context.Background(), prepared.NodeKey); dup {
			return ErrRelayAlreadyEnrolled
		}
	}
	return insertRelay(context.Background(), s.db, prepared, token)
}

type relaySQLExecutor interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

func insertRelay(ctx context.Context, executor relaySQLExecutor, relay Relay, token string) error {
	_, err := executor.ExecContext(ctx, `
		INSERT INTO relays (`+relayColumns+`, token_hash)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		relay.ID, relay.Name, relay.HostName, relay.RegionCode, relay.RegionName,
		relay.NodeKey, relay.Version, relay.DERPPort, relay.STUNPort,
		relayVisibilityOrPrivate(relay.Visibility), relay.DesiredState, int64(relay.ConfigVersion),
		relay.BandwidthLimit, boolToInt(relay.Healthy), relay.UptimeSeconds,
		relay.ConnectedClients, relay.BytesIn, relay.BytesOut,
		nullableTimePtr(relay.LastSeen), relay.Created.UnixNano(), relay.CreatedBy,
		relay.RegionID, relay.CertName,
		RelaySecretHash(token))
	if err != nil {
		if isUniqueViolation(err) {
			if strings.Contains(err.Error(), "relays.region_id") {
				return ErrRelayAlreadyEnrolled
			}
			return ErrRelayTokenExists
		}
		return fmt.Errorf("state: storing relay %s: %w", relay.ID, err)
	}
	return nil
}

// RelayByToken implements [RelayStore].
func (s *SQLiteStore) RelayByToken(token string) (Relay, bool) {
	if !ValidRelayToken(token) {
		return Relay{}, false
	}
	row := s.db.QueryRowContext(context.Background(),
		`SELECT `+relaySelectColumns+` FROM relays WHERE token_hash = ?`, RelaySecretHash(token))
	relay, err := scanRelay(row)
	if err != nil {
		return Relay{}, false
	}
	return relay, true
}

// RelayByID implements [RelayStore].
func (s *SQLiteStore) RelayByID(id string) (Relay, bool) {
	relay, err := s.LookupRelay(context.Background(), id)
	return relay, err == nil
}

func (s *SQLiteStore) LookupRelay(ctx context.Context, id string) (Relay, error) {
	relay, err := scanRelay(s.db.QueryRowContext(ctx, `SELECT `+relaySelectColumns+` FROM relays WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return Relay{}, ErrRelayNotFound
	}
	return relay, err
}

// RelayByNodeKey implements [RelayStore].
func (s *SQLiteStore) RelayByNodeKey(nodeKey string) (Relay, bool) {
	if nodeKey == "" {
		return Relay{}, false
	}
	return s.relayByNodeKeyLocked(context.Background(), nodeKey)
}

// relayByNodeKeyLocked reads a relay by node key. It takes no lock: callers
// either hold s.mu or only read.
func (s *SQLiteStore) relayByNodeKeyLocked(ctx context.Context, nodeKey string) (Relay, bool) {
	row := s.db.QueryRowContext(ctx, `SELECT `+relaySelectColumns+` FROM relays WHERE node_key = ?`, nodeKey)
	relay, err := scanRelay(row)
	if err != nil {
		return Relay{}, false
	}
	return relay, true
}

// ListRelays implements [RelayStore].
func (s *SQLiteStore) ListRelays() []Relay {
	relays, _ := s.ListRelaysContext(context.Background())
	return relays
}

func (s *SQLiteStore) ListRelaysContext(ctx context.Context) ([]Relay, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+relaySelectColumns+` FROM relays ORDER BY created ASC, id ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]Relay, 0)
	for rows.Next() {
		relay, err := scanRelay(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, relay)
	}
	return out, rows.Err()
}

// UpdateRelayHeartbeat implements [RelayStore].
func (s *SQLiteStore) UpdateRelayHeartbeat(id string, hb RelayHeartbeat) error {
	ctx := context.Background()
	transaction, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer transaction.Rollback()
	relay, err := scanRelay(transaction.QueryRowContext(ctx, `SELECT `+relaySelectColumns+` FROM relays WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return ErrRelayNotFound
	}
	if err != nil {
		return err
	}
	if _, _, err := updateRelayHeartbeatTx(ctx, transaction, relay, hb, time.Now().UTC()); err != nil {
		return err
	}
	return transaction.Commit()
}

func (store *SQLiteStore) RecordRelayHeartbeat(ctx context.Context, token string, heartbeat RelayHeartbeat) (Relay, error) {
	transaction, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return Relay{}, err
	}
	defer transaction.Rollback()
	relay, _, err := RecordRelayHeartbeatTx(ctx, transaction, token, heartbeat, time.Now().UTC())
	if err != nil {
		return Relay{}, err
	}
	return relay, transaction.Commit()
}

// token hash、撤销复查、遥测和回执属于同一事务；存储故障不伪装成未知凭据。
func RecordRelayHeartbeatTx(ctx context.Context, transaction *sql.Tx, token string, heartbeat RelayHeartbeat, now time.Time) (Relay, bool, error) {
	if !ValidRelayToken(token) {
		return Relay{}, false, ErrRelayNotFound
	}
	relay, err := scanRelay(transaction.QueryRowContext(ctx, `SELECT `+relaySelectColumns+` FROM relays WHERE token_hash = ?`, RelaySecretHash(token)))
	if errors.Is(err, sql.ErrNoRows) {
		return Relay{}, false, ErrRelayNotFound
	}
	if err != nil {
		return Relay{}, false, err
	}
	return updateRelayHeartbeatTx(ctx, transaction, relay, heartbeat, now)
}

func updateRelayHeartbeatTx(ctx context.Context, transaction *sql.Tx, relay Relay, heartbeat RelayHeartbeat, now time.Time) (Relay, bool, error) {
	updated, changed, err := applyRelayHeartbeat(relay, heartbeat, now)
	if err != nil {
		return Relay{}, false, err
	}
	report := ""
	if !updated.ExecutionReportedAt.IsZero() {
		raw, err := json.Marshal(updated.Execution)
		if err != nil {
			return Relay{}, false, err
		}
		report = string(raw)
	}
	_, err = transaction.ExecContext(ctx, `UPDATE relays SET healthy = ?, uptime_seconds = ?, connected_clients = ?,
		bytes_in = ?, bytes_out = ?, last_seen = ?, version = ?, execution_report = ?, execution_reported_at = ? WHERE id = ?`,
		boolToInt(updated.Healthy), updated.UptimeSeconds, updated.ConnectedClients, updated.BytesIn, updated.BytesOut,
		updated.LastSeen.UnixNano(), updated.Version, report, nullableTimePtr(updated.ExecutionReportedAt), updated.ID)
	return updated, changed, err
}

// UpdateRelayConfig 是底层兼容入口；HTTP 操作必须使用附带身份复查和审计的外层事务。
func (s *SQLiteStore) UpdateRelayConfig(id string, update RelayConfigUpdate) (Relay, error) {
	ctx := context.Background()
	transaction, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Relay{}, err
	}
	defer transaction.Rollback()
	relay, err := UpdateRelayConfigTx(ctx, transaction, id, update, "system:store", time.Now().UTC())
	if err != nil {
		return Relay{}, err
	}
	return relay, transaction.Commit()
}

// UpdateRelayConfigTx 复用已有历史表，CAS、配置和历史必须属于调用方的同一个事务。
func UpdateRelayConfigTx(ctx context.Context, transaction *sql.Tx, id string, update RelayConfigUpdate, actor string, now time.Time) (Relay, error) {
	relay, err := scanRelay(transaction.QueryRowContext(ctx, `SELECT `+relaySelectColumns+` FROM relays WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return Relay{}, ErrRelayNotFound
	}
	if err != nil {
		return Relay{}, err
	}
	if err := ValidateRelayConfigUpdate(relay, update); err != nil {
		return Relay{}, err
	}
	if err := saveRelayConfigurationSnapshot(ctx, transaction, relay, "system:import", now, true); err != nil {
		return Relay{}, err
	}
	relay = applyRelayConfig(relay, update)
	result, err := transaction.ExecContext(ctx, `UPDATE relays SET desired_state = ?, config_version = ?, bandwidth_limit = ?, region_name = ?
		WHERE id = ? AND config_version = ?`, relay.DesiredState, relay.ConfigVersion, relay.BandwidthLimit, relay.RegionName, id, update.ConfigVersion)
	if err != nil {
		return Relay{}, err
	}
	if count, err := result.RowsAffected(); err != nil || count != 1 {
		if err != nil {
			return Relay{}, err
		}
		return Relay{}, ErrRelayConfigConflict
	}
	if err := saveRelayConfigurationSnapshot(ctx, transaction, relay, actor, now, false); err != nil {
		return Relay{}, err
	}
	return relay, nil
}

func saveRelayConfigurationSnapshot(ctx context.Context, transaction *sql.Tx, relay Relay, actor string, now time.Time, baseline bool) error {
	content, err := json.Marshal(RelayConfigurationFor(relay))
	if err != nil {
		return err
	}
	query := "INSERT INTO network_document_history (kind, revision, content, actor, created) VALUES (?, ?, ?, ?, ?)"
	if baseline {
		query += " ON CONFLICT(kind, revision) DO NOTHING"
	}
	_, err = transaction.ExecContext(ctx, query, RelayConfigurationKind(relay.ID), relay.ConfigVersion, string(content), actor, now.UnixNano())
	return err
}

// ValidateRelayConfigUpdate 的版本是前置条件，不允许操作方直接指定新版本或回退版本号。
func ValidateRelayConfigUpdate(relay Relay, update RelayConfigUpdate) error {
	if update.ConfigVersion == 0 || update.ConfigVersion != relay.ConfigVersion {
		return ErrRelayConfigConflict
	}
	if relay.DesiredState == RelayStateRevoked && update.DesiredState != "" && update.DesiredState != RelayStateRevoked {
		return ErrRelayConfigRevoked
	}
	if relay.ConfigVersion >= 1<<53-1 || (update.DesiredState != "" && !ValidRelayState(update.DesiredState)) ||
		(update.BandwidthLimit != nil && (*update.BandwidthLimit < -1 || *update.BandwidthLimit > 1<<53-1)) ||
		(update.RegionName != nil && (len(*update.RegionName) > 128 || !utf8.ValidString(*update.RegionName) || strings.ContainsFunc(*update.RegionName, unicode.IsControl))) {
		return ErrRelayConfigInvalid
	}
	return nil
}

// DeleteRelay implements [RelayStore].
func (s *SQLiteStore) DeleteRelay(id string) error {
	ctx := context.Background()
	transaction, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer transaction.Rollback()
	var expected uint64
	err = transaction.QueryRowContext(ctx, "SELECT config_version FROM relays WHERE id = ?", id).Scan(&expected)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := DeleteRelayTx(ctx, transaction, id, expected); err != nil {
		return err
	}
	return transaction.Commit()
}

// DeleteRelayTx 删除身份和对应历史，但不能用历史恢复凭据或复活已删除的服务。
func DeleteRelayTx(ctx context.Context, transaction *sql.Tx, id string, expected uint64) error {
	var current uint64
	err := transaction.QueryRowContext(ctx, "SELECT config_version FROM relays WHERE id = ?", id).Scan(&current)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrRelayNotFound
	}
	if err != nil {
		return err
	}
	if expected == 0 || current != expected {
		return ErrRelayConfigConflict
	}
	if _, err := transaction.ExecContext(ctx, "DELETE FROM relays WHERE id = ? AND config_version = ?", id, expected); err != nil {
		return err
	}
	_, err = transaction.ExecContext(ctx, "DELETE FROM network_document_history WHERE kind = ?", RelayConfigurationKind(id))
	return err
}

// scanRelay reads one relay row. rows may be a *sql.Row or a *sql.Rows.
func scanRelay(rows interface{ Scan(...any) error }) (Relay, error) {
	var (
		relay               Relay
		version             sql.NullString
		healthy             int
		configVersion       int64
		lastSeen            sql.NullInt64
		created             int64
		executionReport     string
		executionReportedAt sql.NullInt64
	)
	if err := rows.Scan(
		&relay.ID, &relay.Name, &relay.HostName, &relay.RegionCode, &relay.RegionName,
		&relay.NodeKey, &version, &relay.DERPPort, &relay.STUNPort,
		&relay.Visibility, &relay.DesiredState, &configVersion, &relay.BandwidthLimit,
		&healthy, &relay.UptimeSeconds, &relay.ConnectedClients,
		&relay.BytesIn, &relay.BytesOut, &lastSeen, &created, &relay.CreatedBy,
		&relay.RegionID, &relay.CertName,
		&executionReport, &executionReportedAt,
	); err != nil {
		return Relay{}, err
	}
	relay.Version = version.String
	relay.Healthy = healthy != 0
	relay.ConfigVersion = uint64(configVersion)
	relay.LastSeen = timeFromNanos(lastSeen)
	relay.Created = time.Unix(0, created).UTC()
	if executionReport != "" {
		if err := json.Unmarshal([]byte(executionReport), &relay.Execution); err != nil {
			return Relay{}, err
		}
	}
	relay.ExecutionReportedAt = timeFromNanos(executionReportedAt)
	return relay, nil
}

// scanRelayEnrollmentToken reads one enrollment-token row.
func scanRelayEnrollmentToken(rows interface{ Scan(...any) error }) (RelayEnrollmentToken, error) {
	var (
		tok        RelayEnrollmentToken
		secretHash string
		expiry     sql.NullInt64
		usedAt     sql.NullInt64
		created    int64
	)
	// secret_hash is selected but not part of the record: the hash is the
	// lookup key, never the value a caller needs.
	if err := rows.Scan(&tok.ID, &tok.Name, &secretHash, &tok.Visibility, &expiry, &usedAt, &created, &tok.CreatedBy); err != nil {
		return RelayEnrollmentToken{}, err
	}
	_ = secretHash
	tok.Expiry = timeFromNanos(expiry)
	tok.UsedAt = timeFromNanos(usedAt)
	tok.Created = time.Unix(0, created).UTC()
	return tok, nil
}

// applyRelayConfig applies an operator update to a relay value. It lives here
// so the in-memory and SQLite stores cannot drift apart.
func applyRelayConfig(relay Relay, update RelayConfigUpdate) Relay {
	if update.DesiredState != "" {
		relay.DesiredState = update.DesiredState
	}
	if update.BandwidthLimit != nil {
		relay.BandwidthLimit = *update.BandwidthLimit
	}
	if update.RegionName != nil {
		relay.RegionName = *update.RegionName
	}
	relay.ConfigVersion++
	return relay
}

// relayVisibilityOrPrivate normalizes an empty visibility.
func relayVisibilityOrPrivate(v string) string {
	if v == "" {
		return RelayVisibilityPrivate
	}
	return v
}

// timeFromNanos converts a nullable UnixNano column into a time value.
func timeFromNanos(v sql.NullInt64) time.Time {
	if !v.Valid || v.Int64 == 0 {
		return time.Time{}
	}
	return time.Unix(0, v.Int64).UTC()
}
