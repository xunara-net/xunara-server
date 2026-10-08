package state

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// Relay platform persistence (relay.go holds the types and the contract).

const relayColumns = `id, name, hostname, region_code, region_name, node_key, version,
	derp_port, stun_port, visibility, desired_state, config_version, bandwidth_limit,
	healthy, uptime_seconds, connected_clients, bytes_in, bytes_out, last_seen, created, created_by`

const relayEnrollmentColumns = `id, name, secret_hash, visibility, expiry, used_at, created, created_by`

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
	if !ValidRelayEnrollmentSecret(secret) {
		return RelayEnrollmentToken{}, false
	}
	row := s.db.QueryRowContext(context.Background(),
		`SELECT `+relayEnrollmentColumns+` FROM relay_enrollment_tokens WHERE secret_hash = ?`,
		RelaySecretHash(secret))
	tok, err := scanRelayEnrollmentToken(row)
	if err != nil {
		return RelayEnrollmentToken{}, false
	}
	return tok, true
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
	rows, err := s.db.QueryContext(context.Background(),
		`SELECT `+relayEnrollmentColumns+` FROM relay_enrollment_tokens ORDER BY created DESC, id DESC`)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var out []RelayEnrollmentToken
	for rows.Next() {
		tok, err := scanRelayEnrollmentToken(rows)
		if err != nil {
			return out
		}
		out = append(out, tok)
	}
	return out
}

// ConsumeRelayEnrollmentToken implements [RelayStore].
//
// The read and the write happen in one transaction with an UPDATE that only
// matches an unused row, so two relays enrolling with the same token at the
// same time cannot both succeed.
func (s *SQLiteStore) ConsumeRelayEnrollmentToken(id string, at time.Time) (RelayEnrollmentToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	ctx := context.Background()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return RelayEnrollmentToken{}, fmt.Errorf("state: beginning relay enrollment: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // rollback after commit is a no-op

	tok, err := scanRelayEnrollmentToken(tx.QueryRowContext(ctx,
		`SELECT `+relayEnrollmentColumns+` FROM relay_enrollment_tokens WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return RelayEnrollmentToken{}, ErrRelayNotFound
	}
	if err != nil {
		return RelayEnrollmentToken{}, fmt.Errorf("state: reading relay enrollment token %s: %w", id, err)
	}
	if tok.Used() {
		return RelayEnrollmentToken{}, ErrRelayEnrollmentConsumed
	}
	if tok.Expired(at) {
		return RelayEnrollmentToken{}, ErrRelayEnrollmentExpired
	}

	res, err := tx.ExecContext(ctx,
		`UPDATE relay_enrollment_tokens SET used_at = ? WHERE id = ? AND used_at IS NULL`,
		at.UTC().UnixNano(), id)
	if err != nil {
		return RelayEnrollmentToken{}, fmt.Errorf("state: consuming relay enrollment token %s: %w", id, err)
	}
	if n, err := res.RowsAffected(); err == nil && n == 0 {
		// Another transaction consumed it between the read and the update.
		return RelayEnrollmentToken{}, ErrRelayEnrollmentConsumed
	}
	if err := tx.Commit(); err != nil {
		return RelayEnrollmentToken{}, fmt.Errorf("state: consuming relay enrollment token %s: %w", id, err)
	}

	tok.UsedAt = at.UTC()
	return tok, nil
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
	if relay.ID == "" {
		return fmt.Errorf("state: relay id is required")
	}
	if !ValidRelayToken(token) {
		return fmt.Errorf("state: refusing to store a malformed relay token")
	}
	if relay.Created.IsZero() {
		relay.Created = time.Now().UTC()
	}
	if relay.DesiredState == "" {
		relay.DesiredState = RelayStateOnline
	}
	if relay.ConfigVersion == 0 {
		relay.ConfigVersion = 1
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if relay.NodeKey != "" {
		if _, dup := s.relayByNodeKeyLocked(context.Background(), relay.NodeKey); dup {
			return fmt.Errorf("state: relay node key is already enrolled")
		}
	}

	_, err := s.db.ExecContext(context.Background(), `
		INSERT INTO relays (`+relayColumns+`, token_hash)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		relay.ID, relay.Name, relay.HostName, relay.RegionCode, relay.RegionName,
		relay.NodeKey, relay.Version, relay.DERPPort, relay.STUNPort,
		relayVisibilityOrPrivate(relay.Visibility), relay.DesiredState, int64(relay.ConfigVersion),
		relay.BandwidthLimit, boolToInt(relay.Healthy), relay.UptimeSeconds,
		relay.ConnectedClients, relay.BytesIn, relay.BytesOut,
		nullableTimePtr(relay.LastSeen), relay.Created.UnixNano(), relay.CreatedBy,
		RelaySecretHash(token))
	if err != nil {
		if isUniqueViolation(err) {
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
		`SELECT `+relayColumns+` FROM relays WHERE token_hash = ?`, RelaySecretHash(token))
	relay, err := scanRelay(row)
	if err != nil {
		return Relay{}, false
	}
	return relay, true
}

// RelayByID implements [RelayStore].
func (s *SQLiteStore) RelayByID(id string) (Relay, bool) {
	row := s.db.QueryRowContext(context.Background(),
		`SELECT `+relayColumns+` FROM relays WHERE id = ?`, id)
	relay, err := scanRelay(row)
	if err != nil {
		return Relay{}, false
	}
	return relay, true
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
	row := s.db.QueryRowContext(ctx, `SELECT `+relayColumns+` FROM relays WHERE node_key = ?`, nodeKey)
	relay, err := scanRelay(row)
	if err != nil {
		return Relay{}, false
	}
	return relay, true
}

// ListRelays implements [RelayStore].
func (s *SQLiteStore) ListRelays() []Relay {
	rows, err := s.db.QueryContext(context.Background(),
		`SELECT `+relayColumns+` FROM relays ORDER BY created ASC, id ASC`)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var out []Relay
	for rows.Next() {
		relay, err := scanRelay(rows)
		if err != nil {
			return out
		}
		out = append(out, relay)
	}
	return out
}

// UpdateRelayHeartbeat implements [RelayStore].
func (s *SQLiteStore) UpdateRelayHeartbeat(id string, hb RelayHeartbeat) error {
	if hb.LastSeen.IsZero() {
		hb.LastSeen = time.Now().UTC()
	}
	res, err := s.db.ExecContext(context.Background(), `
		UPDATE relays SET
			healthy = ?, uptime_seconds = ?, connected_clients = ?,
			bytes_in = ?, bytes_out = ?, last_seen = ?,
			version = CASE WHEN ? <> '' THEN ? ELSE version END
		WHERE id = ?`,
		boolToInt(hb.Healthy), hb.UptimeSeconds, hb.ConnectedClients,
		hb.BytesIn, hb.BytesOut, hb.LastSeen.UTC().UnixNano(),
		hb.Version, hb.Version, id)
	if err != nil {
		return fmt.Errorf("state: recording relay heartbeat %s: %w", id, err)
	}
	if n, err := res.RowsAffected(); err == nil && n == 0 {
		return ErrRelayNotFound
	}
	return nil
}

// UpdateRelayConfig implements [RelayStore]. The read-modify-write runs under
// the store mutex so two operators cannot apply half of each other's change.
func (s *SQLiteStore) UpdateRelayConfig(id string, update RelayConfigUpdate) (Relay, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	ctx := context.Background()
	relay, ok := s.relayByIDLocked(ctx, id)
	if !ok {
		return Relay{}, ErrRelayNotFound
	}
	relay = applyRelayConfig(relay, update)

	if _, err := s.db.ExecContext(ctx, `
		UPDATE relays SET desired_state = ?, config_version = ?, bandwidth_limit = ?, region_name = ?
		WHERE id = ?`,
		relay.DesiredState, int64(relay.ConfigVersion), relay.BandwidthLimit, relay.RegionName, id); err != nil {
		return Relay{}, fmt.Errorf("state: updating relay %s: %w", id, err)
	}
	return relay, nil
}

// DeleteRelay implements [RelayStore].
func (s *SQLiteStore) DeleteRelay(id string) error {
	if _, err := s.db.ExecContext(context.Background(), "DELETE FROM relays WHERE id = ?", id); err != nil {
		return fmt.Errorf("state: deleting relay %s: %w", id, err)
	}
	return nil
}

// relayByIDLocked reads one relay while the caller holds s.mu.
func (s *SQLiteStore) relayByIDLocked(ctx context.Context, id string) (Relay, bool) {
	relay, err := scanRelay(s.db.QueryRowContext(ctx, `SELECT `+relayColumns+` FROM relays WHERE id = ?`, id))
	if err != nil {
		return Relay{}, false
	}
	return relay, true
}

// scanRelay reads one relay row. rows may be a *sql.Row or a *sql.Rows.
func scanRelay(rows interface{ Scan(...any) error }) (Relay, error) {
	var (
		relay         Relay
		version       sql.NullString
		healthy       int
		configVersion int64
		lastSeen      sql.NullInt64
		created       int64
	)
	if err := rows.Scan(
		&relay.ID, &relay.Name, &relay.HostName, &relay.RegionCode, &relay.RegionName,
		&relay.NodeKey, &version, &relay.DERPPort, &relay.STUNPort,
		&relay.Visibility, &relay.DesiredState, &configVersion, &relay.BandwidthLimit,
		&healthy, &relay.UptimeSeconds, &relay.ConnectedClients,
		&relay.BytesIn, &relay.BytesOut, &lastSeen, &created, &relay.CreatedBy,
	); err != nil {
		return Relay{}, err
	}
	relay.Version = version.String
	relay.Healthy = healthy != 0
	relay.ConfigVersion = uint64(configVersion)
	relay.LastSeen = timeFromNanos(lastSeen)
	relay.Created = time.Unix(0, created).UTC()
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
	if update.ConfigVersion > relay.ConfigVersion {
		relay.ConfigVersion = update.ConfigVersion
	}
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
