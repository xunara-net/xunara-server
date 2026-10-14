package control

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// Xunara Share: the platform-level registry of cross-organization machine
// shares (PROJECT_SPEC section 38).
//
// The registry is deliberately platform-scoped, not org-scoped: a share is a
// relationship between two organizations, so storing it inside one tenant's
// database would let that tenant's writes define the other tenant's state
// (AGENTS.md section 12). It holds routing keys and lifecycle only: node
// snapshots and synthetic identifiers stay in the organizations themselves.

// Share statuses.
const (
	// SharePending waits for the target identity to accept or reject.
	SharePending = "pending"
	// ShareAccepted is in force: both netmaps expose the peer pair.
	ShareAccepted = "accepted"
	// ShareRejected is terminal: the target declined.
	ShareRejected = "rejected"
	// ShareRevoked is terminal: either side withdrew.
	ShareRevoked        = "revoked"
	ShareTargetExternal = "external"
	ShareTargetAccount  = "account"
)

// Share lifecycle errors, mapped by the API layer to HTTP status codes.
var (
	// ErrShareNotFound is returned for an unknown share ID.
	ErrShareNotFound = errors.New("control: share not found")
	// ErrShareExists is returned when the same source node already has an
	// active share to the same target identity.
	ErrShareExists = errors.New("control: an active share already exists")
	// ErrShareState is returned when a lifecycle action does not apply to the
	// share's current status.
	ErrShareState = errors.New("control: share is not in a state for this action")
	// ErrShareTarget is returned when the caller is not the share's target.
	ErrShareTarget = errors.New("control: caller is not the share target")
)

// Share is one machine shared from a source organization to a user identity
// in a target organization. Timestamps are zero when the step did not happen;
// the wire view omits them.
type Share struct {
	// ID is the stable identifier, also the console/API handle.
	ID string
	// SourceOrg owns the shared machine.
	SourceOrg string
	// SourceNode is the machine's numeric ID in SourceOrg's state store.
	SourceNode int64
	// TargetOrg is the organization the target user must belong to.
	TargetOrg string
	// 实例身份与 stable ID 防止同名租户、数字节点 ID 被重新使用后继承分享。
	SourceGeneration     string
	SourceStableID       string
	SourceUserCreated    int64
	TargetGeneration     string
	TargetKind           string
	TargetAccount        int64
	TargetAccountCreated int64
	// Provider and Subject are the target identity within TargetOrg
	// (AGENTS.md section 6: the identity key, never an email).
	Provider string
	Subject  string
	// Status is one of the Share* constants.
	Status string
	// CreatedBy is the source-organization user who created the share.
	CreatedBy int64
	CreatedAt time.Time

	AcceptedAt time.Time
	AcceptedBy int64
	RejectedAt time.Time
	RejectedBy int64
	RevokedAt  time.Time
	RevokedBy  int64
	// RevokedByOrg records which side revoked an accepted share, for audit.
	RevokedByOrg string
}

// Active reports whether the share still occupies its uniqueness slot.
func (s Share) Active() bool {
	return s.Status == SharePending || s.Status == ShareAccepted
}

// ShareFilter selects shares for listing. Zero fields do not filter, except
// TargetUser: when set it requires an accepted share bound to that user.
type ShareFilter struct {
	SourceOrg     string
	SourceNode    int64
	TargetOrg     string
	TargetUser    int64
	Provider      string
	Subject       string
	TargetKind    string
	TargetAccount int64
	// Statuses limits the result when non-empty.
	Statuses []string
}

// ShareRegistryConfig configures the durable platform share registry.
type ShareRegistryConfig struct {
	// Path is the SQLite database file holding the share table.
	Path string
}

// ShareRegistry is the durable table of cross-organization shares.
type ShareRegistry struct {
	db *sql.DB
}

// shareMigrations are applied in order and tracked in this module's own
// schema_migrations table, like the other SQLite-backed modules.
var shareMigrations = []string{
	`
CREATE TABLE IF NOT EXISTS shares (
	id             TEXT    PRIMARY KEY,
	source_org     TEXT    NOT NULL,
	source_node    INTEGER NOT NULL,
	target_org     TEXT    NOT NULL,
	provider       TEXT    NOT NULL,
	subject        TEXT    NOT NULL,
	status         TEXT    NOT NULL,
	created_by     INTEGER NOT NULL,
	created_at     INTEGER NOT NULL,
	accepted_at    INTEGER NOT NULL DEFAULT 0,
	accepted_by    INTEGER NOT NULL DEFAULT 0,
	rejected_at    INTEGER NOT NULL DEFAULT 0,
	rejected_by    INTEGER NOT NULL DEFAULT 0,
	revoked_at     INTEGER NOT NULL DEFAULT 0,
	revoked_by     INTEGER NOT NULL DEFAULT 0,
	revoked_by_org TEXT    NOT NULL DEFAULT ''
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_shares_active
	ON shares(source_org, source_node, target_org, provider, subject)
	WHERE status IN ('pending', 'accepted');

CREATE INDEX IF NOT EXISTS idx_shares_source ON shares(source_org, source_node, status);
CREATE INDEX IF NOT EXISTS idx_shares_target ON shares(target_org, provider, subject, status);
CREATE INDEX IF NOT EXISTS idx_shares_user ON shares(target_org, accepted_by, status);
`,
	`
ALTER TABLE shares ADD COLUMN source_generation TEXT NOT NULL DEFAULT '';
ALTER TABLE shares ADD COLUMN source_stable_id TEXT NOT NULL DEFAULT '';
ALTER TABLE shares ADD COLUMN source_user_created INTEGER NOT NULL DEFAULT 0;
ALTER TABLE shares ADD COLUMN target_generation TEXT NOT NULL DEFAULT '';
ALTER TABLE shares ADD COLUMN target_kind TEXT NOT NULL DEFAULT 'external';
ALTER TABLE shares ADD COLUMN target_account INTEGER NOT NULL DEFAULT 0;
ALTER TABLE shares ADD COLUMN target_account_created INTEGER NOT NULL DEFAULT 0;
UPDATE shares SET status = 'revoked', revoked_at = unixepoch() WHERE status IN ('pending', 'accepted');
DROP INDEX idx_shares_active;
CREATE UNIQUE INDEX idx_shares_active ON shares(source_org, source_generation, source_stable_id, target_org, target_generation, provider, subject)
 WHERE target_kind = 'external' AND status IN ('pending', 'accepted');
CREATE UNIQUE INDEX idx_shares_account_active ON shares(source_org, source_generation, source_stable_id, target_org, target_generation, target_account, target_account_created)
 WHERE target_kind = 'account' AND status IN ('pending', 'accepted');
CREATE INDEX idx_shares_account ON shares(target_org, target_account, status);
CREATE TABLE share_events (
 id INTEGER PRIMARY KEY AUTOINCREMENT, share_id TEXT NOT NULL REFERENCES shares(id),
 action TEXT NOT NULL, actor_org TEXT NOT NULL, actor_user INTEGER NOT NULL, created_at INTEGER NOT NULL
);
`,
}

// OpenShareRegistry opens (creating if necessary) the registry and applies
// pending migrations.
func OpenShareRegistry(ctx context.Context, cfg ShareRegistryConfig) (*ShareRegistry, error) {
	if cfg.Path == "" {
		return nil, errors.New("control: share registry needs a database path")
	}
	if strings.ContainsAny(cfg.Path, "?#") {
		return nil, fmt.Errorf("control: unsupported character in database path %q", cfg.Path)
	}
	if err := os.MkdirAll(filepath.Dir(cfg.Path), 0o700); err != nil {
		return nil, fmt.Errorf("control: creating the share registry directory: %w", err)
	}

	db, err := sql.Open("sqlite", cfg.Path+"?_pragma=busy_timeout(5000)&_txlock=immediate")
	if err != nil {
		return nil, fmt.Errorf("control: opening the share registry: %w", err)
	}
	// One process owns this file; a single connection keeps the WAL honest
	// and avoids "database is locked" churn between the router's writers.
	db.SetMaxOpenConns(1)
	if _, err := db.ExecContext(ctx, `PRAGMA journal_mode = WAL`); err != nil {
		db.Close()
		return nil, fmt.Errorf("control: enabling WAL: %w", err)
	}
	if _, err := db.ExecContext(ctx, `PRAGMA foreign_keys = ON`); err != nil {
		db.Close()
		return nil, fmt.Errorf("control: enabling foreign keys: %w", err)
	}
	registry := &ShareRegistry{db: db}
	if err := registry.migrate(ctx); err != nil {
		db.Close()
		return nil, err
	}
	return registry, nil
}

// migrate applies pending schema versions.
func (r *ShareRegistry) migrate(ctx context.Context) error {
	return migrateRegistry(ctx, r.db, shareMigrations, "share")
}

// Close releases the registry's database handle.
func (r *ShareRegistry) Close() error {
	if r == nil || r.db == nil {
		return nil
	}
	return r.db.Close()
}

// newShareID returns a fresh random share identifier.
func newShareID() (string, error) {
	var buf [12]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", fmt.Errorf("control: generating a share id: %w", err)
	}
	return "shr_" + hex.EncodeToString(buf[:]), nil
}

// CreateShare stores a new pending share and returns it with its assigned ID
// and timestamp. The caller is responsible for validating the parties.
func (r *ShareRegistry) CreateShare(ctx context.Context, share Share, now time.Time) (Share, error) {
	if share.TargetKind == "" {
		share.TargetKind = ShareTargetExternal
	}
	if share.SourceOrg == "" || share.TargetOrg == "" || share.SourceGeneration == "" || share.TargetGeneration == "" || share.SourceStableID == "" || share.SourceUserCreated <= 0 {
		return Share{}, errors.New("control: share needs a source organization, a target organization and an identity")
	}
	switch share.TargetKind {
	case ShareTargetExternal:
		if share.Provider == "" || share.Subject == "" || share.TargetAccount != 0 || share.TargetAccountCreated != 0 {
			return Share{}, errShareIdentityInvalid
		}
	case ShareTargetAccount:
		if share.TargetAccount <= 0 || share.TargetAccountCreated <= 0 || share.Provider != "" || share.Subject != "" {
			return Share{}, errShareIdentityInvalid
		}
	default:
		return Share{}, errShareIdentityInvalid
	}
	if share.SourceNode <= 0 {
		return Share{}, errors.New("control: share needs a source node")
	}
	if share.Status == "" {
		share.Status = SharePending
	}
	if share.Status != SharePending {
		return Share{}, fmt.Errorf("control: new shares start pending, got %q", share.Status)
	}

	id, err := newShareID()
	if err != nil {
		return Share{}, err
	}
	share.ID = id
	share.CreatedAt = now.UTC()

	transaction, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return Share{}, err
	}
	defer transaction.Rollback()
	_, err = transaction.ExecContext(ctx, `
INSERT INTO shares (id, source_org, source_node, target_org, provider, subject, status, created_by, created_at,
 source_generation, source_stable_id, source_user_created, target_generation, target_kind, target_account, target_account_created)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		share.ID, share.SourceOrg, share.SourceNode, share.TargetOrg, share.Provider, share.Subject,
		share.Status, share.CreatedBy, share.CreatedAt.Unix(), share.SourceGeneration, share.SourceStableID, share.SourceUserCreated,
		share.TargetGeneration, share.TargetKind, share.TargetAccount, share.TargetAccountCreated)
	if err != nil {
		if isUniqueViolation(err) {
			return Share{}, fmt.Errorf("%w: %w", ErrShareExists, err)
		}
		return Share{}, fmt.Errorf("control: storing share: %w", err)
	}
	if err := insertShareEvent(ctx, transaction, share.ID, "created", share.SourceOrg, share.CreatedBy, now); err != nil {
		return Share{}, err
	}
	if err := transaction.Commit(); err != nil {
		return Share{}, err
	}
	return share, nil
}

const shareColumns = `id, source_org, source_node, target_org, provider, subject, status,
 created_by, created_at, accepted_at, accepted_by, rejected_at, rejected_by, revoked_at, revoked_by, revoked_by_org,
 source_generation, source_stable_id, source_user_created, target_generation, target_kind, target_account, target_account_created`

func (r *ShareRegistry) LookupShare(ctx context.Context, id string) (Share, error) {
	share, err := scanShare(r.db.QueryRowContext(ctx, "SELECT "+shareColumns+" FROM shares WHERE id = ?", id))
	if errors.Is(err, sql.ErrNoRows) {
		return Share{}, ErrShareNotFound
	}
	return share, err
}

// GetShare returns a share by ID.
func (r *ShareRegistry) GetShare(id string) (Share, bool) {
	share, err := r.LookupShare(context.Background(), id)
	if err != nil {
		return Share{}, false
	}
	return share, true
}

// ListShares returns matching shares, newest first (ID breaks ties so the
// order is total).
func (r *ShareRegistry) ListShares(filter ShareFilter) []Share {
	shares, _ := r.QueryShares(context.Background(), filter)
	return shares
}

func (r *ShareRegistry) QueryShares(ctx context.Context, filter ShareFilter) ([]Share, error) {
	query := "SELECT " + shareColumns + " FROM shares"
	var (
		where []string
		args  []any
	)
	add := func(clause string, value any) {
		where = append(where, clause)
		args = append(args, value)
	}
	if filter.SourceOrg != "" {
		add("source_org = ?", filter.SourceOrg)
	}
	if filter.SourceNode != 0 {
		add("source_node = ?", filter.SourceNode)
	}
	if filter.TargetOrg != "" {
		add("target_org = ?", filter.TargetOrg)
	}
	if filter.TargetUser != 0 {
		add("accepted_by = ?", filter.TargetUser)
	}
	if filter.Provider != "" {
		add("provider = ?", filter.Provider)
	}
	if filter.Subject != "" {
		add("subject = ?", filter.Subject)
	}
	if filter.TargetKind != "" {
		add("target_kind = ?", filter.TargetKind)
	}
	if filter.TargetAccount != 0 {
		add("target_account = ?", filter.TargetAccount)
	}
	if len(filter.Statuses) > 0 {
		placeholders := make([]string, len(filter.Statuses))
		for i, status := range filter.Statuses {
			placeholders[i] = "?"
			args = append(args, status)
		}
		where = append(where, "status IN ("+strings.Join(placeholders, ", ")+")")
	}
	if len(where) > 0 {
		query += " WHERE " + strings.Join(where, " AND ")
	}
	query += " ORDER BY created_at DESC, id ASC"

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]Share, 0)
	for rows.Next() {
		share, err := scanShare(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, share)
	}
	return out, rows.Err()
}

// AcceptShare binds a pending share to the accepting user. It fails when the
// share is unknown, not pending, or belongs to another organization.
func (r *ShareRegistry) AcceptShare(id, targetOrg string, user int64, now time.Time) (Share, error) {
	return r.ChangeShare(context.Background(), id, targetOrg, user, ShareAccepted, now)
}

// RejectShare declines a pending share. It fails when the share is unknown,
// not pending, or belongs to another organization.
func (r *ShareRegistry) RejectShare(id, targetOrg string, user int64, now time.Time) (Share, error) {
	return r.ChangeShare(context.Background(), id, targetOrg, user, ShareRejected, now)
}

// RevokeShare withdraws a pending or accepted share. Revoking an already
// revoked share is idempotent and returns the existing row.
func (r *ShareRegistry) RevokeShare(id, byOrg string, user int64, now time.Time) (Share, error) {
	return r.ChangeShare(context.Background(), id, byOrg, user, ShareRevoked, now)
}

// 状态与必需事件共用写事务；并发接受/拒绝只能有一方报告成功。
func (r *ShareRegistry) ChangeShare(ctx context.Context, id, byOrg string, user int64, status string, now time.Time) (Share, error) {
	transaction, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return Share{}, err
	}
	defer transaction.Rollback()
	share, err := scanShare(transaction.QueryRowContext(ctx, "SELECT "+shareColumns+" FROM shares WHERE id = ?", id))
	if errors.Is(err, sql.ErrNoRows) {
		return Share{}, ErrShareNotFound
	}
	if err != nil {
		return Share{}, err
	}
	if byOrg != share.TargetOrg && (status != ShareRevoked || byOrg != share.SourceOrg) {
		return Share{}, ErrShareTarget
	}
	if byOrg == share.TargetOrg && share.TargetKind == ShareTargetAccount && user != share.TargetAccount {
		return Share{}, ErrShareTarget
	}
	if status == ShareRevoked && share.Status == ShareRevoked {
		return share, nil
	}
	if share.Status != SharePending && (status != ShareRevoked || share.Status != ShareAccepted) {
		return Share{}, ErrShareState
	}
	var update string
	args := []any{status, now.UTC().Unix(), user}
	switch status {
	case ShareAccepted:
		update = "accepted_at = ?, accepted_by = ?"
	case ShareRejected:
		update = "rejected_at = ?, rejected_by = ?"
	case ShareRevoked:
		update = "revoked_at = ?, revoked_by = ?, revoked_by_org = ?"
		args = append(args, byOrg)
	default:
		return Share{}, ErrShareState
	}
	args = append(args, id, share.Status)
	updated, err := scanShare(transaction.QueryRowContext(ctx, "UPDATE shares SET status = ?, "+update+" WHERE id = ? AND status = ? RETURNING "+shareColumns, args...))
	if errors.Is(err, sql.ErrNoRows) {
		return Share{}, ErrShareState
	}
	if err != nil {
		return Share{}, err
	}
	if err := insertShareEvent(ctx, transaction, id, status, byOrg, user, now); err != nil {
		return Share{}, err
	}
	if err := transaction.Commit(); err != nil {
		return Share{}, err
	}
	return updated, nil
}

func insertShareEvent(ctx context.Context, transaction *sql.Tx, id, action, org string, user int64, now time.Time) error {
	_, err := transaction.ExecContext(ctx, "INSERT INTO share_events (share_id, action, actor_org, actor_user, created_at) VALUES (?, ?, ?, ?, ?)", id, action, org, user, now.UnixNano())
	return err
}

// scanShare reads one share row.
func scanShare(scan interface{ Scan(...any) error }) (Share, error) {
	var (
		share                                        Share
		createdAt, acceptedAt, rejectedAt, revokedAt int64
		acceptedBy, rejectedBy, revokedBy            int64
	)
	if err := scan.Scan(
		&share.ID, &share.SourceOrg, &share.SourceNode, &share.TargetOrg,
		&share.Provider, &share.Subject, &share.Status, &share.CreatedBy, &createdAt,
		&acceptedAt, &acceptedBy, &rejectedAt, &rejectedBy,
		&revokedAt, &revokedBy, &share.RevokedByOrg,
		&share.SourceGeneration, &share.SourceStableID, &share.SourceUserCreated, &share.TargetGeneration,
		&share.TargetKind, &share.TargetAccount, &share.TargetAccountCreated,
	); err != nil {
		return Share{}, err
	}
	share.CreatedAt = time.Unix(createdAt, 0).UTC()
	if acceptedAt != 0 {
		share.AcceptedAt = time.Unix(acceptedAt, 0).UTC()
	}
	if rejectedAt != 0 {
		share.RejectedAt = time.Unix(rejectedAt, 0).UTC()
	}
	if revokedAt != 0 {
		share.RevokedAt = time.Unix(revokedAt, 0).UTC()
	}
	share.AcceptedBy, share.RejectedBy, share.RevokedBy = acceptedBy, rejectedBy, revokedBy
	return share, nil
}

// validShareStatus reports whether status is a known lifecycle value.
func validShareStatus(status string) bool {
	return slices.Contains([]string{SharePending, ShareAccepted, ShareRejected, ShareRevoked}, status)
}
