package identity

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"tailscale.com/tailcfg"
)

const inviteColumns = "id, token_hash, role, note, created_by, created_at, expires_at, used_at, used_by"

// CreateRegistrationInvite implements [RegistrationInviteStore].
func (s *SQLiteStore) CreateRegistrationInvite(opts NewRegistrationInviteOptions) (RegistrationInvite, string, error) {
	invite, token, err := prepareRegistrationInvite(opts)
	if err != nil {
		return RegistrationInvite{}, "", err
	}
	if err := insertRegistrationInvite(context.Background(), s.db, invite); err != nil {
		return RegistrationInvite{}, "", err
	}
	return invite, token, nil
}

func prepareRegistrationInvite(opts NewRegistrationInviteOptions) (RegistrationInvite, string, error) {
	role, err := inviteRole(opts.Role)
	if err != nil {
		return RegistrationInvite{}, "", err
	}

	secret, err := newSecret()
	if err != nil {
		return RegistrationInvite{}, "", err
	}
	token := InvitePrefix + secret

	id, err := newID("inv-")
	if err != nil {
		return RegistrationInvite{}, "", err
	}

	now := time.Now().UTC()
	invite := RegistrationInvite{
		ID:        id,
		TokenHash: HashSecret(token),
		Role:      role,
		Note:      opts.Note,
		CreatedBy: opts.CreatedBy,
		CreatedAt: now,
	}
	if opts.TTL > 0 {
		invite.ExpiresAt = now.Add(opts.TTL)
	}

	// expires_at uses the package's zero sentinel for "no expiry" rather
	// than the zero time's UnixNano, which is a date in 1754 and would make
	// every invite without a TTL look long expired.
	return invite, token, nil
}

func insertRegistrationInvite(ctx context.Context, executor interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}, invite RegistrationInvite) error {
	if _, err := executor.ExecContext(ctx,
		"INSERT INTO registration_invites ("+inviteColumns+") VALUES (?, ?, ?, ?, ?, ?, ?, NULL, NULL)",
		invite.ID, invite.TokenHash, string(invite.Role), invite.Note, invite.CreatedBy,
		invite.CreatedAt.UnixNano(), timeToNanos(invite.ExpiresAt)); err != nil {
		return fmt.Errorf("identity: creating registration invite: %w", err)
	}
	return nil
}

// GetRegistrationInvite implements [RegistrationInviteStore].
func (s *SQLiteStore) GetRegistrationInvite(id string) (RegistrationInvite, bool) {
	row := s.db.QueryRowContext(context.Background(),
		"SELECT "+inviteColumns+" FROM registration_invites WHERE id = ?", id)
	invite, err := scanInvite(row)
	if err != nil {
		return RegistrationInvite{}, false
	}
	return invite, true
}

// ListRegistrationInvites implements [RegistrationInviteStore].
func (s *SQLiteStore) ListRegistrationInvites() []RegistrationInvite {
	invites, _ := s.ListRegistrationInvitesContext(context.Background())
	return invites
}

func (s *SQLiteStore) ListRegistrationInvitesContext(ctx context.Context) ([]RegistrationInvite, error) {
	rows, err := s.db.QueryContext(ctx,
		"SELECT "+inviteColumns+" FROM registration_invites ORDER BY created_at DESC")
	if err != nil {
		return nil, fmt.Errorf("identity: listing registration invites: %w", err)
	}
	defer rows.Close()

	out := make([]RegistrationInvite, 0)
	for rows.Next() {
		invite, err := scanInvite(rows)
		if err != nil {
			return nil, fmt.Errorf("identity: reading registration invite: %w", err)
		}
		out = append(out, invite)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("identity: reading registration invites: %w", err)
	}
	return out, nil
}

// RevokeRegistrationInvite implements [RegistrationInviteStore].
func (s *SQLiteStore) RevokeRegistrationInvite(id string) error {
	ctx := context.Background()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("identity: starting invitation revocation: %w", err)
	}
	defer tx.Rollback()
	if err := revokeRegistrationInvite(ctx, tx, id); err != nil {
		return err
	}
	return tx.Commit()
}

func revokeRegistrationInvite(ctx context.Context, tx *sql.Tx, id string) error {
	res, err := tx.ExecContext(ctx,
		"DELETE FROM registration_invites WHERE id = ? AND used_at IS NULL", id)
	if err != nil {
		return fmt.Errorf("identity: revoking registration invite: %w", err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("identity: revoking registration invite: %w", err)
	}
	if affected == 0 {
		// Either the invite does not exist or it was already redeemed; the
		// second case is reported separately so the console can explain it.
		invite, err := scanInvite(tx.QueryRowContext(ctx, "SELECT "+inviteColumns+" FROM registration_invites WHERE id = ?", id))
		if errors.Is(err, sql.ErrNoRows) {
			return ErrInviteNotFound
		}
		if err != nil {
			return fmt.Errorf("identity: reading invitation for revocation: %w", err)
		}
		if invite.Redeemed() {
			return ErrInviteUsed
		}
		return ErrInviteNotFound
	}
	return nil
}

// FindRegistrationInvite implements [RegistrationInviteStore].
func (s *SQLiteStore) FindRegistrationInvite(token string) (RegistrationInvite, error) {
	return lookupUsableInvite(context.Background(), s.db, token, time.Now().UTC())
}

func lookupUsableInvite(ctx context.Context, query interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, token string, now time.Time) (RegistrationInvite, error) {
	token = normalizeInviteToken(token)
	if token == "" {
		return RegistrationInvite{}, ErrInviteNotFound
	}
	row := query.QueryRowContext(ctx,
		"SELECT "+inviteColumns+" FROM registration_invites WHERE token_hash = ?", HashSecret(token))
	invite, err := scanInvite(row)
	if errors.Is(err, sql.ErrNoRows) {
		return RegistrationInvite{}, ErrInviteNotFound
	}
	if err != nil {
		return RegistrationInvite{}, fmt.Errorf("identity: looking up registration invite: %w", err)
	}
	switch {
	case invite.Redeemed():
		return RegistrationInvite{}, ErrInviteUsed
	case invite.Expired(now):
		return RegistrationInvite{}, ErrInviteExpired
	}
	return invite, nil
}

func scanInvite(sc scanner) (RegistrationInvite, error) {
	var (
		id        string
		tokenHash string
		role      string
		note      string
		createdBy string
		createdAt int64
		expiresAt sql.NullInt64
		usedAt    sql.NullInt64
		usedBy    sql.NullInt64
	)
	if err := sc.Scan(&id, &tokenHash, &role, &note, &createdBy, &createdAt, &expiresAt, &usedAt, &usedBy); err != nil {
		return RegistrationInvite{}, err
	}
	invite := RegistrationInvite{
		ID:        id,
		TokenHash: tokenHash,
		Role:      Role(role),
		Note:      note,
		CreatedBy: createdBy,
		CreatedAt: time.Unix(0, createdAt).UTC(),
	}
	if expiresAt.Valid {
		invite.ExpiresAt = nanosToTime(expiresAt.Int64)
	}
	if usedAt.Valid {
		invite.UsedAt = time.Unix(0, usedAt.Int64).UTC()
	}
	if usedBy.Valid {
		invite.UsedBy = tailcfg.UserID(usedBy.Int64)
	}
	return invite, nil
}
