package identity

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"tailscale.com/tailcfg"
)

const sessionColumns = "id, token_hash, user_id, auth_method, created_at, expires_at, last_seen_at, revoked_at, revoked_reason, rotated_from"

// CreateSession implements [SessionStore].
func (s *SQLiteStore) CreateSession(opts NewSessionOptions) (Session, string, error) {
	token, err := newSecret()
	if err != nil {
		return Session{}, "", err
	}
	session, err := s.createSession(context.Background(), s.db, opts, token)
	if err != nil {
		return Session{}, "", err
	}
	return session, token, nil
}

// createSession inserts a session for an already-generated token. It takes an
// executor so rotation can revoke and reissue inside one transaction.
func (s *SQLiteStore) createSession(ctx context.Context, exec interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}, opts NewSessionOptions, token string) (Session, error) {
	if opts.UserID == 0 {
		return Session{}, fmt.Errorf("identity: session needs a user")
	}

	ttl := opts.TTL
	if ttl <= 0 {
		ttl = DefaultSessionTTL
	}

	id, err := newSecret()
	if err != nil {
		return Session{}, err
	}

	now := time.Now().UTC()
	session := Session{
		ID:          id,
		UserID:      opts.UserID,
		AuthMethod:  opts.AuthMethod,
		CreatedAt:   now,
		ExpiresAt:   now.Add(ttl),
		LastSeenAt:  now,
		RotatedFrom: opts.RotatedFrom,
	}

	if _, err := exec.ExecContext(ctx,
		`INSERT INTO sessions (`+sessionColumns+`) VALUES (?, ?, ?, ?, ?, ?, ?, NULL, '', ?)`,
		session.ID, HashSecret(token), int64(session.UserID), session.AuthMethod,
		session.CreatedAt.UnixNano(), session.ExpiresAt.UnixNano(), session.LastSeenAt.UnixNano(),
		session.RotatedFrom); err != nil {
		return Session{}, fmt.Errorf("identity: creating session: %w", err)
	}
	return session, nil
}

// GetSessionByToken implements [SessionStore].
func (s *SQLiteStore) GetSessionByToken(token string) (Session, error) {
	now := time.Now().UTC()
	row := s.db.QueryRowContext(context.Background(),
		"SELECT "+sessionColumns+" FROM sessions WHERE token_hash = ? AND revoked_at IS NULL AND expires_at > ?",
		HashSecret(token), now.UnixNano())

	session, err := scanSession(row)
	if err != nil {
		return Session{}, ErrSessionNotFound
	}
	return session, nil
}

// GetSessionByID implements [SessionStore].
func (s *SQLiteStore) GetSessionByID(id string) (Session, bool) {
	row := s.db.QueryRowContext(context.Background(),
		"SELECT "+sessionColumns+" FROM sessions WHERE id = ?", id)
	session, err := scanSession(row)
	if err != nil {
		return Session{}, false
	}
	return session, true
}

// ListSessions implements [SessionStore].
func (s *SQLiteStore) ListSessions(userID tailcfg.UserID) []Session {
	rows, err := s.db.QueryContext(context.Background(),
		"SELECT "+sessionColumns+" FROM sessions WHERE user_id = ? ORDER BY created_at DESC", int64(userID))
	if err != nil {
		return nil
	}
	defer rows.Close()

	var out []Session
	for rows.Next() {
		session, err := scanSession(rows)
		if err != nil {
			return nil
		}
		out = append(out, session)
	}
	return out
}

// TouchSession implements [SessionStore].
func (s *SQLiteStore) TouchSession(id string, now time.Time) error {
	_, err := s.db.ExecContext(context.Background(),
		"UPDATE sessions SET last_seen_at = ? WHERE id = ?", now.UnixNano(), id)
	if err != nil {
		return fmt.Errorf("identity: touching session: %w", err)
	}
	return nil
}

// RevokeSession implements [SessionStore].
func (s *SQLiteStore) RevokeSession(id, reason string) error {
	_, err := s.db.ExecContext(context.Background(),
		"UPDATE sessions SET revoked_at = ?, revoked_reason = ? WHERE id = ? AND revoked_at IS NULL",
		time.Now().UTC().UnixNano(), reason, id)
	if err != nil {
		return fmt.Errorf("identity: revoking session: %w", err)
	}
	return nil
}

// RevokeUserSessions implements [SessionStore].
func (s *SQLiteStore) RevokeUserSessions(userID tailcfg.UserID, reason string) (int64, error) {
	res, err := s.db.ExecContext(context.Background(),
		"UPDATE sessions SET revoked_at = ?, revoked_reason = ? WHERE user_id = ? AND revoked_at IS NULL",
		time.Now().UTC().UnixNano(), reason, int64(userID))
	if err != nil {
		return 0, fmt.Errorf("identity: revoking user sessions: %w", err)
	}
	return res.RowsAffected()
}

// RotateSession implements [SessionStore].
func (s *SQLiteStore) RotateSession(token string, ttl time.Duration) (Session, string, error) {
	old, err := s.GetSessionByToken(token)
	if err != nil {
		return Session{}, "", err
	}

	newToken, err := newSecret()
	if err != nil {
		return Session{}, "", err
	}

	ctx := context.Background()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Session{}, "", fmt.Errorf("identity: starting session rotation: %w", err)
	}
	defer tx.Rollback()

	now := time.Now().UTC().UnixNano()
	result, err := tx.ExecContext(ctx,
		"UPDATE sessions SET revoked_at = ?, revoked_reason = 'rotated' WHERE id = ? AND revoked_at IS NULL AND expires_at > ?",
		now, old.ID, now)
	if err != nil {
		return Session{}, "", fmt.Errorf("identity: revoking rotated session: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return Session{}, "", fmt.Errorf("identity: checking rotated session: %w", err)
	}
	if affected != 1 {
		return Session{}, "", ErrSessionRevoked
	}

	session, err := s.createSession(ctx, tx, NewSessionOptions{
		UserID:      old.UserID,
		AuthMethod:  old.AuthMethod,
		TTL:         ttl,
		RotatedFrom: old.ID,
	}, newToken)
	if err != nil {
		return Session{}, "", err
	}
	if err := tx.Commit(); err != nil {
		return Session{}, "", fmt.Errorf("identity: committing session rotation: %w", err)
	}
	return session, newToken, nil
}

// DeleteExpiredSessions implements [SessionStore].
func (s *SQLiteStore) DeleteExpiredSessions(now time.Time) (int64, error) {
	res, err := s.db.ExecContext(context.Background(),
		"DELETE FROM sessions WHERE expires_at <= ?", now.UnixNano())
	if err != nil {
		return 0, fmt.Errorf("identity: deleting expired sessions: %w", err)
	}
	return res.RowsAffected()
}

func scanSession(sc rowScanner) (Session, error) {
	var (
		session   Session
		tokenHash string
		userID    int64
		createdAt int64
		expiresAt int64
		lastSeen  sql.NullInt64
		revokedAt sql.NullInt64
	)
	if err := sc.Scan(&session.ID, &tokenHash, &userID, &session.AuthMethod, &createdAt,
		&expiresAt, &lastSeen, &revokedAt, &session.RevokedReason, &session.RotatedFrom); err != nil {
		return Session{}, err
	}
	session.UserID = tailcfg.UserID(userID)
	session.CreatedAt = time.Unix(0, createdAt).UTC()
	session.ExpiresAt = time.Unix(0, expiresAt).UTC()
	if lastSeen.Valid {
		session.LastSeenAt = time.Unix(0, lastSeen.Int64).UTC()
	}
	if revokedAt.Valid {
		session.RevokedAt = time.Unix(0, revokedAt.Int64).UTC()
	}
	return session, nil
}
