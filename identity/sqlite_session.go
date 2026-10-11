package identity

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"tailscale.com/tailcfg"
)

const sessionColumns = "id, token_hash, user_id, auth_method, created_at, expires_at, last_seen_at, revoked_at, revoked_reason, rotated_from, client_ip, user_agent"

const SessionActivityInterval = time.Minute

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
	QueryRowContext(context.Context, string, ...any) *sql.Row
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
		ClientInfo:  opts.ClientInfo.Normalize(),
	}

	result, err := exec.ExecContext(ctx,
		`INSERT INTO sessions (`+sessionColumns+`) SELECT ?, ?, ?, ?, ?, ?, ?, NULL, '', ?, ?, ?
		WHERE EXISTS (SELECT 1 FROM users WHERE id = ? AND disabled_at IS NULL)`,
		session.ID, HashSecret(token), int64(session.UserID), session.AuthMethod,
		session.CreatedAt.UnixNano(), session.ExpiresAt.UnixNano(), session.LastSeenAt.UnixNano(),
		session.RotatedFrom, session.ClientInfo.IP, session.ClientInfo.UserAgent, int64(session.UserID))
	if err != nil {
		return Session{}, fmt.Errorf("identity: creating session: %w", err)
	}
	// 被触发器忽略的插入不是持久会话，不能返回看似有效的凭据。
	affected, err := result.RowsAffected()
	if err != nil {
		return Session{}, fmt.Errorf("identity: checking session insertion: %w", err)
	}
	if affected != 1 {
		var disabled bool
		err := exec.QueryRowContext(ctx, "SELECT disabled_at IS NOT NULL FROM users WHERE id = ?", int64(opts.UserID)).Scan(&disabled)
		if errors.Is(err, sql.ErrNoRows) {
			return Session{}, ErrUserNotFound
		}
		if err != nil {
			return Session{}, fmt.Errorf("identity: checking account session admission: %w", err)
		}
		if disabled {
			return Session{}, ErrUserDisabled
		}
		return Session{}, errors.New("identity: session did not persist exactly one row")
	}
	return session, nil
}

// GetSessionByToken implements [SessionStore].
func (s *SQLiteStore) GetSessionByToken(token string) (Session, error) {
	return s.lookupSession(context.Background(), token)
}

func (s *SQLiteStore) lookupSession(ctx context.Context, token string) (Session, error) {
	now := time.Now().UTC()
	row := s.db.QueryRowContext(ctx,
		"SELECT "+sessionColumns+" FROM sessions WHERE token_hash = ? AND revoked_at IS NULL AND expires_at > ? AND EXISTS (SELECT 1 FROM users WHERE id = sessions.user_id AND disabled_at IS NULL)",
		HashSecret(token), now.UnixNano())

	session, err := scanSession(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Session{}, ErrSessionNotFound
	}
	if err != nil {
		return Session{}, fmt.Errorf("identity: looking up session: %w", err)
	}
	return session, nil
}

func (s *SQLiteStore) UseSession(ctx context.Context, token string) (Session, error) {
	session, err := s.lookupSession(ctx, token)
	if err != nil {
		return Session{}, err
	}
	now := time.Now().UTC()
	if now.Sub(session.LastSeenAt) < SessionActivityInterval {
		return session, nil
	}
	session.LastSeenAt, err = s.touchSession(ctx, session.ID, session.UserID, now)
	if err != nil {
		return Session{}, err
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
	ctx := context.Background()
	session, err := scanSession(s.db.QueryRowContext(ctx, "SELECT "+sessionColumns+" FROM sessions WHERE id = ?", id))
	if errors.Is(err, sql.ErrNoRows) {
		return ErrSessionNotFound
	}
	if err != nil {
		return fmt.Errorf("identity: reading session for activity: %w", err)
	}
	_, err = s.touchSession(ctx, id, session.UserID, now)
	return err
}

// 数据库条件同时保证节流、单调、用户边界与有效性；跨实例不依赖内存缓存。
func (s *SQLiteStore) touchSession(ctx context.Context, id string, userID tailcfg.UserID, now time.Time) (time.Time, error) {
	result, err := s.db.ExecContext(ctx, `UPDATE sessions SET last_seen_at = ?
		WHERE id = ? AND user_id = ? AND revoked_at IS NULL AND expires_at > ?
		AND COALESCE(last_seen_at, 0) <= ?
		AND EXISTS (SELECT 1 FROM users WHERE id = sessions.user_id AND disabled_at IS NULL)`,
		now.UnixNano(), id, int64(userID), now.UnixNano(), now.Add(-SessionActivityInterval).UnixNano())
	if err != nil {
		return time.Time{}, fmt.Errorf("identity: recording session activity: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return time.Time{}, fmt.Errorf("identity: checking session activity: %w", err)
	}
	if affected == 1 {
		return now, nil
	}
	var lastSeen int64
	err = s.db.QueryRowContext(ctx, `SELECT COALESCE(last_seen_at, 0) FROM sessions
		WHERE id = ? AND user_id = ? AND revoked_at IS NULL AND expires_at > ?
		AND EXISTS (SELECT 1 FROM users WHERE id = sessions.user_id AND disabled_at IS NULL)`,
		id, int64(userID), now.UnixNano()).Scan(&lastSeen)
	if errors.Is(err, sql.ErrNoRows) {
		return time.Time{}, ErrSessionNotFound
	}
	if err != nil {
		return time.Time{}, fmt.Errorf("identity: rereading session activity: %w", err)
	}
	if lastSeen <= now.Add(-SessionActivityInterval).UnixNano() {
		return time.Time{}, errors.New("identity: required session activity was not written")
	}
	return time.Unix(0, lastSeen).UTC(), nil
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
		ClientInfo:  old.ClientInfo,
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
		&expiresAt, &lastSeen, &revokedAt, &session.RevokedReason, &session.RotatedFrom,
		&session.ClientInfo.IP, &session.ClientInfo.UserAgent); err != nil {
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
