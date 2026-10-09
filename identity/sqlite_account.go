package identity

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"tailscale.com/tailcfg"
)

func (store *SQLiteStore) UpdateUserProfile(ctx context.Context, userID tailcfg.UserID, displayName, email *string) (User, error) {
	if displayName == nil && email == nil {
		return User{}, errors.New("identity: no profile fields supplied")
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return User{}, fmt.Errorf("identity: starting profile update: %w", err)
	}
	defer tx.Rollback()

	now := time.Now().UTC()
	user, err := scanUser(tx.QueryRowContext(ctx, `
		UPDATE users SET display_name = COALESCE(?, display_name), email = COALESCE(?, email), updated_at = ?
		WHERE id = ? RETURNING `+userColumns, displayName, email, now.UnixNano(), int64(userID)))
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, ErrUserNotFound
	}
	if err != nil {
		return User{}, fmt.Errorf("identity: updating profile: %w", err)
	}

	var fields []string
	if displayName != nil {
		fields = append(fields, "display_name")
	}
	if email != nil {
		fields = append(fields, "email")
	}
	if err := insertAccountAudit(ctx, tx, userID, AuditUserUpdated, "self-service updated "+strings.Join(fields, ", "), now); err != nil {
		return User{}, err
	}
	if err := tx.Commit(); err != nil {
		return User{}, fmt.Errorf("identity: committing profile update: %w", err)
	}
	return user, nil
}

func (store *SQLiteStore) CreateLocalSession(ctx context.Context, userID tailcfg.UserID, expectedHash []byte, ttl time.Duration) (Session, string, error) {
	if userID == 0 || len(expectedHash) == 0 {
		return Session{}, "", ErrCredentialChanged
	}
	token, err := newSecret()
	if err != nil {
		return Session{}, "", err
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return Session{}, "", fmt.Errorf("identity: starting password session: %w", err)
	}
	defer tx.Rollback()

	result, err := tx.ExecContext(ctx, `
		UPDATE local_credentials SET updated_at = updated_at
		WHERE user_id = ? AND password_hash = ? AND EXISTS (SELECT 1 FROM users WHERE id = ?)`,
		int64(userID), expectedHash, int64(userID))
	if err != nil {
		return Session{}, "", fmt.Errorf("identity: checking password session: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return Session{}, "", fmt.Errorf("identity: checking password session count: %w", err)
	}
	if affected != 1 {
		return Session{}, "", ErrCredentialChanged
	}

	session, err := store.createSession(ctx, tx, NewSessionOptions{
		UserID: userID, AuthMethod: LocalProviderID, TTL: ttl,
	}, token)
	if err != nil {
		return Session{}, "", err
	}
	if err := tx.Commit(); err != nil {
		return Session{}, "", fmt.Errorf("identity: committing password session: %w", err)
	}
	return session, token, nil
}

func (store *SQLiteStore) ChangeLocalPassword(ctx context.Context, userID tailcfg.UserID, sessionID string, expectedHash, replacementHash []byte) (int64, error) {
	if userID == 0 || sessionID == "" || len(expectedHash) == 0 || len(replacementHash) == 0 {
		return 0, ErrCredentialChanged
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("identity: starting password change: %w", err)
	}
	defer tx.Rollback()

	now := time.Now().UTC()
	result, err := tx.ExecContext(ctx, `
		UPDATE local_credentials SET password_hash = ?, updated_at = ?
		WHERE user_id = ? AND password_hash = ? AND EXISTS (
			SELECT 1 FROM sessions WHERE id = ? AND user_id = ? AND revoked_at IS NULL AND expires_at > ?
		) AND EXISTS (SELECT 1 FROM users WHERE id = ?)`,
		replacementHash, now.UnixNano(), int64(userID), expectedHash, sessionID, int64(userID), now.UnixNano(), int64(userID))
	if err != nil {
		return 0, fmt.Errorf("identity: replacing password: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("identity: checking password change count: %w", err)
	}
	if affected != 1 {
		return 0, ErrCredentialChanged
	}

	result, err = tx.ExecContext(ctx, `
		UPDATE sessions SET revoked_at = ?, revoked_reason = 'password changed'
		WHERE user_id = ? AND revoked_at IS NULL`, now.UnixNano(), int64(userID))
	if err != nil {
		return 0, fmt.Errorf("identity: revoking password sessions: %w", err)
	}
	revoked, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("identity: checking revoked session count: %w", err)
	}
	if err := insertAccountAudit(ctx, tx, userID, AuditPasswordChanged, fmt.Sprintf("password changed; revoked %d sessions", revoked), now); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("identity: committing password change: %w", err)
	}
	return revoked, nil
}

// lockAccountSession 用条件写入取得数据库写锁，并再次确认发起会话仍有效。
// 即使另一实例同时撤销或轮换会话，也不能凭 HTTP 层旧快照继续修改安全凭据。
// 自赋值不是活动心跳，不改变用户可见的最后使用时间。
func lockAccountSession(ctx context.Context, tx *sql.Tx, userID tailcfg.UserID, sessionID string, now time.Time) error {
	if userID == 0 || sessionID == "" {
		return ErrSessionRevoked
	}
	result, err := tx.ExecContext(ctx, `
		UPDATE sessions SET last_seen_at = last_seen_at
		WHERE id = ? AND user_id = ? AND revoked_at IS NULL AND expires_at > ?
		AND EXISTS (SELECT 1 FROM users WHERE id = ?)`,
		sessionID, int64(userID), now.UnixNano(), int64(userID))
	if err != nil {
		return fmt.Errorf("identity: checking initiating session: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("identity: checking initiating session count: %w", err)
	}
	if affected != 1 {
		return ErrSessionRevoked
	}
	return nil
}

// insertAccountAudit 与账户变更共用事务：写审计失败时，业务变更也必须回滚。
func insertAccountAudit(ctx context.Context, tx *sql.Tx, userID tailcfg.UserID, action, detail string, now time.Time) error {
	target := fmt.Sprintf("user:%d", userID)
	if _, err := tx.ExecContext(ctx,
		"INSERT INTO audit_events (ts, actor, action, target, detail) VALUES (?, ?, ?, ?, ?)",
		now.UnixNano(), target, action, target, detail); err != nil {
		return fmt.Errorf("identity: auditing account change: %w", err)
	}
	return nil
}
