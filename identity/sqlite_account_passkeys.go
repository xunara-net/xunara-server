package identity

import (
	"context"
	"fmt"
	"time"

	"tailscale.com/tailcfg"
)

// ListAccountPasskeys 不吞掉存储错误；失败不能被 UI 误认为账户尚未绑定凭据。
func (store *SQLiteStore) ListAccountPasskeys(ctx context.Context, userID tailcfg.UserID) ([]Passkey, error) {
	rows, err := store.db.QueryContext(ctx,
		"SELECT "+passkeyColumns+" FROM webauthn_credentials WHERE user_id = ? ORDER BY created_at, id", int64(userID))
	if err != nil {
		return nil, fmt.Errorf("identity: listing account passkeys: %w", err)
	}
	defer rows.Close()
	passkeys := make([]Passkey, 0)
	for rows.Next() {
		passkey, err := scanPasskey(rows)
		if err != nil {
			return nil, fmt.Errorf("identity: reading account passkey: %w", err)
		}
		passkeys = append(passkeys, passkey)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("identity: reading account passkeys: %w", err)
	}
	return passkeys, nil
}

func (store *SQLiteStore) CreateAccountPasskey(ctx context.Context, initiatingID string, passkey Passkey) (Passkey, error) {
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return Passkey{}, fmt.Errorf("identity: starting passkey registration: %w", err)
	}
	defer tx.Rollback()
	now := time.Now().UTC()
	if err := lockAccountSession(ctx, tx, passkey.UserID, initiatingID, now); err != nil {
		return Passkey{}, err
	}
	if err := insertPasskey(ctx, tx, &passkey); err != nil {
		return Passkey{}, err
	}
	if err := insertAccountAudit(ctx, tx, passkey.UserID, AuditPasskeyRegistered, "registered passkey:"+passkey.ID, now); err != nil {
		return Passkey{}, err
	}
	if err := tx.Commit(); err != nil {
		return Passkey{}, fmt.Errorf("identity: committing passkey registration: %w", err)
	}
	return passkey, nil
}

func (store *SQLiteStore) DeleteAccountPasskey(ctx context.Context, userID tailcfg.UserID, initiatingID, passkeyID string) error {
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("identity: starting passkey deletion: %w", err)
	}
	defer tx.Rollback()
	now := time.Now().UTC()
	if err := lockAccountSession(ctx, tx, userID, initiatingID, now); err != nil {
		return err
	}
	// 公共 ID 不能代替所有权；未知 ID 和其他账户的 ID 均返回同一种错误。
	result, err := tx.ExecContext(ctx, "DELETE FROM webauthn_credentials WHERE id = ? AND user_id = ?", passkeyID, int64(userID))
	if err != nil {
		return fmt.Errorf("identity: deleting account passkey: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("identity: checking account passkey deletion: %w", err)
	}
	if affected != 1 {
		return ErrPasskeyNotFound
	}
	if err := insertAccountAudit(ctx, tx, userID, AuditPasskeyDeleted, "deleted passkey:"+passkeyID, now); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("identity: committing passkey deletion: %w", err)
	}
	return nil
}

// CreatePasskeySession 防止签名验证期间凭据被删除后，仍以旧验证结果签发新会话。
// 凭据删除和会话签发通过同一数据库写锁串行化，而不是依赖单实例内存锁。
func (store *SQLiteStore) CreatePasskeySession(ctx context.Context, userID tailcfg.UserID, passkeyID string, ttl time.Duration) (Session, string, error) {
	token, err := newSecret()
	if err != nil {
		return Session{}, "", err
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return Session{}, "", fmt.Errorf("identity: starting passkey session: %w", err)
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `UPDATE webauthn_credentials SET last_used_at = last_used_at
		WHERE id = ? AND user_id = ? AND EXISTS (SELECT 1 FROM users WHERE id = ?)`, passkeyID, int64(userID), int64(userID))
	if err != nil {
		return Session{}, "", fmt.Errorf("identity: checking passkey session: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return Session{}, "", fmt.Errorf("identity: checking passkey session count: %w", err)
	}
	if affected != 1 {
		return Session{}, "", ErrPasskeyNotFound
	}
	session, err := store.createSession(ctx, tx, NewSessionOptions{UserID: userID, AuthMethod: "passkey", TTL: ttl}, token)
	if err != nil {
		return Session{}, "", err
	}
	for _, event := range []struct{ action, detail string }{
		{AuditLoginSucceeded, "authenticated with method=passkey"},
		{AuditSessionCreated, "session:" + session.ID + "; auth method passkey"},
	} {
		if err := insertAccountAudit(ctx, tx, userID, event.action, event.detail, session.CreatedAt); err != nil {
			return Session{}, "", err
		}
	}
	if err := tx.Commit(); err != nil {
		return Session{}, "", fmt.Errorf("identity: committing passkey session: %w", err)
	}
	return session, token, nil
}
