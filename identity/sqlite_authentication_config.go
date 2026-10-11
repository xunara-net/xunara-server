package identity

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"time"

	"tailscale.com/tailcfg"
)

func (store *SQLiteStore) ReadAuthenticationConfig(ctx context.Context) (AuthenticationConfig, error) {
	var config AuthenticationConfig
	err := store.db.QueryRowContext(ctx, "SELECT revision, payload FROM authentication_config WHERE id = 1").Scan(&config.Revision, &config.Payload)
	if errors.Is(err, sql.ErrNoRows) {
		return AuthenticationConfig{}, nil
	}
	return config, err
}

func (store *SQLiteStore) SaveAuthenticationConfig(ctx context.Context, config AuthenticationConfig, writer AuthenticationConfigWrite) (AuthenticationConfig, error) {
	if len(config.Payload) == 0 || len(config.Payload) > 256<<10 || writer.Detail == "" {
		return AuthenticationConfig{}, errors.New("identity: invalid authentication configuration")
	}
	transaction, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return AuthenticationConfig{}, err
	}
	defer transaction.Rollback()
	if err := lockAuthenticationRevision(ctx, transaction, config.Revision); err != nil {
		return AuthenticationConfig{}, err
	}
	// 条件写先取得数据库写锁；所有者权限、最后登录方式和审计随后在同一事务复核。
	result, err := transaction.ExecContext(ctx, `INSERT INTO authentication_config (id, revision, payload) VALUES (1, ?, ?)
		ON CONFLICT(id) DO UPDATE SET revision = excluded.revision, payload = excluded.payload WHERE authentication_config.revision = ?`,
		config.Revision+1, config.Payload, config.Revision)
	if err != nil {
		return AuthenticationConfig{}, err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return AuthenticationConfig{}, err
	}
	if count != 1 {
		return AuthenticationConfig{}, ErrAuthenticationConfigChanged
	}
	now := time.Now().UTC()
	actor := "platform"
	if !writer.Platform {
		if err := lockInviteOwner(ctx, transaction, writer.UserID, writer.SessionID, now); err != nil {
			return AuthenticationConfig{}, err
		}
		actor = fmt.Sprintf("user:%d", writer.UserID)
	}
	if err := protectProviderLoginMethods(ctx, transaction, writer.Removed, writer.Methods); err != nil {
		return AuthenticationConfig{}, err
	}
	// 只取消尚未完成的人类认证，不撤销现有 Session，更不改变设备审批或连接。
	if _, err := transaction.ExecContext(ctx, "DELETE FROM auth_transactions WHERE consumed_at IS NULL AND provider_id != ?", LocalProviderID); err != nil {
		return AuthenticationConfig{}, err
	}
	if err := insertIdentityAudit(ctx, transaction, actor, AuditAuthenticationConfigured, "authentication", writer.Detail, now); err != nil {
		return AuthenticationConfig{}, err
	}
	if err := transaction.Commit(); err != nil {
		return AuthenticationConfig{}, err
	}
	config.Revision++
	return config, nil
}

// 版本 0 表示沿用部署配置。也要锁住无记录的情况，避免首次配置与注册并发绕过。
func lockAuthenticationRevision(ctx context.Context, transaction *sql.Tx, expected uint64) error {
	if _, err := transaction.ExecContext(ctx, "UPDATE authentication_config SET revision = revision WHERE id = 1"); err != nil {
		return err
	}
	var revision uint64
	if err := transaction.QueryRowContext(ctx, "SELECT COALESCE((SELECT revision FROM authentication_config WHERE id = 1), 0)").Scan(&revision); err != nil {
		return err
	}
	if revision != expected {
		return ErrAuthenticationConfigChanged
	}
	return nil
}

func protectProviderLoginMethods(ctx context.Context, transaction *sql.Tx, removed []string, methods LoginMethods) error {
	for _, providerID := range removed {
		rows, err := transaction.QueryContext(ctx, "SELECT DISTINCT user_id FROM external_identities WHERE provider_id = ?", providerID)
		if err != nil {
			return err
		}
		users := make([]tailcfg.UserID, 0)
		for rows.Next() {
			var userID tailcfg.UserID
			if err := rows.Scan(&userID); err != nil {
				rows.Close()
				return err
			}
			users = append(users, userID)
		}
		readErr := rows.Err()
		rows.Close()
		if readErr != nil {
			return readErr
		}
		for _, userID := range users {
			links, err := listAccountIdentities(ctx, transaction, userID)
			if err != nil {
				return err
			}
			usable := false
			for _, link := range links {
				usable = usable || link.ProviderID != LocalProviderID && slices.Contains(methods.Providers, link.ProviderID)
			}
			if !usable && methods.Local {
				if err := transaction.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM local_credentials WHERE user_id = ? AND length(password_hash) > 0)", int64(userID)).Scan(&usable); err != nil {
					return err
				}
			}
			if !usable && methods.Passkeys {
				if err := transaction.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM webauthn_credentials WHERE user_id = ?)", int64(userID)).Scan(&usable); err != nil {
					return err
				}
			}
			if !usable {
				return ErrLastLoginMethod
			}
		}
	}
	return nil
}
