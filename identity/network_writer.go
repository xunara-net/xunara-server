package identity

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"tailscale.com/tailcfg"
)

var ErrNetworkWriterForbidden = errors.New("identity: network administrator required")

// CheckNetworkWriter 复用持久会话校验；事务内再次确认角色，避免 HTTP 快照降权竞争。
func CheckNetworkWriter(ctx context.Context, tx *sql.Tx, userID tailcfg.UserID, sessionID, apiKeyID string, now time.Time) error {
	if (sessionID == "") == (apiKeyID == "") {
		return ErrNetworkWriterForbidden
	}
	if sessionID != "" {
		if err := lockAccountSession(ctx, tx, userID, sessionID, now); err != nil {
			return err
		}
	} else {
		var rawScopes string
		err := tx.QueryRowContext(ctx, `SELECT scopes FROM api_keys WHERE id = ? AND user_id = ?
			AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > ?)`,
			apiKeyID, int64(userID), now.UnixNano()).Scan(&rawScopes)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNetworkWriterForbidden
		}
		if err != nil {
			return fmt.Errorf("identity: checking network service key: %w", err)
		}
		// 持久格式与 CreateAPIKey/scanAPIKey 一致，不能把逗号分隔范围误读成 JSON。
		scopes := strings.Split(rawScopes, ",")
		if !slices.Contains(scopes, ScopeWrite) {
			return ErrNetworkWriterForbidden
		}
		for _, scope := range scopes {
			if !slices.Contains(validScopes, scope) {
				return ErrNetworkWriterForbidden
			}
		}
	}
	var role string
	if err := tx.QueryRowContext(ctx, "SELECT role FROM users WHERE id = ?", int64(userID)).Scan(&role); err != nil {
		return fmt.Errorf("identity: checking network writer: %w", err)
	}
	if !Role(role).CanWrite() {
		return ErrNetworkWriterForbidden
	}
	return nil
}
