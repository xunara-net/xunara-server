package identity

import (
	"context"
	"database/sql"
	"errors"

	"tailscale.com/tailcfg"
)

// 已发布的旧表保留给迁移和成套回退；只清理残存凭证，不再生成或兑换重置码。
func deletePasswordReset(ctx context.Context, transaction *sql.Tx, userID tailcfg.UserID) error {
	var expected int64
	if err := transaction.QueryRowContext(ctx, "SELECT COUNT(*) FROM password_reset_tickets WHERE user_id = ?", int64(userID)).Scan(&expected); err != nil {
		return err
	}
	result, err := transaction.ExecContext(ctx, "DELETE FROM password_reset_tickets WHERE user_id = ?", int64(userID))
	if err != nil {
		return err
	}
	deleted, err := result.RowsAffected()
	if err != nil || deleted != expected {
		return errors.New("identity: password reset was not fully invalidated")
	}
	return nil
}
