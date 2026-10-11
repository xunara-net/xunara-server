package identity

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"tailscale.com/tailcfg"
)

func (store *SQLiteStore) ListAccountLoginHistory(ctx context.Context, userID tailcfg.UserID, options LoginHistoryOptions) (LoginHistoryPage, error) {
	limit, cursor, err := options.validate()
	if err != nil {
		return LoginHistoryPage{}, err
	}
	if userID == 0 {
		return LoginHistoryPage{}, ErrUserNotFound
	}
	query := `SELECT id, auth_method, kind, created_at, expires_at, last_seen_at,
		revoked_at, revoked_reason, client_ip, user_agent FROM account_login_records WHERE user_id = ?`
	arguments := []any{int64(userID)}
	if cursor.id != "" {
		query += " AND (created_at < ? OR (created_at = ? AND id < ?))"
		arguments = append(arguments, cursor.createdAt, cursor.createdAt, cursor.id)
	}
	query += " ORDER BY created_at DESC, id DESC LIMIT ?"
	arguments = append(arguments, limit+1)
	rows, err := store.db.QueryContext(ctx, query, arguments...)
	if err != nil {
		return LoginHistoryPage{}, fmt.Errorf("identity: listing account login history: %w", err)
	}
	defer rows.Close()
	page := LoginHistoryPage{Records: make([]LoginRecord, 0, limit)}
	for rows.Next() {
		var record LoginRecord
		var createdAt, expiresAt int64
		var lastSeenAt, revokedAt sql.NullInt64
		if err := rows.Scan(&record.ID, &record.AuthMethod, &record.Kind, &createdAt, &expiresAt,
			&lastSeenAt, &revokedAt, &record.RevokedReason, &record.ClientInfo.IP, &record.ClientInfo.UserAgent); err != nil {
			return LoginHistoryPage{}, fmt.Errorf("identity: reading account login history: %w", err)
		}
		record.UserID = userID
		record.CreatedAt = time.Unix(0, createdAt).UTC()
		record.ExpiresAt = time.Unix(0, expiresAt).UTC()
		if lastSeenAt.Valid {
			record.LastSeenAt = time.Unix(0, lastSeenAt.Int64).UTC()
		}
		if revokedAt.Valid {
			record.RevokedAt = time.Unix(0, revokedAt.Int64).UTC()
		}
		page.Records = append(page.Records, record)
	}
	if err := rows.Err(); err != nil {
		return LoginHistoryPage{}, fmt.Errorf("identity: reading account login history rows: %w", err)
	}
	if len(page.Records) > limit {
		page.Records = page.Records[:limit]
		page.NextCursor = encodeLoginHistoryCursor(page.Records[limit-1])
	}
	return page, nil
}

// 删除账号的隐私清理不能只依赖连接的 foreign_keys 设置；忽略写入也必须回滚。
func deleteAccountLoginHistory(ctx context.Context, transaction *sql.Tx, userID tailcfg.UserID) error {
	for _, table := range []string{"sessions", "account_login_records"} {
		var expected int64
		if err := transaction.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+table+" WHERE user_id = ?", int64(userID)).Scan(&expected); err != nil {
			return fmt.Errorf("identity: counting account login cleanup: %w", err)
		}
		result, err := transaction.ExecContext(ctx, "DELETE FROM "+table+" WHERE user_id = ?", int64(userID))
		if err != nil {
			return fmt.Errorf("identity: deleting account login history: %w", err)
		}
		affected, err := result.RowsAffected()
		if err != nil || affected != expected {
			return fmt.Errorf("identity: incomplete account login cleanup (expected %d, got %d): %v", expected, affected, err)
		}
	}
	return nil
}
