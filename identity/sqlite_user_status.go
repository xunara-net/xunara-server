package identity

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"tailscale.com/tailcfg"
)

func (store *SQLiteStore) SetUserStatusByPlatform(ctx context.Context, userID tailcfg.UserID, change UserStatusChange) (UserStatusResult, error) {
	reason := strings.TrimSpace(change.Reason)
	if userID == 0 || change.ExpectedUpdatedAt.IsZero() || reason == "" || !utf8.ValidString(reason) || utf8.RuneCountInString(reason) > 256 || strings.ContainsFunc(reason, unicode.IsControl) {
		return UserStatusResult{}, ErrMemberInvalid
	}
	transaction, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return UserStatusResult{}, fmt.Errorf("identity: starting account status change: %w", err)
	}
	defer transaction.Rollback()

	previous, err := scanUser(transaction.QueryRowContext(ctx, "SELECT "+userColumns+" FROM users WHERE id = ?", int64(userID)))
	if errors.Is(err, sql.ErrNoRows) {
		return UserStatusResult{}, ErrUserNotFound
	}
	if err != nil {
		return UserStatusResult{}, fmt.Errorf("identity: reading account status: %w", err)
	}
	if !previous.UpdatedAt.Equal(change.ExpectedUpdatedAt) {
		return UserStatusResult{}, ErrMemberConflict
	}
	if change.Disabled == !previous.DisabledAt.IsZero() {
		return UserStatusResult{User: previous}, nil
	}
	if change.Disabled {
		if err := checkOwnerRemoval(ctx, transaction, previous); err != nil {
			return UserStatusResult{}, err
		}
	}

	now := time.Now().UTC()
	if !now.After(previous.UpdatedAt) {
		now = previous.UpdatedAt.Add(time.Nanosecond)
	}
	updated := previous
	updated.UpdatedAt = now
	updated.DisabledAt = time.Time{}
	updated.DisabledReason = ""
	var disabledAt any
	action := AuditUserEnabled
	if change.Disabled {
		disabledAt = now.UnixNano()
		updated.DisabledAt, updated.DisabledReason = now, reason
		action = AuditUserDisabled
	}
	if err := requireIdentityWrite(transaction.ExecContext(ctx, `UPDATE users SET disabled_at = ?, disabled_reason = ?, updated_at = ?
		WHERE id = ? AND updated_at = ?`, disabledAt, updated.DisabledReason, now.UnixNano(), int64(userID), previous.UpdatedAt.UnixNano())); err != nil {
		return UserStatusResult{}, err
	}
	var revoked int64
	if change.Disabled {
		// 先取得期望行数，再核对实际写入；触发器忽略一部分撤销不能算作成功。
		var expected int64
		if err := transaction.QueryRowContext(ctx, "SELECT COUNT(*) FROM sessions WHERE user_id = ? AND revoked_at IS NULL", int64(userID)).Scan(&expected); err != nil {
			return UserStatusResult{}, err
		}
		result, err := transaction.ExecContext(ctx, `UPDATE sessions SET revoked_at = ?, revoked_reason = 'account disabled by platform'
			WHERE user_id = ? AND revoked_at IS NULL`, now.UnixNano(), int64(userID))
		if err != nil {
			return UserStatusResult{}, err
		}
		revoked, err = result.RowsAffected()
		if err != nil {
			return UserStatusResult{}, err
		}
		if revoked != expected {
			return UserStatusResult{}, errors.New("identity: account sessions were not fully revoked")
		}
	}
	detail := fmt.Sprintf("disabled=%t -> %t; revoked_sessions=%d; reason=%s", !previous.DisabledAt.IsZero(), change.Disabled, revoked, reason)
	if err := insertIdentityAudit(ctx, transaction, "platform", action, fmt.Sprintf("user:%d", userID), detail, now); err != nil {
		return UserStatusResult{}, err
	}
	if err := transaction.Commit(); err != nil {
		return UserStatusResult{}, fmt.Errorf("identity: committing account status: %w", err)
	}
	return UserStatusResult{User: updated, RevokedSessions: revoked}, nil
}
