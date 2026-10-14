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

// 明文仅用于本次平台响应，不能随账户列表、日志或 JSON 自动序列化。
type RandomPasswordReset struct {
	User              User
	TemporaryPassword string `json:"-"`
	RevokedSessions   int64
}

func (store *SQLiteStore) ResetRandomPasswordByPlatform(ctx context.Context, userID tailcfg.UserID, options PasswordResetOptions, actor string) (RandomPasswordReset, error) {
	reason := strings.TrimSpace(options.Reason)
	if userID == 0 || !options.OwnershipVerified || options.ExpectedUpdatedAt.IsZero() || reason == "" || !utf8.ValidString(reason) || utf8.RuneCountInString(reason) > 256 || strings.ContainsFunc(reason, unicode.IsControl) || actor == "" || strings.ContainsFunc(actor, unicode.IsControl) {
		return RandomPasswordReset{}, ErrMemberInvalid
	}
	password, err := NewSecret(24)
	if err != nil {
		return RandomPasswordReset{}, err
	}
	// 慢哈希不占 SQLite 写锁；提交时重新读取账户与凭据，不复用 HTTP 快照。
	hash, err := HashPassword(password)
	if err != nil {
		return RandomPasswordReset{}, err
	}
	transaction, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return RandomPasswordReset{}, err
	}
	defer transaction.Rollback()
	user, err := scanUser(transaction.QueryRowContext(ctx, "SELECT "+userColumns+" FROM users WHERE id = ?", int64(userID)))
	if errors.Is(err, sql.ErrNoRows) {
		return RandomPasswordReset{}, ErrUserNotFound
	}
	if err != nil {
		return RandomPasswordReset{}, err
	}
	if !user.UpdatedAt.Equal(options.ExpectedUpdatedAt) {
		return RandomPasswordReset{}, ErrMemberConflict
	}
	if !user.DisabledAt.IsZero() {
		return RandomPasswordReset{}, ErrUserDisabled
	}
	if err := CheckPassword(user.LoginName, password); err != nil {
		return RandomPasswordReset{}, ErrMemberInvalid
	}
	var currentHash []byte
	var credentialUpdatedAt int64
	if err := transaction.QueryRowContext(ctx, "SELECT password_hash, updated_at FROM local_credentials WHERE user_id = ?", int64(userID)).Scan(&currentHash, &credentialUpdatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return RandomPasswordReset{}, ErrCredentialNotFound
		}
		return RandomPasswordReset{}, err
	}
	now := time.Now().UTC()
	if !now.After(user.UpdatedAt) {
		now = user.UpdatedAt.Add(time.Nanosecond)
	}
	if err := requireIdentityWrite(transaction.ExecContext(ctx, `UPDATE local_credentials SET password_hash = ?, updated_at = ?
		WHERE user_id = ? AND password_hash = ? AND updated_at = ?`, hash, now.UnixNano(), int64(userID), currentHash, credentialUpdatedAt)); err != nil {
		return RandomPasswordReset{}, err
	}
	if err := deletePasswordReset(ctx, transaction, userID); err != nil {
		return RandomPasswordReset{}, err
	}
	var expected int64
	if err := transaction.QueryRowContext(ctx, "SELECT COUNT(*) FROM sessions WHERE user_id = ? AND revoked_at IS NULL", int64(userID)).Scan(&expected); err != nil {
		return RandomPasswordReset{}, err
	}
	result, err := transaction.ExecContext(ctx, "UPDATE sessions SET revoked_at = ?, revoked_reason = 'password reset' WHERE user_id = ? AND revoked_at IS NULL", now.UnixNano(), int64(userID))
	if err != nil {
		return RandomPasswordReset{}, err
	}
	revoked, err := result.RowsAffected()
	if err != nil || revoked != expected {
		return RandomPasswordReset{}, errors.New("identity: password reset sessions were not fully revoked")
	}
	if err := requireIdentityWrite(transaction.ExecContext(ctx, `UPDATE users SET updated_at = ?, password_change_required = 1
		WHERE id = ? AND updated_at = ?`, now.UnixNano(), int64(userID), user.UpdatedAt.UnixNano())); err != nil {
		return RandomPasswordReset{}, err
	}
	if err := insertIdentityAudit(ctx, transaction, actor, AuditPasswordReset, fmt.Sprintf("user:%d", userID), fmt.Sprintf("random temporary password set; ownership verified; revoked %d sessions; reason=%s", revoked, reason), now); err != nil {
		return RandomPasswordReset{}, err
	}
	if err := transaction.Commit(); err != nil {
		return RandomPasswordReset{}, err
	}
	user.UpdatedAt, user.PasswordChangeRequired = now, true
	return RandomPasswordReset{User: user, TemporaryPassword: password, RevokedSessions: revoked}, nil
}
