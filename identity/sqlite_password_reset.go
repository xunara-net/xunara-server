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

func (store *SQLiteStore) IssuePasswordResetByPlatform(ctx context.Context, userID tailcfg.UserID, options PasswordResetOptions) (PasswordResetIssuance, error) {
	reason := strings.TrimSpace(options.Reason)
	if userID == 0 || !options.OwnershipVerified || options.ExpectedUpdatedAt.IsZero() || reason == "" || !utf8.ValidString(reason) || utf8.RuneCountInString(reason) > 256 || strings.ContainsFunc(reason, unicode.IsControl) {
		return PasswordResetIssuance{}, ErrMemberInvalid
	}
	transaction, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return PasswordResetIssuance{}, fmt.Errorf("identity: starting password reset issuance: %w", err)
	}
	defer transaction.Rollback()
	user, err := scanUser(transaction.QueryRowContext(ctx, "SELECT "+userColumns+" FROM users WHERE id = ?", int64(userID)))
	if errors.Is(err, sql.ErrNoRows) {
		return PasswordResetIssuance{}, ErrUserNotFound
	}
	if err != nil {
		return PasswordResetIssuance{}, err
	}
	if !user.UpdatedAt.Equal(options.ExpectedUpdatedAt) {
		return PasswordResetIssuance{}, ErrMemberConflict
	}
	if !user.DisabledAt.IsZero() {
		return PasswordResetIssuance{}, ErrUserDisabled
	}
	var credentialHash []byte
	var credentialUpdatedAt int64
	if err := transaction.QueryRowContext(ctx, "SELECT password_hash, updated_at FROM local_credentials WHERE user_id = ?", int64(userID)).Scan(&credentialHash, &credentialUpdatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return PasswordResetIssuance{}, ErrCredentialNotFound
		}
		return PasswordResetIssuance{}, err
	}
	secret, err := newSecret()
	if err != nil {
		return PasswordResetIssuance{}, err
	}
	id, err := newID("pr_")
	if err != nil {
		return PasswordResetIssuance{}, err
	}
	code := "reset-" + secret
	now := time.Now().UTC()
	revision := now
	if !revision.After(user.UpdatedAt) {
		revision = user.UpdatedAt.Add(time.Nanosecond)
	}
	expiresAt := now.Add(PasswordResetTTL)
	// 生成不锁号、不改密码；只替换待用凭证并推进版本，避免并发管理员各拿到一个有效码。
	if err := requireIdentityWrite(transaction.ExecContext(ctx, `INSERT INTO password_reset_tickets
		(user_id, id, token_hash, credential_fingerprint, credential_updated_at, created_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT(user_id) DO UPDATE SET
		id = excluded.id, token_hash = excluded.token_hash, credential_fingerprint = excluded.credential_fingerprint,
		credential_updated_at = excluded.credential_updated_at, created_at = excluded.created_at, expires_at = excluded.expires_at`,
		int64(userID), id, HashSecret(code), HashSecret(string(credentialHash)), credentialUpdatedAt, now.UnixNano(), expiresAt.UnixNano())); err != nil {
		return PasswordResetIssuance{}, err
	}
	if err := requireIdentityWrite(transaction.ExecContext(ctx, "UPDATE users SET updated_at = ? WHERE id = ? AND updated_at = ?",
		revision.UnixNano(), int64(userID), user.UpdatedAt.UnixNano())); err != nil {
		return PasswordResetIssuance{}, err
	}
	if err := insertIdentityAudit(ctx, transaction, "platform", AuditPasswordResetIssued, fmt.Sprintf("user:%d", userID), "reset issued; operator verified ownership; reason="+reason, now); err != nil {
		return PasswordResetIssuance{}, err
	}
	if err := transaction.Commit(); err != nil {
		return PasswordResetIssuance{}, err
	}
	user.UpdatedAt = revision
	return PasswordResetIssuance{User: user, Status: PasswordResetStatus{ID: id, UserID: userID, CreatedAt: now, ExpiresAt: expiresAt}, Code: code}, nil
}

type passwordResetRecord struct {
	status                PasswordResetStatus
	credentialFingerprint string
	credentialUpdatedAt   int64
}

const passwordResetColumns = "id, user_id, credential_fingerprint, credential_updated_at, created_at, expires_at"

func scanPasswordReset(scanner rowScanner) (passwordResetRecord, error) {
	var record passwordResetRecord
	var userID, createdAt, expiresAt int64
	if err := scanner.Scan(&record.status.ID, &userID, &record.credentialFingerprint, &record.credentialUpdatedAt, &createdAt, &expiresAt); err != nil {
		return passwordResetRecord{}, err
	}
	record.status.UserID = tailcfg.UserID(userID)
	record.status.CreatedAt = time.Unix(0, createdAt).UTC()
	record.status.ExpiresAt = time.Unix(0, expiresAt).UTC()
	return record, nil
}

type passwordResetQuery interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func validPasswordResetUser(ctx context.Context, query passwordResetQuery, record passwordResetRecord) (User, error) {
	if !record.status.ExpiresAt.After(time.Now()) {
		return User{}, ErrPasswordResetInvalid
	}
	user, err := scanUser(query.QueryRowContext(ctx, "SELECT "+userColumns+" FROM users WHERE id = ?", int64(record.status.UserID)))
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, ErrPasswordResetInvalid
	}
	if err != nil {
		return User{}, err
	}
	if !user.DisabledAt.IsZero() {
		return User{}, ErrPasswordResetInvalid
	}
	var hash []byte
	var updatedAt int64
	if err := query.QueryRowContext(ctx, "SELECT password_hash, updated_at FROM local_credentials WHERE user_id = ?", int64(user.ID)).Scan(&hash, &updatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return User{}, ErrPasswordResetInvalid
		}
		return User{}, err
	}
	if updatedAt != record.credentialUpdatedAt || !SecretEqual(record.credentialFingerprint, string(hash)) {
		return User{}, ErrPasswordResetInvalid
	}
	return user, nil
}

func (store *SQLiteStore) GetPasswordResetStatus(ctx context.Context, userID tailcfg.UserID) (PasswordResetStatus, bool, error) {
	record, err := scanPasswordReset(store.db.QueryRowContext(ctx, "SELECT "+passwordResetColumns+" FROM password_reset_tickets WHERE user_id = ?", int64(userID)))
	if errors.Is(err, sql.ErrNoRows) {
		return PasswordResetStatus{}, false, nil
	}
	if err != nil {
		return PasswordResetStatus{}, false, err
	}
	if _, err := validPasswordResetUser(ctx, store.db, record); err != nil {
		if errors.Is(err, ErrPasswordResetInvalid) {
			return PasswordResetStatus{}, false, nil
		}
		return PasswordResetStatus{}, false, err
	}
	return record.status, true, nil
}

func lookupPasswordReset(ctx context.Context, query passwordResetQuery, code string) (passwordResetRecord, User, error) {
	if !validPasswordResetCode(code) {
		return passwordResetRecord{}, User{}, ErrPasswordResetInvalid
	}
	record, err := scanPasswordReset(query.QueryRowContext(ctx, "SELECT "+passwordResetColumns+" FROM password_reset_tickets WHERE token_hash = ?", HashSecret(code)))
	if errors.Is(err, sql.ErrNoRows) {
		return passwordResetRecord{}, User{}, ErrPasswordResetInvalid
	}
	if err != nil {
		return passwordResetRecord{}, User{}, err
	}
	user, err := validPasswordResetUser(ctx, query, record)
	return record, user, err
}

func (store *SQLiteStore) LookupPasswordReset(ctx context.Context, code string) (User, error) {
	_, user, err := lookupPasswordReset(ctx, store.db, code)
	return user, err
}

func (store *SQLiteStore) RedeemPasswordReset(ctx context.Context, code string, replacementHash []byte) (PasswordResetResult, error) {
	if len(replacementHash) == 0 {
		return PasswordResetResult{}, ErrPasswordResetInvalid
	}
	transaction, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return PasswordResetResult{}, err
	}
	defer transaction.Rollback()
	// 慢哈希前的查询只是预检，真正消费必须再次核对当前持久事实，不能复用旧用户快照。
	record, user, err := lookupPasswordReset(ctx, transaction, code)
	if err != nil {
		return PasswordResetResult{}, err
	}
	now := time.Now().UTC()
	if !now.After(user.UpdatedAt) {
		now = user.UpdatedAt.Add(time.Nanosecond)
	}
	if err := requireIdentityWrite(transaction.ExecContext(ctx, "UPDATE local_credentials SET password_hash = ?, updated_at = ? WHERE user_id = ? AND updated_at = ?",
		replacementHash, now.UnixNano(), int64(user.ID), record.credentialUpdatedAt)); err != nil {
		return PasswordResetResult{}, err
	}
	if err := deletePasswordReset(ctx, transaction, user.ID); err != nil {
		return PasswordResetResult{}, err
	}
	var expected int64
	if err := transaction.QueryRowContext(ctx, "SELECT COUNT(*) FROM sessions WHERE user_id = ? AND revoked_at IS NULL", int64(user.ID)).Scan(&expected); err != nil {
		return PasswordResetResult{}, err
	}
	result, err := transaction.ExecContext(ctx, "UPDATE sessions SET revoked_at = ?, revoked_reason = 'password reset' WHERE user_id = ? AND revoked_at IS NULL", now.UnixNano(), int64(user.ID))
	if err != nil {
		return PasswordResetResult{}, err
	}
	revoked, err := result.RowsAffected()
	if err != nil || revoked != expected {
		return PasswordResetResult{}, errors.New("identity: password reset sessions were not fully revoked")
	}
	if err := requireIdentityWrite(transaction.ExecContext(ctx, "UPDATE users SET updated_at = ? WHERE id = ? AND updated_at = ?", now.UnixNano(), int64(user.ID), user.UpdatedAt.UnixNano())); err != nil {
		return PasswordResetResult{}, err
	}
	if err := insertIdentityAudit(ctx, transaction, fmt.Sprintf("user:%d", user.ID), AuditPasswordResetUsed, fmt.Sprintf("user:%d", user.ID), fmt.Sprintf("password reset; revoked %d sessions", revoked), now); err != nil {
		return PasswordResetResult{}, err
	}
	if err := transaction.Commit(); err != nil {
		return PasswordResetResult{}, err
	}
	return PasswordResetResult{UserID: user.ID, RevokedSessions: revoked}, nil
}

// 状态变更和自助改密均在自己的写事务调用，防止恢复启用后旧码又可兑换。
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
