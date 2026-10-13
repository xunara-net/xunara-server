package identity

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

func (store *SQLiteStore) CreateLocalAccountByPlatform(ctx context.Context, account PlatformLocalAccount) (User, error) {
	if strings.TrimSpace(account.LoginName) == "" || len(account.PasswordHash) == 0 || !account.Role.Valid() || account.MaxUsers < -1 || account.Actor == "" {
		return User{}, ErrMemberInvalid
	}
	transaction, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return User{}, err
	}
	defer transaction.Rollback()
	if err := lockAuthenticationRevision(ctx, transaction, account.AuthenticationRevision); err != nil {
		return User{}, err
	}
	if err := checkMemberLimit(ctx, transaction, account.MaxUsers); err != nil {
		return User{}, err
	}
	now := time.Now().UTC()
	display := account.DisplayName
	if display == "" {
		display = account.LoginName
	}
	user, err := scanUser(transaction.QueryRowContext(ctx, `INSERT INTO users
		(login_name, display_name, email, role, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?) RETURNING `+userColumns,
		account.LoginName, display, account.Email, string(account.Role), now.UnixNano(), now.UnixNano()))
	if isUniqueViolation(err) {
		return User{}, ErrLoginNameTaken
	}
	if err != nil {
		return User{}, err
	}
	// RETURNING 要求实际落下一行；触发器静默忽略凭据/绑定时也必须回滚账户。
	var insertedUserID int64
	if err := transaction.QueryRowContext(ctx, `INSERT INTO local_credentials (user_id, password_hash, created_at, updated_at) VALUES (?, ?, ?, ?) RETURNING user_id`,
		int64(user.ID), account.PasswordHash, now.UnixNano(), now.UnixNano()).Scan(&insertedUserID); err != nil {
		return User{}, err
	}
	if insertedUserID != int64(user.ID) {
		return User{}, errors.New("identity: local credential ownership mismatch")
	}
	if err := transaction.QueryRowContext(ctx, `INSERT INTO external_identities (`+externalIdentityColumns+`) VALUES (?, ?, ?, ?, ?, ?, ?) RETURNING user_id`,
		LocalProviderID, user.LoginName, int64(user.ID), user.Email, user.DisplayName, now.UnixNano(), now.UnixNano()).Scan(&insertedUserID); err != nil {
		return User{}, err
	}
	if insertedUserID != int64(user.ID) {
		return User{}, errors.New("identity: local identity ownership mismatch")
	}
	if err := insertIdentityAudit(ctx, transaction, account.Actor, AuditUserRegistered, fmt.Sprintf("user:%d", user.ID), "platform created local account; role="+string(user.Role), now); err != nil {
		return User{}, err
	}
	if err := transaction.Commit(); err != nil {
		return User{}, err
	}
	return user, nil
}

// 首次令牌登录原子建立平台人身份、短期会话和必需审计；后续登录复用同一身份。
func (store *SQLiteStore) CreatePlatformSession(ctx context.Context, ttl time.Duration, info SessionClientInfo) (Session, string, error) {
	token, err := newSecret()
	if err != nil {
		return Session{}, "", err
	}
	transaction, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return Session{}, "", err
	}
	defer transaction.Rollback()
	now := time.Now().UTC()
	if _, err := transaction.ExecContext(ctx, `INSERT INTO users (login_name, display_name, email, role, created_at, updated_at)
		VALUES (?, '平台管理员', '', 'owner', ?, ?) ON CONFLICT(login_name) DO NOTHING`, PlatformLoginName, now.UnixNano(), now.UnixNano()); err != nil {
		return Session{}, "", err
	}
	user, err := scanUser(transaction.QueryRowContext(ctx, "SELECT "+userColumns+" FROM users WHERE login_name = ?", PlatformLoginName))
	if err != nil {
		return Session{}, "", err
	}
	if user.Role != RoleOwner || !user.DisabledAt.IsZero() {
		return Session{}, "", errors.New("identity: platform account unavailable")
	}
	session, err := store.createSession(ctx, transaction, NewSessionOptions{UserID: user.ID, AuthMethod: "platform-token", TTL: ttl, ClientInfo: info}, token)
	if err != nil {
		return Session{}, "", err
	}
	for _, action := range []string{AuditLoginSucceeded, AuditSessionCreated} {
		if err := insertAccountAudit(ctx, transaction, user.ID, action, "platform-token; session:"+session.ID, now); err != nil {
			return Session{}, "", err
		}
	}
	if err := transaction.Commit(); err != nil {
		return Session{}, "", err
	}
	return session, token, nil
}
