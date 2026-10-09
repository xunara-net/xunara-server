package identity

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

func (store *SQLiteStore) LocalAccountSetupRequired(ctx context.Context) (bool, error) {
	var required bool
	if err := store.db.QueryRowContext(ctx, `
		SELECT NOT EXISTS (SELECT 1 FROM local_bootstrap_state WHERE id = 1)
		AND NOT EXISTS (SELECT 1 FROM local_credentials)`).Scan(&required); err != nil {
		return false, fmt.Errorf("identity: reading local initialization state: %w", err)
	}
	return required, nil
}

func (store *SQLiteStore) ClaimLocalAccount(ctx context.Context, claim LocalAccountClaim) (User, Session, string, error) {
	if err := ctx.Err(); err != nil {
		return User{}, Session{}, "", err
	}
	if strings.TrimSpace(claim.LoginName) == "" || len(claim.PasswordHash) == 0 || (claim.Kind != ClaimAdministrator && claim.Kind != ClaimTenantOwner) {
		return User{}, Session{}, "", errors.New("identity: invalid local account claim")
	}
	token, err := newSecret()
	if err != nil {
		return User{}, Session{}, "", err
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return User{}, Session{}, "", fmt.Errorf("identity: starting local account claim: %w", err)
	}
	defer tx.Rollback()

	now := time.Now().UTC()
	// 第一条语句取得写锁并争用持久的一次性名额，不能依赖 HTTP 检查或进程内锁。
	// 名额与后续写入一起回滚；已删除密码或残留文件令牌不能重新认领。
	result, err := tx.ExecContext(ctx, `
		INSERT INTO local_bootstrap_state (id, completed_at)
		SELECT 1, ? WHERE NOT EXISTS (SELECT 1 FROM local_bootstrap_state WHERE id = 1)
		AND NOT EXISTS (SELECT 1 FROM local_credentials)`, now.UnixNano())
	if err != nil {
		return User{}, Session{}, "", fmt.Errorf("identity: reserving local account claim: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return User{}, Session{}, "", fmt.Errorf("identity: checking local account claim: %w", err)
	}
	if affected != 1 {
		return User{}, Session{}, "", ErrLocalAccountClaimed
	}

	previous, err := scanUser(tx.QueryRowContext(ctx, "SELECT "+userColumns+" FROM users WHERE id = 1"))
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, Session{}, "", ErrUserNotFound
	}
	if err != nil {
		return User{}, Session{}, "", fmt.Errorf("identity: reading built-in owner: %w", err)
	}
	displayName := claim.DisplayName
	if displayName == "" {
		displayName = previous.DisplayName
	}
	if displayName == "" {
		displayName = claim.LoginName
	}
	email := claim.Email
	if email == "" {
		email = previous.Email
	}
	user, err := scanUser(tx.QueryRowContext(ctx, `
		UPDATE users SET login_name = ?, display_name = ?, email = ?, role = ?, updated_at = ?
		WHERE id = ? RETURNING `+userColumns,
		claim.LoginName, displayName, email, string(RoleOwner), now.UnixNano(), int64(previous.ID)))
	if isUniqueViolation(err) {
		return User{}, Session{}, "", ErrLoginNameTaken
	}
	if err != nil {
		return User{}, Session{}, "", fmt.Errorf("identity: claiming built-in owner: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO local_credentials (user_id, password_hash, created_at, updated_at) VALUES (?, ?, ?, ?)`,
		int64(user.ID), claim.PasswordHash, now.UnixNano(), now.UnixNano()); err != nil {
		return User{}, Session{}, "", fmt.Errorf("identity: initializing local password: %w", err)
	}
	session, err := store.createSession(ctx, tx, NewSessionOptions{
		UserID: user.ID, AuthMethod: LocalProviderID, TTL: claim.SessionTTL,
	}, token)
	if err != nil {
		return User{}, Session{}, "", err
	}

	actor := fmt.Sprintf("user:%d", user.ID)
	var events []AuditEvent
	if claim.Kind == ClaimAdministrator {
		events = append(events, AuditEvent{
			Actor: actor, Action: AuditAdminBootstrap, Target: "user:" + user.LoginName,
			Detail: fmt.Sprintf("administrator set up (was %q, display %q)", previous.LoginName, previous.DisplayName),
		})
		if previous.LoginName != user.LoginName || previous.DisplayName != user.DisplayName || previous.Email != user.Email {
			events = append(events, AuditEvent{Actor: "system", Action: AuditUserUpdated, Target: actor, Detail: "login, display name or email changed during setup"})
		}
	} else {
		events = append(events, AuditEvent{Actor: "system", Action: AuditUserRegistered, Target: actor, Detail: "tenant owner created by self-service sign-up"})
	}
	events = append(events,
		AuditEvent{Actor: actor, Action: AuditLoginSucceeded, Target: "provider:" + LocalProviderID, Detail: "authenticated " + user.LoginName},
		AuditEvent{Actor: actor, Action: AuditSessionCreated, Target: "session:" + session.ID, Detail: "auth method " + LocalProviderID},
	)
	for _, event := range events {
		if err := insertIdentityAudit(ctx, tx, event.Actor, event.Action, event.Target, event.Detail, now); err != nil {
			return User{}, Session{}, "", err
		}
	}
	if err := tx.Commit(); err != nil {
		return User{}, Session{}, "", fmt.Errorf("identity: committing local account claim: %w", err)
	}
	return user, session, token, nil
}
