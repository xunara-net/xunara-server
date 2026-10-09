package identity

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

func (store *SQLiteStore) RegisterLocalAccount(ctx context.Context, registration LocalRegistration) (User, Session, string, error) {
	if strings.TrimSpace(registration.LoginName) == "" || len(registration.PasswordHash) == 0 || registration.MaxUsers < -1 {
		return User{}, Session{}, "", errors.New("identity: invalid local registration")
	}
	sessionToken, err := newSecret()
	if err != nil {
		return User{}, Session{}, "", err
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return User{}, Session{}, "", fmt.Errorf("identity: starting registration: %w", err)
	}
	defer tx.Rollback()

	now := time.Now().UTC()
	inviteToken := normalizeInviteToken(registration.InviteToken)
	var invitation RegistrationInvite
	role := RoleMember
	if inviteToken != "" {
		invitation, err = lookupUsableInvite(ctx, tx, inviteToken, now)
		if err != nil {
			return User{}, Session{}, "", err
		}
		role, err = inviteRole(invitation.Role)
		if err != nil {
			return User{}, Session{}, "", err
		}
	}
	if err := checkMemberLimit(ctx, tx, registration.MaxUsers); err != nil {
		return User{}, Session{}, "", err
	}

	displayName := registration.DisplayName
	if displayName == "" {
		displayName = registration.LoginName
	}
	user, err := scanUser(tx.QueryRowContext(ctx, `
		INSERT INTO users (login_name, display_name, email, role, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?) RETURNING `+userColumns,
		registration.LoginName, displayName, registration.Email, string(role), now.UnixNano(), now.UnixNano()))
	if isUniqueViolation(err) {
		return User{}, Session{}, "", ErrLoginNameTaken
	}
	if err != nil {
		return User{}, Session{}, "", fmt.Errorf("identity: registering user: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO local_credentials (user_id, password_hash, created_at, updated_at) VALUES (?, ?, ?, ?)`,
		int64(user.ID), registration.PasswordHash, now.UnixNano(), now.UnixNano()); err != nil {
		return User{}, Session{}, "", fmt.Errorf("identity: registering credential: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO external_identities (`+externalIdentityColumns+`) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		LocalProviderID, user.LoginName, int64(user.ID), user.Email, user.DisplayName, now.UnixNano(), now.UnixNano()); err != nil {
		return User{}, Session{}, "", fmt.Errorf("identity: registering local identity: %w", err)
	}
	if invitation.ID != "" {
		if _, err := tx.ExecContext(ctx, "UPDATE registration_invites SET used_at = ?, used_by = ? WHERE id = ?",
			now.UnixNano(), int64(user.ID), invitation.ID); err != nil {
			return User{}, Session{}, "", fmt.Errorf("identity: redeeming registration invitation: %w", err)
		}
		if err := insertIdentityAudit(ctx, tx, "system", AuditInviteRedeemed, "invite:"+invitation.ID,
			"redeemed by user "+user.LoginName, now); err != nil {
			return User{}, Session{}, "", err
		}
	}
	session, err := store.createSession(ctx, tx, NewSessionOptions{
		UserID: user.ID, AuthMethod: LocalProviderID, TTL: registration.SessionTTL,
	}, sessionToken)
	if err != nil {
		return User{}, Session{}, "", err
	}
	actor := fmt.Sprintf("user:%d", user.ID)
	for _, event := range []AuditEvent{
		{Actor: "system", Action: AuditUserRegistered, Target: actor, Detail: "registered as " + string(user.Role)},
		{Actor: actor, Action: AuditLoginSucceeded, Target: "provider:" + LocalProviderID, Detail: "authenticated " + user.LoginName},
		{Actor: actor, Action: AuditSessionCreated, Target: "session:" + session.ID, Detail: "auth method " + LocalProviderID},
	} {
		if err := insertIdentityAudit(ctx, tx, event.Actor, event.Action, event.Target, event.Detail, now); err != nil {
			return User{}, Session{}, "", err
		}
	}
	if err := tx.Commit(); err != nil {
		return User{}, Session{}, "", fmt.Errorf("identity: committing registration: %w", err)
	}
	return user, session, sessionToken, nil
}

// checkMemberLimit 在持有数据库写事务时读取额度使用量，跨实例也不能抢占同一名额。
func checkMemberLimit(ctx context.Context, tx *sql.Tx, maxUsers int) error {
	if maxUsers < -1 {
		return errors.New("identity: invalid member limit")
	}
	if maxUsers == -1 {
		return nil
	}
	var used int
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM users").Scan(&used); err != nil {
		return fmt.Errorf("identity: checking member limit: %w", err)
	}
	if used >= maxUsers {
		return ErrMemberLimitReached
	}
	return nil
}

func insertIdentityAudit(ctx context.Context, tx *sql.Tx, actor, action, target, detail string, now time.Time) error {
	if _, err := tx.ExecContext(ctx, "INSERT INTO audit_events (ts, actor, action, target, detail) VALUES (?, ?, ?, ?, ?)",
		now.UnixNano(), actor, action, target, detail); err != nil {
		return fmt.Errorf("identity: auditing identity transaction: %w", err)
	}
	return nil
}
