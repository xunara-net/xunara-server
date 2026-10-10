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

func (store *SQLiteStore) ListAccountIdentities(ctx context.Context, userID tailcfg.UserID) ([]ExternalIdentity, error) {
	return listAccountIdentities(ctx, store.db, userID)
}

func listAccountIdentities(ctx context.Context, query interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}, userID tailcfg.UserID) ([]ExternalIdentity, error) {
	rows, err := query.QueryContext(ctx, "SELECT "+externalIdentityColumns+" FROM external_identities WHERE user_id = ? ORDER BY provider_id, subject", int64(userID))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	links := make([]ExternalIdentity, 0)
	for rows.Next() {
		link, err := scanExternalIdentity(rows)
		if err != nil {
			return nil, err
		}
		links = append(links, link)
	}
	return links, rows.Err()
}

// 完成外部认证只有一个提交点；绑定、注册和登录不能各自留下半个账户。
func (store *SQLiteStore) CompleteExternalAuthentication(ctx context.Context, transactionID string, result IdentityResult, options ExternalAuthenticationOptions) (ExternalAuthentication, error) {
	if result.ProviderID == "" || result.ProviderID == LocalProviderID || result.Subject == "" {
		return ExternalAuthentication{}, ErrCredentialChanged
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return ExternalAuthentication{}, err
	}
	defer tx.Rollback()
	now := time.Now().UTC()
	// 条件写入先取得跨实例写锁，并在提交时消费一次；失败会回滚消费标记。
	affected, err := tx.ExecContext(ctx, `UPDATE auth_transactions SET consumed_at = ? WHERE id = ? AND consumed_at IS NULL AND expires_at > ?`, now.UnixNano(), transactionID, now.UnixNano())
	if err != nil {
		return ExternalAuthentication{}, err
	}
	count, err := affected.RowsAffected()
	if err != nil {
		return ExternalAuthentication{}, err
	}
	if count != 1 {
		return ExternalAuthentication{}, ErrTransactionConsumed
	}
	authorization, err := scanAuthTransaction(tx.QueryRowContext(ctx, "SELECT "+authTransactionColumns+" FROM auth_transactions WHERE id = ?", transactionID))
	if err != nil {
		return ExternalAuthentication{}, err
	}
	if authorization.ProviderID != result.ProviderID {
		return ExternalAuthentication{}, ErrCredentialChanged
	}
	link, err := scanExternalIdentity(tx.QueryRowContext(ctx, "SELECT "+externalIdentityColumns+" FROM external_identities WHERE provider_id = ? AND subject = ?", result.ProviderID, result.Subject))
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return ExternalAuthentication{}, err
	}
	exists := err == nil
	var user User
	if authorization.RequestedAction == AuthActionLink {
		if err := lockAccountSession(ctx, tx, authorization.AccountUserID, authorization.AccountSessionID, now); err != nil {
			return ExternalAuthentication{}, err
		}
		if exists && link.UserID != authorization.AccountUserID {
			return ExternalAuthentication{}, ErrExternalIdentityExists
		}
		user, err = scanUser(tx.QueryRowContext(ctx, "SELECT "+userColumns+" FROM users WHERE id = ?", int64(authorization.AccountUserID)))
	} else if exists {
		// 邀请不能对已存在身份执行角色变更，也不浪费邀请码。
		user, err = scanUser(tx.QueryRowContext(ctx, "SELECT "+userColumns+" FROM users WHERE id = ?", int64(link.UserID)))
	} else {
		user, err = registerExternalUser(ctx, tx, authorization, result, options, now)
	}
	if err != nil {
		return ExternalAuthentication{}, err
	}
	if err := requireIdentityWrite(tx.ExecContext(ctx, `INSERT INTO external_identities (`+externalIdentityColumns+`) VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(provider_id, subject) DO UPDATE SET email = excluded.email, display_name = excluded.display_name, updated_at = excluded.updated_at`,
		result.ProviderID, result.Subject, int64(user.ID), result.Email, result.DisplayName, now.UnixNano(), now.UnixNano())); err != nil {
		return ExternalAuthentication{}, err
	}
	completed := ExternalAuthentication{User: user, Linked: authorization.RequestedAction == AuthActionLink}
	actor := fmt.Sprintf("user:%d", user.ID)
	if completed.Linked {
		if err := insertIdentityAudit(ctx, tx, actor, AuditIdentityLinked, "provider:"+result.ProviderID, "account binding confirmed", now); err != nil {
			return ExternalAuthentication{}, err
		}
	} else {
		completed.Token, err = newSecret()
		if err != nil {
			return ExternalAuthentication{}, err
		}
		completed.Session, err = store.createSession(ctx, tx, NewSessionOptions{UserID: user.ID, AuthMethod: result.ProviderID, TTL: options.SessionTTL}, completed.Token)
		if err != nil {
			return ExternalAuthentication{}, err
		}
		for _, event := range []AuditEvent{
			{Action: AuditLoginSucceeded, Target: "provider:" + result.ProviderID, Detail: "external authentication confirmed"},
			{Action: AuditSessionCreated, Target: "session:" + completed.Session.ID, Detail: "auth method " + result.ProviderID},
		} {
			if err := insertIdentityAudit(ctx, tx, actor, event.Action, event.Target, event.Detail, now); err != nil {
				return ExternalAuthentication{}, err
			}
		}
	}
	if err := tx.Commit(); err != nil {
		return ExternalAuthentication{}, err
	}
	return completed, nil
}

func registerExternalUser(ctx context.Context, tx *sql.Tx, authorization AuthTransaction, result IdentityResult, options ExternalAuthenticationOptions, now time.Time) (User, error) {
	var invite RegistrationInvite
	role := RoleMember
	var err error
	if authorization.RequestedAction == AuthActionInvite {
		invite, err = lookupUsableInviteHash(ctx, tx, authorization.InviteTokenHash, now)
		if err != nil {
			return User{}, err
		}
		role, err = inviteRole(invite.Role)
		if err != nil {
			return User{}, err
		}
	} else if !options.AllowCreate {
		return User{}, ErrExternalRegistrationClosed
	}
	if err := checkMemberLimit(ctx, tx, options.MaxUsers); err != nil {
		return User{}, err
	}
	base := options.LoginName
	if base == "" {
		base = "user"
	}
	for attempt := 1; attempt < 4096; attempt++ {
		login := base
		if attempt > 1 {
			login = fmt.Sprintf("%s-%d", base, attempt)
		}
		display := result.DisplayName
		if display == "" {
			display = login
		}
		user, err := scanUser(tx.QueryRowContext(ctx, `INSERT INTO users (login_name, display_name, email, role, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, ?) RETURNING `+userColumns, login, display, result.Email, string(role), now.UnixNano(), now.UnixNano()))
		if isUniqueViolation(err) {
			continue
		}
		if err != nil {
			return User{}, err
		}
		if invite.ID != "" {
			if err := requireIdentityWrite(tx.ExecContext(ctx, "UPDATE registration_invites SET used_at = ?, used_by = ? WHERE id = ? AND used_at IS NULL", now.UnixNano(), int64(user.ID), invite.ID)); err != nil {
				return User{}, err
			}
			if err := insertIdentityAudit(ctx, tx, fmt.Sprintf("user:%d", user.ID), AuditInviteRedeemed, "invite:"+invite.ID, "external registration", now); err != nil {
				return User{}, err
			}
		}
		if err := insertIdentityAudit(ctx, tx, "system", AuditUserRegistered, fmt.Sprintf("user:%d", user.ID), "external registration as "+string(role), now); err != nil {
			return User{}, err
		}
		return user, nil
	}
	return User{}, ErrLoginNameTaken
}

func (store *SQLiteStore) UnlinkAccountIdentity(ctx context.Context, userID tailcfg.UserID, sessionID, reference string, methods LoginMethods) (bool, error) {
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	now := time.Now().UTC()
	if err := lockAccountSession(ctx, tx, userID, sessionID, now); err != nil {
		return false, err
	}
	links, err := listAccountIdentities(ctx, tx, userID)
	if err != nil {
		return false, err
	}
	var target ExternalIdentity
	usable := false
	for _, link := range links {
		if IdentityReference(link) == reference && link.ProviderID != LocalProviderID {
			target = link
		} else if link.ProviderID != LocalProviderID && slices.Contains(methods.Providers, link.ProviderID) {
			usable = true
		}
	}
	if target.ProviderID == "" {
		return false, ErrAccountIdentityNotFound
	}
	if !usable && methods.Local {
		if err := tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM local_credentials WHERE user_id = ? AND length(password_hash) > 0)", int64(userID)).Scan(&usable); err != nil {
			return false, err
		}
	}
	if !usable && methods.Passkeys {
		if err := tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM webauthn_credentials WHERE user_id = ?)", int64(userID)).Scan(&usable); err != nil {
			return false, err
		}
	}
	if !usable {
		return false, ErrLastLoginMethod
	}
	if err := requireIdentityWrite(tx.ExecContext(ctx, "DELETE FROM external_identities WHERE provider_id = ? AND subject = ? AND user_id = ?", target.ProviderID, target.Subject, int64(userID))); err != nil {
		return false, err
	}
	// 撤销此认证来源的会话，防止解绑后旧 SSO 会话继续持有访问权。
	if _, err := tx.ExecContext(ctx, `UPDATE sessions SET revoked_at = ?, revoked_reason = 'identity unlinked' WHERE user_id = ? AND auth_method = ? AND revoked_at IS NULL`, now.UnixNano(), int64(userID), target.ProviderID); err != nil {
		return false, err
	}
	var currentRevoked bool
	if err := tx.QueryRowContext(ctx, "SELECT revoked_at IS NOT NULL FROM sessions WHERE id = ?", sessionID).Scan(&currentRevoked); err != nil {
		return false, err
	}
	if err := insertIdentityAudit(ctx, tx, fmt.Sprintf("user:%d", userID), AuditIdentityUnlinked, "provider:"+target.ProviderID, "binding removed; provider sessions revoked", now); err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return currentRevoked, nil
}

func requireIdentityWrite(result sql.Result, err error) error {
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count != 1 {
		return errors.New("identity: required write did not affect exactly one row")
	}
	return nil
}
