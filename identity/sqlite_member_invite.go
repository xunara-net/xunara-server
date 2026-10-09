package identity

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"tailscale.com/tailcfg"
)

// lockInviteOwner 不信任 HTTP 层的角色快照：另一实例撤销会话或降权后不能继续发邀请。
func lockInviteOwner(ctx context.Context, tx *sql.Tx, userID tailcfg.UserID, sessionID string, now time.Time) error {
	if err := lockAccountSession(ctx, tx, userID, sessionID, now); err != nil {
		return err
	}
	var role string
	if err := tx.QueryRowContext(ctx, "SELECT role FROM users WHERE id = ?", int64(userID)).Scan(&role); err != nil {
		return fmt.Errorf("identity: checking invitation owner: %w", err)
	}
	if Role(role) != RoleOwner {
		return ErrInviteOwnerRequired
	}
	return nil
}

func (store *SQLiteStore) CreateMemberInvitation(ctx context.Context, invitation MemberInvitation) (RegistrationInvite, string, error) {
	if invitation.TTL <= 0 || invitation.TTL > 365*24*time.Hour {
		return RegistrationInvite{}, "", errors.New("identity: invalid invitation lifetime")
	}
	invite, token, err := prepareRegistrationInvite(NewRegistrationInviteOptions{
		Role: invitation.Role, Note: invitation.Note, TTL: invitation.TTL,
		CreatedBy: fmt.Sprintf("user:%d", invitation.UserID),
	})
	if err != nil {
		return RegistrationInvite{}, "", err
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return RegistrationInvite{}, "", fmt.Errorf("identity: starting member invitation: %w", err)
	}
	defer tx.Rollback()
	if err := lockInviteOwner(ctx, tx, invitation.UserID, invitation.SessionID, time.Now().UTC()); err != nil {
		return RegistrationInvite{}, "", err
	}
	if err := checkMemberLimit(ctx, tx, invitation.MaxUsers); err != nil {
		return RegistrationInvite{}, "", err
	}
	if err := insertRegistrationInvite(ctx, tx, invite); err != nil {
		return RegistrationInvite{}, "", err
	}
	if err := insertIdentityAudit(ctx, tx, invite.CreatedBy, AuditInviteCreated, "invite:"+invite.ID, "role "+string(invite.Role), invite.CreatedAt); err != nil {
		return RegistrationInvite{}, "", err
	}
	if err := tx.Commit(); err != nil {
		return RegistrationInvite{}, "", fmt.Errorf("identity: committing member invitation: %w", err)
	}
	return invite, token, nil
}

func (store *SQLiteStore) RevokeMemberInvitation(ctx context.Context, userID tailcfg.UserID, sessionID, inviteID string) error {
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("identity: starting member invitation revocation: %w", err)
	}
	defer tx.Rollback()
	now := time.Now().UTC()
	if err := lockInviteOwner(ctx, tx, userID, sessionID, now); err != nil {
		return err
	}
	if err := revokeRegistrationInvite(ctx, tx, inviteID); err != nil {
		return err
	}
	if err := insertIdentityAudit(ctx, tx, fmt.Sprintf("user:%d", userID), AuditInviteRevoked, "invite:"+inviteID, "revoked by owner", now); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("identity: committing member invitation revocation: %w", err)
	}
	return nil
}
