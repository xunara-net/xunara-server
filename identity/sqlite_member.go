package identity

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"tailscale.com/tailcfg"
)

func (store *SQLiteStore) UpdateMember(ctx context.Context, caller MemberCaller, userID tailcfg.UserID, patch MemberPatch) (User, error) {
	actor := fmt.Sprintf("user:%d", caller.UserID)
	if caller.APIKeyID != "" {
		actor += "/apikey:" + caller.APIKeyID
	}
	return store.updateMember(ctx, &caller, userID, patch, actor)
}

func (store *SQLiteStore) UpdateUserByOperator(ctx context.Context, userID tailcfg.UserID, patch MemberPatch) (User, error) {
	return store.updateMember(ctx, nil, userID, patch, "cli")
}

func (store *SQLiteStore) updateMember(ctx context.Context, caller *MemberCaller, userID tailcfg.UserID, patch MemberPatch, actor string) (User, error) {
	if patch.Role != nil && !patch.Role.Valid() || patch.LoginName != nil && strings.TrimSpace(*patch.LoginName) == "" ||
		patch.ExpectedUpdatedAt != nil && patch.ExpectedUpdatedAt.IsZero() {
		return User{}, ErrMemberInvalid
	}
	transaction, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return User{}, fmt.Errorf("identity: starting member update: %w", err)
	}
	defer transaction.Rollback()

	now := time.Now().UTC()
	if caller != nil {
		if err := CheckNetworkWriter(ctx, transaction, caller.UserID, caller.SessionID, caller.APIKeyID, now); err != nil {
			return User{}, err
		}
		var role string
		if err := transaction.QueryRowContext(ctx, "SELECT role FROM users WHERE id = ?", int64(caller.UserID)).Scan(&role); err != nil {
			return User{}, fmt.Errorf("identity: checking member owner: %w", err)
		}
		if Role(role) != RoleOwner {
			return User{}, ErrMemberOwnerRequired
		}
	}

	previous, err := scanUser(transaction.QueryRowContext(ctx, "SELECT "+userColumns+" FROM users WHERE id = ?", int64(userID)))
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, ErrUserNotFound
	}
	if err != nil {
		return User{}, fmt.Errorf("identity: reading member for update: %w", err)
	}
	if patch.ExpectedUpdatedAt != nil && !previous.UpdatedAt.Equal(*patch.ExpectedUpdatedAt) {
		return User{}, ErrMemberConflict
	}

	updated := previous
	var changed []string
	if patch.LoginName != nil && *patch.LoginName != previous.LoginName {
		updated.LoginName = *patch.LoginName
		changed = append(changed, "login_name")
	}
	if patch.DisplayName != nil && *patch.DisplayName != previous.DisplayName {
		updated.DisplayName = *patch.DisplayName
		changed = append(changed, "display_name")
	}
	if patch.Email != nil && *patch.Email != previous.Email {
		updated.Email = *patch.Email
		changed = append(changed, "email")
	}
	roleChanged := patch.Role != nil && *patch.Role != previous.Role
	if roleChanged {
		if err := checkOwnerRemoval(ctx, transaction, previous); err != nil {
			return User{}, err
		}
		updated.Role = *patch.Role
		changed = append(changed, "role")
	}
	if len(changed) > 0 {
		// 防止时钟回拨或相同时间戳让已变更的事实继续接受旧版本。
		if !now.After(previous.UpdatedAt) {
			now = previous.UpdatedAt.Add(time.Nanosecond)
		}
		updated.UpdatedAt = now
		result, err := transaction.ExecContext(ctx, `
			UPDATE users SET login_name = ?, display_name = ?, email = ?, role = ?, updated_at = ? WHERE id = ?`,
			updated.LoginName, updated.DisplayName, updated.Email, string(updated.Role), now.UnixNano(), int64(userID))
		if err != nil {
			if isUniqueViolation(err) {
				return User{}, ErrLoginNameTaken
			}
			return User{}, fmt.Errorf("identity: updating member: %w", err)
		}
		affected, err := result.RowsAffected()
		if err != nil {
			return User{}, fmt.Errorf("identity: checking member update: %w", err)
		}
		if affected != 1 {
			return User{}, errors.New("identity: member update did not persist exactly one user")
		}
		if actor != "" {
			action := AuditUserUpdated
			detail := "updated " + strings.Join(changed, ", ")
			if roleChanged {
				action = AuditUserRoleChanged
				detail += fmt.Sprintf("; role %s -> %s", previous.Role, updated.Role)
			}
			if err := insertIdentityAudit(ctx, transaction, actor, action, fmt.Sprintf("user:%d", userID), detail, now); err != nil {
				return User{}, err
			}
		}
	}
	if err := transaction.Commit(); err != nil {
		return User{}, fmt.Errorf("identity: committing member update: %w", err)
	}
	return updated, nil
}

// checkOwnerRemoval 必须在相同写事务内使用；修改与删除共用这个不变量，不能各看旧列表。
func checkOwnerRemoval(ctx context.Context, transaction *sql.Tx, user User) error {
	if !user.Role.IsOwner() {
		return nil
	}
	var otherOwner bool
	if err := transaction.QueryRowContext(ctx, "SELECT EXISTS (SELECT 1 FROM users WHERE role = ? AND id != ?)",
		string(RoleOwner), int64(user.ID)).Scan(&otherOwner); err != nil {
		return fmt.Errorf("identity: checking other owner: %w", err)
	}
	if !otherOwner {
		return ErrLastOwner
	}
	return nil
}
