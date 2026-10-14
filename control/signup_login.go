package control

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

var errSignupLoginTaken = errors.New("control: public signup login is already reserved")

type signupLoginReservation struct {
	login string
	orgID string
}

func signupLoginKey(raw string) (string, error) {
	login := strings.ToLower(strings.TrimSpace(raw))
	if login == "" || len(login) > 128 || sanitizeLoginName(login) != login {
		return "", orgInvalidf("choose a login of 1–128 letters, digits, @ . _ - + without leading or trailing punctuation")
	}
	return login, nil
}

// reserveExistingSignupLoginsLocked 仅补齐名称占用，不合并身份，也不用于决定登录归属。
// 路由器开始接收请求前执行；历史同名账户都保留，名称后续不能再次公开开户。
func (router *Router) reserveExistingSignupLoginsLocked(ctx context.Context) error {
	if err := router.releaseDeletedSignupLoginsLocked(ctx); err != nil {
		return err
	}
	var reservations []signupLoginReservation
	for _, org := range router.orgs {
		users, err := org.site.Server.identity.ListUsersContext(ctx)
		if err != nil {
			return fmt.Errorf("control: reading existing signup logins: %w", err)
		}
		for _, user := range users {
			login, err := signupLoginKey(user.LoginName)
			if err == nil {
				reservations = append(reservations, signupLoginReservation{login: login, orgID: org.site.ID})
			}
		}
	}
	return router.cfg.Registry.reserveSignupLogins(ctx, reservations)
}

// 旧版本删除租户没有释放名称。仅清理完全退出服务且原状态已归档的占用。
func (router *Router) releaseDeletedSignupLoginsLocked(ctx context.Context) error {
	rows, err := router.cfg.Registry.db.QueryContext(ctx, `SELECT DISTINCT org_id FROM signup_login_claims
		WHERE NOT EXISTS (SELECT 1 FROM managed_organizations WHERE id = org_id)`)
	if err != nil {
		return err
	}
	var orphanIDs []string
	for rows.Next() {
		var orgID string
		if err := rows.Scan(&orgID); err != nil {
			rows.Close()
			return err
		}
		orphanIDs = append(orphanIDs, orgID)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, orgID := range orphanIDs {
		if router.orgByIDLocked(orgID) != nil || !managedOrgIDPattern.MatchString(orgID) {
			continue
		}
		if _, err := os.Stat(router.cfg.Registry.StateDir(orgID)); err == nil {
			continue
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if router.cfg.Plans != nil {
			if err := router.cfg.Plans.Delete(ctx, orgID); err != nil {
				return err
			}
		}
		if _, err := router.cfg.Registry.db.ExecContext(ctx, `DELETE FROM signup_login_claims WHERE org_id = ?
			AND NOT EXISTS (SELECT 1 FROM managed_organizations WHERE id = ?)`, orgID, orgID); err != nil {
			return err
		}
	}
	return nil
}

func (registry *OrgRegistry) reserveSignupLogins(ctx context.Context, reservations []signupLoginReservation) error {
	transaction, err := registry.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer transaction.Rollback()
	now := time.Now().UTC().UnixNano()
	for _, reservation := range reservations {
		if _, err := transaction.ExecContext(ctx, `
			INSERT INTO signup_login_claims (login_name, org_id, completed, created_at) VALUES (?, ?, 1, ?)
			ON CONFLICT(login_name) DO UPDATE SET completed = 1
			WHERE signup_login_claims.org_id = excluded.org_id`,
			reservation.login, reservation.orgID, now); err != nil {
			return fmt.Errorf("control: reserving existing signup logins: %w", err)
		}
	}
	return transaction.Commit()
}

func (registry *OrgRegistry) completeSignupLogin(ctx context.Context, login, orgID string) error {
	result, err := registry.db.ExecContext(ctx,
		"UPDATE signup_login_claims SET completed = 1 WHERE login_name = ? AND org_id = ?", login, orgID)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil || count != 1 {
		return errors.New("control: signup login completion was not confirmed")
	}
	return nil
}

func (registry *OrgRegistry) signupLoginReserved(ctx context.Context, login string) (bool, error) {
	var reserved bool
	err := registry.db.QueryRowContext(ctx, "SELECT EXISTS (SELECT 1 FROM signup_login_claims WHERE login_name = ?)", login).Scan(&reserved)
	return reserved, err
}

// releaseFailedSignupLogin 只能释放本次未完成开户，且组织必须已从注册表移除。
// 已完成账户或清理失败的名称仍占用，避免旧身份被新的公开账户接管。
func (registry *OrgRegistry) releaseFailedSignupLogin(ctx context.Context, login, orgID string) error {
	_, err := registry.db.ExecContext(ctx, `
		DELETE FROM signup_login_claims
		WHERE login_name = ? AND org_id = ? AND completed = 0
		AND NOT EXISTS (SELECT 1 FROM managed_organizations WHERE id = ?)`, login, orgID, orgID)
	return err
}
