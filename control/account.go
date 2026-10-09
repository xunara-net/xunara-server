package control

import (
	"context"
	"fmt"

	"github.com/xunara-net/xunara-server/identity"
)

// The built-in local account.
//
// Every control plane starts with one user: the built-in local owner
// (identity.EnsureLocalUser). It exists so that a brand-new installation has
// somebody who can grant the first role, and so that nodes and pre-auth keys
// have a user to belong to.
//
// Two flows turn that placeholder into a real account by claiming it: the
// first-run setup page, and the platform's tenant provisioner, which creates a
// tenant per sign-up. Claiming rather than creating a second user matters for
// more than tidiness: the new tenant is on a plan from the moment it exists,
// and the shipped free plan allows exactly one member. Creating another user
// would either burn that allowance on an account nobody can sign in as, or
// fail the sign-up outright on the customer's first day.

// claimLocalAccount 供初始化和自助开租户共用；认领只能成功一次，不能充当改密入口。
// 慢哈希不占数据库写锁，资料、密码、会话和必需审计由 Store 原子提交。
func (s *Server) claimLocalAccount(ctx context.Context, kind identity.LocalAccountClaimKind, login, display, email, password string) (identity.User, identity.Session, string, error) {
	if err := ctx.Err(); err != nil {
		return identity.User{}, identity.Session{}, "", err
	}

	hash, err := identity.HashPassword(password)
	if err != nil {
		return identity.User{}, identity.Session{}, "", fmt.Errorf("hashing password: %w", err)
	}
	return s.identity.ClaimLocalAccount(ctx, identity.LocalAccountClaim{
		Kind: kind, LoginName: login, DisplayName: display, Email: email,
		PasswordHash: hash, SessionTTL: s.sessionTTL,
	})
}
