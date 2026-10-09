package control

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/xunara-net/xunara-server/identity"
)

var (
	errPasswordRejected    = errors.New("control: password sign-in rejected")
	errPasswordRateLimited = errors.New("control: password sign-in rate limited")
)

type passwordSignInResult struct {
	user       identity.User
	session    identity.Session
	token      string
	retryAfter int
}

func (server *Server) localSetupRequired(ctx context.Context) (bool, error) {
	if !server.localLogin {
		return false, nil
	}
	count, err := server.identity.LocalCredentialCount(ctx)
	return count == 0, err
}

// signInWithPassword 是 JSON 与旧 HTML 共用的业务路径，适配层只处理载荷、CSRF 与响应。
// 任何存储错误都中止认证；不能因限流失效而继续验证，也不能将读取故障解释为密码错误。
func (server *Server) signInWithPassword(ctx context.Context, address, login, password string) (passwordSignInResult, error) {
	if err := ctx.Err(); err != nil {
		return passwordSignInResult{}, err
	}
	login = strings.TrimSpace(login)
	now := time.Now()
	for _, limit := range []struct {
		scope  string
		limit  int
		window time.Duration
	}{
		{"login-ip:" + address, loginAddressLimit, loginAddressWindow},
		{"login-name:" + strings.ToLower(login), loginNameLimit, loginNameWindow},
	} {
		allowed, retryAfter, err := server.store.AllowRate(limit.scope, limit.limit, limit.window, now)
		if err != nil {
			return passwordSignInResult{}, fmt.Errorf("control: checking password admission: %w", err)
		}
		if !allowed {
			server.audit("system", identity.AuditLoginFailed, "provider:"+identity.LocalProviderID, "rate limited")
			return passwordSignInResult{retryAfter: int(retryAfter.Seconds()) + 1}, errPasswordRateLimited
		}
	}

	reject := func(detail string) (passwordSignInResult, error) {
		server.audit("system", identity.AuditLoginFailed, "provider:"+identity.LocalProviderID, detail)
		return passwordSignInResult{}, errPasswordRejected
	}
	user, err := server.identity.LookupUserByLoginName(ctx, login)
	if errors.Is(err, identity.ErrUserNotFound) {
		identity.VerifyPasswordMissing(password)
		return reject("unknown login name")
	}
	if err != nil {
		return passwordSignInResult{}, err
	}
	credential, err := server.identity.LookupLocalCredential(ctx, user.ID)
	if errors.Is(err, identity.ErrCredentialNotFound) {
		identity.VerifyPasswordMissing(password)
		return reject("account has no password")
	}
	if err != nil {
		return passwordSignInResult{}, err
	}
	if !identity.VerifyPassword(credential.PasswordHash, password) {
		return reject("wrong password")
	}

	// 慢哈希完成后再次在事务中核对原密码，避免并发改密后签发旧密码登录。
	session, token, err := server.identity.CreateLocalSession(ctx, user.ID, credential.PasswordHash, server.sessionTTL)
	if errors.Is(err, identity.ErrCredentialChanged) {
		return reject("credential changed during sign-in")
	}
	if err != nil {
		return passwordSignInResult{}, err
	}
	actor := fmt.Sprintf("user:%d", user.ID)
	server.audit(actor, identity.AuditLoginSucceeded, "provider:"+identity.LocalProviderID, "authenticated "+user.LoginName)
	server.audit(actor, identity.AuditSessionCreated, "session:"+session.ID, "auth method "+identity.LocalProviderID)
	return passwordSignInResult{user: user, session: session, token: token}, nil
}
