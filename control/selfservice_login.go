package control

import (
	"context"
	"errors"
	"fmt"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/xunara-net/xunara-server/identity"
)

const selfServiceLoginPath = "/api/self-service/v1/login"

// 登录名只定位人类账户；确认密码后仍要独立审批设备，不能直接信任机器。
func (router *Router) signInAccount(ctx context.Context, request *http.Request, login, password string) (*routerOrg, passwordSignInResult, error) {
	desk := router.selfService.Load()
	if desk == nil {
		return nil, passwordSignInResult{}, errPasswordRejected
	}
	front := desk.site.site.Server
	allowed, retryAfter, err := front.store.AllowRate("account-login-ip:"+front.clientIP(request), loginAddressLimit, loginAddressWindow, time.Now())
	if err != nil {
		return nil, passwordSignInResult{}, err
	}
	if !allowed {
		return nil, passwordSignInResult{retryAfter: int(retryAfter.Seconds()) + 1}, errPasswordRateLimited
	}
	login = strings.TrimSpace(login)
	target, _, err := router.resolveAccount(ctx, login)
	if err != nil {
		return nil, passwordSignInResult{}, err
	}
	if target == nil || !target.site.Server.localLogin {
		identity.VerifyPasswordMissing(password)
		return nil, passwordSignInResult{}, errPasswordRejected
	}
	required, err := target.site.Server.localSetupRequired(ctx)
	if err != nil {
		return nil, passwordSignInResult{}, err
	}
	if required {
		identity.VerifyPasswordMissing(password)
		return nil, passwordSignInResult{}, errPasswordRejected
	}
	result, err := target.site.Server.signInWithPassword(ctx, front.clientIP(request), login, password, front.sessionClientInfo(request))
	return target, result, err
}

// 账户归属由当前身份库唯一解析，不接受浏览器旧路径提供的租户提示。
func (router *Router) resolveAccount(ctx context.Context, login string) (*routerOrg, identity.User, error) {
	login = strings.TrimSpace(login)
	var target *routerOrg
	var account identity.User
	if login != "" && len(login) <= 128 {
		for _, org := range router.orgSnapshot() {
			user, err := org.site.Server.identity.LookupUserByLoginName(ctx, login)
			if errors.Is(err, identity.ErrUserNotFound) {
				continue
			}
			if err != nil {
				return nil, identity.User{}, err
			}
			// 历史同名账户不能按默认租户或密码猜测，避免身份串网。
			if target != nil {
				return nil, identity.User{}, nil
			}
			target = org
			account = user
		}
	}
	return target, account, nil
}

func (router *Router) accountConsolePath(org *routerOrg) string {
	if org.managed {
		return tenantConsolePrefix(org.site.ID)
	}
	if desk := router.selfService.Load(); desk != nil && org == desk.site {
		return ""
	}
	return ""
}

func (router *Router) accountSessionWriter(writer http.ResponseWriter, org *routerOrg) http.ResponseWriter {
	if org.managed {
		origin, _ := url.Parse(router.selfService.Load().cfg.ConsoleURL)
		return &tenantConsoleWriter{ResponseWriter: writer, orgID: org.site.ID, secure: origin.Scheme == "https"}
	}
	return writer
}

func (router *Router) handleSelfServiceLogin(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	desk := router.selfService.Load()
	if desk == nil || desk.cfg.ConsoleURL == "" {
		http.NotFound(writer, request)
		return
	}
	origin, _ := url.Parse(desk.cfg.ConsoleURL)
	if !strings.EqualFold(request.Host, origin.Host) {
		http.NotFound(writer, request)
		return
	}
	if !requireAccountJSON(writer, request) {
		return
	}
	var credentials apiLoginRequest
	if !decodeAPIBody(writer, request, &credentials) {
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), 20*time.Second)
	defer cancel()
	org, result, err := router.signInAccount(ctx, request, credentials.Login, credentials.Password)
	if err != nil {
		writeAccountLoginError(writer, result, err)
		return
	}
	// 配置组织只能在其自己的 Host 登录；共享入口不冒充其他独立域名。
	if !org.managed && org != desk.site {
		_ = org.site.Server.identity.RevokeSession(result.session.ID, "shared account entry unavailable")
		writeAccountLoginError(writer, result, errPasswordRejected)
		return
	}
	response := router.accountSessionWriter(writer, org)
	org.site.Server.setSessionCookie(response, result.token, result.session.ExpiresAt)
	writeJSON(response, http.StatusOK, map[string]any{
		"console_path": router.accountConsolePath(org),
		"session":      org.site.Server.apiSessionPayload(result.user, result.session),
	})
}

// 登录只接受 JSON，不能由外站普通 HTML 表单替浏览器发起账户切换。
func requireAccountJSON(writer http.ResponseWriter, request *http.Request) bool {
	mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		writeAPIError(writer, http.StatusUnsupportedMediaType, "JSON_REQUIRED: send an application/json body")
		return false
	}
	return true
}

func writeAccountLoginError(writer http.ResponseWriter, result passwordSignInResult, err error) {
	switch {
	case errors.Is(err, errPasswordRejected):
		writeAPIError(writer, http.StatusUnauthorized, "wrong login name or password")
	case errors.Is(err, errPasswordRateLimited):
		writer.Header().Set("Retry-After", fmt.Sprint(result.retryAfter))
		writeAPIError(writer, http.StatusTooManyRequests, "too many sign-in attempts; try again later")
	default:
		writeAuthenticationError(writer, err)
	}
}
