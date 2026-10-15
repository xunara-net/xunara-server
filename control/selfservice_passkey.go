package control

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/xunara-net/xunara-server/identity"
)

const (
	selfServicePasskeyBeginPath  = "/api/self-service/v1/passkey/begin"
	selfServicePasskeyFinishPath = "/api/self-service/v1/passkey/finish"
)

type accountPasskeyRequest struct {
	Login      string          `json:"login"`
	Credential json.RawMessage `json:"credential,omitempty"`
}

func (router *Router) accountPasskeySite(writer http.ResponseWriter, request *http.Request) *selfService {
	writer.Header().Set("Cache-Control", "no-store")
	desk := router.selfService.Load()
	if desk == nil || desk.cfg.ConsoleURL == "" {
		http.NotFound(writer, request)
		return nil
	}
	origin, _ := url.Parse(desk.cfg.ConsoleURL)
	if !strings.EqualFold(request.Host, origin.Host) {
		http.NotFound(writer, request)
		return nil
	}
	if !desk.site.site.Server.requirePasskeys(writer) {
		return nil
	}
	if !requireAccountJSON(writer, request) {
		return nil
	}
	return desk
}

// 用户名只是查找范围；密钥签名才证明身份，旧租户 URL 从不参与查找。
func (router *Router) accountPasskeyTarget(ctx context.Context, desk *selfService, login string) (*routerOrg, identity.User, error) {
	org, user, err := router.resolveAccount(ctx, login)
	if err != nil {
		return nil, identity.User{}, err
	}
	if org == nil || !user.DisabledAt.IsZero() || org.site.Server.passkeys == nil || (!org.managed && org != desk.site) {
		return nil, identity.User{}, nil
	}
	return org, user, nil
}

func (router *Router) handleSelfServicePasskeyBegin(writer http.ResponseWriter, request *http.Request) {
	desk := router.accountPasskeySite(writer, request)
	if desk == nil {
		return
	}
	var body accountPasskeyRequest
	if !decodeAPIBody(writer, request, &body) {
		return
	}
	front := desk.site.site.Server
	allowed, retryAfter, err := front.store.AllowRate("account-passkey-login-ip:"+front.clientIP(request), 20, 5*time.Minute, time.Now())
	if err != nil {
		writeAPIError(writer, http.StatusServiceUnavailable, "PASSKEY_START_FAILED: try again later")
		return
	}
	if !allowed {
		writer.Header().Set("Retry-After", fmt.Sprintf("%d", int(retryAfter.Seconds())+1))
		writeAPIError(writer, http.StatusTooManyRequests, "PASSKEY_RATE_LIMITED: too many sign-in attempts")
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), 20*time.Second)
	defer cancel()
	org, _, err := router.accountPasskeyTarget(ctx, desk, body.Login)
	if err != nil {
		writeAuthenticationError(writer, err)
		return
	}
	service := front.passkeys
	if org != nil {
		service = org.site.Server.passkeys
	}
	// 无效账户也返回不含 allowCredentials 的匿名挑战，Cookie 不泄露账户或租户。
	options, ceremonyID, browserSecret, err := service.BeginLogin()
	if err != nil {
		writeAPIError(writer, http.StatusInternalServerError, "PASSKEY_START_FAILED: could not start passkey sign-in")
		return
	}
	front.setPasskeyCookie(writer, ceremonyID, browserSecret, time.Now().Add(identity.DefaultPasskeyCeremonyTTL))
	writeJSON(writer, http.StatusOK, map[string]any{"options": options})
}

func (router *Router) handleSelfServicePasskeyFinish(writer http.ResponseWriter, request *http.Request) {
	desk := router.accountPasskeySite(writer, request)
	if desk == nil {
		return
	}
	var body accountPasskeyRequest
	if !decodeAPIBody(writer, request, &body) {
		return
	}
	front := desk.site.site.Server
	ceremonyID, browserSecret, bound := passkeyCookieValue(request)
	if !bound || len(body.Credential) == 0 || len(body.Credential) > 64<<10 {
		writeAPIError(writer, http.StatusBadRequest, "PASSKEY_LOGIN_FAILED: start sign-in again in the same browser")
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), 20*time.Second)
	defer cancel()
	org, expected, err := router.accountPasskeyTarget(ctx, desk, body.Login)
	if err != nil {
		writeAuthenticationError(writer, err)
		return
	}
	service := front.passkeys
	if org != nil {
		service = org.site.Server.passkeys
	}
	credentialRequest := request.Clone(ctx)
	credentialRequest.Body = io.NopCloser(bytes.NewReader(body.Credential))
	credentialRequest.ContentLength = int64(len(body.Credential))
	user, used, err := service.FinishLogin(ceremonyID, browserSecret, credentialRequest)
	if err != nil || org == nil || user.ID != expected.ID || user.LoginName != expected.LoginName {
		front.clearPasskeyCookie(writer)
		// 不记录原始断言、绑定 Secret 或库错误，也不按同名 / 同 ID 猜测另一身份库。
		front.audit("system", identity.AuditLoginFailed, "provider:passkey", "shared account assertion rejected")
		writeAPIError(writer, http.StatusBadRequest, "PASSKEY_LOGIN_FAILED: verification failed; start sign-in again")
		return
	}
	server := org.site.Server
	session, token, err := server.identity.CreatePasskeySession(ctx, user.ID, used.ID, server.sessionTTL, front.sessionClientInfo(request))
	if err != nil {
		front.clearPasskeyCookie(writer)
		if errors.Is(err, identity.ErrUserDisabled) {
			writeAPIError(writer, http.StatusUnauthorized, "PASSKEY_LOGIN_FAILED: sign-in is not available for this credential")
		} else {
			writeAPIError(writer, http.StatusInternalServerError, "PASSKEY_LOGIN_FAILED: could not create a session; start sign-in again")
		}
		return
	}
	response := router.accountSessionWriter(writer, org)
	server.setSessionCookie(response, token, session.ExpiresAt)
	if scoped, ok := response.(*tenantConsoleWriter); ok {
		scoped.prepare()
	}
	// 会话 Cookie 属于目标租户；入口挑战 Cookie 必须在根路径单独清除。
	front.clearPasskeyCookie(response)
	writeJSON(response, http.StatusOK, map[string]any{
		"console_path": router.accountConsolePath(org),
		"session":      server.apiSessionPayload(user, session),
	})
}
