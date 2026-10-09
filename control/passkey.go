package control

import (
	"errors"
	"fmt"
	"mime"
	"net/http"
	"strings"
	"time"

	"github.com/xunara-net/xunara-server/identity"
)

// 通行密钥只建立 Human Session；登录成功不会直接批准任何组网设备。
// HTML 与独立 Web 共用这些处理器和持久化挑战，不维护两套认证逻辑。
func (server *Server) requirePasskeys(writer http.ResponseWriter) bool {
	writer.Header().Set("Cache-Control", "no-store")
	if server.passkeys == nil {
		writeAPIError(writer, http.StatusNotFound, "PASSKEY_UNAVAILABLE: passkey sign-in is not configured")
		return false
	}
	return true
}

func (server *Server) handlePasskeyLoginBegin(writer http.ResponseWriter, request *http.Request) {
	if !server.requirePasskeys(writer) {
		return
	}
	// 无用户名登录也要持久限流，避免匿名请求无限创建挑战。存储故障时拒绝放行。
	allowed, retryAfter, err := server.store.AllowRate("passkey-login-ip:"+server.clientIP(request), 20, 5*time.Minute, time.Now())
	if err != nil {
		writeAPIError(writer, http.StatusServiceUnavailable, "PASSKEY_START_FAILED: try again later")
		return
	}
	if !allowed {
		writer.Header().Set("Retry-After", fmt.Sprintf("%d", int(retryAfter.Seconds())+1))
		writeAPIError(writer, http.StatusTooManyRequests, "PASSKEY_RATE_LIMITED: too many sign-in attempts")
		return
	}
	options, ceremonyID, browserSecret, err := server.passkeys.BeginLogin()
	if err != nil {
		writeAPIError(writer, http.StatusInternalServerError, "PASSKEY_START_FAILED: could not start passkey sign-in")
		return
	}
	server.setPasskeyCookie(writer, ceremonyID, browserSecret, time.Now().Add(identity.DefaultPasskeyCeremonyTTL))
	writeJSON(writer, http.StatusOK, map[string]any{"options": options})
}

func (server *Server) handlePasskeyLoginFinish(writer http.ResponseWriter, request *http.Request) {
	if !server.requirePasskeys(writer) {
		return
	}
	mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		writeAPIError(writer, http.StatusUnsupportedMediaType, "JSON_REQUIRED: send an application/json body")
		return
	}
	ceremonyID, browserSecret, ok := passkeyCookieValue(request)
	if !ok {
		server.audit("system", identity.AuditLoginFailed, "provider:passkey", "missing browser binding")
		writeAPIError(writer, http.StatusBadRequest, "PASSKEY_LOGIN_FAILED: start sign-in again in the same browser")
		return
	}
	request.Body = http.MaxBytesReader(writer, request.Body, 64<<10)
	user, used, err := server.passkeys.FinishLogin(ceremonyID, browserSecret, request)
	server.clearPasskeyCookie(writer)
	if err != nil {
		// 不记录原始凭据、断言或库错误；它们可能包含认证器和挑战的内部数据。
		server.audit("system", identity.AuditLoginFailed, "provider:passkey", passkeyLoginFailureReason(err))
		writeAPIError(writer, http.StatusBadRequest, "PASSKEY_LOGIN_FAILED: verification failed; start sign-in again")
		return
	}
	session, token, err := server.identity.CreatePasskeySession(request.Context(), user.ID, used.ID, server.sessionTTL)
	if err != nil {
		writeAPIError(writer, http.StatusInternalServerError, "PASSKEY_LOGIN_FAILED: could not create a session; start sign-in again")
		return
	}
	server.setSessionCookie(writer, token, session.ExpiresAt)
	// 只有序列化形状不同：保留旧 HTML fetch 契约，SPA 使用统一会话快照。
	if strings.HasPrefix(request.URL.Path, "/api/v1/auth/") {
		writeJSON(writer, http.StatusOK, server.apiSessionPayload(user, session))
		return
	}
	writeJSON(writer, http.StatusOK, map[string]string{"redirect": safeReturnTo(request.URL.Query().Get("return_to"))})
}

func passkeyLoginFailureReason(err error) string {
	switch {
	case errors.Is(err, identity.ErrPasskeyCeremonyNotFound),
		errors.Is(err, identity.ErrPasskeyCeremonyConsumed),
		errors.Is(err, identity.ErrPasskeyCeremonyExpired):
		return "ceremony expired, replayed or not this browser"
	case errors.Is(err, identity.ErrPasskeyNotFound), errors.Is(err, identity.ErrUserNotFound):
		return "unknown credential"
	default:
		return "assertion verification failed"
	}
}
