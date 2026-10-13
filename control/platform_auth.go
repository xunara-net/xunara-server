package control

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/xunara-net/xunara-server/identity"
	"github.com/xunara-net/xunara-server/state"
)

const platformSessionTTL = 4 * time.Hour
const platformCeremonyCookie = "xunara_platform_ceremony"
const platformAuthPath = "/api/platform/v1/auth"

// Origin 是管理员唯一可信入口，不从请求 Host/转发头动态推导 RP 或允许来源。
type PlatformAuthConfig struct {
	Path   string
	Origin string
}

type platformAuthentication struct {
	store    identity.Store
	database *state.SQLiteStore
	passkeys *identity.PasskeyService
	origin   string
	host     string
}

type platformSessionContextKey struct{}

func openPlatformAuthentication(ctx context.Context, config PlatformAuthConfig) (*platformAuthentication, error) {
	origin, err := url.Parse(config.Origin)
	if err != nil || origin.Host == "" || origin.User != nil || origin.RawQuery != "" || origin.Fragment != "" || (origin.Path != "" && origin.Path != "/") {
		return nil, errors.New("control: invalid platform authentication origin")
	}
	if config.Path == "" {
		return nil, errors.New("control: platform identity needs a dedicated database path")
	}
	passkeyConfig := identity.PasskeyConfig{RPID: origin.Hostname(), Origins: []string{strings.TrimSuffix(config.Origin, "/")}, DisplayName: "玄序平台管理员", UserHandleNamespace: identity.PlatformPasskeyNamespace}
	if err := passkeyConfig.Validate(); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(config.Path), 0700); err != nil {
		return nil, err
	}
	database, err := state.OpenSQLite(ctx, config.Path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(config.Path, 0600); err != nil {
		database.Close()
		return nil, err
	}
	store, err := identity.NewSQLiteStore(ctx, database.DB())
	if err != nil {
		database.Close()
		return nil, err
	}
	passkeys, err := identity.NewPasskeyService(store, passkeyConfig)
	if err != nil {
		database.Close()
		return nil, err
	}
	return &platformAuthentication{store: store, database: database, passkeys: passkeys, origin: strings.TrimSuffix(config.Origin, "/"), host: origin.Host}, nil
}

func (router *Router) mountPlatformAuthentication(mux chi.Router) {
	mux.Get(platformAuthPath+"/status", func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Cache-Control", "no-store")
		origin := ""
		if router.platformAuth != nil {
			origin = router.platformAuth.origin
		}
		writeJSON(writer, http.StatusOK, map[string]any{"enabled": router.platformAuth != nil, "origin": origin, "token_login_enabled": router.cfg.PlatformAdminToken != ""})
	})
	mux.Group(func(routes chi.Router) {
		routes.Use(router.requirePlatformAuthOrigin)
		routes.Post(platformAuthPath+"/token", router.handlePlatformTokenLogin)
		routes.Post(platformAuthPath+"/passkey/begin", router.handlePlatformPasskeyLoginBegin)
		routes.Post(platformAuthPath+"/passkey/finish", router.handlePlatformPasskeyLoginFinish)
	})
}

func (router *Router) requirePlatformAuthOrigin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Cache-Control", "no-store")
		if router.platformAuth == nil {
			writeAPIError(writer, 503, "PLATFORM_AUTH_DISABLED: platform passkeys are not configured")
			return
		}
		if !strings.EqualFold(request.Host, router.platformAuth.host) || request.Header.Get("Origin") != router.platformAuth.origin {
			writeAPIError(writer, 403, "PLATFORM_ORIGIN_INVALID: use the configured administrator origin")
			return
		}
		next.ServeHTTP(writer, request)
	})
}

func (router *Router) allowPlatformAuthentication(writer http.ResponseWriter, request *http.Request) bool {
	ip, _, _ := net.SplitHostPort(request.RemoteAddr)
	if org := router.orgForHost(request.Host); org != nil {
		ip = org.site.Server.clientIP(request)
	}
	allowed, retry, err := router.platformAuth.database.AllowRate("platform-auth:"+ip, 20, 5*time.Minute, time.Now())
	if err != nil {
		writeAPIError(writer, 503, "PLATFORM_AUTH_UNAVAILABLE: authentication storage unavailable")
		return false
	}
	if !allowed {
		writer.Header().Set("Retry-After", fmt.Sprint(int(retry.Seconds())+1))
		writeAPIError(writer, 429, "PLATFORM_AUTH_RATE_LIMITED: too many attempts")
		return false
	}
	return true
}

func platformClientInfo(request *http.Request) identity.SessionClientInfo {
	ip, _, _ := net.SplitHostPort(request.RemoteAddr)
	return (identity.SessionClientInfo{IP: ip, UserAgent: request.UserAgent()}).Normalize()
}

func (router *Router) handlePlatformTokenLogin(writer http.ResponseWriter, request *http.Request) {
	if !router.allowPlatformAuthentication(writer, request) {
		return
	}
	token, ok := bearerToken(request)
	if !ok || router.cfg.PlatformAdminToken == "" || !constantTimeTokenEqual(router.platformTokenHash, token) {
		writeAPIError(writer, 401, "PLATFORM_LOGIN_FAILED: invalid recovery token")
		return
	}
	session, sessionToken, err := router.platformAuth.store.CreatePlatformSession(request.Context(), platformSessionTTL, platformClientInfo(request))
	if err != nil {
		writeAPIError(writer, 503, "PLATFORM_AUTH_UNAVAILABLE: could not create administrator session")
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"token": sessionToken, "expires_at": session.ExpiresAt})
}

func (router *Router) setPlatformCeremony(writer http.ResponseWriter, id, secret, sessionID string) {
	http.SetCookie(writer, &http.Cookie{Name: platformCeremonyCookie, Value: id + "." + secret + "." + identity.HashSecret(sessionID), Path: platformAuthPath,
		HttpOnly: true, Secure: strings.HasPrefix(router.platformAuth.origin, "https:"), SameSite: http.SameSiteStrictMode, MaxAge: int(identity.DefaultPasskeyCeremonyTTL.Seconds())})
}

func (router *Router) takePlatformCeremony(writer http.ResponseWriter, request *http.Request, sessionID string) (string, string, bool) {
	http.SetCookie(writer, &http.Cookie{Name: platformCeremonyCookie, Value: "", Path: platformAuthPath, MaxAge: -1, HttpOnly: true,
		Secure: strings.HasPrefix(router.platformAuth.origin, "https:"), SameSite: http.SameSiteStrictMode})
	cookie, err := request.Cookie(platformCeremonyCookie)
	if err != nil {
		return "", "", false
	}
	parts := strings.Split(cookie.Value, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] != identity.HashSecret(sessionID) {
		return "", "", false
	}
	return parts[0], parts[1], true
}

func (router *Router) handlePlatformPasskeyLoginBegin(writer http.ResponseWriter, request *http.Request) {
	if !router.allowPlatformAuthentication(writer, request) {
		return
	}
	options, id, secret, err := router.platformAuth.passkeys.BeginLogin()
	if err != nil {
		writeAPIError(writer, 503, "PLATFORM_AUTH_UNAVAILABLE: could not begin authentication")
		return
	}
	router.setPlatformCeremony(writer, id, secret, "")
	writeJSON(writer, http.StatusOK, map[string]any{"options": options})
}

func (router *Router) handlePlatformPasskeyLoginFinish(writer http.ResponseWriter, request *http.Request) {
	if !router.allowPlatformAuthentication(writer, request) {
		return
	}
	id, secret, ok := router.takePlatformCeremony(writer, request, "")
	var credential json.RawMessage
	if !decodeAccountBodyLimit(writer, request, &credential, 64<<10) {
		return
	}
	if !ok {
		writeAPIError(writer, 400, "PLATFORM_PASSKEY_FAILED: restart authentication in this browser")
		return
	}
	finish := request.Clone(request.Context())
	finish.Body = io.NopCloser(bytes.NewReader(credential))
	finish.ContentLength = int64(len(credential))
	user, passkey, err := router.platformAuth.passkeys.FinishLogin(id, secret, finish)
	if err != nil || user.LoginName != identity.PlatformLoginName || !user.Role.IsOwner() {
		writeAPIError(writer, 400, "PLATFORM_PASSKEY_FAILED: verification failed; restart authentication")
		return
	}
	session, token, err := router.platformAuth.store.CreatePasskeySession(request.Context(), user.ID, passkey.ID, platformSessionTTL, platformClientInfo(request))
	if err != nil {
		writeAPIError(writer, 503, "PLATFORM_AUTH_UNAVAILABLE: could not create administrator session")
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"token": token, "expires_at": session.ExpiresAt})
}

func (router *Router) requirePlatformSession(writer http.ResponseWriter, request *http.Request) (identity.Session, bool) {
	session, ok := request.Context().Value(platformSessionContextKey{}).(identity.Session)
	if !ok {
		writeAPIError(writer, 403, "PLATFORM_SESSION_REQUIRED: sign in to manage administrator credentials")
		return identity.Session{}, false
	}
	if request.Method != http.MethodGet && request.Header.Get("Origin") != router.platformAuth.origin {
		writeAPIError(writer, 403, "PLATFORM_ORIGIN_INVALID: use the configured administrator origin")
		return identity.Session{}, false
	}
	if request.Method != http.MethodGet && request.URL.Path != platformAuthPath+"/logout" && time.Since(session.CreatedAt) > 15*time.Minute {
		writeAPIError(writer, 403, "PLATFORM_REAUTH_REQUIRED: sign in again before changing administrator credentials")
		return identity.Session{}, false
	}
	return session, true
}

func (router *Router) handlePlatformPasskeys(writer http.ResponseWriter, request *http.Request) {
	session, ok := router.requirePlatformSession(writer, request)
	if !ok {
		return
	}
	keys, err := router.platformAuth.store.ListAccountPasskeys(request.Context(), session.UserID)
	if err != nil {
		writeAPIError(writer, 503, "PLATFORM_AUTH_UNAVAILABLE: could not read administrator credentials")
		return
	}
	views := make([]accountPasskeyView, 0, len(keys))
	for _, key := range keys {
		views = append(views, accountPasskey(key))
	}
	writeJSON(writer, http.StatusOK, map[string]any{"passkeys": views, "recovery_available": router.cfg.PlatformAdminToken != "", "auth_method": session.AuthMethod, "expires_at": session.ExpiresAt})
}

func (router *Router) handlePlatformPasskeyRegisterBegin(writer http.ResponseWriter, request *http.Request) {
	session, ok := router.requirePlatformSession(writer, request)
	if !ok || !router.allowPlatformAuthentication(writer, request) {
		return
	}
	user, err := router.platformAuth.store.LookupUser(request.Context(), session.UserID)
	if err != nil {
		writeAPIError(writer, 503, "PLATFORM_AUTH_UNAVAILABLE: could not read administrator account")
		return
	}
	options, id, secret, err := router.platformAuth.passkeys.BeginRegistrationForSession(user, session.ID)
	if err != nil {
		writeAPIError(writer, 503, "PLATFORM_AUTH_UNAVAILABLE: could not begin registration")
		return
	}
	router.setPlatformCeremony(writer, id, secret, session.ID)
	writeJSON(writer, http.StatusOK, map[string]any{"options": options})
}

func (router *Router) handlePlatformPasskeyRegisterFinish(writer http.ResponseWriter, request *http.Request) {
	session, ok := router.requirePlatformSession(writer, request)
	if !ok {
		return
	}
	var body struct {
		Name       string          `json:"name"`
		Credential json.RawMessage `json:"credential"`
	}
	if !decodeAccountBodyLimit(writer, request, &body, 64<<10) {
		return
	}
	name, err := passkeyDisplayName(body.Name)
	if err != nil || len(body.Credential) == 0 || string(body.Credential) == "null" {
		writeAPIError(writer, 400, "PASSKEY_INVALID: invalid name or credential")
		return
	}
	id, secret, ok := router.takePlatformCeremony(writer, request, session.ID)
	if !ok {
		writeAPIError(writer, 400, "PLATFORM_PASSKEY_FAILED: restart registration in the initiating session")
		return
	}
	user, err := router.platformAuth.store.LookupUser(request.Context(), session.UserID)
	if err != nil {
		writeAPIError(writer, 503, "PLATFORM_AUTH_UNAVAILABLE: could not read administrator account")
		return
	}
	finish := request.Clone(request.Context())
	finish.Body = io.NopCloser(bytes.NewReader(body.Credential))
	finish.ContentLength = int64(len(body.Credential))
	key, err := router.platformAuth.passkeys.FinishRegistration(id, secret, user, session.ID, name, finish)
	if err != nil {
		var verificationError *protocol.Error
		switch {
		case errors.Is(err, identity.ErrSessionRevoked):
			writeAPIError(writer, 401, "PLATFORM_SESSION_CHANGED: initiating session revoked")
		case errors.As(err, &verificationError), errors.Is(err, identity.ErrPasskeyCeremonyNotFound), errors.Is(err, identity.ErrPasskeyCeremonyConsumed), errors.Is(err, identity.ErrPasskeyCeremonyExpired):
			writeAPIError(writer, 400, "PLATFORM_PASSKEY_FAILED: could not verify registration; restart verification")
		default:
			writeAPIError(writer, 503, "PLATFORM_AUTH_UNAVAILABLE: could not save registration; refresh to check")
		}
		return
	}
	writeJSON(writer, 201, map[string]any{"passkey": accountPasskey(key)})
}

func (router *Router) handlePlatformDeletePasskey(writer http.ResponseWriter, request *http.Request) {
	session, ok := router.requirePlatformSession(writer, request)
	if !ok {
		return
	}
	err := router.platformAuth.store.DeletePlatformPasskey(request.Context(), session.UserID, session.ID, chi.URLParam(request, "id"), router.cfg.PlatformAdminToken != "")
	if err != nil {
		switch {
		case errors.Is(err, identity.ErrPasskeyNotFound):
			writeAPIError(writer, 404, "PASSKEY_NOT_FOUND: refresh administrator credentials")
		case errors.Is(err, identity.ErrLastLoginMethod):
			writeAPIError(writer, 409, "LAST_LOGIN_METHOD: bind another passkey or configure recovery first")
		case errors.Is(err, identity.ErrSessionRevoked):
			writeAPIError(writer, 401, "PLATFORM_SESSION_CHANGED: sign in again")
		default:
			writeAPIError(writer, 503, "PLATFORM_AUTH_UNAVAILABLE: could not unbind credential; refresh to check")
		}
		return
	}
	writeJSON(writer, 200, map[string]any{"signed_out": session.AuthMethod == "passkey"})
}

func (router *Router) handlePlatformLogout(writer http.ResponseWriter, request *http.Request) {
	session, ok := router.requirePlatformSession(writer, request)
	if !ok {
		return
	}
	_, err := router.platformAuth.store.RevokeAccountSessions(request.Context(), session.UserID, session.ID, identity.SessionRevocation{Mode: identity.RevokeSingleSession, SessionID: session.ID})
	if err != nil {
		writeAPIError(writer, 503, "PLATFORM_AUTH_UNAVAILABLE: could not revoke administrator session")
		return
	}
	writer.WriteHeader(http.StatusNoContent)
}
