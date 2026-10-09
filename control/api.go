package control

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"tailscale.com/tailcfg"

	"github.com/xunara-net/xunara-server/identity"
)

// apiPrincipal is the authenticated caller of a platform API request.
//
// A principal is a human session or a service API key; the machine identity of
// a node is never a principal (AGENTS.md section 5).
type apiPrincipal struct {
	Kind string // "session" or "api_key"

	UserID tailcfg.UserID
	// Role is the acting user's platform role. A service key acts for its
	// owner's role: its scopes narrow that role, they never widen it.
	Role   identity.Role
	Scopes map[string]bool

	Session identity.Session
	APIKey  identity.APIKey
}

// actor names the principal in the audit log.
func (p apiPrincipal) actor() string {
	actor := "user:" + strconv.FormatUint(uint64(p.UserID), 10)
	if p.APIKey.ID != "" {
		actor += "/apikey:" + p.APIKey.ID
	}
	return actor
}

// authenticateAPI resolves the request's credentials: a bearer token (API key
// or session token) or the browser session cookie.
func (s *Server) authenticateAPI(r *http.Request) (apiPrincipal, error) {
	if raw := r.Header.Get("Authorization"); raw != "" {
		scheme, token, ok := strings.Cut(raw, " ")
		if !ok || !strings.EqualFold(scheme, "Bearer") {
			return apiPrincipal{}, errAuthenticationRequired
		}
		token = strings.TrimSpace(token)
		if token == "" {
			return apiPrincipal{}, errAuthenticationRequired
		}
		return s.principalForToken(r.Context(), token)
	}

	session, _, err := s.resolveCookieSession(r)
	if err != nil {
		return apiPrincipal{}, err
	}
	return s.resolveSessionPrincipal(r.Context(), session)
}

// principalForToken resolves a bearer token, without an HTTP request: an API
// key (service identity) or a session token. The gRPC surface uses it too, so
// both transports accept exactly the same credentials.
func (s *Server) principalForToken(ctx context.Context, token string) (apiPrincipal, error) {
	if strings.HasPrefix(token, identity.APIKeyPrefix) {
		key, err := s.identity.GetAPIKeyByToken(token)
		if err != nil {
			return apiPrincipal{}, err
		}
		user, err := s.identity.LookupUser(ctx, key.UserID)
		if err != nil {
			// The owning user is gone; the key is a dangling service
			// identity and must not authenticate.
			return apiPrincipal{}, err
		}
		if err := s.identity.TouchAPIKey(key.ID, time.Now().UTC()); err != nil {
			s.log.Warn("recording API key use", "key", key.ID, "err", err)
		}
		return apiPrincipal{
			Kind:   "api_key",
			UserID: key.UserID,
			Role:   user.Role,
			Scopes: scopeSet(key.Scopes),
			APIKey: key,
		}, nil
	}

	session, err := s.identity.GetSessionByToken(token)
	if err != nil {
		return apiPrincipal{}, err
	}
	return s.resolveSessionPrincipal(ctx, session)
}

// sessionPrincipal grants a signed-in human the full scope set; the role still
// bounds what those scopes can do.
func (s *Server) sessionPrincipal(session identity.Session) (apiPrincipal, bool) {
	principal, err := s.resolveSessionPrincipal(context.Background(), session)
	return principal, err == nil
}

func (server *Server) resolveSessionPrincipal(ctx context.Context, session identity.Session) (apiPrincipal, error) {
	user, err := server.identity.LookupUser(ctx, session.UserID)
	if err != nil {
		// A session for a deleted user is not a valid principal.
		return apiPrincipal{}, err
	}
	return apiPrincipal{
		Kind:    "session",
		UserID:  session.UserID,
		Role:    user.Role,
		Scopes:  map[string]bool{identity.ScopeRead: true, identity.ScopeWrite: true},
		Session: session,
	}, nil
}

var errAuthenticationRequired = errors.New("authentication required")

func isAuthenticationRequired(err error) bool {
	return errors.Is(err, errAuthenticationRequired) || errors.Is(err, identity.ErrSessionNotFound) ||
		errors.Is(err, identity.ErrAPIKeyNotFound) || errors.Is(err, identity.ErrUserNotFound)
}

// 无效身份与认证服务故障使用不同结果；错误正文不暴露数据库信息或原始凭据。
func writeAuthenticationError(writer http.ResponseWriter, err error) {
	writer.Header().Set("Cache-Control", "no-store")
	if isAuthenticationRequired(err) {
		writer.Header().Set("WWW-Authenticate", `Bearer realm="xunara"`)
		writeAPIError(writer, http.StatusUnauthorized, "authentication required")
		return
	}
	writer.Header().Set("Retry-After", "5")
	writeAPIError(writer, http.StatusServiceUnavailable, "AUTH_UNAVAILABLE: could not check authentication; try again later")
}

func (server *Server) requireAPIPrincipal(writer http.ResponseWriter, request *http.Request) (apiPrincipal, bool) {
	principal, err := server.authenticateAPI(request)
	if err != nil {
		writeAuthenticationError(writer, err)
		return apiPrincipal{}, false
	}
	return principal, true
}

// requireScope authenticates the request and checks the scope. The write
// scope additionally requires a role that may change tailnet state; service
// keys inherit their owner's role.
func (s *Server) requireScope(w http.ResponseWriter, r *http.Request, scope string) (apiPrincipal, bool) {
	principal, ok := s.requireAPIPrincipal(w, r)
	if !ok {
		return apiPrincipal{}, false
	}
	if err := authorizeScope(principal, scope); err != nil {
		writeAPIError(w, http.StatusForbidden, err.Error())
		return apiPrincipal{}, false
	}
	return principal, true
}

// authorizeScope applies the scope and role rules shared by every transport:
// the scope must be granted, and a write additionally needs a role that may
// change tailnet state (service keys inherit their owner's role).
func authorizeScope(principal apiPrincipal, scope string) error {
	if !principal.Scopes[scope] {
		return errors.New("missing scope: " + scope)
	}
	if scope == identity.ScopeWrite && !principal.Role.CanWrite() {
		return errors.New("role " + principal.Role.String() + " may not change the tailnet")
	}
	return nil
}

// requireSelfScope authenticates the request and checks the scope without
// consulting the role: it guards actions a principal may always take on its
// own objects, such as revoking its own session or service key.
func (s *Server) requireSelfScope(w http.ResponseWriter, r *http.Request, scope string) (apiPrincipal, bool) {
	principal, ok := s.requireAPIPrincipal(w, r)
	if !ok {
		return apiPrincipal{}, false
	}
	if !principal.Scopes[scope] {
		writeAPIError(w, http.StatusForbidden, "missing scope: "+scope)
		return apiPrincipal{}, false
	}
	return principal, true
}

// requireOwner authenticates the request and requires the owner role.
func (s *Server) requireOwner(w http.ResponseWriter, r *http.Request) (apiPrincipal, bool) {
	principal, ok := s.requireScope(w, r, identity.ScopeWrite)
	if !ok {
		return apiPrincipal{}, false
	}
	if !principal.Role.IsOwner() {
		writeAPIError(w, http.StatusForbidden, "owner role required")
		return apiPrincipal{}, false
	}
	return principal, true
}

// scopeSet turns a scope list into a lookup set.
func scopeSet(scopes []string) map[string]bool {
	out := make(map[string]bool, len(scopes))
	for _, scope := range scopes {
		out[scope] = true
	}
	return out
}

// apiRouter builds the versioned platform API.
func (s *Server) apiRouter() http.Handler {
	r := chi.NewRouter()

	// Authentication is the one surface the console must reach before it has
	// a session, so it lives here rather than behind requireScope.
	r.Mount("/auth", s.apiAuthRouter())
	r.Get("/capabilities", s.handleAPICapabilities)

	r.Get("/overview", s.handleAPIOverview)
	r.Get("/plan", s.handleAPIPlan)
	r.Get("/account", s.handleAPIAccount)
	r.Patch("/account", s.handleAPIUpdateAccount)
	r.Post("/account/password", s.handleAPIChangePassword)
	r.Get("/account/sessions", s.handleAPIAccountSessions)
	r.Post("/account/sessions/revoke", s.handleAPIRevokeAccountSessions)
	r.Delete("/account/sessions/{id}", s.handleAPIRevokeAccountSession)
	r.Get("/account/passkeys", s.handleAPIAccountPasskeys)
	r.Post("/account/passkeys/begin", s.handleAPIAccountPasskeyBegin)
	r.Post("/account/passkeys/finish", s.handleAPIAccountPasskeyFinish)
	r.Delete("/account/passkeys/{id}", s.handleAPIDeleteAccountPasskey)

	r.Get("/machines", s.handleAPIMachines)
	r.Get("/machines/{ref}", s.handleAPIMachine)
	r.Delete("/machines/{ref}", s.handleAPIDeleteMachine)
	r.Post("/machines/{ref}/routes", s.handleAPIMachineRoutes)
	r.Get("/routes", s.handleAPIRoutes)

	r.Get("/users", s.handleAPIUsers)
	r.Get("/users/{id}", s.handleAPIUser)
	r.Patch("/users/{id}", s.handleAPIUpdateUser)

	r.Get("/dns", s.handleAPIDNS)
	r.Delete("/dns/{id}", s.handleAPIDeleteDNS)

	r.Get("/policy", s.handleAPIPolicy)

	r.Get("/auth-keys", s.handleAPIAuthKeys)
	r.Post("/auth-keys", s.handleAPICreateAuthKey)
	r.Delete("/auth-keys/{id}", s.handleAPIDeleteAuthKey)

	r.Get("/devices", s.handleAPIDevices)
	r.Post("/devices/{id}/approve", s.handleAPIApproveDevice)
	r.Post("/devices/{id}/deny", s.handleAPIDenyDevice)

	r.Get("/audit", s.handleAPIAudit)

	r.Get("/api-keys", s.handleAPIKeys)
	r.Post("/api-keys", s.handleAPICreateAPIKey)
	r.Delete("/api-keys/{id}", s.handleAPIRevokeAPIKey)

	r.With(deprecatedAccountEndpoint).Get("/sessions", s.handleAPISessions)
	// 旧路径只做兼容适配，不能绕过账户接口的人类身份、CSRF 和事务边界。
	r.With(deprecatedAccountEndpoint).Delete("/sessions/{id}", s.handleAPIRevokeAccountSession)

	return r
}

// writeAPIError writes a JSON error response.
func writeAPIError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]any{"error": msg})
}

// decodeAPIBody decodes a bounded JSON body, rejecting unknown fields so typos
// are errors instead of silent no-ops.
func decodeAPIBody(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid JSON body")
		return false
	}
	return true
}
