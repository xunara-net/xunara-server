package control

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/xunara-net/xunara-server/identity"
	"github.com/xunara-net/xunara-server/plan"
	"tailscale.com/tailcfg"
)

// JSON authentication API (Xunara Core API v1).
//
// The product Web console (xunara-web) and the platform console (xunara-admin)
// are separate applications; they never render through the control plane.
// This file is the browser-facing half of the API they use: it exposes the
// same server-side sessions the HTML sign-in establishes as JSON, and hands
// the session cookie back exactly the way the HTML flow does, so both surfaces
// share one session store, one rate limiter and one audit trail.
//
// CSRF: the session cookie is SameSite=Lax and this API answers no CORS
// preflight for other origins, so a cross-site request cannot carry the
// cookie. Deployments serve the console and the API from one origin (see
// xunara-deploy); splitting them requires an explicit origin policy, never an
// accidental wildcard.

// apiAuthRouter mounts the JSON authentication surface under /api/v1/auth.
func (s *Server) apiAuthRouter() http.Handler {
	r := chi.NewRouter()
	r.Get("/session", s.handleAPIAuthSession)
	r.Get("/providers", s.handleAPIAuthProviders)
	r.Get("/start", s.handleAPIAuthStart)
	r.Post("/login", s.handleAPIAuthLogin)
	r.Post("/signup", s.handleAPIAuthSignup)
	r.With(deprecatedAccountEndpoint).Post("/logout", s.handleAPIAuthLogout)
	r.Post("/passkey/begin", s.handlePasskeyLoginBegin)
	r.Post("/passkey/finish", s.handlePasskeyLoginFinish)
	return r
}

// apiUserView is the JSON shape of one account. It carries no secrets and no
// identity-provider subjects: those stay inside the identity layer.
func apiUserView(user identity.User) map[string]any {
	return map[string]any{
		"id":           uint64(user.ID),
		"login_name":   user.LoginName,
		"display_name": user.DisplayName,
		"email":        user.Email,
		"role":         string(user.Role),
		"created_at":   user.CreatedAt,
		"updated_at":   user.UpdatedAt,
	}
}

// apiPlanView is the commercial view of this tenant: the plan, its quotas,
// what is used and the network the devices are allocated from. It is what the
// console's plan page and the upgrade prompts read.
func (s *Server) apiPlanView() map[string]any {
	p := s.Plan()
	used, limit := s.DeviceUsage()
	view := map[string]any{
		"id":                  p.ID,
		"name":                p.Name,
		"price_cents":         p.PriceCents,
		"currency":            p.Currency,
		"billing_cycle":       p.BillingCycle,
		"unlimited":           p.ID == "" || p.MaxDevices == plan.Unlimited,
		"max_devices":         limit,
		"max_users":           p.MaxUsers,
		"max_routes":          p.MaxRoutes,
		"max_auth_keys":       p.MaxAuthKeys,
		"devices_used":        used,
		"allow_custom_cidr":   p.AllowCustomCIDR,
		"allow_exit_node":     p.AllowExitNode,
		"allow_subnet_router": p.AllowSubnetRouter,
		"allow_api":           p.AllowAPI,
		"allow_acl":           p.AllowACL,
		"allow_grants":        p.AllowGrants,
		"allow_custom_dns":    p.AllowCustomDNS,
		"allow_audit_log":     p.AllowAuditLog,
		"allow_multi_member":  p.AllowMultiMember,
	}
	v4, v6 := s.store.AddressPrefixes()
	if v4.IsValid() {
		ranges := []string{v4.String()}
		if v6.IsValid() {
			ranges = append(ranges, v6.String())
		}
		view["network_prefix"] = ranges[0]
		view["network_ranges"] = ranges
	}
	return view
}

// apiCapabilities lists what this deployment and this tenant can do. Clients
// ask before rendering a surface, so adding a capability never requires
// teaching every client a new version (AGENTS.md section 13).
func (s *Server) apiCapabilities() []string {
	caps := []string{"auth.password"}
	p := s.Plan()
	if s.passkeys != nil {
		caps = append(caps, "auth.passkey")
	}
	if len(s.providers.IDs()) > 0 {
		caps = append(caps, "auth.oidc")
	}
	// Which self-service path this deployment accepts is a capability, not a
	// guess: a console that offers an invitation field on an open deployment
	// (or hides the sign-up link on a closed one) is worse than useless.
	switch s.registration {
	case RegistrationInvite:
		caps = append(caps, "auth.register.invite")
	case RegistrationOpen:
		caps = append(caps, "auth.register.open")
	}
	if s.tokens != nil {
		caps = append(caps, "identity.id_token")
	}
	if s.sharingEnabled() {
		caps = append(caps, "sharing")
	}
	if s.webhooksEnabled() {
		caps = append(caps, "webhooks")
	}
	if s.DERPMap() != nil {
		caps = append(caps, "derp")
	}
	if s.cfg.DNSProvider != nil {
		caps = append(caps, "dns.managed")
	}
	if s.cfg.ReachEnabled {
		caps = append(caps, "reach")
	}
	if s.flux != nil {
		caps = append(caps, "flux")
	}
	caps = append(caps, "services.agent")
	if p.AllowCustomCIDR {
		caps = append(caps, "network.custom_cidr")
	}
	if p.AllowExitNode {
		caps = append(caps, "route.exit_node")
	}
	if p.AllowSubnetRouter {
		caps = append(caps, "route.subnet_router")
	}
	if p.AllowAPI {
		caps = append(caps, "api.keys")
	}
	if p.AllowAuditLog {
		caps = append(caps, "audit")
	}
	if p.AllowMultiMember {
		caps = append(caps, "team.members")
	}
	return caps
}

// apiSessionPayload is the shared body of every request that establishes or
// reports a session: the SPA boots from it, so it answers "who am I, what
// tenant is this, what may we do" in one round trip.
func (s *Server) apiSessionPayload(user identity.User, session identity.Session) map[string]any {
	org := s.Organization()
	tenant := map[string]any{"id": s.TenantID()}
	if org.ID != "" {
		tenant["organization_id"] = org.ID
		tenant["organization_name"] = org.Name
	}
	return map[string]any{
		"authenticated": true,
		"user":          apiUserView(user),
		"session": map[string]any{
			"id":           session.ID,
			"auth_method":  session.AuthMethod,
			"created_at":   session.CreatedAt,
			"expires_at":   session.ExpiresAt,
			"last_seen_at": session.LastSeenAt,
		},
		"tenant":       tenant,
		"plan":         s.apiPlanView(),
		"capabilities": s.apiCapabilities(),
	}
}

// writeAPIAnonymousSession answers an unauthenticated session probe. It is a
// 200 with authenticated=false on purpose: the console uses it to decide
// between the sign-in page and the dashboard, and a 401 in the devtools
// console on every anonymous boot is noise, not security.
func (s *Server) writeAPIAnonymousSession(w http.ResponseWriter, r *http.Request, clearCookie bool) {
	required, err := s.localSetupRequired(r.Context())
	if err != nil {
		writeAuthenticationError(w, err)
		return
	}
	// 先确认完整快照可读取，再处理已删除用户的 Cookie，故障时保留原登录凭据。
	if clearCookie {
		s.clearSessionCookie(w)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"authenticated":  false,
		"setup_required": required,
		"local_login":    s.localLogin,
		"registration":   s.registration.String(),
		"capabilities":   s.apiCapabilities(),
	})
}

// handleAPIAuthSession implements GET /api/v1/auth/session.
func (s *Server) handleAPIAuthSession(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	session, _, err := s.resolveCookieSession(r)
	if errors.Is(err, identity.ErrSessionNotFound) {
		s.writeAPIAnonymousSession(w, r, false)
		return
	}
	if err != nil {
		writeAuthenticationError(w, err)
		return
	}
	user, err := s.identity.LookupUser(r.Context(), session.UserID)
	if errors.Is(err, identity.ErrUserNotFound) {
		// A session whose user is gone is not a session.
		s.writeAPIAnonymousSession(w, r, true)
		return
	}
	if err != nil {
		writeAuthenticationError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, s.apiSessionPayload(user, session))
}

// handleAPIAuthProviders implements GET /api/v1/auth/providers: what sign-in
// methods this deployment offers, so the console renders the right buttons
// without hardcoding the deployment's identity configuration.
func (s *Server) handleAPIAuthProviders(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	required, err := s.localSetupRequired(r.Context())
	if err != nil {
		writeAuthenticationError(w, err)
		return
	}
	views := make([]map[string]any, 0, len(s.providers.IDs()))
	for _, id := range s.providers.IDs() {
		if id == identity.LocalProviderID {
			continue
		}
		views = append(views, map[string]any{
			"id":        id,
			"name":      s.providerName(id),
			"start_url": "/api/v1/auth/start?provider=" + url.QueryEscape(id),
		})
	}
	payload := map[string]any{
		"providers":      views,
		"local_login":    s.localLogin,
		"setup_required": required,
		"passkeys":       s.passkeys != nil,
		"registration":   s.registration.String(),
	}
	// A deployment whose sign-up desk creates a tenant per account says so,
	// so the console posts to the platform endpoint instead of the
	// organization's own sign-up.
	if info := s.selfServiceInfo(); info != nil {
		payload["self_service"] = info
	}
	writeJSON(w, http.StatusOK, payload)
}

// handleAPIAuthStart 供浏览器整页导航，避免 SPA 的 /login 吞掉第三方认证请求。
// 这里只更换入口，状态、PKCE、浏览器绑定与回调仍由同一套持久认证事务处理。
func (server *Server) handleAPIAuthStart(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	providerID := request.URL.Query().Get("provider")
	if providerID == "" || providerID == identity.LocalProviderID {
		writeAPIError(writer, http.StatusBadRequest, "EXTERNAL_PROVIDER_REQUIRED: choose a configured external provider")
		return
	}
	returnTo := request.URL.Query().Get("return_to")
	if returnTo == "" {
		returnTo = "/dashboard"
	}
	server.startExternalLogin(writer, request, providerID, safeReturnTo(returnTo))
}

// apiLoginRequest is the JSON body of POST /api/v1/auth/login.
type apiLoginRequest struct {
	Login    string `json:"login"`
	Password string `json:"password"`
}

// handleAPIAuthLogin implements POST /api/v1/auth/login.
//
// It is the JSON twin of POST /login: the same rate-limit buckets, the same
// answer for every failure (whether the login name exists is not something an
// anonymous caller learns) and the same session cookie.
func (s *Server) handleAPIAuthLogin(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !s.localLogin {
		writeAPIError(w, http.StatusForbidden, "password sign-in is disabled on this server")
		return
	}
	requiresSetup, err := s.localSetupRequired(r.Context())
	if err != nil {
		writeAuthenticationError(w, err)
		return
	}
	if requiresSetup {
		writeAPIError(w, http.StatusConflict, "SETUP_REQUIRED: the deployment has not been initialized")
		return
	}

	var req apiLoginRequest
	if !decodeAPIBody(w, r, &req) {
		return
	}
	login := strings.TrimSpace(req.Login)
	password := req.Password
	result, err := s.signInWithPassword(r.Context(), s.clientIP(r), login, password)
	if err != nil {
		switch {
		case errors.Is(err, errPasswordRejected):
			writeAPIError(w, http.StatusUnauthorized, "wrong login name or password")
		case errors.Is(err, errPasswordRateLimited):
			w.Header().Set("Retry-After", fmt.Sprintf("%d", result.retryAfter))
			writeAPIError(w, http.StatusTooManyRequests, "too many sign-in attempts; wait a few minutes and try again")
		default:
			writeAuthenticationError(w, err)
		}
		return
	}

	s.setSessionCookie(w, result.token, result.session.ExpiresAt)
	writeJSON(w, http.StatusOK, s.apiSessionPayload(result.user, result.session))
}

// apiSignupRequest is the JSON body of POST /api/v1/auth/signup.
type apiSignupRequest struct {
	Invite      string `json:"invite"`
	Login       string `json:"login"`
	DisplayName string `json:"display_name"`
	Email       string `json:"email"`
	Password    string `json:"password"`
}

// handleAPIAuthSignup implements POST /api/v1/auth/signup: the JSON twin of
// the invitation page, enforcing the same invitation and quota rules.
func (s *Server) handleAPIAuthSignup(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !s.localLogin {
		writeAPIError(w, http.StatusForbidden, "registration is disabled on this server")
		return
	}
	required, err := s.localSetupRequired(r.Context())
	if err != nil {
		writeAuthenticationError(w, err)
		return
	}
	if required {
		writeAPIError(w, http.StatusConflict, "SETUP_REQUIRED: the deployment has not been initialized")
		return
	}

	var req apiSignupRequest
	if !decodeAPIBody(w, r, &req) {
		return
	}

	now := time.Now()
	allowed, retryAfter, err := s.store.AllowRate("signup:"+s.clientIP(r), signupRateLimit, signupRateWindow, now)
	if err != nil {
		s.log.Error("rate limiting registration", "err", err)
		writeAPIError(w, http.StatusServiceUnavailable, "REGISTRATION_UNAVAILABLE: try again later")
		return
	}
	if !allowed {
		w.Header().Set("Retry-After", fmt.Sprintf("%d", int(retryAfter.Seconds())+1))
		writeAPIError(w, http.StatusTooManyRequests, "too many registration attempts from this address; try again later")
		return
	}

	user, session, token, err := s.signupLocalUser(r.Context(), localSignupRequest{
		Invite:   req.Invite,
		Login:    req.Login,
		Display:  req.DisplayName,
		Email:    req.Email,
		Password: req.Password,
		Confirm:  req.Password,
	})
	if err != nil {
		var rejection signupRejection
		switch {
		case errors.As(err, &rejection):
			writeAPIError(w, rejection.Code, rejection.Message)
		default:
			s.log.Error("registration failed", "err", err)
			writeAPIError(w, http.StatusInternalServerError, "registration failed; try again")
		}
		return
	}

	s.setSessionCookie(w, token, session.ExpiresAt)
	writeJSON(w, http.StatusCreated, s.apiSessionPayload(user, session))
}

// handleAPIAuthLogout 保留旧 JSON 退出入口，但撤销与新账户接口共用同一事务。
// 匿名重复退出仍返回 204；有效会话必须有 CSRF，写入失败不能伪装成成功。
func (s *Server) handleAPIAuthLogout(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Header.Get("Authorization") == "" {
		_, _, err := s.resolveCookieSession(r)
		if errors.Is(err, identity.ErrSessionNotFound) {
			s.clearSessionCookie(w)
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if err != nil {
			writeAuthenticationError(w, err)
			return
		}
	}
	principal, ok := s.requireAccountSession(w, r, true)
	if !ok {
		return
	}
	if _, _, ok := s.revokeAccountSessions(w, r, principal, identity.SessionRevocation{
		Mode: identity.RevokeSingleSession, SessionID: principal.Session.ID,
	}); !ok {
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleAPIPlan implements GET /api/v1/plan: this tenant's plan, quotas and
// allocated network. Read scope, any role.
func (s *Server) handleAPIPlan(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireScope(w, r, identity.ScopeRead); !ok {
		return
	}
	writeJSON(w, http.StatusOK, s.apiPlanView())
}

// handleAPICapabilities implements GET /api/v1/capabilities. It is public:
// a client asks what the server supports before it has credentials, exactly
// like it fetches /key.
func (s *Server) handleAPICapabilities(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	required, err := s.localSetupRequired(r.Context())
	if err != nil {
		writeAuthenticationError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"version":                       Version,
		"protocol":                      "ts2021",
		"capabilities":                  s.apiCapabilities(),
		"local_login":                   s.localLogin,
		"setup_required":                required,
		"registration":                  s.registration.String(),
		"min_client_capability_version": uint64(MinSupportedCapabilityVersion),
		"server_capability_version":     uint64(tailcfg.CurrentCapabilityVersion),
	})
}
