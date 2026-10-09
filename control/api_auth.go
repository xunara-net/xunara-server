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
	r.Post("/login", s.handleAPIAuthLogin)
	r.Post("/signup", s.handleAPIAuthSignup)
	r.Post("/logout", s.handleAPIAuthLogout)
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
	if s.cfg.DERPMap != nil {
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
func (s *Server) writeAPIAnonymousSession(w http.ResponseWriter) {
	writeJSON(w, http.StatusOK, map[string]any{
		"authenticated":  false,
		"setup_required": s.setupRequired(),
		"local_login":    s.localLogin,
		"registration":   s.registration.String(),
		"capabilities":   s.apiCapabilities(),
	})
}

// handleAPIAuthSession implements GET /api/v1/auth/session.
func (s *Server) handleAPIAuthSession(w http.ResponseWriter, r *http.Request) {
	session, ok := s.currentSession(r)
	if !ok {
		s.writeAPIAnonymousSession(w)
		return
	}
	user, ok := s.identity.GetUser(session.UserID)
	if !ok {
		// A session whose user is gone is not a session.
		s.clearSessionCookie(w)
		s.writeAPIAnonymousSession(w)
		return
	}
	writeJSON(w, http.StatusOK, s.apiSessionPayload(user, session))
}

// handleAPIAuthProviders implements GET /api/v1/auth/providers: what sign-in
// methods this deployment offers, so the console renders the right buttons
// without hardcoding the deployment's identity configuration.
func (s *Server) handleAPIAuthProviders(w http.ResponseWriter, r *http.Request) {
	views := make([]map[string]any, 0, len(s.providers.IDs()))
	for _, id := range s.providers.IDs() {
		if id == identity.LocalProviderID {
			continue
		}
		views = append(views, map[string]any{
			"id":        id,
			"name":      s.providerName(id),
			"start_url": "/login?provider=" + url.QueryEscape(id),
		})
	}
	payload := map[string]any{
		"providers":      views,
		"local_login":    s.localLogin,
		"setup_required": s.setupRequired(),
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
	if !s.localLogin {
		writeAPIError(w, http.StatusForbidden, "password sign-in is disabled on this server")
		return
	}
	if s.setupRequired() {
		writeAPIError(w, http.StatusConflict, "SETUP_REQUIRED: the deployment has not been initialized")
		return
	}

	var req apiLoginRequest
	if !decodeAPIBody(w, r, &req) {
		return
	}
	login := strings.TrimSpace(req.Login)
	password := req.Password
	now := time.Now()

	reject := func(status int, detail string) {
		s.audit("system", identity.AuditLoginFailed, "provider:"+identity.LocalProviderID, detail)
		writeAPIError(w, status, "wrong login name or password")
	}

	for _, limit := range []struct {
		scope  string
		limit  int
		window time.Duration
	}{
		{"login-ip:" + s.clientIP(r), loginAddressLimit, loginAddressWindow},
		{"login-name:" + strings.ToLower(login), loginNameLimit, loginNameWindow},
	} {
		allowed, retryAfter, err := s.store.AllowRate(limit.scope, limit.limit, limit.window, now)
		if err != nil {
			s.log.Error("rate limiting sign-in", "err", err)
			break
		}
		if !allowed {
			w.Header().Set("Retry-After", fmt.Sprintf("%d", int(retryAfter.Seconds())+1))
			s.audit("system", identity.AuditLoginFailed, "provider:"+identity.LocalProviderID, "rate limited")
			writeAPIError(w, http.StatusTooManyRequests, "too many sign-in attempts; wait a few minutes and try again")
			return
		}
	}

	user, ok := s.identity.GetUserByLoginName(login)
	if !ok || login == "" {
		identity.VerifyPasswordMissing(password)
		reject(http.StatusUnauthorized, "unknown login name")
		return
	}
	credential, hasCredential := s.identity.GetLocalCredential(user.ID)
	if !hasCredential {
		identity.VerifyPasswordMissing(password)
		reject(http.StatusUnauthorized, "account has no password")
		return
	}
	if !identity.VerifyPassword(credential.PasswordHash, password) {
		reject(http.StatusUnauthorized, "wrong password for "+user.LoginName)
		return
	}

	session, token, err := s.identity.CreateSession(identity.NewSessionOptions{
		UserID:     user.ID,
		AuthMethod: identity.LocalProviderID,
		TTL:        s.sessionTTL,
	})
	if err != nil {
		s.log.Error("creating session", "user", int(user.ID), "err", err)
		writeAPIError(w, http.StatusInternalServerError, "sign-in failed; try again")
		return
	}

	actor := fmt.Sprintf("user:%d", user.ID)
	s.audit(actor, identity.AuditLoginSucceeded, "provider:"+identity.LocalProviderID, "authenticated "+user.LoginName)
	s.audit(actor, identity.AuditSessionCreated, "session:"+session.ID, "auth method "+identity.LocalProviderID)
	s.setSessionCookie(w, token, session.ExpiresAt)
	writeJSON(w, http.StatusOK, s.apiSessionPayload(user, session))
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
	if !s.localLogin {
		writeAPIError(w, http.StatusForbidden, "registration is disabled on this server")
		return
	}
	if s.setupRequired() {
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
	}
	if err == nil && !allowed {
		w.Header().Set("Retry-After", fmt.Sprintf("%d", int(retryAfter.Seconds())+1))
		writeAPIError(w, http.StatusTooManyRequests, "too many registration attempts from this address; try again later")
		return
	}

	user, session, token, err := s.signupLocalUser(localSignupRequest{
		Invite:   req.Invite,
		Login:    req.Login,
		Display:  req.DisplayName,
		Email:    req.Email,
		Password: req.Password,
		Confirm:  req.Password,
	}, now)
	if err != nil {
		var rejection signupRejection
		switch {
		case errors.As(err, &rejection):
			writeAPIError(w, rejection.Code, rejection.Message)
		case errors.Is(err, errSignupNoSession):
			writeAPIError(w, http.StatusInternalServerError, "the account was created; sign in to continue")
		default:
			s.log.Error("registration failed", "err", err)
			writeAPIError(w, http.StatusInternalServerError, "registration failed; try again")
		}
		return
	}

	s.setSessionCookie(w, token, session.ExpiresAt)
	writeJSON(w, http.StatusCreated, s.apiSessionPayload(user, session))
}

// handleAPIAuthLogout implements POST /api/v1/auth/logout. It is idempotent:
// signing out twice, or without a session, is not an error.
func (s *Server) handleAPIAuthLogout(w http.ResponseWriter, r *http.Request) {
	token := sessionToken(r)
	if token != "" {
		if session, err := s.identity.GetSessionByToken(token); err == nil {
			if err := s.identity.RevokeSession(session.ID, "logout"); err != nil {
				s.log.Error("revoking session", "session", session.ID, "err", err)
			}
			s.audit(fmt.Sprintf("user:%d", session.UserID), identity.AuditSessionRevoked, "session:"+session.ID, "logout")
		}
	}
	s.clearSessionCookie(w)
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
	writeJSON(w, http.StatusOK, map[string]any{
		"version":                       Version,
		"protocol":                      "ts2021",
		"capabilities":                  s.apiCapabilities(),
		"local_login":                   s.localLogin,
		"setup_required":                s.setupRequired(),
		"registration":                  s.registration.String(),
		"min_client_capability_version": uint64(MinSupportedCapabilityVersion),
		"server_capability_version":     uint64(tailcfg.CurrentCapabilityVersion),
	})
}
