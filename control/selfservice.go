package control

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/xunara-net/xunara-server/identity"
)

// Self-service tenant provisioning (PROJECT_SPEC section 54).
//
// A hosted deployment is not a shared tailnet: every account owns one. This
// file is the desk where that happens. A visitor posts to
// /api/self-service/v1/signup on the deployment's front door, and the router
// — which owns the organization table, the plan registry and the network pool
// — creates a whole tenant for them:
//
//	organization row  → routing domain "<org>.<suffix>" and its own control plane
//	plan assignment   → the commercial limits their devices will meet
//	network block     → the tailnet address range allocated from the pool
//	owner account     → the person who signed up, as owner of that tenant
//	session           → so the browser lands in their console already signed in
//
// The router does this because it is the only component that can (AGENTS.md
// section 13: the platform layer depends on the core, never the other way
// around). A control plane serving one organization could not create another.

// selfServiceSignupPath is the platform-level sign-up endpoint. It is part of
// the console's contract, so it is a constant rather than a literal.
const selfServiceSignupPath = "/api/self-service/v1/signup"

const msgTenantSignupRequired = "TENANT_SIGNUP_REQUIRED: create an independent network through the self-service registration page"

// setSelfService attaches the sign-up desk to one organization's console
// payload. Only the front-door organization gets one.
func (s *Server) setSelfService(info *SelfServiceInfo) { s.selfService.Store(info) }

// selfServiceInfo reports this organization's sign-up desk, or nil.
func (s *Server) selfServiceInfo() *SelfServiceInfo { return s.selfService.Load() }

// selfServiceRateLimit bounds how many tenants one address may create per
// window. It is deliberately stricter than the per-tenant sign-up limit: each
// accepted request allocates a state directory and a network block.
const (
	selfServiceRateLimit  = 5
	selfServiceRateWindow = time.Hour
)

// SelfServiceConfig turns a deployment's front door into a sign-up desk.
type SelfServiceConfig struct {
	// Site is the ID of the configured organization whose hosts serve the
	// sign-up page and this API. Requests on every other host fall through to
	// their own organization's control plane.
	Site string
	// DomainSuffix is the parent domain new tenants are placed under: the
	// account "alice" becomes the organization "alice" at
	// "alice.<DomainSuffix>". It is required — a managed organization needs a
	// routing domain, so a deployment without one cannot host self-service.
	DomainSuffix string
	// Scheme is the URL scheme of new tenants' server URLs. Empty means
	// "https", which is what a hosted deployment serves.
	Scheme string
	// Port is the public port new tenants' server URLs carry. Empty means
	// the scheme's default port; a deployment reachable only on a
	// non-standard port (say 9090 behind one nginx) sets "9090", because the
	// URL it hands a new owner must be the URL that answers.
	Port string
	// CookieDomain scopes the new session to a parent domain
	// ("example.com" for "app.example.com" and "alice.example.com"), so the
	// browser carries the session from the sign-up desk to the tenant's own
	// host. Empty leaves the cookie host-only, which sends the new owner
	// through a sign-in on their tenant host instead.
	CookieDomain string
	// Plan is the plan every new tenant starts on. Empty means the catalog's
	// default (the free plan in the shipped catalog).
	Plan string
}

// SelfServiceInfo is what a console needs to use the sign-up desk.
type SelfServiceInfo struct {
	Endpoint     string `json:"endpoint"`
	DomainSuffix string `json:"domain_suffix,omitempty"`
	Plan         string `json:"plan,omitempty"`
}

// selfService is the normalized configuration, or nil when the deployment
// does not host a sign-up desk.
type selfService struct {
	cfg  SelfServiceConfig
	site *routerOrg
}

// enableSelfServiceLocked validates the deployment's sign-up desk and
// attaches it to the front-door organization. It runs once, before the router
// serves; the caller holds mu, because it reads the organization table the
// desk is being attached to.
func (r *Router) enableSelfServiceLocked() error {
	cfg := *r.cfg.SelfService
	if r.cfg.Registry == nil {
		return errors.New("control: self-service sign-up needs platform-managed organizations (-platform-state-dir)")
	}
	if r.cfg.Plans == nil {
		return errors.New("control: self-service sign-up needs a plan catalog (-plans): every tenant is created on a plan")
	}

	site := r.orgByIDLocked(cfg.Site)
	switch {
	case site == nil:
		return fmt.Errorf("control: self-service sign-up names the unknown organization %q", cfg.Site)
	case site.managed:
		return fmt.Errorf("control: self-service sign-up needs a configured organization, but %q is platform-managed", cfg.Site)
	}

	// The desk is public sign-up, so the front door must say the same thing.
	// Otherwise the console would offer an invitation form (or nothing) while
	// the API created tenants for anyone who found the endpoint.
	if mode := site.site.Server.registration; mode != RegistrationOpen {
		return fmt.Errorf("control: self-service sign-up needs open registration on %q (registration = %q, want %q)",
			cfg.Site, mode, RegistrationOpen)
	}

	suffix := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(cfg.DomainSuffix), "."))
	if suffix == "" {
		return errors.New("control: self-service sign-up needs a domain suffix (e.g. tailnet.example.com)")
	}
	if _, err := normalizeRouterDomain(suffix); err != nil {
		return fmt.Errorf("control: self-service domain suffix: %w", err)
	}
	cfg.DomainSuffix = suffix

	switch cfg.Scheme {
	case "":
		cfg.Scheme = "https"
	case "http", "https":
	default:
		return fmt.Errorf("control: self-service scheme %q must be http or https", cfg.Scheme)
	}

	cfg.Port = strings.TrimSpace(cfg.Port)
	if cfg.Port != "" {
		port, err := strconv.Atoi(cfg.Port)
		if err != nil || port < 1 || port > 65535 {
			return fmt.Errorf("control: self-service port %q must be a number between 1 and 65535", cfg.Port)
		}
	}

	// A cookie may only be widened to a domain the front door itself lives
	// under; otherwise every browser would reject it and the hand-off would
	// silently stop working.
	if cfg.CookieDomain != "" {
		domain := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(cfg.CookieDomain), "."))
		ok := false
		for _, front := range site.site.Domains {
			if hostCoveredByDomain(normalizeRouterHost(front), domain) {
				ok = true
				break
			}
		}
		if !ok {
			return fmt.Errorf("control: self-service cookie domain %q does not cover the sign-up host", cfg.CookieDomain)
		}
		cfg.CookieDomain = domain
	}

	if cfg.Plan != "" {
		if _, ok := r.cfg.Plans.Catalog().Get(cfg.Plan); !ok {
			return fmt.Errorf("control: self-service names the unknown plan %q", cfg.Plan)
		}
	}

	r.selfService.Store(&selfService{cfg: cfg, site: site})
	site.site.Server.setSelfService(&SelfServiceInfo{
		Endpoint:     selfServiceSignupPath,
		DomainSuffix: cfg.DomainSuffix,
		Plan:         cfg.Plan,
	})
	r.log.Info("self-service sign-up enabled",
		"site", cfg.Site, "domain_suffix", cfg.DomainSuffix,
		"plans", r.cfg.Plans.Catalog().Default().ID)
	return nil
}

// selfServiceRequest is the JSON body of a sign-up.
type selfServiceRequest struct {
	Login       string `json:"login"`
	DisplayName string `json:"display_name"`
	Email       string `json:"email"`
	Password    string `json:"password"`
}

// handleSelfServiceSignup implements POST /api/self-service/v1/signup: one
// account, one new organization, one owner.
func (r *Router) handleSelfServiceSignup(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	cfg := r.selfService.Load()
	org := r.orgForHost(req.Host)
	if org == nil {
		w.Header().Set("Cache-Control", "no-store")
		http.Error(w, "unknown organization", http.StatusNotFound)
		return
	}
	if cfg == nil || org.site.ID != cfg.cfg.Site {
		// The path exists platform-wide, but it belongs to the sign-up desk:
		// anywhere else the organization's own control plane answers (404,
		// because no tenant serves it).
		org.handler.ServeHTTP(w, req)
		return
	}
	if err := req.Context().Err(); err != nil {
		w.Header().Set("Retry-After", "5")
		writeAPIError(w, http.StatusServiceUnavailable, "REGISTRATION_UNAVAILABLE: try again later")
		return
	}

	now := time.Now()
	front := org.site.Server
	if allowed, retryAfter, err := front.store.AllowRate(
		"self-signup:"+front.clientIP(req), selfServiceRateLimit, selfServiceRateWindow, now); err != nil {
		front.log.Error("rate limiting self-service sign-up", "err", err)
		w.Header().Set("Retry-After", "5")
		writeAPIError(w, http.StatusServiceUnavailable, "REGISTRATION_UNAVAILABLE: try again later")
		return
	} else if !allowed {
		w.Header().Set("Retry-After", fmt.Sprintf("%d", int(retryAfter.Seconds())+1))
		writeAPIError(w, http.StatusTooManyRequests,
			"too many tenants created from this address; try again later")
		return
	}

	var body selfServiceRequest
	if !decodeAPIBody(w, req, &body) {
		return
	}
	login := sanitizeLoginName(body.Login)
	if login == "" {
		writeAPIError(w, http.StatusBadRequest, "Choose a login name (letters, digits, @ . _ - +).")
		return
	}
	if err := identity.CheckPassword(login, body.Password); err != nil {
		writeAPIError(w, http.StatusBadRequest, passwordPolicyMessage(err))
		return
	}
	display := strings.TrimSpace(body.DisplayName)
	if display == "" {
		display = login
	}
	email := strings.TrimSpace(body.Email)

	ctx := req.Context()
	orgID, err := r.selfServiceOrgID(login)
	if err != nil {
		writeAPIError(w, http.StatusConflict, "that login name is taken; choose another")
		return
	}
	domain := orgID + "." + cfg.cfg.DomainSuffix
	host := domain
	if cfg.cfg.Port != "" {
		host = net.JoinHostPort(domain, cfg.cfg.Port)
	}
	serverURL := cfg.cfg.Scheme + "://" + host

	site, err := r.CreateManagedOrg(ctx, ManagedOrg{
		ID:        orgID,
		Name:      display,
		Domains:   []string{domain},
		ServerURL: serverURL,
	})
	if err != nil {
		r.log.Error("creating a self-service organization", "organization", orgID, "err", err)
		writeAPIError(w, http.StatusConflict, "the tenant could not be created; try again")
		return
	}

	// Everything after the organization exists has a rollback: a tenant with
	// no owner or no address range is a broken tenant, not a partial one.
	srv := site.Server
	rollback := func(reason error) {
		r.log.Error("rolling back a self-service organization", "organization", orgID, "err", reason)
		// The request context is already gone on the failure paths that
		// matter (timeouts, client disconnects), so the cleanup must not
		// depend on it.
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		if _, err := r.DeleteManagedOrg(cleanupCtx, orgID); err != nil {
			r.log.Error("rolling back a self-service organization failed", "organization", orgID, "err", err)
			return
		}
		// 只有组织成功退出后才能释放分配，不能给仍存活的租户回收网段。
		if err := r.cfg.Plans.Delete(cleanupCtx, orgID); err != nil {
			r.log.Error("releasing a self-service allocation failed", "organization", orgID, "err", err)
		}
	}

	if _, err := r.cfg.Plans.Allocate(ctx, orgID); err != nil {
		rollback(err)
		writeAPIError(w, http.StatusInternalServerError, "the tenant's plan could not be assigned")
		return
	}
	if cfg.cfg.Plan != "" {
		if _, err := r.cfg.Plans.AssignPlan(ctx, orgID, cfg.cfg.Plan); err != nil {
			rollback(err)
			writeAPIError(w, http.StatusInternalServerError, "the tenant's plan could not be assigned")
			return
		}
	}
	// The block Allocate() handed the tenant is applied as the tenant's
	// address range. This is the automatic path, not the operator's custom
	// range: a plan that forbids custom CIDRs (the free plan) still gets the
	// block it was allocated.
	{
		if err := srv.refreshAddressAllocation(ctx); err != nil {
			rollback(err)
			w.Header().Set("Retry-After", "5")
			writeAPIError(w, http.StatusServiceUnavailable, "REGISTRATION_UNAVAILABLE: the tenant's network range could not be initialized; try again later")
			return
		}
	}

	// The commercial rules apply to the new tenant like to any other: a plan
	// that allows no members refuses its own owner, and the sign-up is rolled
	// back rather than creating a tenant nobody can use. The owner is the
	// tenant's one built-in account (account.go), so the count checked is the
	// count the tenant will have.
	if err := srv.assertMemberQuota(1); err != nil {
		rollback(err)
		var he HTTPError
		if errors.As(err, &he) {
			writeAPIError(w, he.Code, he.Msg)
			return
		}
		writeAPIError(w, http.StatusInternalServerError, "the tenant could not be created")
		return
	}

	user, session, token, err := srv.claimLocalAccount(ctx, identity.ClaimTenantOwner, login, display, email, body.Password)
	if err != nil {
		rollback(err)
		w.Header().Set("Retry-After", "5")
		writeAPIError(w, http.StatusServiceUnavailable, "REGISTRATION_UNAVAILABLE: the tenant's owner could not be initialized; try again later")
		return
	}
	if err := srv.clearSetupToken(); err != nil {
		srv.log.Warn("clearing initialized tenant setup token", "err", err)
	}

	// 租户内 owner、会话及成功审计已经一起提交；入口站事件仍是跨库记录。
	front.audit("system", identity.AuditUserRegistered, "org:"+orgID,
		"self-service organization created for "+login)

	// The shared cookie only helps when the request arrived on a host the
	// cookie domain covers: a browser silently drops a cookie whose Domain
	// does not suffix-match the response host. Claiming a hand-off that did
	// not happen would strand the new owner on a skeleton console, so the
	// cookie stays host-only and the console asks for one sign-in instead.
	handoff := false
	serveDomain := ""
	if cfg.cfg.CookieDomain != "" && hostCoveredByDomain(normalizeRouterHost(req.Host), cfg.cfg.CookieDomain) {
		handoff = true
		serveDomain = cfg.cfg.CookieDomain
	}
	srv.setSessionCookieFor(w, token, session.ExpiresAt, serveDomain)

	writeJSON(w, http.StatusCreated, map[string]any{
		"authenticated": true,
		"organization": map[string]any{
			"id":     orgID,
			"name":   display,
			"domain": domain,
			"url":    serverURL,
		},
		"handoff": handoff,
		"user": map[string]any{
			"id":           int(user.ID),
			"login_name":   user.LoginName,
			"display_name": user.DisplayName,
			"email":        user.Email,
			"role":         string(user.Role),
		},
	})
}

// hostCoveredByDomain reports whether domain may scope a cookie served to
// host: an exact match, or a subdomain of it (RFC 6265 domain matching).
func hostCoveredByDomain(host, domain string) bool {
	return host == domain || strings.HasSuffix(host, "."+domain)
}

// selfServiceOrgID derives the organization ID of a new tenant from the login
// name, and makes it unique. It prefers the readable form ("alice") and falls
// back to a random suffix, because the tenant's domain is derived from it and
// a sign-up that fails on a name collision is a worse experience than a
// slightly longer host name.
func (r *Router) selfServiceOrgID(login string) (string, error) {
	base := orgIDFromLogin(login)
	if base == "" {
		base = "tailnet"
	}
	for attempt := 0; attempt < 8; attempt++ {
		id := base
		if attempt > 0 {
			id = base + "-" + randomHex(3)
		}
		if len(id) > 32 {
			id = id[:32]
			id = strings.Trim(id, "-")
		}
		if managedOrgIDPattern.MatchString(id) && r.orgByID(id) == nil {
			return id, nil
		}
	}
	return "", errors.New("control: no free organization id")
}

// orgIDFromLogin maps a login name to the organization-id alphabet (lowercase
// letters, digits and dashes).
func orgIDFromLogin(login string) string {
	var b strings.Builder
	for _, ru := range strings.ToLower(login) {
		switch {
		case ru >= 'a' && ru <= 'z', ru >= '0' && ru <= '9':
			b.WriteRune(ru)
		case ru == '-' || ru == '_' || ru == '.' || ru == '@' || ru == '+':
			b.WriteByte('-')
		}
	}
	id := strings.Trim(b.String(), "-")
	if len(id) > 24 {
		id = strings.Trim(id[:24], "-")
	}
	return id
}

// randomHex returns n random bytes as hex, for the collision suffix.
func randomHex(n int) string {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		// crypto/rand failing is not a condition a request can recover from;
		// fall back to a fixed suffix so the caller still gets a valid ID and
		// the collision loop retries.
		return strings.Repeat("0", n*2)
	}
	return hex.EncodeToString(buf)
}
