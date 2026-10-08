package control

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
)

// This file implements /api/platform: the cross-organization platform API a
// multi-tenant deployment exposes to its operator. It is deliberately not
// reachable with an organization's own credentials (session cookie or
// organization API key): those are tenant-scoped, and letting one tenant
// enumerate the others would be a tenant-boundary violation (AGENTS.md
// section 12). The only credential accepted is the platform admin token from
// the process environment; when unset, the API is disabled.

// PlatformOrg is the platform API's view of one organization.
type PlatformOrg struct {
	ID      string           `json:"id"`
	Name    string           `json:"name"`
	Domains []string         `json:"domains,omitempty"`
	Stats   PlatformOrgStats `json:"stats"`
	// Managed is true for organizations created through the platform API.
	// Configured organizations are read-only here.
	Managed bool `json:"managed"`
}

// PlatformOrgStats is a small, read-only summary of an organization's control
// plane. It intentionally exposes no key material, addresses or identities.
type PlatformOrgStats struct {
	Nodes          int  `json:"nodes"`
	Online         int  `json:"online"`
	Users          int  `json:"users"`
	PendingDevices int  `json:"pending_devices"`
	PolicyLoaded   bool `json:"policy_loaded"`

	// Plan is the commercial plan the tenant is on; empty when this
	// deployment does not sell plans (spec section 54).
	Plan string `json:"plan,omitempty"`
	// PlanName is the plan's display name, for surfaces that show a label.
	PlanName string `json:"plan_name,omitempty"`
	// NetworkPrefix is the tenant's tailnet address range; empty means the
	// deployment default.
	NetworkPrefix string `json:"network_prefix,omitempty"`
	// DeviceLimit is how many devices the plan allows (-1 for unlimited, 0
	// when the deployment does not sell plans).
	DeviceLimit int `json:"device_limit,omitempty"`
}

// mountPlatform registers the platform API under /api/platform.
func (r *Router) mountPlatform(pr chi.Router) {
	pr.Use(r.requirePlatformToken)
	pr.Get("/v1/organizations", r.handlePlatformOrganizations)
	pr.Get("/v1/organizations/{orgID}", r.handlePlatformOrganization)
	pr.Post("/v1/organizations", r.handlePlatformCreateOrganization)
	pr.Get("/v1/organizations/{orgID}/plan", r.handlePlatformTenantPlan)
	pr.Patch("/v1/organizations/{orgID}/plan", r.handlePlatformSetTenantPlan)
	pr.Post("/v1/organizations/{orgID}/plan/allocate", r.handlePlatformAllocateTenant)
	pr.Get("/v1/plans", r.handlePlatformPlans)
	pr.Post("/v1/plans", r.handlePlatformUpsertPlan)
	pr.Delete("/v1/plans/{planID}", r.handlePlatformDeletePlan)
	pr.Patch("/v1/organizations/{orgID}", r.handlePlatformUpdateOrganization)
	pr.Delete("/v1/organizations/{orgID}", r.handlePlatformDeleteOrganization)
	pr.Get("/v1/audit", r.handlePlatformAudit)
	pr.Get("/v1/audit/actions", r.handlePlatformAuditActions)

	// Cross-tenant user administration: the operator console and automation
	// read the same list and apply the same two guards before a deletion.
	pr.Get("/v1/users", r.handlePlatformUsers)
	pr.Post("/v1/organizations/{orgID}/users/{userID}/revoke", r.handlePlatformRevokeUserSessions)
	pr.Delete("/v1/organizations/{orgID}/users/{userID}", r.handlePlatformDeleteUser)
}

// requirePlatformToken enforces bearer-token auth on the platform API. It is
// fail closed: no configured token means no platform API.
func (r *Router) requirePlatformToken(next http.Handler) http.Handler {
	enabled := r.cfg.PlatformAdminToken != ""
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if !enabled {
			http.Error(w, "platform API is disabled", http.StatusForbidden)
			return
		}
		token, ok := bearerToken(req)
		if !ok || !constantTimeTokenEqual(r.platformTokenHash, token) {
			w.Header().Set("WWW-Authenticate", `Bearer realm="xunara-platform"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, req)
	})
}

// handlePlatformOrganizations lists every organization with a status summary.
func (r *Router) handlePlatformOrganizations(w http.ResponseWriter, _ *http.Request) {
	snapshot := r.orgSnapshot()
	orgs := make([]PlatformOrg, 0, len(snapshot))
	for _, org := range snapshot {
		orgs = append(orgs, r.platformOrgView(org))
	}
	writeJSON(w, http.StatusOK, map[string]any{"organizations": orgs})
}

// handlePlatformOrganization returns one organization by ID.
func (r *Router) handlePlatformOrganization(w http.ResponseWriter, req *http.Request) {
	id := chi.URLParam(req, "orgID")
	if org := r.orgByID(id); org != nil {
		writeJSON(w, http.StatusOK, r.platformOrgView(org))
		return
	}
	http.Error(w, "organization not found", http.StatusNotFound)
}

// platformOrgView snapshots one organization for the platform API.
func (r *Router) platformOrgView(org *routerOrg) PlatformOrg {
	server := org.site.Server
	view := PlatformOrg{
		ID:      org.site.ID,
		Name:    org.site.Name,
		Domains: append([]string(nil), org.patterns...),
		Managed: org.managed,
		Stats: PlatformOrgStats{
			Users:        len(server.identity.ListUsers()),
			PolicyLoaded: server.policy.Load() != nil,
		},
	}
	for _, node := range server.store.ListNodes() {
		view.Stats.Nodes++
		if server.isOnline(node.ID) {
			view.Stats.Online++
		}
	}
	view.Stats.PendingDevices = len(server.identity.ListPendingDeviceAuthorizations(time.Now().UTC()))
	if registry := r.cfg.Plans; registry != nil {
		assigned := registry.Plan(context.Background(), org.site.ID)
		view.Stats.Plan = assigned.ID
		view.Stats.PlanName = assigned.Name
		view.Stats.DeviceLimit = assigned.MaxDevices
		if prefix, ok := registry.NetworkPrefix(context.Background(), org.site.ID); ok {
			view.Stats.NetworkPrefix = prefix.String()
		}
	}
	return view
}

// bearerToken extracts a Bearer token from the Authorization header. The
// scheme is case-insensitive per RFC 7235.
func bearerToken(req *http.Request) (string, bool) {
	header := req.Header.Get("Authorization")
	scheme, token, ok := strings.Cut(header, " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return "", false
	}
	token = strings.TrimSpace(token)
	if token == "" {
		return "", false
	}
	return token, true
}

// constantTimeTokenEqual compares a pre-hashed token with a candidate. Both
// sides are hashed, so the comparison neither short-circuits on length nor
// leaks it.
func constantTimeTokenEqual(wantHash [32]byte, candidate string) bool {
	got := sha256.Sum256([]byte(candidate))
	return subtle.ConstantTimeCompare(wantHash[:], got[:]) == 1
}

// sha256Sum is a small helper used where a full hash value is needed.
func sha256Sum(s string) [32]byte { return sha256.Sum256([]byte(s)) }
