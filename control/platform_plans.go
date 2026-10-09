package control

import (
	"errors"
	"net/http"
	"net/netip"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/xunara-net/xunara-server/plan"
)

// Plans over the platform API (PROJECT_SPEC section 54).
//
// These endpoints are the operator's view of the commercial layer: the plan
// catalog itself (so a deployment can add or retune a plan without shipping a
// new binary) and each tenant's assignment. Like every /api/platform route
// they require the process-level platform token; a tenant's own credentials
// never reach them.

// plansDisabled is returned when the deployment runs without a plan registry.
var plansDisabled = errors.New("control: this deployment does not serve plans")

// handlePlatformPlans implements GET /api/platform/v1/plans.
func (r *Router) handlePlatformPlans(w http.ResponseWriter, req *http.Request) {
	registry := r.cfg.Plans
	if registry == nil {
		http.Error(w, plansDisabled.Error(), http.StatusForbidden)
		return
	}
	def := registry.Catalog().Default()
	plans := registry.Catalog().List()
	out := make([]map[string]any, 0, len(plans))
	for _, p := range plans {
		out = append(out, planView(p, p.ID == def.ID))
	}
	writeJSON(w, http.StatusOK, map[string]any{"plans": out, "default": def.ID})
}

// handlePlatformUpsertPlan implements POST /api/platform/v1/plans: the Plan
// Editor's save. A plan with an existing ID is replaced, a new ID is added.
func (r *Router) handlePlatformUpsertPlan(w http.ResponseWriter, req *http.Request) {
	registry := r.cfg.Plans
	if registry == nil {
		http.Error(w, plansDisabled.Error(), http.StatusForbidden)
		return
	}
	var body plan.Plan
	if !decodePlatformOrgBody(w, req, &body) {
		return
	}
	stored, err := registry.UpsertPlan(req.Context(), body)
	if err != nil {
		r.writeOrgAPIError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, planView(stored, registry.Catalog().Default().ID == stored.ID))
}

// handlePlatformDeletePlan implements DELETE
// /api/platform/v1/plans/{planID}.
func (r *Router) handlePlatformDeletePlan(w http.ResponseWriter, req *http.Request) {
	registry := r.cfg.Plans
	if registry == nil {
		http.Error(w, plansDisabled.Error(), http.StatusForbidden)
		return
	}
	id := chi.URLParam(req, "planID")
	if err := registry.DeletePlan(req.Context(), id); err != nil {
		r.writeOrgAPIError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": id, "deleted": true})
}

// handlePlatformTenantPlan implements GET
// /api/platform/v1/organizations/{orgID}/plan.
func (r *Router) handlePlatformTenantPlan(w http.ResponseWriter, req *http.Request) {
	row, err := r.TenantPlan(req.Context(), chi.URLParam(req, "orgID"))
	if err != nil {
		r.writeOrgAPIError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, tenantPlanView(row))
}

// handlePlatformSetTenantPlan implements PATCH
// /api/platform/v1/organizations/{orgID}/plan. Both halves are optional:
// plan_id moves the tenant to another plan, network_prefix sets its tailnet
// address range (an empty network_prefix restores the automatic block).
func (r *Router) handlePlatformSetTenantPlan(w http.ResponseWriter, req *http.Request) {
	if r.cfg.Plans == nil {
		http.Error(w, plansDisabled.Error(), http.StatusForbidden)
		return
	}
	var body struct {
		PlanID        *string `json:"plan_id,omitempty"`
		NetworkPrefix *string `json:"network_prefix,omitempty"`
	}
	if !decodePlatformOrgBody(w, req, &body) {
		return
	}
	orgID := chi.URLParam(req, "orgID")

	row, err := r.TenantPlan(req.Context(), orgID)
	if err != nil {
		r.writeOrgAPIError(w, err)
		return
	}
	if body.PlanID != nil {
		row, err = r.SetTenantPlan(req.Context(), orgID, strings.TrimSpace(*body.PlanID))
		if err != nil {
			r.writeOrgAPIError(w, err)
			return
		}
	}
	if body.NetworkPrefix != nil {
		prefix, err := parseNetworkPrefix(*body.NetworkPrefix)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		row, err = r.SetTenantNetwork(req.Context(), orgID, prefix)
		if err != nil {
			r.writeOrgAPIError(w, err)
			return
		}
	}
	writeJSON(w, http.StatusOK, tenantPlanView(row))
}

// handlePlatformAllocateTenant implements POST
// /api/platform/v1/organizations/{orgID}/plan/allocate: put a tenant on the
// default plan and hand it a free network block. It is what a hosted sign-up
// calls once the organization exists.
func (r *Router) handlePlatformAllocateTenant(w http.ResponseWriter, req *http.Request) {
	registry := r.cfg.Plans
	if registry == nil {
		http.Error(w, plansDisabled.Error(), http.StatusForbidden)
		return
	}
	orgID := chi.URLParam(req, "orgID")
	if _, err := r.TenantPlan(req.Context(), orgID); err != nil {
		r.writeOrgAPIError(w, err)
		return
	}
	if _, err := registry.Allocate(req.Context(), orgID); err != nil {
		r.writeOrgAPIError(w, err)
		return
	}
	// Allocate() runs the automatic path: it hands the tenant a block from the
	// pool (or clears a custom range when the deployment runs no pool). Going
	// through SetTenantNetwork here would be wrong — that path is the
	// operator's *custom* range and is refused for plans that forbid custom
	// CIDRs, which is the shipped free plan.
	if prefix, ok := registry.NetworkPrefix(req.Context(), orgID); ok {
		org := r.orgByID(orgID)
		if org == nil {
			r.writeOrgAPIError(w, ErrOrgNotFound)
			return
		}
		if err := org.site.Server.SetAddressPrefix(prefix); err != nil {
			r.writeOrgAPIError(w, err)
			return
		}
	}
	row, err := r.TenantPlan(req.Context(), orgID)
	if err != nil {
		r.writeOrgAPIError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, tenantPlanView(row))
}

// parseNetworkPrefix parses the API's network_prefix field. An empty string
// clears the tenant's custom range, which the registry turns back into an
// automatically allocated block.
func parseNetworkPrefix(raw string) (netip.Prefix, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || raw == "auto" {
		return netip.Prefix{}, nil
	}
	prefix, err := netip.ParsePrefix(raw)
	if err != nil {
		return netip.Prefix{}, errors.New("network_prefix is not a CIDR range")
	}
	return prefix, nil
}

// planView renders one plan for the API. JSON tags on plan.Plan already carry
// the field names, so the map only adds what the catalog knows and the plan
// does not: whether it is the default.
func planView(p plan.Plan, isDefault bool) map[string]any {
	// 编辑器需要完整读取配额再回写；零额度也必须显式导出，不能被当成缺失字段。
	return map[string]any{
		"id": p.ID, "name": p.Name, "price_cents": p.PriceCents, "currency": p.Currency,
		"billing_cycle": p.BillingCycle,
		"max_devices":   p.MaxDevices, "max_users": p.MaxUsers,
		"max_routes": p.MaxRoutes, "max_auth_keys": p.MaxAuthKeys,
		"max_relays":        p.MaxRelays,
		"allow_custom_cidr": p.AllowCustomCIDR, "allow_exit_node": p.AllowExitNode,
		"allow_subnet_router": p.AllowSubnetRouter, "allow_api": p.AllowAPI,
		"allow_acl": p.AllowACL, "allow_grants": p.AllowGrants,
		"allow_custom_dns": p.AllowCustomDNS, "allow_audit_log": p.AllowAuditLog,
		"allow_multi_member": p.AllowMultiMember,
		"device_allowance":   p.DeviceAllowance(),
		"default":            isDefault,
	}
}

// tenantPlanView renders one tenant's plan state for the API.
func tenantPlanView(row TenantPlanRow) map[string]any {
	return map[string]any{
		"organization":   row.OrgID,
		"name":           row.Name,
		"plan":           row.Plan.ID,
		"plan_name":      row.Plan.Name,
		"assigned":       row.Assigned,
		"network_prefix": row.NetworkPrefix,
		"devices":        row.Devices,
		"online":         row.Online,
		"users":          row.Users,
		"max_devices":    row.Plan.MaxDevices,
		"max_users":      row.Plan.MaxUsers,
		"updated_at":     row.UpdatedAt,
	}
}
