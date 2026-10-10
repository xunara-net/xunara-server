package control

import (
	"crypto/subtle"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/xunara-net/xunara-server/identity"
	"github.com/xunara-net/xunara-server/plan"
)

// The platform console (PROJECT_SPEC section 54).
//
// It is a separate surface, not a privilege level of the tenant console: its
// own path (/admin), its own credential (the platform admin token), its own
// session store and its own pages. A tenant session cookie is never accepted
// here, and this cookie is never accepted there — the two are different
// identity domains, and mixing them would make one tenant's browser a path to
// every tenant's data.
//
// The console exists when the deployment runs a plan registry, which is what
// "commercial deployment" means here.

// adminCookieName is the platform console's session cookie. The tenant console
// uses its own name, so a browser can hold both without either being mistaken
// for the other.
const adminCookieName = "xunara_admin_session"

// adminMutable reports whether the console may change platform state.
func (r *Router) mountAdmin(mux chi.Router) {
	if r.cfg.Plans == nil || r.cfg.PlatformAdminToken == "" {
		return
	}
	mux.Route("/admin", func(ar chi.Router) {
		ar.Get("/login", r.handleAdminLoginPage)
		ar.Post("/login", r.handleAdminLoginSubmit)
		ar.Post("/logout", r.handleAdminLogout)

		ar.Group(func(ar chi.Router) {
			ar.Use(r.requireAdminSession)
			ar.Get("/", r.handleAdminDashboard)
			ar.Get("/tenants", r.handleAdminTenants)
			ar.Get("/users", r.handleAdminUsers)
			ar.Get("/plans", r.handleAdminPlans)
			ar.Post("/tenants/plan", r.handleAdminSetPlan)
			ar.Post("/tenants/network", r.handleAdminSetNetwork)
			ar.Post("/tenants/delete", r.handleAdminDeleteTenant)
			ar.Post("/users/revoke", r.handleAdminRevokeUser)
			ar.Post("/users/delete", r.handleAdminDeleteUser)
			ar.Post("/plans/save", r.handleAdminSavePlan)
			ar.Post("/plans/delete", r.handleAdminDeletePlan)
		})
	})
}

// checkPlatformToken compares a presented token with the configured one in
// constant time.
func (r *Router) checkPlatformToken(token string) bool {
	if r.cfg.PlatformAdminToken == "" || token == "" {
		return false
	}
	return constantTimeTokenEqual(r.platformTokenHash, token)
}

// adminSession resolves the console session from the request cookie.
func (r *Router) adminSession(req *http.Request) (AdminSession, bool) {
	cookie, err := req.Cookie(adminCookieName)
	if err != nil {
		return AdminSession{}, false
	}
	session, err := r.cfg.Plans.AdminSession(cookie.Value)
	if err != nil {
		return AdminSession{}, false
	}
	return session, true
}

// requireAdminSession gates the console's authenticated pages. Unauthenticated
// requests are redirected to the sign-in page rather than answered with a
// status code, so a bookmark keeps working.
func (r *Router) requireAdminSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if _, ok := r.adminSession(req); !ok {
			http.Redirect(w, req, "/admin/login", http.StatusFound)
			return
		}
		next.ServeHTTP(w, req)
	})
}

// handleAdminLoginPage implements GET /admin/login.
func (r *Router) handleAdminLoginPage(w http.ResponseWriter, req *http.Request) {
	if _, ok := r.adminSession(req); ok {
		http.Redirect(w, req, "/admin/", http.StatusFound)
		return
	}
	r.renderAdmin(w, req, adminLoginTemplate, adminPageData{
		Title: "Platform sign-in",
		Lede:  "This console belongs to the deployment operator. Tenant accounts cannot sign in here.",
		Path:  "/admin/login",
		Login: true,
	})
}

// handleAdminLoginSubmit implements POST /admin/login. The only credential is
// the platform admin token from the process environment.
func (r *Router) handleAdminLoginSubmit(w http.ResponseWriter, req *http.Request) {
	if err := req.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	token := strings.TrimSpace(req.PostFormValue("token"))
	if !r.checkPlatformToken(token) {
		r.log.Warn("platform console sign-in rejected", "remote", remoteIP(req))
		r.renderAdmin(w, req, adminLoginTemplate, adminPageData{
			Title: "Platform sign-in",
			Lede:  "This console belongs to the deployment operator. Tenant accounts cannot sign in here.",
			Path:  "/admin/login",
			Login: true,
			Error: "The platform token was not accepted.",
		}, http.StatusUnauthorized)
		return
	}

	// Prune on the rare event of a sign-in rather than with a background
	// worker: the table only grows when an operator signs in.
	if err := r.cfg.Plans.PruneAdminSessions(); err != nil {
		r.log.Warn("pruning admin sessions", "err", err)
	}
	session, secret, err := r.cfg.Plans.CreateAdminSession(AdminSessionTTL)
	if err != nil {
		r.log.Error("creating an admin session", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     adminCookieName,
		Value:    secret,
		Path:     "/admin",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   adminSessionSecure(req),
		Expires:  session.ExpiresAt,
	})
	http.Redirect(w, req, "/admin/", http.StatusFound)
}

// handleAdminLogout implements POST /admin/logout.
func (r *Router) handleAdminLogout(w http.ResponseWriter, req *http.Request) {
	if cookie, err := req.Cookie(adminCookieName); err == nil {
		if err := r.cfg.Plans.RevokeAdminSession(cookie.Value); err != nil {
			r.log.Warn("revoking the admin session", "err", err)
		}
	}
	cleared := &http.Cookie{Name: adminCookieName, Value: "", Path: "/admin", MaxAge: -1, HttpOnly: true}
	http.SetCookie(w, cleared)
	http.Redirect(w, req, "/admin/login", http.StatusFound)
}

// adminSessionSecure marks the cookie Secure when the console is reached over
// TLS, directly or through a proxy that said so.
func adminSessionSecure(req *http.Request) bool {
	if req.TLS != nil {
		return true
	}
	return strings.EqualFold(req.Header.Get("X-Forwarded-Proto"), "https")
}

// handleAdminDashboard implements GET /admin.
func (r *Router) handleAdminDashboard(w http.ResponseWriter, req *http.Request) {
	data := r.adminBaseData(req, "Platform", "Every tenant this deployment hosts, at a glance.")
	rows, err := r.TenantPlans(req.Context())
	if err != nil {
		r.adminError(w, req, err)
		return
	}
	totals := adminTotals{
		Tenants:   len(rows),
		Plans:     len(r.cfg.Plans.Catalog().List()),
		Version:   Version,
		CatalogID: r.cfg.Plans.Catalog().Default().ID,
	}
	distribution := make(map[string]int)
	for _, row := range rows {
		totals.Devices += row.Devices
		totals.Online += row.Online
		totals.Users += row.Users
		distribution[row.Plan.ID]++
	}
	data.Totals = totals
	data.Distribution = adminPlanDistribution(r.cfg.Plans.Catalog(), distribution)
	data.Tenants = rows
	data.Managed = r.cfg.Registry != nil
	r.renderAdmin(w, req, adminDashboardTemplate, data)
}

// handleAdminTenants implements GET /admin/tenants.
func (r *Router) handleAdminTenants(w http.ResponseWriter, req *http.Request) {
	data := r.adminBaseData(req, "Tailnets", "One row per tenant: its plan, its network range and what it uses.")
	rows, err := r.TenantPlans(req.Context())
	if err != nil {
		r.adminError(w, req, err)
		return
	}
	data.Tenants = rows
	data.Plans = r.cfg.Plans.Catalog().List()
	data.Managed = r.cfg.Registry != nil
	r.renderAdmin(w, req, adminTenantsTemplate, data)
}

// adminUserRow is one member account across every tenant.
type adminUserRow struct {
	Org       string
	OrgName   string
	ID        uint64
	Login     string
	Display   string
	Email     string
	Role      string
	Plan      string
	CreatedAt string
	LastSeen  string
	Sessions  int
}

// handleAdminUsers implements GET /admin/users.
func (r *Router) handleAdminUsers(w http.ResponseWriter, req *http.Request) {
	data := r.adminBaseData(req, "Users", "Every account on this deployment, by tenant.")
	rows, err := r.TenantPlans(req.Context())
	if err != nil {
		r.adminError(w, req, err)
		return
	}
	var users []adminUserRow
	for _, org := range r.orgSnapshot() {
		server := org.site.Server
		for _, u := range server.identity.ListUsers() {
			row := adminUserRow{
				Org: org.site.ID, OrgName: org.site.Name,
				ID: uint64(u.ID), Login: u.LoginName, Display: u.DisplayName,
				Email: u.Email, Role: string(u.Role), Plan: r.cfg.Plans.Plan(req.Context(), org.site.ID).ID,
				CreatedAt: server.consoleTime(u.CreatedAt),
			}
			for _, session := range server.identity.ListSessions(u.ID) {
				if session.RevokedAt.IsZero() && session.ExpiresAt.After(nowUTC()) {
					row.Sessions++
					if session.LastSeenAt.After(session.CreatedAt) {
						row.LastSeen = server.consoleTime(session.LastSeenAt)
					}
				}
			}
			users = append(users, row)
		}
	}
	data.Users = users
	_ = rows
	r.renderAdmin(w, req, adminUsersTemplate, data)
}

// handleAdminPlans implements GET /admin/plans: the Plan Editor.
func (r *Router) handleAdminPlans(w http.ResponseWriter, req *http.Request) {
	data := r.adminBaseData(req, "Plans", "Plans are data: add or retune one here and every tenant picks it up on its next request.")
	data.Plans = r.cfg.Plans.Catalog().List()
	data.DefaultPlan = r.cfg.Plans.Catalog().Default().ID
	counts := make(map[string]int)
	for _, row := range mustTenantPlans(r, req) {
		counts[row.Plan.ID]++
	}
	data.PlanCounts = counts
	r.renderAdmin(w, req, adminPlansTemplate, data)
}

// handleAdminSetPlan implements POST /admin/tenants/plan.
func (r *Router) handleAdminSetPlan(w http.ResponseWriter, req *http.Request) {
	session, ok := r.adminWriteGuard(w, req)
	if !ok {
		return
	}
	orgID := strings.TrimSpace(req.PostFormValue("org"))
	planID := strings.TrimSpace(req.PostFormValue("plan"))
	if orgID == "" || planID == "" {
		r.redirectNotice(w, req, "/admin/tenants", "Choose a tenant and a plan.")
		return
	}
	row, err := r.SetTenantPlan(req.Context(), orgID, planID)
	if err != nil {
		r.redirectNotice(w, req, "/admin/tenants", adminErrorText(err))
		return
	}
	r.auditTenant(orgID, "platform", identity.AuditPlanChanged, "organization:"+orgID,
		"plan set to "+planID+" by the platform console")
	_ = session
	r.redirectNotice(w, req, "/admin/tenants", "Tenant "+row.OrgID+" is now on plan "+row.Plan.Name+".")
}

// handleAdminSetNetwork implements POST /admin/tenants/network.
func (r *Router) handleAdminSetNetwork(w http.ResponseWriter, req *http.Request) {
	if _, ok := r.adminWriteGuard(w, req); !ok {
		return
	}
	orgID := strings.TrimSpace(req.PostFormValue("org"))
	raw := strings.TrimSpace(req.PostFormValue("network_prefix"))
	prefix, err := parseNetworkPrefix(raw)
	if err != nil {
		r.redirectNotice(w, req, "/admin/tenants", err.Error())
		return
	}
	row, err := r.SetTenantNetwork(req.Context(), orgID, prefix)
	if err != nil {
		r.redirectNotice(w, req, "/admin/tenants", adminErrorText(err))
		return
	}
	detail := "network range cleared; a block is allocated automatically"
	if row.NetworkPrefix != "" {
		detail = "network range set to " + row.NetworkPrefix
	}
	r.auditTenant(orgID, "platform", identity.AuditNetworkSet, "organization:"+orgID,
		detail+" by the platform console; devices keep their addresses")
	r.redirectNotice(w, req, "/admin/tenants", "Network updated: "+row.NetworkPrefix)
}

// handleAdminDeleteTenant implements POST /admin/tenants/delete.
func (r *Router) handleAdminDeleteTenant(w http.ResponseWriter, req *http.Request) {
	if _, ok := r.adminWriteGuard(w, req); !ok {
		return
	}
	orgID := strings.TrimSpace(req.PostFormValue("org"))
	if r.cfg.Registry == nil {
		r.redirectNotice(w, req, "/admin/tenants", "This deployment has no managed-organization registry.")
		return
	}
	archived, err := r.DeleteManagedOrg(req.Context(), orgID)
	if err != nil {
		r.redirectNotice(w, req, "/admin/tenants", adminErrorText(err))
		return
	}
	if err := r.cfg.Plans.Delete(req.Context(), orgID); err != nil {
		r.log.Warn("deleting the plan assignment of a removed tenant", "organization", orgID, "err", err)
	}
	notice := "Tenant " + orgID + " deleted."
	if archived != "" {
		notice += " Its state was archived at " + archived + "."
	}
	r.redirectNotice(w, req, "/admin/tenants", notice)
}

// handleAdminRevokeUser implements POST /admin/users/revoke: it signs the user
// out everywhere without touching their account.
func (r *Router) handleAdminRevokeUser(w http.ResponseWriter, req *http.Request) {
	if _, ok := r.adminWriteGuard(w, req); !ok {
		return
	}
	orgID := strings.TrimSpace(req.PostFormValue("org"))
	server := r.serverFor(orgID)
	id, err := strconv.ParseUint(strings.TrimSpace(req.PostFormValue("user")), 10, 64)
	if server == nil || err != nil {
		r.redirectNotice(w, req, "/admin/users", "Unknown tenant or user.")
		return
	}
	revoked, err := server.identity.RevokeUserSessions(tailcfgUserID(id), "revoked by the platform operator")
	if err != nil {
		r.redirectNotice(w, req, "/admin/users", adminErrorText(err))
		return
	}
	r.auditTenant(orgID, "platform", identity.AuditSessionRevoked, "user:"+strconv.FormatUint(id, 10),
		"all sessions revoked by the platform console")
	r.redirectNotice(w, req, "/admin/users",
		"Signed out user "+strconv.FormatUint(id, 10)+" of tenant "+orgID+" ("+
			strconv.FormatInt(revoked, 10)+" session(s)).")
}

// handleAdminDeleteUser implements POST /admin/users/delete.
func (r *Router) handleAdminDeleteUser(w http.ResponseWriter, req *http.Request) {
	if _, ok := r.adminWriteGuard(w, req); !ok {
		return
	}
	orgID := strings.TrimSpace(req.PostFormValue("org"))
	server := r.serverFor(orgID)
	id, err := strconv.ParseUint(strings.TrimSpace(req.PostFormValue("user")), 10, 64)
	if server == nil || err != nil {
		r.redirectNotice(w, req, "/admin/users", "Unknown tenant or user.")
		return
	}
	userID := tailcfgUserID(id)
	users, err := server.identity.ListUsersContext(req.Context())
	if err != nil {
		r.redirectNotice(w, req, "/admin/users", "Could not check the accounts. Please try again.")
		return
	}
	if len(users) <= 1 {
		r.redirectNotice(w, req, "/admin/users", "The last account of a tenant cannot be deleted.")
		return
	}
	if err := server.identity.DeleteUserContext(req.Context(), userID); err != nil {
		if errors.Is(err, identity.ErrLastOwner) {
			r.redirectNotice(w, req, "/admin/users", "A tailnet needs at least one owner.")
			return
		}
		r.redirectNotice(w, req, "/admin/users", adminErrorText(err))
		return
	}
	if _, err := server.identity.RevokeUserSessions(userID, "account deleted by the platform operator"); err != nil {
		r.log.Warn("revoking sessions of a deleted account", "err", err)
	}
	r.auditTenant(orgID, "platform", identity.AuditUserUpdated, "user:"+strconv.FormatUint(id, 10),
		"account deleted by the platform console")
	r.redirectNotice(w, req, "/admin/users", "Account deleted.")
}

// handleAdminSavePlan implements POST /admin/plans/save.
func (r *Router) handleAdminSavePlan(w http.ResponseWriter, req *http.Request) {
	if _, ok := r.adminWriteGuard(w, req); !ok {
		return
	}
	if err := req.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	definition, err := parsePlanForm(req)
	if err != nil {
		r.redirectNotice(w, req, "/admin/plans", err.Error())
		return
	}
	stored, err := r.cfg.Plans.UpsertPlan(req.Context(), definition)
	if err != nil {
		r.redirectNotice(w, req, "/admin/plans", adminErrorText(err))
		return
	}
	r.redirectNotice(w, req, "/admin/plans", "Plan "+stored.Name+" ("+stored.ID+") saved.")
}

// handleAdminDeletePlan implements POST /admin/plans/delete.
func (r *Router) handleAdminDeletePlan(w http.ResponseWriter, req *http.Request) {
	if _, ok := r.adminWriteGuard(w, req); !ok {
		return
	}
	id := strings.TrimSpace(req.PostFormValue("plan"))
	if err := r.cfg.Plans.DeletePlan(req.Context(), id); err != nil {
		r.redirectNotice(w, req, "/admin/plans", adminErrorText(err))
		return
	}
	r.redirectNotice(w, req, "/admin/plans", "Plan "+id+" deleted.")
}

// adminWriteGuard enforces the session, its CSRF token and the action's
// parameters for a console write. It answers the request itself when it
// refuses.
func (r *Router) adminWriteGuard(w http.ResponseWriter, req *http.Request) (AdminSession, bool) {
	session, ok := r.adminSession(req)
	if !ok {
		http.Redirect(w, req, "/admin/login", http.StatusFound)
		return AdminSession{}, false
	}
	if err := req.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return AdminSession{}, false
	}
	presented := req.PostFormValue("csrf")
	if subtle.ConstantTimeCompare([]byte(presented), []byte(session.CSRF)) != 1 {
		http.Error(w, "invalid CSRF token", http.StatusForbidden)
		return AdminSession{}, false
	}
	return session, true
}

// redirectNotice sends the operator back to a console page with a one-line
// message. Notices are short and carry no secrets, so a query parameter is
// safe here.
func (r *Router) redirectNotice(w http.ResponseWriter, req *http.Request, path, notice string) {
	target := path + "?notice=" + urlQueryEscape(notice)
	http.Redirect(w, req, target, http.StatusFound)
}

// adminErrorText renders an error for the console: client mistakes verbatim,
// everything else generic.
func adminErrorText(err error) string {
	var apiErr *orgAPIError
	switch {
	case errors.As(err, &apiErr):
		return apiErr.msg
	case errors.Is(err, ErrTenantNotFound):
		return "Unknown tenant."
	case errors.Is(err, ErrNetworkNotAllowed):
		return "That plan does not allow a custom network range."
	case errors.Is(err, ErrNetworkConflict):
		return "That range overlaps another tenant's network."
	case errors.Is(err, ErrNoNetworkBlock):
		return "The deployment's network pool is exhausted."
	case errors.Is(err, ErrPlanBuiltIn):
		return "Configured plans cannot be deleted, only overridden."
	case errors.Is(err, plan.ErrDefaultPlan):
		return "The default plan cannot be deleted."
	case errors.Is(err, plan.ErrPlanNotFound):
		return "No such plan."
	default:
		return "The operation failed; see the server log."
	}
}

// auditTenant writes an audit event into one tenant's log.
func (r *Router) auditTenant(orgID, actor, action, target, detail string) {
	server := r.serverFor(orgID)
	if server == nil {
		return
	}
	if err := server.identity.AppendAudit(&identity.AuditEvent{
		Actor: actor, Action: action, Target: target, Detail: detail,
	}); err != nil {
		r.log.Error("appending platform audit event", "organization", orgID, "err", err)
	}
}

// serverFor returns the control plane of one tenant, or nil.
func (r *Router) serverFor(orgID string) *Server {
	if org := r.orgByID(orgID); org != nil {
		return org.site.Server
	}
	return nil
}

// mustTenantPlans returns tenant rows for page rendering, or nil when the
// registry cannot be read (the page then shows no counts).
func mustTenantPlans(r *Router, req *http.Request) []TenantPlanRow {
	rows, err := r.TenantPlans(req.Context())
	if err != nil {
		r.log.Warn("listing tenant plans", "err", err)
		return nil
	}
	return rows
}

// parsePlanForm reads the Plan Editor's form into a plan definition. The form
// is a plan, field for field: adding a quota to plan.Plan makes it editable
// without touching this function's structure, only its field list.
func parsePlanForm(req *http.Request) (plan.Plan, error) {
	quota := func(name string) (int, error) {
		raw := strings.TrimSpace(req.PostFormValue(name))
		if raw == "" {
			return plan.Unlimited, nil
		}
		if strings.EqualFold(raw, "unlimited") {
			return plan.Unlimited, nil
		}
		value, err := strconv.Atoi(raw)
		if err != nil {
			return 0, errors.New("quota " + name + " must be a whole number or 'unlimited'")
		}
		return value, nil
	}
	definition := plan.Plan{
		ID:           strings.TrimSpace(req.PostFormValue("id")),
		Name:         strings.TrimSpace(req.PostFormValue("name")),
		Currency:     strings.TrimSpace(req.PostFormValue("currency")),
		BillingCycle: strings.TrimSpace(req.PostFormValue("billing_cycle")),
	}
	if raw := strings.TrimSpace(req.PostFormValue("price_cents")); raw != "" {
		price, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			return plan.Plan{}, errors.New("price must be given in minor units (cents)")
		}
		definition.PriceCents = price
	}
	var err error
	if definition.MaxDevices, err = quota("max_devices"); err != nil {
		return plan.Plan{}, err
	}
	if definition.MaxUsers, err = quota("max_users"); err != nil {
		return plan.Plan{}, err
	}
	if definition.MaxRoutes, err = quota("max_routes"); err != nil {
		return plan.Plan{}, err
	}
	if definition.MaxAuthKeys, err = quota("max_auth_keys"); err != nil {
		return plan.Plan{}, err
	}
	definition.AllowCustomCIDR = req.PostFormValue("allow_custom_cidr") != ""
	definition.AllowExitNode = req.PostFormValue("allow_exit_node") != ""
	definition.AllowSubnetRouter = req.PostFormValue("allow_subnet_router") != ""
	definition.AllowAPI = req.PostFormValue("allow_api") != ""
	definition.AllowACL = req.PostFormValue("allow_acl") != ""
	definition.AllowGrants = req.PostFormValue("allow_grants") != ""
	definition.AllowCustomDNS = req.PostFormValue("allow_custom_dns") != ""
	definition.AllowAuditLog = req.PostFormValue("allow_audit_log") != ""
	definition.AllowMultiMember = req.PostFormValue("allow_multi_member") != ""
	return definition, nil
}
