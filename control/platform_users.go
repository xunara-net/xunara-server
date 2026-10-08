package control

import (
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/xunara-net/xunara-server/identity"
)

// Platform user administration over JSON: the same operations the operator
// console offers, for the platform admin SPA and for automation. Every route
// here is behind the platform admin token (mountPlatform), and every mutation
// is audited in the affected tenant's log.

// platformUser is one account as the platform API reports it.
type platformUser struct {
	Org         string     `json:"org"`
	OrgName     string     `json:"orgName"`
	ID          uint64     `json:"id"`
	Login       string     `json:"login"`
	DisplayName string     `json:"displayName"`
	Email       string     `json:"email"`
	Role        string     `json:"role"`
	Plan        string     `json:"plan"`
	Sessions    int        `json:"sessions"`
	LastSeen    *time.Time `json:"lastSeen,omitempty"`
	CreatedAt   time.Time  `json:"createdAt"`
}

// handlePlatformUsers implements GET /api/platform/v1/users: every account on
// the deployment, grouped by tenant.
func (r *Router) handlePlatformUsers(w http.ResponseWriter, req *http.Request) {
	now := time.Now().UTC()
	out := []platformUser{}
	for _, org := range r.orgSnapshot() {
		server := org.site.Server
		planID := ""
		if r.cfg.Plans != nil {
			planID = r.cfg.Plans.Plan(req.Context(), org.site.ID).ID
		}
		for _, u := range server.identity.ListUsers() {
			row := platformUser{
				Org: org.site.ID, OrgName: org.site.Name,
				ID: uint64(u.ID), Login: u.LoginName, DisplayName: u.DisplayName,
				Email: u.Email, Role: string(u.Role), Plan: planID,
				CreatedAt: u.CreatedAt,
			}
			for _, session := range server.identity.ListSessions(u.ID) {
				if session.RevokedAt.IsZero() && session.ExpiresAt.After(now) {
					row.Sessions++
					if session.LastSeenAt.After(session.CreatedAt) && (row.LastSeen == nil || session.LastSeenAt.After(*row.LastSeen)) {
						seen := session.LastSeenAt
						row.LastSeen = &seen
					}
				}
			}
			out = append(out, row)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"users": out})
}

// handlePlatformRevokeUserSessions implements
// POST /api/platform/v1/organizations/{orgID}/users/{userID}/revoke: force a
// user off every device.
func (r *Router) handlePlatformRevokeUserSessions(w http.ResponseWriter, req *http.Request) {
	orgID := chi.URLParam(req, "orgID")
	server := r.serverFor(orgID)
	userID, err := strconv.ParseUint(chi.URLParam(req, "userID"), 10, 64)
	if server == nil || err != nil {
		http.Error(w, "unknown tenant or user", http.StatusNotFound)
		return
	}
	revoked, err := server.identity.RevokeUserSessions(tailcfgUserID(userID), "revoked by the platform operator")
	if err != nil {
		http.Error(w, "could not revoke sessions", http.StatusInternalServerError)
		return
	}
	r.auditTenant(orgID, "platform", identity.AuditSessionRevoked, "user:"+strconv.FormatUint(userID, 10),
		"all sessions revoked by the platform API")
	writeJSON(w, http.StatusOK, map[string]any{"revoked": revoked})
}

// handlePlatformDeleteUser implements
// DELETE /api/platform/v1/organizations/{orgID}/users/{userID}. The same two
// guards the console applies protect a tenant from locking itself out: the
// last account cannot be deleted, and the last owner cannot be deleted.
func (r *Router) handlePlatformDeleteUser(w http.ResponseWriter, req *http.Request) {
	orgID := chi.URLParam(req, "orgID")
	server := r.serverFor(orgID)
	userID64, err := strconv.ParseUint(chi.URLParam(req, "userID"), 10, 64)
	if server == nil || err != nil {
		http.Error(w, "unknown tenant or user", http.StatusNotFound)
		return
	}
	userID := tailcfgUserID(userID64)
	if len(server.identity.ListUsers()) <= 1 {
		http.Error(w, "the last account of a tenant cannot be deleted", http.StatusConflict)
		return
	}
	if user, ok := server.identity.GetUser(userID); ok && user.Role == identity.RoleOwner {
		if !otherOwnerExists(server, userID64) {
			http.Error(w, "a tailnet needs at least one owner", http.StatusConflict)
			return
		}
	}
	if err := server.identity.DeleteUser(userID); err != nil {
		http.Error(w, "could not delete the account", http.StatusInternalServerError)
		return
	}
	if _, err := server.identity.RevokeUserSessions(userID, "account deleted by the platform operator"); err != nil {
		r.log.Warn("revoking sessions of a deleted account", "err", err)
	}
	r.auditTenant(orgID, "platform", identity.AuditUserUpdated, "user:"+strconv.FormatUint(userID64, 10),
		"account deleted by the platform API")
	w.WriteHeader(http.StatusNoContent)
}

// handlePlatformAuditActions is a small discovery endpoint for the console's
// action filter: the distinct actions seen in the recent window of the
// selected tenants.
func (r *Router) handlePlatformAuditActions(w http.ResponseWriter, req *http.Request) {
	orgs, err := r.selectAuditOrgs(req.URL.Query()["org"])
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	seen := map[string]bool{}
	actions := []string{}
	for _, org := range orgs {
		for _, event := range org.site.Server.identity.ListAudit(200) {
			if !seen[event.Action] {
				seen[event.Action] = true
				actions = append(actions, event.Action)
			}
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"actions": actions})
}
