package control

import (
	"errors"
	"net/http"
	"net/mail"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/go-chi/chi/v5"

	"github.com/xunara-net/xunara-server/identity"
)

// Platform user administration over JSON: the same operations the operator
// console offers, for the platform admin SPA and for automation. Every route
// here is behind the platform admin token (mountPlatform), and every mutation
// is audited in the affected tenant's log.

// platformUser is one account as the platform API reports it.
type platformUser struct {
	Org                    string     `json:"org"`
	OrgName                string     `json:"orgName"`
	ID                     uint64     `json:"id"`
	Login                  string     `json:"login"`
	DisplayName            string     `json:"displayName"`
	Email                  string     `json:"email"`
	Role                   string     `json:"role"`
	Plan                   string     `json:"plan"`
	Sessions               int        `json:"sessions"`
	LastSeen               *time.Time `json:"lastSeen,omitempty"`
	CreatedAt              time.Time  `json:"createdAt"`
	UpdatedAt              time.Time  `json:"updatedAt"`
	Disabled               bool       `json:"disabled"`
	DisabledAt             *time.Time `json:"disabledAt,omitempty"`
	DisabledReason         string     `json:"disabledReason"`
	PasswordResetAvailable bool       `json:"passwordResetAvailable"`
	PasswordResetExpiresAt *time.Time `json:"passwordResetExpiresAt,omitempty"`
}

// 明确选定已有租户，只创建人类成员，不新建网络、签发会话或批准设备。
func (router *Router) handlePlatformCreateUser(writer http.ResponseWriter, request *http.Request) {
	server := router.serverFor(chi.URLParam(request, "orgID"))
	if server == nil {
		writeAPIError(writer, 404, "USER_NOT_FOUND: unknown tenant")
		return
	}
	if !server.localLogin {
		writeAPIError(writer, 403, "LOCAL_LOGIN_DISABLED: tenant does not allow local password login")
		return
	}
	var body struct {
		Login       string `json:"login"`
		DisplayName string `json:"display_name"`
		Email       string `json:"email"`
		Password    string `json:"password"`
		Role        string `json:"role"`
	}
	if !decodeAccountBodyLimit(writer, request, &body, 8<<10) {
		return
	}
	login := strings.ToLower(strings.TrimSpace(body.Login))
	display, email := strings.TrimSpace(body.DisplayName), strings.TrimSpace(body.Email)
	role, err := identity.ParseRole(body.Role)
	if err != nil || login == "" || len(login) > 128 || sanitizeLoginName(login) != login || !utf8.ValidString(display) || utf8.RuneCountInString(display) > 100 || strings.ContainsFunc(display, unicode.IsControl) {
		writeAPIError(writer, 400, "USER_CREATE_INVALID: invalid login, display name or role")
		return
	}
	if email != "" {
		address, err := mail.ParseAddress(email)
		if err != nil || address.Name != "" || address.Address != email || len(email) > 254 || strings.ContainsFunc(email, unicode.IsControl) {
			writeAPIError(writer, 400, "USER_CREATE_INVALID: invalid contact email")
			return
		}
	}
	if err := identity.CheckPassword(login, body.Password); err != nil {
		writeAPIError(writer, 400, "USER_CREATE_INVALID: "+passwordPolicyMessage(err))
		return
	}
	hash, err := identity.HashPassword(body.Password)
	if err != nil {
		writeAPIError(writer, 503, "USER_CREATE_UNAVAILABLE: could not prepare credential")
		return
	}
	actor := "platform-token"
	if session, ok := request.Context().Value(platformSessionContextKey{}).(identity.Session); ok {
		actor = "platform-user:" + strconv.FormatUint(uint64(session.UserID), 10)
	}
	user, err := server.identity.CreateLocalAccountByPlatform(request.Context(), identity.PlatformLocalAccount{
		LoginName: login, DisplayName: display, Email: email, PasswordHash: hash, Role: role,
		MaxUsers: server.Plan().MaxUsers, AuthenticationRevision: server.authenticationRevision(), Actor: actor,
	})
	if err != nil {
		switch {
		case errors.Is(err, identity.ErrLoginNameTaken):
			writeAPIError(writer, 409, "LOGIN_NAME_TAKEN: this tenant already has that login")
		case errors.Is(err, identity.ErrMemberLimitReached):
			writeAPIError(writer, 403, MsgUserLimitReached)
		case errors.Is(err, identity.ErrAuthenticationConfigChanged):
			writeAPIError(writer, 409, "AUTH_CONFIG_CHANGED: refresh tenant authentication settings")
		default:
			writeAPIError(writer, 503, "USER_CREATE_UNAVAILABLE: could not commit account; refresh the list to check")
		}
		return
	}
	writeJSON(writer, 201, map[string]any{"org": server.TenantID(), "id": uint64(user.ID), "login": user.LoginName, "role": user.Role})
}

// handlePlatformUsers implements GET /api/platform/v1/users: every account on
// the deployment, grouped by tenant.
func (r *Router) handlePlatformUsers(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	now := time.Now().UTC()
	out := []platformUser{}
	for _, org := range r.orgSnapshot() {
		server := org.site.Server
		planID := ""
		if r.cfg.Plans != nil {
			planID = r.cfg.Plans.Plan(req.Context(), org.site.ID).ID
		}
		users, err := server.identity.ListUsersContext(req.Context())
		if err != nil {
			writeAPIError(w, http.StatusServiceUnavailable, "USER_STATUS_UNAVAILABLE: could not read accounts")
			return
		}
		for _, u := range users {
			row := platformUser{
				Org: org.site.ID, OrgName: org.site.Name,
				ID: uint64(u.ID), Login: u.LoginName, DisplayName: u.DisplayName,
				Email: u.Email, Role: string(u.Role), Plan: planID,
				CreatedAt: u.CreatedAt, UpdatedAt: u.UpdatedAt,
				Disabled: !u.DisabledAt.IsZero(), DisabledReason: u.DisabledReason,
			}
			if row.Disabled {
				disabledAt := u.DisabledAt
				row.DisabledAt = &disabledAt
			}
			if server.localLogin && !row.Disabled {
				_, err := server.identity.LookupLocalCredential(req.Context(), u.ID)
				if err != nil && !errors.Is(err, identity.ErrCredentialNotFound) {
					writeAPIError(w, http.StatusServiceUnavailable, "PASSWORD_RESET_UNAVAILABLE: could not read password availability")
					return
				}
				row.PasswordResetAvailable = err == nil
				if row.PasswordResetAvailable {
					status, found, err := server.identity.GetPasswordResetStatus(req.Context(), u.ID)
					if err != nil {
						writeAPIError(w, http.StatusServiceUnavailable, "PASSWORD_RESET_UNAVAILABLE: could not read pending reset status")
						return
					}
					if found {
						row.PasswordResetExpiresAt = &status.ExpiresAt
					}
				}
			}
			sessions, err := server.identity.ListAccountSessions(req.Context(), u.ID)
			if err != nil {
				writeAPIError(w, http.StatusServiceUnavailable, "USER_STATUS_UNAVAILABLE: could not read account sessions")
				return
			}
			for _, session := range sessions {
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

// 平台状态写入只接受完整版本与明确布尔值；普通租户 Cookie 不能使用此管理入口。
func (router *Router) handlePlatformUserStatus(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	orgID := chi.URLParam(request, "orgID")
	server := router.serverFor(orgID)
	userID, err := strconv.ParseUint(chi.URLParam(request, "userID"), 10, 64)
	if server == nil || err != nil || userID == 0 {
		writeAPIError(writer, http.StatusNotFound, "USER_NOT_FOUND: unknown tenant or account")
		return
	}
	var body struct {
		Disabled          *bool     `json:"disabled"`
		Reason            string    `json:"reason"`
		ExpectedUpdatedAt time.Time `json:"expected_updated_at"`
	}
	if !decodeAccountBodyLimit(writer, request, &body, 4<<10) {
		return
	}
	if body.ExpectedUpdatedAt.IsZero() {
		writeAPIError(writer, http.StatusPreconditionRequired, "USER_VERSION_REQUIRED: refresh before changing account status")
		return
	}
	if body.Disabled == nil {
		writeAPIError(writer, http.StatusBadRequest, "USER_STATUS_INVALID: disabled must be provided")
		return
	}
	result, err := server.identity.SetUserStatusByPlatform(request.Context(), tailcfgUserID(userID), identity.UserStatusChange{
		Disabled: *body.Disabled, Reason: body.Reason, ExpectedUpdatedAt: body.ExpectedUpdatedAt,
	})
	if err != nil {
		switch {
		case errors.Is(err, identity.ErrMemberConflict):
			writeAPIError(writer, http.StatusConflict, "USER_STATUS_CHANGED: account changed; refresh and review before submitting")
		case errors.Is(err, identity.ErrLastOwner):
			writeAPIError(writer, http.StatusConflict, "LAST_ACTIVE_OWNER: a tailnet needs at least one enabled owner")
		case errors.Is(err, identity.ErrUserNotFound):
			writeAPIError(writer, http.StatusNotFound, "USER_NOT_FOUND: unknown account")
		case errors.Is(err, identity.ErrMemberInvalid):
			writeAPIError(writer, http.StatusBadRequest, "USER_STATUS_INVALID: provide a reason of 1 to 256 characters without control characters")
		default:
			writeAPIError(writer, http.StatusServiceUnavailable, "USER_STATUS_UNAVAILABLE: could not commit account status; refresh to check the result")
		}
		return
	}
	payload := map[string]any{
		"org": orgID, "id": uint64(result.User.ID), "disabled": !result.User.DisabledAt.IsZero(),
		"disabledReason": result.User.DisabledReason, "updatedAt": result.User.UpdatedAt, "revoked": result.RevokedSessions,
	}
	if !result.User.DisabledAt.IsZero() {
		payload["disabledAt"] = result.User.DisabledAt
	}
	writeJSON(writer, http.StatusOK, payload)
}

// handlePlatformRevokeUserSessions implements
// POST /api/platform/v1/organizations/{orgID}/users/{userID}/revoke：只撤销浏览器会话，
// 不改变 Machine Identity、在线节点或独立服务凭据。
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
	users, err := server.identity.ListUsersContext(req.Context())
	if err != nil {
		http.Error(w, "could not check the accounts", http.StatusServiceUnavailable)
		return
	}
	if len(users) <= 1 {
		http.Error(w, "the last account of a tenant cannot be deleted", http.StatusConflict)
		return
	}
	if err := server.identity.DeleteUserContext(req.Context(), userID); err != nil {
		switch {
		case errors.Is(err, identity.ErrLastOwner):
			http.Error(w, "a tailnet needs at least one owner", http.StatusConflict)
		case errors.Is(err, identity.ErrUserNotFound):
			http.Error(w, "unknown user", http.StatusNotFound)
		default:
			http.Error(w, "could not delete the account", http.StatusServiceUnavailable)
		}
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
