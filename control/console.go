package control

import (
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/go-chi/chi/v5"

	"github.com/xunara-net/xunara-server/identity"
	"github.com/xunara-net/xunara-server/state"
)

// consoleDevice is a pending device as shown on the console.
type consoleDevice struct {
	ID       string
	Hostname string
	OS       string
	Created  time.Time
	Expires  time.Time
}

// consoleAuthKey is a pre-auth key as shown on the console. The secret itself
// is deliberately absent: it is displayed exactly once, by the create handler.
type consoleAuthKey struct {
	ID        uint64
	Owner     string
	Reusable  bool
	Ephemeral bool
	Used      bool
	Tags      []string
	Expiry    time.Time
	Created   time.Time
}

// consoleAuthKeyViews renders the key list without secrets.
func (s *Server) consoleAuthKeyViews() []consoleAuthKey {
	keys := s.store.ListPreAuthKeys()
	views := make([]consoleAuthKey, 0, len(keys))
	for _, k := range keys {
		views = append(views, consoleAuthKey{
			ID:        k.ID,
			Owner:     s.UserProfile(k.UserID).LoginName,
			Reusable:  k.Reusable,
			Ephemeral: k.Ephemeral,
			Used:      k.Used,
			Tags:      k.Tags,
			Expiry:    k.Expiry,
			Created:   k.Created,
		})
	}
	return views
}

// splitTagInput splits the console's comma- or whitespace-separated tag field.
func splitTagInput(raw string) []string {
	return strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || unicode.IsSpace(r) })
}

// consoleRouter builds the operator console.
func (s *Server) consoleRouter() http.Handler {
	r := chi.NewRouter()

	r.Get("/", s.handleConsoleOverview)

	r.Get("/prefs", s.handleConsolePrefs)

	r.Get("/machines", s.handleConsoleMachines)
	r.Get("/exit-nodes", s.handleConsoleExitNodes)
	r.Get("/relays", s.handleConsoleRelays)
	r.Get("/serve", s.handleConsoleServe)
	r.Get("/devices", s.handleConsoleDevices)
	r.Get("/users", s.handleConsoleUsers)
	r.Get("/dns", s.handleConsoleDNS)
	r.Get("/derp", s.handleConsoleDERP)
	r.Get("/auth-keys", s.handleConsoleAuthKeys)
	r.Get("/agents", s.handleConsoleAgents)
	r.Get("/api-keys", s.handleConsoleAPIKeys)
	r.Get("/shares", s.handleConsoleShares)
	r.Get("/services", s.handleConsoleServices)
	r.Get("/reach", s.handleConsoleReach)
	r.Get("/reach/{id}", s.handleConsoleReachSession)
	r.Get("/flux", s.handleConsoleFlux)
	r.Get("/flux/{id}", s.handleConsoleFluxTransfer)
	r.Get("/webhooks", s.handleConsoleWebhooks)
	r.Get("/policy", s.handleConsolePolicy)
	r.Get("/security", s.handleConsoleSecurity)
	r.Get("/plan", s.handleConsolePlan)
	r.Get("/ssh-check", s.handleConsoleSSHCheck)
	r.Get("/audit", s.handleConsoleAudit)
	// 旧管理页面和业务处理器已删除；旧地址暂留弃用提示与薄适配，方便平滑升级。
	r.Method(http.MethodGet, "/passkeys", deprecatedAccountEndpoint(http.RedirectHandler("/security", http.StatusFound)))
	r.With(deprecatedAccountEndpoint).Post("/passkeys/begin", s.handleAPIAccountPasskeyBegin)
	r.With(deprecatedAccountEndpoint).Post("/passkeys/finish", s.handleAPIAccountPasskeyFinish)
	r.With(deprecatedAccountEndpoint).Post("/passkeys/{id}/delete", s.handleLegacyDeletePasskey)

	// Every write goes through the role guard: members may look at the
	// tailnet, admins and owners may change it.
	r.Group(func(r chi.Router) {
		r.Use(s.consoleWriteAccess)
		r.Post("/machines/{id}/delete", s.handleConsoleDeleteMachine)
		r.Post("/machines/{id}/routes", s.handleConsoleMachineRoutes)
		r.Post("/devices/{id}/approve", s.handleConsoleDevice(true))
		r.Post("/devices/{id}/deny", s.handleConsoleDevice(false))
		r.Post("/users/{id}", s.handleConsoleUpdateUser)
		r.Post("/invites", s.handleConsoleCreateInvite)
		r.Post("/invites/{id}/delete", s.handleConsoleRevokeInvite)
		r.Post("/dns/{id}/delete", s.handleConsoleDeleteDNS)
		r.Post("/auth-keys", s.handleConsoleCreateAuthKey)
		r.Post("/auth-keys/{id}/delete", s.handleConsoleDeleteAuthKey)
		r.Post("/agents/{id}/revoke", s.handleConsoleRevokeAgentToken)
		r.Post("/api-keys", s.handleConsoleCreateAPIKey)
		r.Post("/api-keys/{id}/revoke", s.handleConsoleRevokeAPIKey)
		r.Post("/shares", s.handleConsoleCreateShare)
		r.Post("/webhooks", s.handleConsoleCreateWebhook)
		r.Post("/webhooks/{id}/delete", s.handleConsoleDeleteWebhook)
	})

	// Accepting or declining a share is the target identity's own decision,
	// not tailnet administration (like passkeys, any signed-in role may act
	// on its own rows); the share service enforces which rows those are. The
	// handlers check session and CSRF themselves.
	r.Post("/shares/{id}/accept", s.handleConsoleAcceptShare)
	r.Post("/shares/{id}/reject", s.handleConsoleRejectShare)
	r.Post("/shares/{id}/revoke", s.handleConsoleRevokeShare)

	return r
}

// consoleWriteAccess rejects console writes from read-only roles. Unauthenticated
// requests are sent to the login page, matching the read handlers.
func (s *Server) consoleWriteAccess(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, ok := s.currentSession(r)
		if !ok {
			http.Redirect(w, r, "/login?return_to="+url.QueryEscape(r.URL.RequestURI()), http.StatusFound)
			return
		}
		user, ok := s.identity.GetUser(session.UserID)
		if !ok || !user.Role.CanWrite() {
			s.renderError(w, r, http.StatusForbidden, "Read-only access",
				"Your role does not allow changing the tailnet.")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// consoleSession resolves the session and adds the shared page data.
func (s *Server) consoleSession(w http.ResponseWriter, r *http.Request, nav string) (identity.Session, map[string]any, bool) {
	session, token, ok := s.requireSession(w, r, r.URL.RequestURI())
	if !ok {
		return identity.Session{}, nil, false
	}
	profile := s.UserProfile(session.UserID)
	role := identity.RoleMember
	if user, ok := s.identity.GetUser(session.UserID); ok && user.Role.Valid() {
		role = user.Role
	}
	return session, map[string]any{
		"Nav":       nav,
		"Title":     consoleTitles[nav],
		"Lede":      consoleLedes[nav],
		"NavGroups": consoleNavGroups(nav),
		"Lang":      consoleLangFromRequest(r),
		"Accent":    consoleAccentFromRequest(r),
		"Path":      r.URL.RequestURI(),
		"User":      profile.LoginName,
		"Role":      role.String(),
		"CanWrite":  role.CanWrite(),
		"IsOwner":   role.IsOwner(),
		"Version":   Version,
		"CSRF":      csrfTokenFor(token),
		"ServerURL": s.cfg.ServerURL,
		"Domain":    s.cfg.Domain,
	}, true
}

// consoleCheckCSRF verifies the form token of a console POST.
func (s *Server) consoleCheckCSRF(w http.ResponseWriter, r *http.Request) bool {
	if !checkCSRF(r, s.sessionToken(r)) {
		s.renderError(w, r, http.StatusForbidden, "Request rejected",
			"The form token is invalid. Reload the page and try again.")
		return false
	}
	return true
}

// handleConsoleOverview implements GET /console/.
func (s *Server) handleConsoleOverview(w http.ResponseWriter, r *http.Request) {
	_, data, ok := s.consoleSession(w, r, "overview")
	if !ok {
		return
	}

	nodes := s.store.ListNodes()
	online := 0
	for _, n := range nodes {
		if s.isOnline(n.ID) {
			online++
		}
	}
	engine := s.policy.Load()
	if engine != nil {
		// The page composes the sentence from the count so both languages can
		// order the number and the noun their own way.
		data["PolicyDocument"] = true
		data["PolicyRules"] = engine.RuleCount()
	}

	data["MachinesTotal"] = len(nodes)
	data["MachinesOnline"] = online
	data["Users"] = len(s.identity.ListUsers())
	data["PendingDevices"] = len(s.identity.ListPendingDeviceAuthorizations(time.Now()))
	data["DNSRecords"] = len(s.store.ListDNSRecords())
	data["AuthKeys"] = len(s.store.ListPreAuthKeys())
	agentTokens := s.identity.ListAgentTokens(0)
	liveAgents := 0
	for _, t := range agentTokens {
		if t.Live(time.Now()) {
			liveAgents++
		}
	}
	data["Agents"] = liveAgents
	data["TailnetLock"] = s.TKAStatus()
	// The issuer view is best-effort: a keyring an operator must fix (bad
	// permissions, corrupt file) should not blank the whole overview.
	if status, err := s.IDTokenStatus(); err == nil {
		data["IDToken"] = status
	} else {
		data["IDTokenError"] = err.Error()
		s.log.Warn("reading the identity-token issuer state for the console", "err", err)
	}

	s.renderConsole(w, consoleOverviewTemplate, data)
}

// handleConsoleMachines implements GET /console/machines.
func (s *Server) handleConsoleMachines(w http.ResponseWriter, r *http.Request) {
	_, data, ok := s.consoleSession(w, r, "machines")
	if !ok {
		return
	}

	nodes := s.store.ListNodes()
	counts := s.deviceAttrCounts()
	serviceCounts := s.serviceCounts()
	machines := make([]apiMachine, 0, len(nodes))
	for _, n := range nodes {
		view := s.apiMachineView(n)
		view.DeviceAttrCount = counts[n.ID]
		view.ServiceCount = serviceCounts[n.ID]
		machines = append(machines, view)
	}
	data["Machines"] = machines
	s.renderConsole(w, consoleMachinesTemplate, data)
}

// handleConsoleDeleteMachine implements POST /console/machines/{id}/delete.
func (s *Server) handleConsoleDeleteMachine(w http.ResponseWriter, r *http.Request) {
	session, data, ok := s.consoleSession(w, r, "machines")
	if !ok {
		return
	}
	if !s.consoleCheckCSRF(w, r) {
		return
	}

	node, ok := s.lookupAPINode(chi.URLParam(r, "id"))
	if !ok {
		s.renderError(w, r, http.StatusNotFound, "Unknown machine", "This machine does not exist.")
		return
	}
	if err := s.store.DeleteNode(node.ID); err != nil {
		s.log.Error("deleting machine", "node", int(node.ID), "err", err)
		s.renderError(w, r, http.StatusInternalServerError, "Delete failed", "Please try again.")
		return
	}
	s.audit(fmt.Sprintf("user:%d", session.UserID), identity.AuditNodeDeleted, nodeTarget(node),
		"deleted through the console")
	s.notifyNodePeers(node)

	data["Notice"] = fmt.Sprintf("Machine %s deleted.", node.Hostname)
	s.handleConsoleMachinesNotice(w, data)
}

// handleConsoleMachinesNotice re-renders the machine list after an action.
func (s *Server) handleConsoleMachinesNotice(w http.ResponseWriter, data map[string]any) {
	nodes := s.store.ListNodes()
	machines := make([]apiMachine, 0, len(nodes))
	for _, n := range nodes {
		machines = append(machines, s.apiMachineView(n))
	}
	data["Machines"] = machines
	s.renderConsole(w, consoleMachinesTemplate, data)
}

// handleConsoleMachineRoutes implements POST /console/machines/{id}/routes.
//
// The form has two actions: approve every announced route, or withdraw every
// approval. Fine-grained approval is available through the API and CLI.
func (s *Server) handleConsoleMachineRoutes(w http.ResponseWriter, r *http.Request) {
	session, data, ok := s.consoleSession(w, r, "machines")
	if !ok {
		return
	}
	if !s.consoleCheckCSRF(w, r) {
		return
	}

	node, ok := s.lookupAPINode(chi.URLParam(r, "id"))
	if !ok {
		s.renderError(w, r, http.StatusNotFound, "Unknown machine", "This machine does not exist.")
		return
	}

	var (
		before = node.ApprovedRoutes
		after  []netip.Prefix
		notice string
	)
	switch r.PostFormValue("action") {
	case "approve-all":
		after = state.ApplyRouteApproval(before, node.AnnouncedRoutes(), nil)
		notice = "All announced routes approved."
	case "unapprove-all":
		after = nil
		notice = "All route approvals withdrawn."
	default:
		s.renderError(w, r, http.StatusBadRequest, "Unknown action", "The form action is not recognised.")
		return
	}

	if added, _ := state.RouteDelta(before, after); len(added) > 0 {
		if !s.planGateOrRender(w, r, s.assertRouteApprovalAllowed(after), "Route approval rejected") {
			return
		}
	}

	added, removed := state.RouteDelta(before, after)
	if len(added) == 0 && len(removed) == 0 {
		notice = "No change."
	} else {
		if err := s.store.SetNodeApprovedRoutes(node.ID, after); err != nil {
			s.log.Error("setting approved routes", "node", int(node.ID), "err", err)
			s.renderError(w, r, http.StatusInternalServerError, "Update failed", "Please try again.")
			return
		}
		if err := s.store.BumpConfigRevision(); err != nil {
			s.log.Error("bumping config revision", "err", err)
		}
		actor := fmt.Sprintf("user:%d", session.UserID)
		for _, p := range added {
			s.audit(actor, identity.AuditRouteApproved, nodeTarget(node), p.String())
		}
		for _, p := range removed {
			s.audit(actor, identity.AuditRouteUnapproved, nodeTarget(node), p.String())
		}
		s.notifyWatchers()
	}

	data["Notice"] = notice
	s.handleConsoleMachinesNotice(w, data)
}

// handleConsoleDevices implements GET /console/devices.
func (s *Server) handleConsoleDevices(w http.ResponseWriter, r *http.Request) {
	_, data, ok := s.consoleSession(w, r, "devices")
	if !ok {
		return
	}

	data["Devices"] = consoleDeviceViews(s.pendingDeviceViews(time.Now()).Devices)
	s.renderConsole(w, consoleDevicesTemplate, data)
}

// handleConsoleDevice implements POST /console/devices/{id}/approve|deny.
func (s *Server) handleConsoleDevice(approve bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, data, ok := s.consoleSession(w, r, "devices")
		if !ok {
			return
		}
		if !s.consoleCheckCSRF(w, r) {
			return
		}

		id := chi.URLParam(r, "id")
		actor := fmt.Sprintf("user:%d", session.UserID)

		var err error
		if approve {
			_, err = s.approveDevice(id, session.UserID, actor)
		} else {
			_, err = s.denyDevice(id, session.UserID, actor)
		}
		if err != nil {
			var he HTTPError
			if errors.As(err, &he) {
				s.renderError(w, r, he.Code, "Device decision failed", he.Msg)
				return
			}
			s.log.Error("deciding device", "device", id, "err", err)
			s.renderError(w, r, http.StatusInternalServerError, "Device decision failed", "Please try again.")
			return
		}

		if approve {
			data["Notice"] = "Device approved."
		} else {
			data["Notice"] = "Device denied."
		}
		s.handleConsoleDevicesNotice(w, data)
	}
}

// handleConsoleDevicesNotice re-renders the device list after a decision.
func (s *Server) handleConsoleDevicesNotice(w http.ResponseWriter, data map[string]any) {
	data["Devices"] = consoleDeviceViews(s.pendingDeviceViews(time.Now()).Devices)
	s.renderConsole(w, consoleDevicesTemplate, data)
}

// consoleDeviceViews renders the shared pending-device shape for the console,
// with display fallbacks the API leaves to its caller.
func consoleDeviceViews(pending []pendingDeviceView) []consoleDevice {
	devices := make([]consoleDevice, 0, len(pending))
	for _, da := range pending {
		hostname := da.Hostname
		if hostname == "" {
			hostname = "unnamed device"
		}
		os := da.OS
		if os == "" {
			os = "unknown"
		}
		devices = append(devices, consoleDevice{
			ID: da.ID, Hostname: hostname, OS: os, Created: da.Created, Expires: da.Expires,
		})
	}
	return devices
}

// handleConsoleUsers implements GET /console/users.
func (s *Server) handleConsoleUsers(w http.ResponseWriter, r *http.Request) {
	_, data, ok := s.consoleSession(w, r, "users")
	if !ok {
		return
	}

	s.consoleUsersPageData(data)
	s.renderConsole(w, consoleUsersTemplate, data)
}

// handleConsoleUpdateUser implements POST /console/users/{id}.
func (s *Server) handleConsoleUpdateUser(w http.ResponseWriter, r *http.Request) {
	session, data, ok := s.consoleSession(w, r, "users")
	if !ok {
		return
	}
	actor, ok := s.identity.GetUser(session.UserID)
	if !ok || !actor.Role.IsOwner() {
		s.renderError(w, r, http.StatusForbidden, "Owner role required", "Only an owner may manage users.")
		return
	}
	if !s.consoleCheckCSRF(w, r) {
		return
	}

	user, ok := s.lookupAPIUser(chi.URLParam(r, "id"))
	if !ok {
		s.renderError(w, r, http.StatusNotFound, "Unknown user", "This user does not exist.")
		return
	}

	var changed []string
	if v := strings.TrimSpace(r.PostFormValue("displayName")); v != "" && v != user.DisplayName {
		user.DisplayName = v
		changed = append(changed, "display_name")
	}
	if v := strings.TrimSpace(r.PostFormValue("email")); v != user.Email {
		user.Email = v
		changed = append(changed, "email")
	}

	roleChanged := false
	if raw := strings.TrimSpace(r.PostFormValue("role")); raw != "" {
		actor, ok := s.identity.GetUser(session.UserID)
		if !ok || !actor.Role.IsOwner() {
			s.renderError(w, r, http.StatusForbidden, "Owner role required",
				"Only an owner may change roles.")
			return
		}
		role, err := identity.ParseRole(raw)
		if err != nil {
			s.renderError(w, r, http.StatusBadRequest, "Invalid role", err.Error())
			return
		}
		if role != user.Role {
			if user.Role.IsOwner() && role != identity.RoleOwner && !s.otherOwnerExists(user.ID) {
				s.renderError(w, r, http.StatusConflict, "Cannot demote the last owner",
					"A tailnet needs at least one owner.")
				return
			}
			user.Role = role
			roleChanged = true
			changed = append(changed, "role")
		}
	}

	if len(changed) == 0 {
		data["Notice"] = "No change."
	} else if err := s.identity.UpdateUser(user); err != nil {
		s.log.Error("updating user", "user", int(user.ID), "err", err)
		s.renderError(w, r, http.StatusInternalServerError, "Update failed", "Please try again.")
		return
	} else {
		action := identity.AuditUserUpdated
		if roleChanged {
			action = identity.AuditUserRoleChanged
		}
		s.audit(fmt.Sprintf("user:%d", session.UserID), action,
			fmt.Sprintf("user:%d", user.ID), "updated "+strings.Join(changed, ", ")+" through the console")
		data["Notice"] = "User updated."
	}

	s.handleConsoleUsersNotice(w, data)
}

// consoleInvite is a registration invitation as shown on the console. The
// token itself is never part of the list: it exists in the link the create
// handler shows once, and is stored only as a hash.
type consoleInvite struct {
	ID      string
	Role    string
	Note    string
	Created time.Time
	Expires time.Time
	// Redeemed, Expired and Open describe what can still be done with it.
	Redeemed bool
	Expired  bool
	Open     bool
	UsedBy   string
}

// consoleInviteViews renders the invitations without their tokens.
func (s *Server) consoleInviteViews() []consoleInvite {
	invites := s.identity.ListRegistrationInvites()
	now := time.Now()
	views := make([]consoleInvite, 0, len(invites))
	for _, invite := range invites {
		view := consoleInvite{
			ID:       invite.ID,
			Role:     string(invite.Role),
			Note:     invite.Note,
			Created:  invite.CreatedAt,
			Expires:  invite.ExpiresAt,
			Redeemed: invite.Redeemed(),
			Expired:  invite.Expired(now),
		}
		view.Open = !view.Redeemed && !view.Expired
		if view.Redeemed {
			view.UsedBy = s.UserProfile(invite.UsedBy).LoginName
		}
		views = append(views, view)
	}
	return views
}

// consoleUsersPageData fills the user list page: the accounts and the
// invitations that can still create one.
func (s *Server) consoleUsersPageData(data map[string]any) {
	users := s.identity.ListUsers()
	views := make([]apiUser, 0, len(users))
	for _, u := range users {
		views = append(views, s.apiUserView(u))
	}
	data["Users"] = views
	if owner, _ := data["IsOwner"].(bool); owner {
		data["Invites"] = s.consoleInviteViews()
	}
	data["InvitationsEnabled"] = s.memberInvitationsEnabled()
}

// 旧表单保留书签兼容，但邀请规则、owner 复核和事务审计复用正式 API 的实现。
func (s *Server) handleConsoleCreateInvite(w http.ResponseWriter, r *http.Request) {
	session, data, ok := s.consoleSession(w, r, "users")
	if !ok {
		return
	}
	if !s.consoleCheckCSRF(w, r) {
		return
	}

	hours, err := strconv.Atoi(strings.TrimSpace(r.PostFormValue("ttl")))
	if err != nil {
		s.renderError(w, r, http.StatusBadRequest, "Invitation rejected", "Choose how long the invitation stays valid.")
		return
	}
	_, token, err := s.createMemberInvitation(r.Context(), session, memberInviteRequest{
		Role: r.PostFormValue("role"), Note: r.PostFormValue("note"), TTLHours: hours,
	})
	if !s.planGateOrRender(w, r, err, "Invitation rejected") {
		return
	}
	data["Notice"] = "Invitation created."
	data["NewInviteCode"] = token
	s.consoleUsersPageData(data)
	s.renderConsole(w, consoleUsersTemplate, data)
}

// handleConsoleRevokeInvite implements POST /console/invites/{id}/delete.
func (s *Server) handleConsoleRevokeInvite(w http.ResponseWriter, r *http.Request) {
	session, data, ok := s.consoleSession(w, r, "users")
	if !ok {
		return
	}
	if !s.consoleCheckCSRF(w, r) {
		return
	}

	id := chi.URLParam(r, "id")
	err := s.identity.RevokeMemberInvitation(r.Context(), session.UserID, session.ID, id)
	if !s.planGateOrRender(w, r, memberInvitationError(err), "Invitation rejected") {
		return
	}
	data["Notice"] = "Invitation revoked."
	s.consoleUsersPageData(data)
	s.renderConsole(w, consoleUsersTemplate, data)
}

// handleConsoleUsersNotice re-renders the user list after an update.
func (s *Server) handleConsoleUsersNotice(w http.ResponseWriter, data map[string]any) {
	s.consoleUsersPageData(data)
	s.renderConsole(w, consoleUsersTemplate, data)
}

// handleConsoleDNS implements GET /console/dns.
func (s *Server) handleConsoleDNS(w http.ResponseWriter, r *http.Request) {
	_, data, ok := s.consoleSession(w, r, "dns")
	if !ok {
		return
	}
	data["Records"] = s.store.ListDNSRecords()
	s.renderConsole(w, consoleDNSTemplate, data)
}

// handleConsoleDeleteDNS implements POST /console/dns/{id}/delete.
func (s *Server) handleConsoleDeleteDNS(w http.ResponseWriter, r *http.Request) {
	session, data, ok := s.consoleSession(w, r, "dns")
	if !ok {
		return
	}
	if !s.consoleCheckCSRF(w, r) {
		return
	}

	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		s.renderError(w, r, http.StatusBadRequest, "Invalid record", "The record ID is not valid.")
		return
	}

	var record *state.DNSRecord
	for _, rec := range s.store.ListDNSRecords() {
		if rec.ID == id {
			record = &rec
			break
		}
	}
	if record == nil {
		s.renderError(w, r, http.StatusNotFound, "Unknown record", "This DNS record does not exist.")
		return
	}

	if err := s.store.DeleteDNSRecord(id); err != nil {
		s.log.Error("deleting DNS record", "record", id, "err", err)
		s.renderError(w, r, http.StatusInternalServerError, "Delete failed", "Please try again.")
		return
	}
	if err := s.store.BumpConfigRevision(); err != nil {
		s.log.Error("bumping config revision", "err", err)
	}
	s.audit(fmt.Sprintf("user:%d", session.UserID), identity.AuditDNSRecordDeleted,
		fmt.Sprintf("dns:%s/%s", record.Name, record.Type), fmt.Sprintf("deleted record %d", record.ID))
	s.notifyWatchers()

	data["Notice"] = "DNS record deleted."
	data["Records"] = s.store.ListDNSRecords()
	s.renderConsole(w, consoleDNSTemplate, data)
}

// handleConsoleDERP implements GET /console/derp: the read-only DERP view of
// this organization (spec section 32.2), built from the same renderer the API
// uses so the page and the endpoint cannot disagree.
func (s *Server) handleConsoleDERP(w http.ResponseWriter, r *http.Request) {
	_, data, ok := s.consoleSession(w, r, "derp")
	if !ok {
		return
	}
	status, nodes := s.derpStatus()
	data["Status"] = status
	data["Nodes"] = nodes
	s.renderConsole(w, consoleDERPTemplate, data)
}

// handleConsoleAuthKeys implements GET /console/auth-keys.
func (s *Server) handleConsoleAuthKeys(w http.ResponseWriter, r *http.Request) {
	_, data, ok := s.consoleSession(w, r, "auth-keys")
	if !ok {
		return
	}
	data["AuthKeys"] = s.consoleAuthKeyViews()
	s.renderConsole(w, consoleAuthKeysTemplate, data)
}

// handleConsoleCreateAuthKey implements POST /console/auth-keys.
func (s *Server) handleConsoleCreateAuthKey(w http.ResponseWriter, r *http.Request) {
	session, data, ok := s.consoleSession(w, r, "auth-keys")
	if !ok {
		return
	}
	if !s.consoleCheckCSRF(w, r) {
		return
	}

	if !s.planGateOrRender(w, r, s.assertAuthKeyQuota(), "Create failed") {
		return
	}

	secret, err := state.NewPreAuthKeySecret()
	if err != nil {
		s.log.Error("generating pre-auth key", "err", err)
		s.renderError(w, r, http.StatusInternalServerError, "Create failed", "Please try again.")
		return
	}

	key := state.PreAuthKey{
		Key:       secret,
		UserID:    session.UserID,
		Reusable:  r.PostFormValue("reusable") != "",
		Ephemeral: r.PostFormValue("ephemeral") != "",
	}
	tags, err := s.validateKeyTags(splitTagInput(r.PostFormValue("tags")))
	if err != nil {
		s.renderError(w, r, http.StatusBadRequest, "Invalid tags", err.Error())
		return
	}
	key.Tags = tags
	if ttlRaw := strings.TrimSpace(r.PostFormValue("ttl")); ttlRaw != "" {
		ttl, err := time.ParseDuration(ttlRaw)
		if err != nil || ttl <= 0 {
			s.renderError(w, r, http.StatusBadRequest, "Invalid lifetime", "The key lifetime is not a valid duration.")
			return
		}
		key.Expiry = time.Now().Add(ttl).UTC()
	}
	if err := s.store.CreatePreAuthKey(&key); err != nil {
		s.log.Error("storing pre-auth key", "err", err)
		s.renderError(w, r, http.StatusInternalServerError, "Create failed", "Please try again.")
		return
	}
	s.audit(fmt.Sprintf("user:%d", session.UserID), identity.AuditPreAuthKeyCreated,
		fmt.Sprintf("preauthkey:%d", key.ID), "created through the console")

	// The secret is shown exactly once.
	data["CreatedKey"] = key.Key
	data["AuthKeys"] = s.consoleAuthKeyViews()
	s.renderConsole(w, consoleAuthKeysTemplate, data)
}

// handleConsoleDeleteAuthKey implements POST /console/auth-keys/{id}/delete.
func (s *Server) handleConsoleDeleteAuthKey(w http.ResponseWriter, r *http.Request) {
	session, data, ok := s.consoleSession(w, r, "auth-keys")
	if !ok {
		return
	}
	if !s.consoleCheckCSRF(w, r) {
		return
	}

	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		s.renderError(w, r, http.StatusBadRequest, "Invalid key", "The key ID is not valid.")
		return
	}

	var secret string
	for _, k := range s.store.ListPreAuthKeys() {
		if k.ID == id {
			secret = k.Key
			break
		}
	}
	if secret == "" {
		s.renderError(w, r, http.StatusNotFound, "Unknown key", "This pre-auth key does not exist.")
		return
	}
	if err := s.store.DeletePreAuthKey(secret); err != nil {
		s.log.Error("deleting pre-auth key", "key", id, "err", err)
		s.renderError(w, r, http.StatusInternalServerError, "Delete failed", "Please try again.")
		return
	}
	s.audit(fmt.Sprintf("user:%d", session.UserID), identity.AuditPreAuthKeyDeleted,
		fmt.Sprintf("preauthkey:%d", id), "deleted through the console")

	data["Notice"] = "Key revoked."
	data["AuthKeys"] = s.consoleAuthKeyViews()
	s.renderConsole(w, consoleAuthKeysTemplate, data)
}

// consoleAgentTokenViews renders native-client credentials for the console.
func (s *Server) consoleAgentTokenViews() []apiAgentTokenView {
	tokens := s.identity.ListAgentTokens(0)
	out := make([]apiAgentTokenView, 0, len(tokens))
	for _, t := range tokens {
		out = append(out, s.apiAgentTokenView(t))
	}
	return out
}

// handleConsoleServices implements GET /console/services: the read-only
// registry of services nodes advertise about themselves (Xunara Atlas).
func (s *Server) handleConsoleServices(w http.ResponseWriter, r *http.Request) {
	_, data, ok := s.consoleSession(w, r, "services")
	if !ok {
		return
	}

	services := []serviceView{}
	for _, svc := range s.store.ListServices() {
		node, ok := s.store.GetNodeByID(svc.NodeID)
		if !ok {
			continue
		}
		services = append(services, s.serviceView(svc, node))
	}
	data["Services"] = services
	s.renderConsole(w, consoleServicesTemplate, data)
}

// consoleReachOutputLimit is how much of each stream the console detail page
// renders. A session may hold up to 2 MiB (spec section 29); the console is a
// supervision view, so it truncates and says so instead of shipping megabytes
// of debugging text to a browser.
const consoleReachOutputLimit = 64 << 10

// consoleReachStates is the filter menu on the Reach list; it is built from
// the state constants so the page cannot offer a state the store rejects.
var consoleReachStates = []string{
	string(state.ReachOffered), string(state.ReachAccepted), string(state.ReachRunning),
	string(state.ReachSucceeded), string(state.ReachFailed), string(state.ReachDenied),
	string(state.ReachCanceled), string(state.ReachExpired),
}

// consoleReachListLimit caps the list page. The console is a supervision view,
// not an archival read; the API pages through everything (spec section 31.4).
const consoleReachListLimit = 200

// consoleFluxStates is the filter menu on the Flux list; it is built from the
// state constants so the page cannot offer a state the store rejects.
var consoleFluxStates = []string{
	string(state.FluxPending), string(state.FluxAccepted), string(state.FluxUploaded),
	string(state.FluxCompleted), string(state.FluxDenied), string(state.FluxFailed),
	string(state.FluxCancelled), string(state.FluxExpired),
}

// consoleFluxListLimit caps the list page, like the Reach console.
const consoleFluxListLimit = 200

// handleConsoleFlux implements GET /console/flux: the read-only Flux transfer
// list (spec section 33.3). The control plane holds ciphertext only, so the
// page has no content to leak even if it wanted to.
func (s *Server) handleConsoleFlux(w http.ResponseWriter, r *http.Request) {
	_, data, ok := s.consoleSession(w, r, "flux")
	if !ok {
		return
	}
	data["Enabled"] = s.flux != nil
	if s.flux == nil {
		s.renderConsole(w, consoleFluxTemplate, data)
		return
	}
	data["States"] = consoleFluxStates

	var filter state.FluxTransferState
	if raw := r.URL.Query().Get("state"); raw != "" {
		filter = state.FluxTransferState(raw)
		if !filter.Valid() {
			s.renderError(w, r, http.StatusBadRequest, "Unknown state",
				"That is not a Flux transfer state.")
			return
		}
	}
	data["StateFilter"] = string(filter)

	transfers := make([]fluxAdminTransfer, 0, 16)
	for _, transfer := range s.store.ListAllFluxTransfers() {
		if filter != "" && transfer.State != filter {
			continue
		}
		if len(transfers) == consoleFluxListLimit {
			data["More"] = true
			break
		}
		view, ok := s.fluxAdminView(transfer)
		if !ok {
			// A participant's node row is gone; the transfer cascade removes
			// it too, so this is only a race with the deletion.
			continue
		}
		transfers = append(transfers, view)
	}
	data["Transfers"] = transfers
	s.renderConsole(w, consoleFluxTemplate, data)
}

// handleConsoleFluxTransfer implements GET /console/flux/{id}: one transfer's
// metadata, never its content.
func (s *Server) handleConsoleFluxTransfer(w http.ResponseWriter, r *http.Request) {
	_, data, ok := s.consoleSession(w, r, "flux")
	if !ok {
		return
	}
	data["Enabled"] = s.flux != nil
	if s.flux == nil {
		// The page explains the disabled feature rather than 404ing, like the
		// list page; only the API hides behind 404.
		s.renderConsole(w, consoleFluxTransferTemplate, data)
		return
	}
	transfer, ok := s.store.GetFluxTransfer(chi.URLParam(r, "id"))
	if !ok {
		s.renderError(w, r, http.StatusNotFound, "Unknown transfer",
			"No Flux transfer has that ID.")
		return
	}
	view, ok := s.fluxAdminView(transfer)
	if !ok {
		s.renderError(w, r, http.StatusNotFound, "Unknown transfer",
			"No Flux transfer has that ID.")
		return
	}
	data["Transfer"] = view
	s.renderConsole(w, consoleFluxTransferTemplate, data)
}

// handleConsoleReach implements GET /console/reach: the read-only Reach
// management list (spec section 31.3), newest first, optionally filtered by
// state. Output text stays on the detail page.
func (s *Server) handleConsoleReach(w http.ResponseWriter, r *http.Request) {
	_, data, ok := s.consoleSession(w, r, "reach")
	if !ok {
		return
	}
	data["Enabled"] = s.cfg.ReachEnabled
	if !s.cfg.ReachEnabled {
		s.renderConsole(w, consoleReachTemplate, data)
		return
	}
	data["States"] = consoleReachStates

	// The filter is fail-closed for the same reason the API's is: a filter
	// that silently widens its result is a security bug.
	var filter state.ReachState
	if raw := r.URL.Query().Get("state"); raw != "" {
		filter = state.ReachState(raw)
		if !filter.Valid() {
			s.renderError(w, r, http.StatusBadRequest, "Unknown state",
				"That is not a Reach session state.")
			return
		}
	}
	data["StateFilter"] = string(filter)

	sessions := make([]reachAdminSession, 0, 16)
	for _, session := range s.store.ListAllReachSessions() {
		if filter != "" && session.State != filter {
			continue
		}
		if len(sessions) == consoleReachListLimit {
			data["More"] = true
			break
		}
		view, ok := s.reachAdminView(session)
		if !ok {
			// A participant's node row is gone; the session cascade removes
			// it too, so this is only a race with the deletion.
			continue
		}
		sessions = append(sessions, view)
	}
	data["Sessions"] = sessions
	s.renderConsole(w, consoleReachTemplate, data)
}

// handleConsoleReachSession implements GET /console/reach/{id}: the session,
// argv included (the approver saw it; the administrator may too), with a
// bounded read of the output. Still read-only: no cancel, no re-run.
func (s *Server) handleConsoleReachSession(w http.ResponseWriter, r *http.Request) {
	_, data, ok := s.consoleSession(w, r, "reach")
	if !ok {
		return
	}
	data["Enabled"] = s.cfg.ReachEnabled

	id := chi.URLParam(r, "id")
	session, found := s.store.GetReachSession(id)
	if !s.cfg.ReachEnabled {
		// The page explains the disabled feature rather than 404ing, like
		// the list page; only the API hides behind 404.
		s.renderConsole(w, consoleReachSessionTemplate, data)
		return
	}
	if !found {
		s.renderError(w, r, http.StatusNotFound, "Unknown session",
			"No Reach session has that ID.")
		return
	}
	view, ok := s.reachAdminView(session)
	if !ok {
		s.renderError(w, r, http.StatusNotFound, "Unknown session",
			"No Reach session has that ID.")
		return
	}
	stdout, stderr, truncatedOut, truncatedErr := s.consoleReachOutput(id)

	data["Session"] = view
	data["Stdout"] = string(stdout)
	data["Stderr"] = string(stderr)
	data["TruncatedOut"] = truncatedOut
	data["TruncatedErr"] = truncatedErr
	data["OutputLimit"] = consoleReachOutputLimit
	s.renderConsole(w, consoleReachSessionTemplate, data)
}

// consoleReachOutput reads a session's output through the same bounded pages
// the API serves, stopping at consoleReachOutputLimit bytes per stream. It
// reports per-stream whether further output was dropped.
func (s *Server) consoleReachOutput(id string) (stdout, stderr []byte, truncatedOut, truncatedErr bool) {
	afterOut, afterErr := int64(-1), int64(-1)
	for {
		page, err := s.reachChunksPage(id, afterOut, afterErr)
		if err != nil {
			// The page still renders what was read; the API is the complete
			// read path, so a partial failure is not worth an error page.
			s.log.Warn("reading reach output for the console", "session", id, "err", err)
			break
		}
		for _, chunk := range page.Out {
			stdout, truncatedOut = appendConsoleOutput(stdout, chunk.Data, truncatedOut)
		}
		for _, chunk := range page.Err {
			stderr, truncatedErr = appendConsoleOutput(stderr, chunk.Data, truncatedErr)
		}
		if len(page.Out) == 0 && len(page.Err) == 0 {
			break
		}
		if page.NextOut == afterOut && page.NextErr == afterErr {
			// Defensive: a page must advance at least one cursor.
			break
		}
		afterOut, afterErr = page.NextOut, page.NextErr
		if truncatedOut && truncatedErr {
			break
		}
	}
	return stdout, stderr, truncatedOut, truncatedErr
}

// appendConsoleOutput appends one chunk to dst, capping the total at
// consoleReachOutputLimit and flagging the first byte that did not fit.
func appendConsoleOutput(dst, chunk []byte, truncated bool) ([]byte, bool) {
	if remaining := consoleReachOutputLimit - len(dst); remaining > 0 {
		if len(chunk) > remaining {
			return append(dst, chunk[:remaining]...), true
		}
		return append(dst, chunk...), truncated
	}
	return dst, true
}

// handleConsoleAgents implements GET /console/agents.
func (s *Server) handleConsoleAgents(w http.ResponseWriter, r *http.Request) {
	_, data, ok := s.consoleSession(w, r, "agents")
	if !ok {
		return
	}
	data["Tokens"] = s.consoleAgentTokenViews()
	s.renderConsole(w, consoleAgentsTemplate, data)
}

// handleConsoleRevokeAgentToken implements POST /console/agents/{id}/revoke.
func (s *Server) handleConsoleRevokeAgentToken(w http.ResponseWriter, r *http.Request) {
	session, data, ok := s.consoleSession(w, r, "agents")
	if !ok {
		return
	}
	if !s.consoleCheckCSRF(w, r) {
		return
	}

	id := chi.URLParam(r, "id")
	var found *identity.AgentToken
	for _, t := range s.identity.ListAgentTokens(0) {
		if t.ID == id {
			token := t
			found = &token
			break
		}
	}
	if found == nil {
		s.renderError(w, r, http.StatusNotFound, "Unknown credential",
			"This agent credential does not exist.")
		return
	}
	if found.RevokedAt.IsZero() {
		if err := s.identity.RevokeAgentToken(id, time.Now().UTC()); err != nil {
			s.log.Error("revoking agent token", "token", id, "err", err)
			s.renderError(w, r, http.StatusInternalServerError, "Revoke failed", "Please try again.")
			return
		}
		s.audit(fmt.Sprintf("user:%d", session.UserID), identity.AuditAgentTokenRevoked,
			"agenttoken:"+id,
			fmt.Sprintf("revoked through the console (node %d)", found.NodeID))
	}

	data["Notice"] = "Agent credential revoked."
	data["Tokens"] = s.consoleAgentTokenViews()
	s.renderConsole(w, consoleAgentsTemplate, data)
}

// consoleAPIKeyView is a service identity credential as the console lists it.
// The token is deliberately absent: only its hash is stored, and the console
// shows it exactly once, at creation.
type consoleAPIKeyView struct {
	ID      string
	Name    string
	Owner   string
	Scopes  []string
	Created time.Time
	// Expires, LastUsed and Revoked are pointers so the template can tell
	// "never" from a real timestamp (a zero time.Time is always truthy).
	Expires  *time.Time
	LastUsed *time.Time
	Revoked  *time.Time
}

// consoleAPIKeyViews renders every API key, newest first.
func (s *Server) consoleAPIKeyViews() []consoleAPIKeyView {
	keys := s.identity.ListAPIKeys()
	out := make([]consoleAPIKeyView, 0, len(keys))
	for _, key := range keys {
		view := consoleAPIKeyView{
			ID:      key.ID,
			Name:    key.Name,
			Owner:   s.userLoginName(key.UserID),
			Scopes:  key.Scopes,
			Created: key.CreatedAt,
		}
		if !key.ExpiresAt.IsZero() {
			expires := key.ExpiresAt
			view.Expires = &expires
		}
		if !key.LastUsedAt.IsZero() {
			used := key.LastUsedAt
			view.LastUsed = &used
		}
		if !key.RevokedAt.IsZero() {
			revoked := key.RevokedAt
			view.Revoked = &revoked
		}
		out = append(out, view)
	}
	return out
}

// handleConsoleAPIKeys implements GET /console/api-keys: the service identity
// credential list (spec section 36.1).
func (s *Server) handleConsoleAPIKeys(w http.ResponseWriter, r *http.Request) {
	_, data, ok := s.consoleSession(w, r, "api-keys")
	if !ok {
		return
	}
	data["Keys"] = s.consoleAPIKeyViews()
	s.renderConsole(w, consoleAPIKeysTemplate, data)
}

// handleConsoleCreateAPIKey implements POST /console/api-keys. The owner is
// always the signed-in user; the role guard already ensured they may write,
// and the server still bounds the key's scopes by the owner's role at use
// time, so a key can never outgrow its creator.
func (s *Server) handleConsoleCreateAPIKey(w http.ResponseWriter, r *http.Request) {
	// API access is a plan capability: the gate runs before anything is
	// parsed so a tenant without it cannot mint a token by accident.
	session, data, ok := s.consoleSession(w, r, "api-keys")
	if !ok {
		return
	}
	if !s.consoleCheckCSRF(w, r) {
		return
	}
	if !s.planGateOrRender(w, r, s.assertAPIAllowed(), "Create failed") {
		return
	}

	var scopes []string
	for _, scope := range []string{identity.ScopeRead, identity.ScopeWrite} {
		if r.PostFormValue("scope_"+scope) != "" {
			scopes = append(scopes, scope)
		}
	}
	if len(scopes) == 0 {
		s.renderError(w, r, http.StatusBadRequest, "Invalid scopes",
			"Select at least one scope for the key.")
		return
	}

	opts := identity.NewAPIKeyOptions{
		Name:   strings.TrimSpace(r.PostFormValue("name")),
		UserID: session.UserID,
		Scopes: scopes,
	}
	if opts.Name == "" {
		s.renderError(w, r, http.StatusBadRequest, "Invalid name",
			"Give the key a name that says which automation holds it.")
		return
	}
	if ttlRaw := strings.TrimSpace(r.PostFormValue("ttl")); ttlRaw != "" {
		ttl, err := time.ParseDuration(ttlRaw)
		if err != nil || ttl <= 0 {
			s.renderError(w, r, http.StatusBadRequest, "Invalid lifetime",
				"The key lifetime is not a valid duration.")
			return
		}
		opts.TTL = ttl
	}

	key, token, err := s.identity.CreateAPIKey(opts)
	if err != nil {
		s.log.Error("creating API key", "err", err)
		s.renderError(w, r, http.StatusBadRequest, "Create failed", err.Error())
		return
	}
	s.audit(fmt.Sprintf("user:%d", session.UserID), identity.AuditAPIKeyCreated,
		"apikey:"+key.ID, "created through the console")

	// The token is shown exactly once.
	data["CreatedToken"] = token
	data["Keys"] = s.consoleAPIKeyViews()
	s.renderConsole(w, consoleAPIKeysTemplate, data)
}

// handleConsoleRevokeAPIKey implements POST /console/api-keys/{id}/revoke.
// Revocation is idempotent: a second click reports success, not an error.
func (s *Server) handleConsoleRevokeAPIKey(w http.ResponseWriter, r *http.Request) {
	session, data, ok := s.consoleSession(w, r, "api-keys")
	if !ok {
		return
	}
	if !s.consoleCheckCSRF(w, r) {
		return
	}

	id := chi.URLParam(r, "id")
	key, ok := s.identity.GetAPIKeyByID(id)
	if !ok {
		s.renderError(w, r, http.StatusNotFound, "Unknown key", "This API key does not exist.")
		return
	}
	if key.RevokedAt.IsZero() {
		if err := s.identity.RevokeAPIKey(id); err != nil {
			s.log.Error("revoking API key", "key", id, "err", err)
			s.renderError(w, r, http.StatusInternalServerError, "Revoke failed", "Please try again.")
			return
		}
		s.audit(fmt.Sprintf("user:%d", session.UserID), identity.AuditAPIKeyRevoked,
			"apikey:"+id, "revoked through the console")
	}

	data["Notice"] = "API key revoked."
	data["Keys"] = s.consoleAPIKeyViews()
	s.renderConsole(w, consoleAPIKeysTemplate, data)
}

// consoleWebhookView is a webhook receiver as the console lists it. The
// signing secret is never included (AGENTS.md section 8).
type consoleWebhookView struct {
	ID      string
	URL     string
	Events  []string
	Enabled bool
	Source  string
	Created time.Time
	Updated time.Time
}

// consoleWebhookViews renders both deployment-configured and managed
// receivers; the source tells the operator which ones can be removed at
// runtime.
func (s *Server) consoleWebhookViews() []consoleWebhookView {
	views := make([]consoleWebhookView, 0, len(s.cfg.Webhooks)+4)
	for _, ep := range s.cfg.Webhooks {
		views = append(views, consoleWebhookView{
			ID:      ep.ID,
			URL:     ep.URL,
			Events:  ep.Events,
			Enabled: true,
			Source:  "config",
		})
	}
	for _, managed := range s.identity.ListWebhookEndpoints() {
		views = append(views, consoleWebhookView{
			ID:      managed.ID,
			URL:     managed.URL,
			Events:  managed.Events,
			Enabled: managed.Enabled,
			Source:  "managed",
			Created: managed.CreatedAt,
			Updated: managed.UpdatedAt,
		})
	}
	return views
}

// handleConsoleWebhooks implements GET /console/webhooks.
func (s *Server) handleConsoleWebhooks(w http.ResponseWriter, r *http.Request) {
	_, data, ok := s.consoleSession(w, r, "webhooks")
	if !ok {
		return
	}
	data["Webhooks"] = s.consoleWebhookViews()
	s.renderConsole(w, consoleWebhooksTemplate, data)
}

// handleConsoleCreateWebhook implements POST /console/webhooks.
func (s *Server) handleConsoleCreateWebhook(w http.ResponseWriter, r *http.Request) {
	session, data, ok := s.consoleSession(w, r, "webhooks")
	if !ok {
		return
	}
	if !s.consoleCheckCSRF(w, r) {
		return
	}

	endpoint, err := s.normalizeManagedWebhook(
		strings.TrimSpace(r.PostFormValue("id")),
		strings.TrimSpace(r.PostFormValue("url")),
		r.PostFormValue("secret"),
		splitTagInput(r.PostFormValue("events")),
	)
	switch {
	case errors.Is(err, errWebhookIDInvalid):
		s.renderError(w, r, http.StatusBadRequest, "Invalid webhook ID",
			"The ID must start with a letter or digit and may contain letters, digits, dots, dashes and underscores.")
		return
	case errors.Is(err, errWebhookIDManaged):
		s.renderError(w, r, http.StatusConflict, "Webhook exists",
			"A managed webhook already uses this ID.")
		return
	case errors.Is(err, errWebhookConfigured):
		s.renderError(w, r, http.StatusConflict, "Webhook exists",
			"This ID belongs to a webhook configured at startup.")
		return
	case err != nil:
		s.renderError(w, r, http.StatusBadRequest, "Invalid webhook", err.Error())
		return
	}

	managed, err := s.storeManagedWebhook(endpoint, true)
	if err != nil {
		s.log.Error("creating webhook endpoint", "webhook", endpoint.ID, "err", err)
		s.renderError(w, r, http.StatusInternalServerError, "Create failed", "Please try again.")
		return
	}
	s.audit(fmt.Sprintf("user:%d", session.UserID), identity.AuditWebhookCreated,
		"webhook:"+managed.ID, "created through the console")

	data["Notice"] = "Webhook created."
	data["Webhooks"] = s.consoleWebhookViews()
	s.renderConsole(w, consoleWebhooksTemplate, data)
}

// handleConsoleDeleteWebhook implements POST /console/webhooks/{id}/delete.
func (s *Server) handleConsoleDeleteWebhook(w http.ResponseWriter, r *http.Request) {
	session, data, ok := s.consoleSession(w, r, "webhooks")
	if !ok {
		return
	}
	if !s.consoleCheckCSRF(w, r) {
		return
	}

	id := chi.URLParam(r, "id")
	switch err := s.deleteManagedWebhook(id); {
	case errors.Is(err, errWebhookConfigured):
		s.renderError(w, r, http.StatusConflict, "Configured webhook",
			"This receiver comes from the server configuration. Remove it there and restart.")
		return
	case errors.Is(err, errWebhookUnknown):
		s.renderError(w, r, http.StatusNotFound, "Unknown webhook", "This webhook does not exist.")
		return
	case err != nil:
		s.log.Error("deleting webhook endpoint", "webhook", id, "err", err)
		s.renderError(w, r, http.StatusInternalServerError, "Delete failed", "Please try again.")
		return
	}
	s.audit(fmt.Sprintf("user:%d", session.UserID), identity.AuditWebhookDeleted,
		"webhook:"+id, "deleted through the console")

	data["Notice"] = "Webhook deleted."
	data["Webhooks"] = s.consoleWebhookViews()
	s.renderConsole(w, consoleWebhooksTemplate, data)
}

// handleConsolePolicy implements GET /console/policy: the read-only policy view
// that GET /api/v2/policy renders (spec section 34.2).
func (s *Server) handleConsolePolicy(w http.ResponseWriter, r *http.Request) {
	_, data, ok := s.consoleSession(w, r, "policy")
	if !ok {
		return
	}
	data["View"] = s.policyView()
	s.renderConsole(w, consolePolicyTemplate, data)
}

// consoleSSHCheckLimit bounds the console's SSH check table.
const consoleSSHCheckLimit = 200

// handleConsoleSSHCheck implements GET /console/ssh-check: the read-only SSH
// check session list (spec section 35.2).
func (s *Server) handleConsoleSSHCheck(w http.ResponseWriter, r *http.Request) {
	_, data, ok := s.consoleSession(w, r, "ssh-check")
	if !ok {
		return
	}

	// The filter is fail-closed for the same reason the API's is: a filter
	// that silently widens its result is a security bug.
	stateFilter := r.URL.Query().Get("state")
	if stateFilter != "" && !sshCheckStateValid(stateFilter) {
		s.renderError(w, r, http.StatusBadRequest, "Unknown state",
			"That is not an SSH check state.")
		return
	}
	sessions, next, err := s.sshCheckPage(stateFilter, 0, consoleSSHCheckLimit, time.Time{}, "")
	if err != nil {
		s.renderError(w, r, http.StatusInternalServerError, "SSH checks unavailable",
			"The identity store could not be read. Please try again.")
		return
	}
	data["Sessions"] = sessions
	data["StateFilter"] = stateFilter
	data["States"] = sshCheckStates
	data["More"] = next != ""
	s.renderConsole(w, consoleSSHCheckTemplate, data)
}

// handleConsoleAudit implements GET /console/audit.
func (s *Server) handleConsoleAudit(w http.ResponseWriter, r *http.Request) {
	_, data, ok := s.consoleSession(w, r, "audit")
	if !ok {
		return
	}
	if !s.planGateOrRender(w, r, s.assertAuditLogAllowed(), "Audit log unavailable") {
		return
	}
	// The console shows the newest events first; the store returns the audit
	// log oldest first for streaming consumers.
	events := s.identity.ListAudit(0)
	const consoleAuditLimit = 200
	if len(events) > consoleAuditLimit {
		events = events[len(events)-consoleAuditLimit:]
	}
	slices.Reverse(events)
	data["Events"] = events
	s.renderConsole(w, consoleAuditTemplate, data)
}

// handleConsolePlan implements GET /console/plan: the tenant's commercial page
// (spec section 54). It reports the plan, the quotas it imposes and the
// network range devices are allocated from — the facts a member needs when a
// device or an invitation is refused.
func (s *Server) handleConsolePlan(w http.ResponseWriter, r *http.Request) {
	_, data, ok := s.consoleSession(w, r, "plan")
	if !ok {
		return
	}

	assigned := s.Plan()
	known := assigned.ID != "" && assigned.ID != "unlimited"
	used, limit := s.DeviceUsage()
	v4, _ := s.store.AddressPrefixes()

	allowance := func(value int) string {
		if value == -1 {
			return "∞"
		}
		return strconv.Itoa(value)
	}
	flag := func(allowed bool) string {
		if allowed {
			return "✓"
		}
		return "—"
	}

	data["PlanKnown"] = known
	data["PlanName"] = assigned.Name
	data["PlanID"] = assigned.ID
	data["DevicesUsed"] = used
	data["DeviceAllowance"] = allowance(limit)
	data["UsersUsed"] = len(s.identity.ListUsers())
	data["UserAllowance"] = allowance(assigned.MaxUsers)
	data["RouteAllowance"] = allowance(assigned.MaxRoutes)
	data["NetworkPrefix"] = v4.String()
	data["NetworkManaged"] = !assigned.AllowCustomCIDR
	data["QuotaReached"] = known && (used >= assigned.MaxDevices && assigned.MaxDevices >= 0 ||
		len(s.identity.ListUsers()) >= assigned.MaxUsers && assigned.MaxUsers >= 0)
	data["Feature"] = map[string]string{
		"Devices":      flag(assigned.MaxDevices != 0),
		"Users":        flag(assigned.MaxUsers != 0),
		"SubnetRouter": flag(assigned.AllowSubnetRouter),
		"ExitNode":     flag(assigned.AllowExitNode),
		"CustomCIDR":   flag(assigned.AllowCustomCIDR),
		"API":          flag(assigned.AllowAPI),
		"Members":      flag(assigned.AllowMultiMember),
		"Audit":        flag(assigned.AllowAuditLog),
	}
	s.renderConsole(w, consolePlanTemplate, data)
}
