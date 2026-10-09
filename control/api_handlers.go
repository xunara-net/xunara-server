package control

import (
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"tailscale.com/tailcfg"

	"github.com/xunara-net/xunara-server/identity"
	"github.com/xunara-net/xunara-server/policy"
	"github.com/xunara-net/xunara-server/state"
)

// apiMachine is the JSON shape of a node.
type apiMachine struct {
	ID              uint64     `json:"id"`
	StableID        string     `json:"stableId"`
	Hostname        string     `json:"hostname"`
	UserID          uint64     `json:"userId"`
	UserLoginName   string     `json:"userLoginName"`
	Online          bool       `json:"online"`
	Ephemeral       bool       `json:"ephemeral"`
	Expired         bool       `json:"expired"`
	Method          string     `json:"method"`
	IPv4            string     `json:"ipv4,omitempty"`
	IPv6            string     `json:"ipv6,omitempty"`
	Created         time.Time  `json:"created"`
	LastSeen        *time.Time `json:"lastSeen,omitempty"`
	ApprovedRoutes  []string   `json:"approvedRoutes"`
	AnnouncedRoutes []string   `json:"announcedRoutes"`
	EffectiveRoutes []string   `json:"effectiveRoutes"`
	ExitNode        bool       `json:"exitNode"`
	// DeviceAttrCount is how many device posture attributes the machine has
	// reported; the values themselves come from the per-machine endpoint. It
	// is omitted when the machine has none.
	DeviceAttrCount int `json:"deviceAttrCount,omitempty"`
	// ServiceCount is how many services the machine advertises (Xunara Atlas);
	// the records themselves come from GET /api/v2/services. It is omitted
	// when the machine advertises none.
	ServiceCount int `json:"serviceCount,omitempty"`
}

// apiMachineView builds the JSON shape of a node.
func (s *Server) apiMachineView(n state.Node) apiMachine {
	profile := s.UserProfile(n.UserID)
	return apiMachine{
		ID:              uint64(n.ID),
		StableID:        n.StableID,
		Hostname:        n.Hostname,
		UserID:          uint64(n.UserID),
		UserLoginName:   profile.LoginName,
		Online:          s.isOnline(n.ID),
		Ephemeral:       n.Ephemeral,
		Expired:         n.Expired(time.Now()),
		Method:          string(n.Method),
		IPv4:            addrString(n.IPv4),
		IPv6:            addrString(n.IPv6),
		Created:         n.Created,
		LastSeen:        n.LastSeen,
		ApprovedRoutes:  prefixStrings(n.ApprovedRoutes),
		AnnouncedRoutes: prefixStrings(n.AnnouncedRoutes()),
		EffectiveRoutes: prefixStrings(n.EffectiveRoutes()),
		ExitNode:        n.IsExitNode(),
	}
}

func addrString(a netip.Addr) string {
	if !a.IsValid() {
		return ""
	}
	return a.String()
}

func prefixStrings(prefixes []netip.Prefix) []string {
	out := make([]string, 0, len(prefixes))
	for _, p := range prefixes {
		out = append(out, p.String())
	}
	return out
}

// deviceAttrCounts returns how many device posture attributes each node has
// reported. List views call it once per request so a page reports counts
// without a query per machine. A store error is not fatal: the count is
// informational, and the values have their own endpoint that does fail closed.
func (s *Server) deviceAttrCounts() map[state.NodeID]int {
	counts, err := s.store.NodeDeviceAttrCounts()
	if err != nil {
		s.log.Warn("counting device posture attributes", "err", err)
		return nil
	}
	return counts
}

// serviceCounts returns how many services each node advertises. Like
// deviceAttrCounts, a store error is not fatal: the count is informational and
// the records themselves have their own endpoint.
func (s *Server) serviceCounts() map[state.NodeID]int {
	counts, err := s.store.NodeServiceCounts()
	if err != nil {
		s.log.Warn("counting advertised services", "err", err)
		return nil
	}
	return counts
}

// handleAPIOverview implements GET /api/v1/overview.
func (s *Server) handleAPIOverview(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireScope(w, r, identity.ScopeRead); !ok {
		return
	}

	nodes := s.store.ListNodes()
	online := 0
	for _, n := range nodes {
		if s.isOnline(n.ID) {
			online++
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"version":        Version,
		"serverUrl":      s.cfg.ServerURL,
		"domain":         s.cfg.Domain,
		"machines":       map[string]int{"total": len(nodes), "online": online},
		"users":          len(s.identity.ListUsers()),
		"pendingDevices": len(s.identity.ListPendingDeviceAuthorizations(time.Now())),
		"dnsRecords":     len(s.store.ListDNSRecords()),
		"authKeys":       len(s.store.ListPreAuthKeys()),
		"apiKeys":        len(s.identity.ListAPIKeys()),
	})
}

// handleAPIMachines implements GET /api/v1/machines.
func (s *Server) handleAPIMachines(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireScope(w, r, identity.ScopeRead); !ok {
		return
	}

	nodes := s.store.ListNodes()
	out := make([]apiMachine, 0, len(nodes))
	for _, n := range nodes {
		out = append(out, s.apiMachineView(n))
	}
	writeJSON(w, http.StatusOK, map[string]any{"machines": out})
}

// lookupAPINode resolves a numeric node ID or a stable ID.
func (s *Server) lookupAPINode(ref string) (state.Node, bool) {
	if id, err := strconv.ParseUint(ref, 10, 64); err == nil {
		return s.store.GetNodeByID(state.NodeID(id))
	}
	return s.store.GetNodeByStableID(ref)
}

// handleAPIMachine implements GET /api/v1/machines/{ref}.
func (s *Server) handleAPIMachine(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireScope(w, r, identity.ScopeRead); !ok {
		return
	}

	node, ok := s.lookupAPINode(chi.URLParam(r, "ref"))
	if !ok {
		writeAPIError(w, http.StatusNotFound, "machine not found")
		return
	}
	writeJSON(w, http.StatusOK, s.apiMachineView(node))
}

// handleAPIDeleteMachine implements DELETE /api/v1/machines/{ref}: the node
// logs out.
func (s *Server) handleAPIDeleteMachine(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireScope(w, r, identity.ScopeWrite)
	if !ok {
		return
	}

	node, ok := s.lookupAPINode(chi.URLParam(r, "ref"))
	if !ok {
		writeAPIError(w, http.StatusNotFound, "machine not found")
		return
	}
	if err := s.store.DeleteNode(node.ID); err != nil {
		s.log.Error("deleting machine", "node", int(node.ID), "err", err)
		writeAPIError(w, http.StatusInternalServerError, "could not delete machine")
		return
	}

	s.audit(principal.actor(), identity.AuditNodeDeleted, nodeTarget(node), "deleted through the platform API")
	s.notifyNodePeers(node)
	writeJSON(w, http.StatusOK, map[string]any{"deleted": node.StableID})
}

// handleAPIMachineRoutes implements POST /api/v1/machines/{ref}/routes.
func (s *Server) handleAPIMachineRoutes(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireScope(w, r, identity.ScopeWrite)
	if !ok {
		return
	}

	node, ok := s.lookupAPINode(chi.URLParam(r, "ref"))
	if !ok {
		writeAPIError(w, http.StatusNotFound, "machine not found")
		return
	}

	var body struct {
		Approve   []string `json:"approve"`
		Unapprove []string `json:"unapprove"`
	}
	if !decodeAPIBody(w, r, &body) {
		return
	}

	approve, err := parsePrefixes(body.Approve)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, err.Error())
		return
	}
	unapprove, err := parsePrefixes(body.Unapprove)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, err.Error())
		return
	}

	before := node.ApprovedRoutes
	after := state.ApplyRouteApproval(before, approve, unapprove)
	if pending, _ := state.RouteDelta(before, after); len(pending) > 0 {
		if err := s.assertRouteApprovalAllowed(after); err != nil {
			writeAPIError(w, http.StatusForbidden, err.Error())
			return
		}
	}
	added, removed := state.RouteDelta(before, after)
	if len(added) == 0 && len(removed) == 0 {
		writeJSON(w, http.StatusOK, s.apiMachineView(node))
		return
	}

	if err := s.store.SetNodeApprovedRoutes(node.ID, after); err != nil {
		s.log.Error("setting approved routes", "node", int(node.ID), "err", err)
		writeAPIError(w, http.StatusInternalServerError, "could not update routes")
		return
	}
	if err := s.store.BumpConfigRevision(); err != nil {
		s.log.Error("bumping config revision", "err", err)
	}
	for _, p := range added {
		s.audit(principal.actor(), identity.AuditRouteApproved, nodeTarget(node), p.String())
	}
	for _, p := range removed {
		s.audit(principal.actor(), identity.AuditRouteUnapproved, nodeTarget(node), p.String())
	}
	s.notifyWatchers()

	updated, _ := s.store.GetNodeByID(node.ID)
	writeJSON(w, http.StatusOK, s.apiMachineView(updated))
}

// parsePrefixes parses a list of CIDR strings.
func parsePrefixes(raw []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(raw))
	for _, s := range raw {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, fmt.Errorf("invalid route %q", s)
		}
		out = append(out, p)
	}
	return out, nil
}

// handleAPIRoutes implements GET /api/v1/routes.
func (s *Server) handleAPIRoutes(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireScope(w, r, identity.ScopeRead); !ok {
		return
	}

	type routeView struct {
		Machine   string `json:"machine"`
		MachineID uint64 `json:"machineId"`
		Route     string `json:"route"`
		Approved  bool   `json:"approved"`
		Primary   bool   `json:"primary"`
		ExitNode  bool   `json:"exitNode"`
	}

	// Primary holders are the nodes whose effective route wins: the smallest
	// node ID announcing each prefix, matching the mapper's election.
	primary := map[string]uint64{}
	for _, n := range s.store.ListNodes() {
		for _, p := range n.EffectiveRoutes() {
			key := p.String()
			if id, ok := primary[key]; !ok || uint64(n.ID) < id {
				primary[key] = uint64(n.ID)
			}
		}
	}

	var out []routeView
	for _, n := range s.store.ListNodes() {
		announced := map[string]bool{}
		for _, p := range n.AnnouncedRoutes() {
			announced[p.String()] = true
		}
		for _, p := range n.EffectiveRoutes() {
			out = append(out, routeView{
				Machine:   n.Hostname,
				MachineID: uint64(n.ID),
				Route:     p.String(),
				Approved:  true,
				Primary:   primary[p.String()] == uint64(n.ID),
				ExitNode:  state.IsExitRoute(p),
			})
		}
		for _, p := range n.ApprovedRoutes {
			if !announced[p.String()] {
				out = append(out, routeView{
					Machine:   n.Hostname,
					MachineID: uint64(n.ID),
					Route:     p.String(),
					Approved:  true,
					ExitNode:  state.IsExitRoute(p),
				})
			}
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"routes": out})
}

// apiUser is the JSON shape of a user.
type apiUser struct {
	ID          uint64                `json:"id"`
	LoginName   string                `json:"loginName"`
	DisplayName string                `json:"displayName"`
	Email       string                `json:"email,omitempty"`
	Role        string                `json:"role"`
	CreatedAt   time.Time             `json:"createdAt"`
	Identities  []apiExternalIdentity `json:"identities"`
}

type apiExternalIdentity struct {
	ProviderID  string `json:"providerId"`
	Subject     string `json:"subject"`
	Email       string `json:"email,omitempty"`
	DisplayName string `json:"displayName,omitempty"`
}

func (s *Server) apiUserView(u identity.User) apiUser {
	role := u.Role
	if !role.Valid() {
		role = identity.RoleMember
	}
	view := apiUser{
		ID:          uint64(u.ID),
		LoginName:   u.LoginName,
		DisplayName: u.DisplayName,
		Email:       u.Email,
		Role:        role.String(),
		CreatedAt:   u.CreatedAt,
		Identities:  []apiExternalIdentity{},
	}
	for _, link := range s.identity.ListExternalIdentities(u.ID) {
		view.Identities = append(view.Identities, apiExternalIdentity{
			ProviderID:  link.ProviderID,
			Subject:     link.Subject,
			Email:       link.Email,
			DisplayName: link.DisplayName,
		})
	}
	return view
}

// handleAPIUsers implements GET /api/v1/users.
func (s *Server) handleAPIUsers(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireScope(w, r, identity.ScopeRead); !ok {
		return
	}

	users := s.identity.ListUsers()
	out := make([]apiUser, 0, len(users))
	for _, u := range users {
		out = append(out, s.apiUserView(u))
	}
	writeJSON(w, http.StatusOK, map[string]any{"users": out})
}

// handleAPIUser implements GET /api/v1/users/{id}.
func (s *Server) handleAPIUser(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireScope(w, r, identity.ScopeRead); !ok {
		return
	}

	user, ok := s.lookupAPIUser(chi.URLParam(r, "id"))
	if !ok {
		writeAPIError(w, http.StatusNotFound, "user not found")
		return
	}
	writeJSON(w, http.StatusOK, s.apiUserView(user))
}

func (s *Server) lookupAPIUser(ref string) (identity.User, bool) {
	if id, err := strconv.ParseUint(ref, 10, 64); err == nil {
		return s.identity.GetUser(tailcfg.UserID(id))
	}
	return s.identity.GetUserByLoginName(ref)
}

// handleAPIUpdateUser implements PATCH /api/v1/users/{id}.
func (s *Server) handleAPIUpdateUser(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireOwner(w, r)
	if !ok {
		return
	}

	user, ok := s.lookupAPIUser(chi.URLParam(r, "id"))
	if !ok {
		writeAPIError(w, http.StatusNotFound, "user not found")
		return
	}

	var body struct {
		LoginName   *string `json:"loginName"`
		DisplayName *string `json:"displayName"`
		Email       *string `json:"email"`
		Role        *string `json:"role"`
	}
	if !decodeAPIBody(w, r, &body) {
		return
	}

	if body.Role != nil && !principal.Role.IsOwner() {
		writeAPIError(w, http.StatusForbidden, "owner role required to change roles")
		return
	}

	var changed []string
	if body.LoginName != nil && *body.LoginName != user.LoginName {
		if *body.LoginName == "" {
			writeAPIError(w, http.StatusBadRequest, "loginName cannot be empty")
			return
		}
		user.LoginName = *body.LoginName
		changed = append(changed, "login_name")
	}
	if body.DisplayName != nil && *body.DisplayName != user.DisplayName {
		user.DisplayName = *body.DisplayName
		changed = append(changed, "display_name")
	}
	if body.Email != nil && *body.Email != user.Email {
		user.Email = *body.Email
		changed = append(changed, "email")
	}
	roleChanged := false
	if body.Role != nil {
		role, err := identity.ParseRole(*body.Role)
		if err != nil {
			writeAPIError(w, http.StatusBadRequest, err.Error())
			return
		}
		if role != user.Role {
			if user.Role.IsOwner() && role != identity.RoleOwner && !s.otherOwnerExists(user.ID) {
				writeAPIError(w, http.StatusConflict, "cannot demote the last owner")
				return
			}
			user.Role = role
			roleChanged = true
			changed = append(changed, "role")
		}
	}
	if len(changed) == 0 {
		writeJSON(w, http.StatusOK, s.apiUserView(user))
		return
	}

	if err := s.identity.UpdateUser(user); err != nil {
		switch {
		case errors.Is(err, identity.ErrLoginNameTaken):
			writeAPIError(w, http.StatusConflict, "login name already in use")
		case errors.Is(err, identity.ErrUserNotFound):
			writeAPIError(w, http.StatusNotFound, "user not found")
		default:
			s.log.Error("updating user", "user", int(user.ID), "err", err)
			writeAPIError(w, http.StatusInternalServerError, "could not update user")
		}
		return
	}

	action := identity.AuditUserUpdated
	if roleChanged {
		action = identity.AuditUserRoleChanged
	}
	s.audit(principal.actor(), action, fmt.Sprintf("user:%d", user.ID),
		"updated "+strings.Join(changed, ", "))
	writeJSON(w, http.StatusOK, s.apiUserView(user))
}

// handleAPIDNS implements GET /api/v1/dns.
func (s *Server) handleAPIDNS(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireScope(w, r, identity.ScopeRead); !ok {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"records": s.store.ListDNSRecords()})
}

// handleAPIDeleteDNS implements DELETE /api/v1/dns/{id}.
func (s *Server) handleAPIDeleteDNS(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireScope(w, r, identity.ScopeWrite)
	if !ok {
		return
	}

	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid record ID")
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
		writeAPIError(w, http.StatusNotFound, "record not found")
		return
	}

	if err := s.store.DeleteDNSRecord(id); err != nil {
		s.log.Error("deleting DNS record", "record", id, "err", err)
		writeAPIError(w, http.StatusInternalServerError, "could not delete record")
		return
	}
	if err := s.store.BumpConfigRevision(); err != nil {
		s.log.Error("bumping config revision", "err", err)
	}
	s.audit(principal.actor(), identity.AuditDNSRecordDeleted,
		fmt.Sprintf("dns:%s/%s", record.Name, record.Type), fmt.Sprintf("deleted record %d", record.ID))
	s.notifyWatchers()
	writeJSON(w, http.StatusOK, map[string]any{"deleted": id})
}

// handleAPIPolicy implements GET /api/v1/policy.
func (s *Server) handleAPIPolicy(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireScope(w, r, identity.ScopeRead); !ok {
		return
	}

	engine := s.policy.Load()
	if engine == nil {
		writeJSON(w, http.StatusOK, map[string]any{"configured": false})
		return
	}

	resp := map[string]any{
		"configured": true,
		"path":       s.cfg.PolicyPath,
		"rules":      engine.RuleCount(),
		"warnings":   engine.Warnings(),
	}
	if doc, err := policy.Load(s.cfg.PolicyPath); err == nil {
		resp["unsupported"] = doc.Unsupported
	} else {
		resp["loadError"] = err.Error()
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleAPIAuthKeys implements GET /api/v1/auth-keys.
//
// Secrets are never listed: a pre-auth key is shown exactly once, when it is
// created.
func (s *Server) handleAPIAuthKeys(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireScope(w, r, identity.ScopeRead); !ok {
		return
	}

	type authKeyView struct {
		ID        uint64     `json:"id"`
		UserID    uint64     `json:"userId"`
		Reusable  bool       `json:"reusable"`
		Ephemeral bool       `json:"ephemeral"`
		Used      bool       `json:"used"`
		Tags      []string   `json:"tags,omitempty"`
		Expiry    *time.Time `json:"expiry,omitempty"`
		Created   time.Time  `json:"created"`
		UsedAt    *time.Time `json:"usedAt,omitempty"`
	}

	keys := s.store.ListPreAuthKeys()
	out := make([]authKeyView, 0, len(keys))
	for _, k := range keys {
		view := authKeyView{
			ID: k.ID, UserID: uint64(k.UserID), Reusable: k.Reusable,
			Ephemeral: k.Ephemeral, Used: k.Used, Created: k.Created, UsedAt: k.UsedAt,
			Tags: k.Tags,
		}
		if !k.Expiry.IsZero() {
			expiry := k.Expiry
			view.Expiry = &expiry
		}
		out = append(out, view)
	}
	writeJSON(w, http.StatusOK, map[string]any{"authKeys": out})
}

// handleAPICreateAuthKey implements POST /api/v1/auth-keys.
func (s *Server) handleAPICreateAuthKey(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireScope(w, r, identity.ScopeWrite)
	if !ok {
		return
	}

	var body struct {
		UserID    uint64   `json:"userId"`
		Reusable  bool     `json:"reusable"`
		Ephemeral bool     `json:"ephemeral"`
		TTL       string   `json:"ttl"`
		Tags      []string `json:"tags"`
	}
	if !decodeAPIBody(w, r, &body) {
		return
	}

	userID := tailcfg.UserID(body.UserID)
	if userID == 0 {
		userID = principal.UserID
	}
	if _, ok := s.identity.GetUser(userID); !ok {
		writeAPIError(w, http.StatusBadRequest, "unknown user")
		return
	}

	secret, err := state.NewPreAuthKeySecret()
	if err != nil {
		s.log.Error("generating pre-auth key", "err", err)
		writeAPIError(w, http.StatusInternalServerError, "could not create key")
		return
	}

	tags, err := s.validateKeyTags(body.Tags)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, err.Error())
		return
	}

	key := state.PreAuthKey{
		Key:       secret,
		UserID:    userID,
		Reusable:  body.Reusable,
		Ephemeral: body.Ephemeral,
		Tags:      tags,
	}
	if body.TTL != "" {
		ttl, err := time.ParseDuration(body.TTL)
		if err != nil || ttl <= 0 {
			writeAPIError(w, http.StatusBadRequest, "invalid ttl")
			return
		}
		key.Expiry = time.Now().Add(ttl).UTC()
	}
	if err := s.store.CreatePreAuthKey(&key); err != nil {
		s.log.Error("storing pre-auth key", "err", err)
		writeAPIError(w, http.StatusInternalServerError, "could not create key")
		return
	}

	s.audit(principal.actor(), identity.AuditPreAuthKeyCreated,
		fmt.Sprintf("preauthkey:%d", key.ID), "created through the platform API")

	// The secret is returned exactly once.
	writeJSON(w, http.StatusCreated, map[string]any{
		"id":        key.ID,
		"key":       key.Key,
		"userId":    uint64(key.UserID),
		"reusable":  key.Reusable,
		"ephemeral": key.Ephemeral,
		"tags":      key.Tags,
		"expiry":    key.Expiry,
	})
}

// handleAPIDeleteAuthKey implements DELETE /api/v1/auth-keys/{id}.
func (s *Server) handleAPIDeleteAuthKey(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireScope(w, r, identity.ScopeWrite)
	if !ok {
		return
	}

	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid key ID")
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
		writeAPIError(w, http.StatusNotFound, "key not found")
		return
	}

	if err := s.store.DeletePreAuthKey(secret); err != nil {
		s.log.Error("deleting pre-auth key", "key", id, "err", err)
		writeAPIError(w, http.StatusInternalServerError, "could not delete key")
		return
	}
	s.audit(principal.actor(), identity.AuditPreAuthKeyDeleted,
		fmt.Sprintf("preauthkey:%d", id), "deleted through the platform API")
	writeJSON(w, http.StatusOK, map[string]any{"deleted": id})
}

// handleAPIDevices implements GET /api/v1/devices.
func (s *Server) handleAPIDevices(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireScope(w, r, identity.ScopeRead); !ok {
		return
	}

	pending := s.identity.ListPendingDeviceAuthorizations(time.Now())
	out := make([]map[string]any, 0, len(pending))
	for _, da := range pending {
		meta := decodeDeviceMetadata(da.ClientMetadata)
		out = append(out, map[string]any{
			"id":         da.ID,
			"hostname":   meta.Hostname,
			"os":         meta.OS,
			"machineKey": da.MachineKey,
			"nodeKey":    da.NodeKey,
			"created":    da.CreatedAt,
			"expires":    da.ExpiresAt,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"devices": out})
}

// handleAPIApproveDevice implements POST /api/v1/devices/{id}/approve.
func (s *Server) handleAPIApproveDevice(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireScope(w, r, identity.ScopeWrite)
	if !ok {
		return
	}
	s.apiDecideDevice(w, r, principal, true)
}

// handleAPIDenyDevice implements POST /api/v1/devices/{id}/deny.
func (s *Server) handleAPIDenyDevice(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireScope(w, r, identity.ScopeWrite)
	if !ok {
		return
	}
	s.apiDecideDevice(w, r, principal, false)
}

// handleAPIAudit implements GET /api/v1/audit.
func (s *Server) handleAPIAudit(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireScope(w, r, identity.ScopeRead); !ok {
		return
	}

	limit := 100
	if raw := r.URL.Query().Get("limit"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 0 {
			writeAPIError(w, http.StatusBadRequest, "invalid limit")
			return
		}
		if parsed > 1000 {
			parsed = 1000
		}
		limit = parsed
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": s.identity.ListAudit(limit)})
}

// handleAPIKeys implements GET /api/v1/api-keys.
func (s *Server) handleAPIKeys(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireScope(w, r, identity.ScopeRead); !ok {
		return
	}

	type keyView struct {
		ID         string     `json:"id"`
		Name       string     `json:"name"`
		UserID     uint64     `json:"userId"`
		Scopes     []string   `json:"scopes"`
		CreatedAt  time.Time  `json:"createdAt"`
		ExpiresAt  *time.Time `json:"expiresAt,omitempty"`
		LastUsedAt *time.Time `json:"lastUsedAt,omitempty"`
		RevokedAt  *time.Time `json:"revokedAt,omitempty"`
	}

	keys := s.identity.ListAPIKeys()
	out := make([]keyView, 0, len(keys))
	for _, k := range keys {
		view := keyView{
			ID: k.ID, Name: k.Name, UserID: uint64(k.UserID), Scopes: k.Scopes, CreatedAt: k.CreatedAt,
		}
		if !k.ExpiresAt.IsZero() {
			t := k.ExpiresAt
			view.ExpiresAt = &t
		}
		if !k.LastUsedAt.IsZero() {
			t := k.LastUsedAt
			view.LastUsedAt = &t
		}
		if !k.RevokedAt.IsZero() {
			t := k.RevokedAt
			view.RevokedAt = &t
		}
		out = append(out, view)
	}
	writeJSON(w, http.StatusOK, map[string]any{"apiKeys": out})
}

// handleAPICreateAPIKey implements POST /api/v1/api-keys.
func (s *Server) handleAPICreateAPIKey(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireScope(w, r, identity.ScopeWrite)
	if !ok {
		return
	}

	var body struct {
		Name   string   `json:"name"`
		Scopes []string `json:"scopes"`
		TTL    string   `json:"ttl"`
	}
	if !decodeAPIBody(w, r, &body) {
		return
	}

	opts := identity.NewAPIKeyOptions{
		Name:   body.Name,
		UserID: principal.UserID,
		Scopes: body.Scopes,
	}
	if len(opts.Scopes) == 0 {
		opts.Scopes = []string{identity.ScopeRead}
	}
	if body.TTL != "" {
		ttl, err := time.ParseDuration(body.TTL)
		if err != nil || ttl <= 0 {
			writeAPIError(w, http.StatusBadRequest, "invalid ttl")
			return
		}
		opts.TTL = ttl
	}

	if err := s.assertAPIAllowed(); err != nil {
		writeAPIError(w, http.StatusForbidden, err.Error())
		return
	}
	key, token, err := s.identity.CreateAPIKey(opts)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, err.Error())
		return
	}

	s.audit(principal.actor(), identity.AuditAPIKeyCreated, "apikey:"+key.ID, "created "+key.Name)

	// The token is returned exactly once.
	writeJSON(w, http.StatusCreated, map[string]any{
		"id": key.ID, "name": key.Name, "userId": uint64(key.UserID),
		"scopes": key.Scopes, "createdAt": key.CreatedAt, "expiresAt": key.ExpiresAt,
		"token": token,
	})
}

// handleAPIRevokeAPIKey implements DELETE /api/v1/api-keys/{id}. A principal
// may always revoke its own keys; revoking someone else's needs a role that
// may write.
func (s *Server) handleAPIRevokeAPIKey(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireSelfScope(w, r, identity.ScopeWrite)
	if !ok {
		return
	}

	id := chi.URLParam(r, "id")
	key, ok := s.identity.GetAPIKeyByID(id)
	if !ok {
		writeAPIError(w, http.StatusNotFound, "key not found")
		return
	}
	if key.UserID != principal.UserID && !principal.Role.CanWrite() {
		writeAPIError(w, http.StatusForbidden, "cannot revoke another user's key")
		return
	}
	if err := s.identity.RevokeAPIKey(id); err != nil {
		s.log.Error("revoking API key", "key", id, "err", err)
		writeAPIError(w, http.StatusInternalServerError, "could not revoke key")
		return
	}
	s.audit(principal.actor(), identity.AuditAPIKeyRevoked, "apikey:"+id, "revoked")
	writeJSON(w, http.StatusOK, map[string]any{"revoked": id})
}

// handleAPISessions implements GET /api/v1/sessions: the caller's own browser
// sessions.
func (s *Server) handleAPISessions(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireScope(w, r, identity.ScopeRead)
	if !ok {
		return
	}
	sessions := s.identity.ListSessions(principal.UserID)
	if sessions == nil {
		sessions = []identity.Session{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"sessions": sessions})
}

// handleAPIRevokeSession implements DELETE /api/v1/sessions/{id}. Users may
// always sign themselves out, whatever their role.
func (s *Server) handleAPIRevokeSession(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireSelfScope(w, r, identity.ScopeWrite)
	if !ok {
		return
	}

	id := chi.URLParam(r, "id")
	session, ok := s.identity.GetSessionByID(id)
	if !ok || session.UserID != principal.UserID {
		writeAPIError(w, http.StatusNotFound, "session not found")
		return
	}
	if err := s.identity.RevokeSession(id, "revoked through the platform API"); err != nil {
		s.log.Error("revoking session", "session", id, "err", err)
		writeAPIError(w, http.StatusInternalServerError, "could not revoke session")
		return
	}
	s.audit(principal.actor(), identity.AuditSessionRevoked, "session:"+id, "revoked through the platform API")
	writeJSON(w, http.StatusOK, map[string]any{"revoked": id})
}
