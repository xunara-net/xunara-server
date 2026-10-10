package control

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"tailscale.com/tailcfg"

	"github.com/xunara-net/xunara-server/identity"
	"github.com/xunara-net/xunara-server/state"
)

// This file implements /api/v2, the cursor-paginated platform API.
//
// v1 stays as it is for existing clients: every response shape there is
// stable. v2 adds three things v1 cannot express without a breaking change:
//
//   - bounded, cursor-paginated list endpoints (machines, audit,
//     agent-tokens), so a large tailnet cannot make an API client allocate an
//     unbounded response;
//   - server capability discovery (GET /api/v2/meta), so a client can learn
//     which optional features this build has before calling them;
//   - administration of native-client (Xunara Agent) credentials.
//
// Authentication is the same principal model as v1 (AGENTS.md section 5: a
// node is never a principal), and cursors are opaque: callers round-trip them
// and never construct one.

// apiV2MaxPageSize bounds every v2 list response.
const apiV2MaxPageSize = 500

// apiV2AuditScanMax bounds how many audit rows one page scans while filtering,
// so a filter that matches nothing cannot turn a request into a full-table
// walk.
const apiV2AuditScanMax = 10_000

// apiV2Router builds /api/v2.
func (s *Server) apiV2Router() http.Handler {
	r := chi.NewRouter()
	r.Use(apiV2QueryGuard)

	r.Get("/meta", s.handleAPIV2Meta)
	r.Get("/organization", s.handleAPIV2Organization)
	r.Get("/network/addresses", s.handleAPIAddressConfiguration)
	r.Post("/network/addresses/validate", s.handleAPISaveAddressConfiguration)
	r.Put("/network/addresses", s.handleAPISaveAddressConfiguration)
	r.Put("/machines/{ref}/ipv4", s.handleAPIChangeNodeIPv4)
	r.Get("/tka", s.handleAPIV2TKA)
	r.Get("/derp", s.handleAPIV2DERP)
	r.Get("/derp/configuration", s.handleAPIExternalDERPConfiguration)
	r.Put("/derp/configuration", s.handleAPISaveExternalDERP)
	r.Get("/derp/history", s.handleAPIExternalDERPHistory)
	r.Post("/derp/import-official", s.handleAPIImportOfficialDERP)
	r.Get("/policy", s.handleAPIV2Policy)
	r.Get("/policy/configuration", s.handleAPIV2PolicyConfiguration)
	r.Post("/policy/validate", s.handleAPIV2ValidatePolicy)
	r.Put("/policy/configuration", s.handleAPIV2PublishPolicy)
	r.Get("/policy/history", s.handleAPIV2PolicyHistory)
	r.Post("/policy/simulate", s.handleAPIV2SimulatePolicy)
	r.Post("/policy/matrix", s.handleAPIV2PolicyMatrix)
	r.Get("/dns/configuration", s.handleAPIV2DNSConfiguration)
	r.Put("/dns/configuration", s.handleAPIV2SaveDNSConfiguration)
	r.Get("/dns/records", s.handleAPIV2DNSRecords)
	r.Post("/dns/records", s.handleAPIV2SaveDNSRecord)
	r.Put("/dns/records/{id}", s.handleAPIV2SaveDNSRecord)
	r.Delete("/dns/records/{id}", s.handleAPIV2DeleteDNSRecord)
	r.Get("/security", s.handleAPIV2Security)
	r.Get("/exit-nodes", s.handleAPIV2ExitNodes)
	r.Get("/relays", s.handleAPIV2Relays)

	// Enrolled relays and their one-time enrollment tokens. The read-only
	// /relays view above reports the served DERP map; these manage the relays
	// this organization enrolled.
	r.Get("/relays/enrolled", s.handleAPIV2RelaysEnrolled)
	r.Get("/relays/enroll-tokens", s.handleAPIV2RelayEnrollTokens)
	r.Post("/relays/enroll-tokens", s.handleAPIV2CreateRelayEnrollToken)
	r.Delete("/relays/enroll-tokens/{id}", s.handleAPIV2DeleteRelayEnrollToken)
	r.Get("/relays/{id}", s.handleAPIV2Relay)
	r.Get("/relays/{id}/history", s.handleAPIV2RelayHistory)
	r.Patch("/relays/{id}", s.handleAPIV2UpdateRelay)
	r.Delete("/relays/{id}", s.handleAPIV2DeleteRelay)
	r.Get("/serve", s.handleAPIV2Serve)
	r.Get("/devices", s.handleAPIV2Devices)
	r.Post("/devices/{id}/approve", s.handleAPIV2ApproveDevice)
	r.Post("/devices/{id}/deny", s.handleAPIV2DenyDevice)
	r.Get("/ssh-check/sessions", s.handleAPIV2SSHCheckSessions)
	r.Get("/id-token", s.handleAPIV2IDToken)

	r.Get("/machines", s.handleAPIV2Machines)
	r.Get("/machines/{id}/device-attrs", s.handleAPIV2MachineDeviceAttrs)
	r.Get("/services", s.handleAPIV2Services)
	r.Get("/flux/transfers", s.handleAPIV2FluxTransfers)
	r.Get("/flux/transfers/{id}", s.handleAPIV2FluxTransfer)
	r.Get("/audit", s.handleAPIV2Audit)

	r.Get("/reach/sessions", s.handleAPIV2ReachSessions)
	r.Get("/reach/sessions/{id}", s.handleAPIV2ReachSession)
	r.Get("/reach/sessions/{id}/chunks", s.handleAPIV2ReachChunks)

	r.Get("/agent-tokens", s.handleAPIV2AgentTokens)
	r.Delete("/agent-tokens/{id}", s.handleAPIV2RevokeAgentToken)

	r.Get("/webhooks", s.handleAPIV2Webhooks)
	r.Post("/webhooks", s.handleAPIV2CreateWebhook)
	r.Delete("/webhooks/{id}", s.handleAPIV2DeleteWebhook)

	r.Get("/shares", s.handleAPIV2Shares)
	r.Post("/shares", s.handleAPIV2CreateShare)
	r.Get("/shares/{id}", s.handleAPIV2Share)
	r.Post("/shares/{id}/accept", s.handleAPIV2AcceptShare)
	r.Post("/shares/{id}/reject", s.handleAPIV2RejectShare)
	r.Delete("/shares/{id}", s.handleAPIV2RevokeShare)

	return r
}

// apiV2QueryGuard rejects a request whose raw query string does not parse.
// net/url's Query() drops malformed pairs silently, which would let a typo
// turn into an ignored filter (or an ignored cursor); failing closed is
// cheaper to debug and never serves a request the client did not make.
func apiV2QueryGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := url.ParseQuery(r.URL.RawQuery); err != nil {
			writeAPIError(w, http.StatusBadRequest, "invalid query string")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// apiV2EncodeCursor packs a page position into an opaque token.
func apiV2EncodeCursor(parts ...string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(strings.Join(parts, "\x1f")))
}

// apiV2DecodeCursor unpacks a cursor, returning its kind and fields. An empty
// cursor decodes to an empty kind, which callers read as "from the start".
func apiV2DecodeCursor(raw string) (kind string, parts []string, ok bool) {
	if raw == "" {
		return "", nil, true
	}
	if len(raw) > 256 {
		return "", nil, false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return "", nil, false
	}
	fields := strings.Split(string(decoded), "\x1f")
	return fields[0], fields[1:], true
}

// apiV2CursorUint reads a single-number cursor of the given kind.
func apiV2CursorUint(w http.ResponseWriter, r *http.Request, kind string) (uint64, bool) {
	cursorKind, parts, ok := apiV2DecodeCursor(r.URL.Query().Get("cursor"))
	if !ok || (cursorKind != "" && cursorKind != kind) || len(parts) > 1 {
		writeAPIError(w, http.StatusBadRequest, "invalid cursor")
		return 0, false
	}
	if cursorKind == "" {
		return 0, true
	}
	id, err := strconv.ParseUint(parts[0], 10, 64)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid cursor")
		return 0, false
	}
	return id, true
}

// apiV2CursorString reads a single-string cursor of the given kind.
func apiV2CursorString(w http.ResponseWriter, r *http.Request, kind string) (string, bool) {
	cursorKind, parts, ok := apiV2DecodeCursor(r.URL.Query().Get("cursor"))
	if !ok || (cursorKind != "" && cursorKind != kind) || len(parts) > 1 {
		writeAPIError(w, http.StatusBadRequest, "invalid cursor")
		return "", false
	}
	if cursorKind == "" {
		return "", true
	}
	return parts[0], true
}

// apiV2EncodeTimeCursor packs a list position: an item's creation time and
// ID, so the next page resumes exactly after it.
func apiV2EncodeTimeCursor(kind string, created time.Time, id string) string {
	return apiV2EncodeCursor(kind, strconv.FormatInt(created.UnixNano(), 10), id)
}

// apiV2TimeCursor decodes a newest-first list cursor; an empty cursor means
// "from the top".
func apiV2TimeCursor(w http.ResponseWriter, r *http.Request, kind string) (time.Time, string, bool) {
	cursorKind, parts, ok := apiV2DecodeCursor(r.URL.Query().Get("cursor"))
	if !ok || (cursorKind != "" && (cursorKind != kind || len(parts) != 2)) {
		writeAPIError(w, http.StatusBadRequest, "invalid cursor")
		return time.Time{}, "", false
	}
	if cursorKind == "" {
		return time.Time{}, "", true
	}
	nanos, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid cursor")
		return time.Time{}, "", false
	}
	return time.Unix(0, nanos).UTC(), parts[1], true
}

// newestFirstAfterCursor reports whether (created, id) comes after the cursor
// position in the newest-first order (createdAt descending, ID ascending).
// The zero cursor matches everything.
func newestFirstAfterCursor(created time.Time, id string, afterCreated time.Time, afterID string) bool {
	if afterID == "" {
		return true
	}
	switch {
	case created.Before(afterCreated):
		return true
	case created.After(afterCreated):
		return false
	default:
		return id > afterID
	}
}

// apiV2NodeFilter parses a node=<id|stable ID> listing filter, shared by the
// Reach, Flux and SSH check management surfaces. An unknown node - including
// "0", which is not a node ID - matches nothing rather than being ignored,
// because a filter that silently widens its result is a security bug.
func (s *Server) apiV2NodeFilter(raw string) state.NodeID {
	if raw == "" {
		return 0
	}
	if id, err := strconv.ParseUint(raw, 10, 64); err == nil && id > 0 {
		return state.NodeID(id)
	}
	if node, ok := s.store.GetNodeByStableID(raw); ok {
		return node.ID
	}
	return ^state.NodeID(0)
}

// apiV2Limit parses ?limit=, bounded and defaulted.
func apiV2Limit(w http.ResponseWriter, r *http.Request, def int) (int, bool) {
	raw := r.URL.Query().Get("limit")
	if raw == "" {
		return def, true
	}
	parsed, err := strconv.Atoi(raw)
	if err != nil || parsed < 1 {
		writeAPIError(w, http.StatusBadRequest, "invalid limit")
		return 0, false
	}
	if parsed > apiV2MaxPageSize {
		parsed = apiV2MaxPageSize
	}
	return parsed, true
}

// handleAPIV2Meta implements GET /api/v2/meta: what this server is and which
// optional features are configured. It never exposes secrets or key material.
func (s *Server) handleAPIV2Meta(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireScope(w, r, identity.ScopeRead); !ok {
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"version":               Version,
		"serverUrl":             s.cfg.ServerURL,
		"domain":                s.cfg.Domain,
		"capabilityVersion":     uint64(tailcfg.CurrentCapabilityVersion),
		"minCapabilityVersion":  uint64(MinSupportedCapabilityVersion),
		"maxPageSize":           apiV2MaxPageSize,
		"identityProviders":     s.providers.IDs(),
		"agentProtocolVersion":  agentProtocolVersion,
		"webhooksEnabled":       s.webhooksEnabled(),
		"dnsProviderConfigured": s.cfg.DNSProvider != nil,
		"certDomains":           s.certDomains,
		"derpMapConfigured":     s.DERPMap() != nil,
		"derpPolicy":            string(s.cfg.DERPPolicy.Mode),
		"derpRegionsServed":     s.derpRegionsServed(),
		"identityTokensEnabled": s.tokens != nil,
		"reachEnabled":          s.cfg.ReachEnabled,
		"fluxEnabled":           s.flux != nil,
		"passkeysEnabled":       s.passkeys != nil,
		"sharingEnabled":        s.sharingEnabled(),
	})
}

// webhooksEnabled reports whether any receiver would receive deliveries:
// an endpoint from the deployment configuration, or an enabled managed
// endpoint (Console/API). A paused managed endpoint is configured but does
// not deliver, so it does not count (spec 37.1).
func (s *Server) webhooksEnabled() bool {
	if len(s.cfg.Webhooks) > 0 {
		return true
	}
	for _, managed := range s.identity.ListWebhookEndpoints() {
		if managed.Enabled {
			return true
		}
	}
	return false
}

// derpRegionsServed counts the DERP regions this organization advertises.
func (s *Server) derpRegionsServed() int {
	derpMap := s.DERPMap()
	if derpMap == nil {
		return 0
	}
	served := 0
	for _, region := range derpMap.Regions {
		if region != nil {
			served++
		}
	}
	return served
}

// handleAPIV2TKA implements GET /api/v2/tka: the read-only tailnet-lock
// status (flags, chain head, signed/unsigned node counts).
//
// The AUM chain contents and the sealed support disablement secret stay out of
// the response; the head hash and per-node signature presence are public, and
// clients already receive them in the netmap.
func (s *Server) handleAPIV2TKA(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireScope(w, r, identity.ScopeRead); !ok {
		return
	}
	writeJSON(w, http.StatusOK, s.TKAStatus())
}

// handleAPIV2IDToken implements GET /api/v2/id-token: the read-only state of
// the OIDC identity-token issuer (issuer URL, JWKS location, signing keys and
// which one is active). Only public key material is reported.
func (s *Server) handleAPIV2IDToken(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireScope(w, r, identity.ScopeRead); !ok {
		return
	}

	status, err := s.IDTokenStatus()
	if err != nil {
		// The error names the state-directory file that needs attention; it is
		// for the operator reading the log, not for the API client.
		s.log.Error("reading the identity-token issuer state", "err", err)
		writeAPIError(w, http.StatusInternalServerError, "identity-token issuer state is unavailable")
		return
	}
	writeJSON(w, http.StatusOK, status)
}

// handleAPIV2Machines implements GET /api/v2/machines.
//
// Filters: state=online|offline, user=<id|login>, tag=<tag:<name>>. Results
// are ordered by node ID and paged with nextCursor.
func (s *Server) handleAPIV2Machines(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireScope(w, r, identity.ScopeRead); !ok {
		return
	}

	limit, ok := apiV2Limit(w, r, 50)
	if !ok {
		return
	}
	after, ok := apiV2CursorUint(w, r, "machines")
	if !ok {
		return
	}

	query := r.URL.Query()
	stateFilter := query.Get("state")
	switch stateFilter {
	case "", "online", "offline":
	default:
		writeAPIError(w, http.StatusBadRequest, "invalid state filter")
		return
	}

	// An unknown user matches nothing instead of being ignored: silently
	// returning every machine would mislead a filter.
	var userFilter uint64
	if raw := query.Get("user"); raw != "" {
		if id, err := strconv.ParseUint(raw, 10, 64); err == nil && id > 0 {
			userFilter = id
		} else if user, ok := s.identity.GetUserByLoginName(raw); ok {
			userFilter = uint64(user.ID)
		} else {
			userFilter = ^uint64(0)
		}
	}
	tagFilter := query.Get("tag")

	nodes := s.store.ListNodes()
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].ID < nodes[j].ID })

	items := make([]apiMachine, 0, limit)
	counts := s.deviceAttrCounts()
	serviceCounts := s.serviceCounts()
	var last uint64
	next := ""
	for _, n := range nodes {
		id := uint64(n.ID)
		if id <= after {
			continue
		}
		if userFilter != 0 && uint64(n.UserID) != userFilter {
			continue
		}
		if tagFilter != "" && !slices.Contains(n.Tags, tagFilter) {
			continue
		}
		online := s.isOnline(n.ID)
		if stateFilter == "online" && !online {
			continue
		}
		if stateFilter == "offline" && online {
			continue
		}
		if len(items) == limit {
			next = apiV2EncodeCursor("machines", strconv.FormatUint(last, 10))
			break
		}
		view := s.apiMachineView(n)
		view.DeviceAttrCount = counts[n.ID]
		view.ServiceCount = serviceCounts[n.ID]
		items = append(items, view)
		last = id
	}

	writeJSON(w, http.StatusOK, map[string]any{"items": items, "nextCursor": next})
}

// handleAPIV2Services implements GET /api/v2/services: the services nodes
// advertise about themselves (Xunara Atlas), ordered by name.
//
// Filters: node=<machine id|stable id> (unknown matches nothing) and
// name=<exact name>. The cursor is the last name of the previous page.
func (s *Server) handleAPIV2Services(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireScope(w, r, identity.ScopeRead); !ok {
		return
	}
	limit, ok := apiV2Limit(w, r, 100)
	if !ok {
		return
	}
	after, ok := apiV2CursorString(w, r, "services")
	if !ok {
		return
	}

	query := r.URL.Query()
	nodeFilter := s.apiV2NodeFilter(query.Get("node"))
	nameFilter := query.Get("name")

	items := make([]serviceView, 0, limit)
	var last string
	next := ""
	for _, svc := range s.store.ListServices() {
		if after != "" && svc.Name <= after {
			continue
		}
		if nodeFilter != 0 && svc.NodeID != nodeFilter {
			continue
		}
		if nameFilter != "" && svc.Name != nameFilter {
			continue
		}
		if len(items) == limit {
			next = apiV2EncodeCursor("services", last)
			break
		}
		node, ok := s.store.GetNodeByID(svc.NodeID)
		if !ok {
			// The node was deleted; the store cascade removes its services,
			// so a stale row is only a race with the deletion.
			continue
		}
		items = append(items, s.serviceView(svc, node))
		last = svc.Name
	}

	writeJSON(w, http.StatusOK, map[string]any{"items": items, "nextCursor": next})
}

// handleAPIV2Audit implements GET /api/v2/audit, oldest first.
//
// Filters: action=<exact action>, actor=<exact actor>, target=<prefix>.
func (s *Server) handleAPIV2Audit(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireScope(w, r, identity.ScopeRead); !ok {
		return
	}

	limit, ok := apiV2Limit(w, r, 100)
	if !ok {
		return
	}
	after, ok := apiV2CursorUint(w, r, "audit")
	if !ok {
		return
	}

	query := r.URL.Query()
	actionFilter := query.Get("action")
	actorFilter := query.Get("actor")
	targetFilter := query.Get("target")

	items := make([]apiAuditEvent, 0, limit)
	scanned := 0
	for len(items) < limit && scanned < apiV2AuditScanMax {
		batch := s.identity.ListAuditAfter(after, 256)
		if len(batch) == 0 {
			break
		}
		for _, e := range batch {
			after = e.ID
			scanned++
			if actionFilter != "" && e.Action != actionFilter {
				continue
			}
			if actorFilter != "" && e.Actor != actorFilter {
				continue
			}
			if targetFilter != "" && !strings.HasPrefix(e.Target, targetFilter) {
				continue
			}
			items = append(items, apiAuditEvent{
				ID:     e.ID,
				Time:   e.Time,
				Actor:  e.Actor,
				Action: e.Action,
				Target: e.Target,
				Detail: e.Detail,
			})
			if len(items) == limit {
				break
			}
		}
		if len(batch) < 256 {
			break
		}
	}

	next := ""
	if len(items) == limit {
		next = apiV2EncodeCursor("audit", strconv.FormatUint(items[len(items)-1].ID, 10))
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "nextCursor": next})
}

// apiAuditEvent is the JSON shape of one audit event. v1 returns the store's
// struct verbatim (capitalised field names); v2 names its fields like every
// other endpoint here.
type apiAuditEvent struct {
	ID     uint64    `json:"id"`
	Time   time.Time `json:"time"`
	Actor  string    `json:"actor"`
	Action string    `json:"action"`
	Target string    `json:"target"`
	Detail string    `json:"detail,omitempty"`
}

// apiAgentTokenView is the JSON shape of a native-client credential. It never
// contains the credential itself: only its hash is stored, and it is returned
// once at enrollment.
type apiAgentTokenView struct {
	ID           string     `json:"id"`
	NodeID       int64      `json:"nodeId"`
	NodeStableID string     `json:"nodeStableId,omitempty"`
	NodeHostname string     `json:"nodeHostname,omitempty"`
	NodeOnline   bool       `json:"nodeOnline"`
	MachineKey   string     `json:"machineKey"`
	NodeKey      string     `json:"nodeKey"`
	CreatedAt    time.Time  `json:"createdAt"`
	ExpiresAt    *time.Time `json:"expiresAt,omitempty"`
	LastUsedAt   *time.Time `json:"lastUsedAt,omitempty"`
	RevokedAt    *time.Time `json:"revokedAt,omitempty"`
	Live         bool       `json:"live"`
}

func (s *Server) apiAgentTokenView(t identity.AgentToken) apiAgentTokenView {
	view := apiAgentTokenView{
		ID:         t.ID,
		NodeID:     t.NodeID,
		MachineKey: t.MachineKey,
		NodeKey:    t.NodeKey,
		CreatedAt:  t.CreatedAt,
		Live:       t.Live(time.Now()),
	}
	if node, ok := s.store.GetNodeByID(state.NodeID(t.NodeID)); ok {
		view.NodeStableID = node.StableID
		view.NodeHostname = node.Hostname
		view.NodeOnline = s.isOnline(node.ID)
	}
	if !t.ExpiresAt.IsZero() {
		expires := t.ExpiresAt
		view.ExpiresAt = &expires
	}
	if !t.LastUsedAt.IsZero() {
		used := t.LastUsedAt
		view.LastUsedAt = &used
	}
	if !t.RevokedAt.IsZero() {
		revoked := t.RevokedAt
		view.RevokedAt = &revoked
	}
	return view
}

// handleAPIV2AgentTokens implements GET /api/v2/agent-tokens, newest first.
func (s *Server) handleAPIV2AgentTokens(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireScope(w, r, identity.ScopeRead); !ok {
		return
	}

	limit, ok := apiV2Limit(w, r, 100)
	if !ok {
		return
	}

	query := r.URL.Query()
	var (
		nodeFilter    int64
		nodeFilterSet bool
	)
	if raw := query.Get("node"); raw != "" {
		parsed, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || parsed <= 0 {
			// Zero is not a node ID: it must never silently mean "every
			// credential", which is why a bad filter is refused here.
			writeAPIError(w, http.StatusBadRequest, "invalid node filter")
			return
		}
		nodeFilter, nodeFilterSet = parsed, true
	}

	// The cursor is the (createdAt, id) position of the last item of the
	// previous page. Tokens are ordered newest first, so a page continues with
	// strictly older positions.
	cursorKind, parts, ok := apiV2DecodeCursor(query.Get("cursor"))
	if !ok || (cursorKind != "" && cursorKind != "agent-tokens") || len(parts) > 2 {
		writeAPIError(w, http.StatusBadRequest, "invalid cursor")
		return
	}
	var (
		afterCreated int64
		afterID      string
	)
	if cursorKind == "agent-tokens" {
		if len(parts) != 2 {
			writeAPIError(w, http.StatusBadRequest, "invalid cursor")
			return
		}
		parsed, err := strconv.ParseInt(parts[0], 10, 64)
		if err != nil {
			writeAPIError(w, http.StatusBadRequest, "invalid cursor")
			return
		}
		afterCreated, afterID = parsed, parts[1]
	}

	items := make([]apiAgentTokenView, 0, limit)
	next := ""
	var lastCreated int64
	var lastID string
	for _, t := range s.identity.ListAgentTokens(0) {
		if nodeFilterSet && t.NodeID != nodeFilter {
			continue
		}
		if cursorKind != "" {
			created := t.CreatedAt.UnixNano()
			if created > afterCreated || (created == afterCreated && t.ID >= afterID) {
				continue
			}
		}
		if len(items) == limit {
			next = apiV2EncodeCursor("agent-tokens", strconv.FormatInt(lastCreated, 10), lastID)
			break
		}
		items = append(items, s.apiAgentTokenView(t))
		lastCreated, lastID = t.CreatedAt.UnixNano(), t.ID
	}

	writeJSON(w, http.StatusOK, map[string]any{"items": items, "nextCursor": next})
}

// handleAPIV2RevokeAgentToken implements DELETE /api/v2/agent-tokens/{id}.
//
// Revocation is durable and immediate: the next agent request with that token
// is rejected. It is idempotent, so a retried revocation is not an error.
func (s *Server) handleAPIV2RevokeAgentToken(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireScope(w, r, identity.ScopeWrite)
	if !ok {
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
		writeAPIError(w, http.StatusNotFound, "agent token not found")
		return
	}

	now := time.Now().UTC()
	if err := s.identity.RevokeAgentToken(id, now); err != nil {
		s.log.Error("revoking agent token", "token", id, "err", err)
		writeAPIError(w, http.StatusInternalServerError, "could not revoke the agent token")
		return
	}
	s.audit(principal.actor(), identity.AuditAgentTokenRevoked, "agenttoken:"+id,
		fmt.Sprintf("revoked the native client credential of node %d", found.NodeID))
	writeJSON(w, http.StatusOK, map[string]any{"id": id, "revoked": true})
}
