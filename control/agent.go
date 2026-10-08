package control

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"

	"github.com/xunara-net/xunara-server/identity"
	"github.com/xunara-net/xunara-server/state"
)

// This file implements /api/agent/v1, the protocol Xunara Agent (the native
// client) speaks. It is deliberately separate from TS2021: the official
// client protocol in noise.go stays untouched, and the native client gets
// JSON over HTTPS instead of Noise (PROJECT_SPEC section 3).
//
// Identity model: enrollment is machine identity. The agent generates a
// machine key and a node key, exactly like an official client, and the node
// is created through the same registration decision path (pre-auth key or
// interactive device approval). The credential the agent receives afterwards
// is bound to that node and to both keys, and every request repeats the keys
// so the server can check them against the stored node (AGENTS.md section 11).

// agentProtocolVersion is the wire version of /api/agent/v1. Requests naming a
// newer version are refused: a client that speaks a future dialect must not be
// served a subset of it silently.
const agentProtocolVersion = 1

// agentHeartbeatTTL is how long a heartbeat keeps a node marked online in the
// console and platform API.
const agentHeartbeatTTL = 2 * time.Minute

// agentEnrollRequest is the body of POST /api/agent/v1/enroll.
type agentEnrollRequest struct {
	Version int `json:"version"`
	// AuthKey is the pre-auth key that authorizes the machine without a
	// browser. Empty starts the interactive device-approval flow.
	AuthKey    string `json:"auth_key,omitempty"`
	MachineKey string `json:"machine_key"`
	NodeKey    string `json:"node_key"`
	Hostname   string `json:"hostname,omitempty"`
	OS         string `json:"os,omitempty"`
	// AgentVersion is the native client's own version.
	AgentVersion string `json:"agent_version,omitempty"`
	Ephemeral    bool   `json:"ephemeral,omitempty"`
}

// agentEnrollResponse is the answer to an enrollment attempt.
type agentEnrollResponse struct {
	// Status is "authorized", "pending" or "rejected".
	Status   string `json:"status"`
	NodeID   int64  `json:"node_id,omitempty"`
	StableID string `json:"stable_id,omitempty"`
	// AuthURL is where a human approves the device while Status is "pending".
	AuthURL string `json:"auth_url,omitempty"`
	// Token is the agent credential, returned exactly once when Status is
	// "authorized". Enrolling again rotates it.
	Token string `json:"token,omitempty"`
	Error string `json:"error,omitempty"`
}

// agentRequest is the common body of authenticated agent requests.
type agentRequest struct {
	MachineKey string `json:"machine_key"`
	NodeKey    string `json:"node_key"`
}

// withHeaders fills empty key fields from the request headers. Reach sends
// its credential in headers on every call (creates included), so a session
// endpoint reads the same way whether the keys arrive in a JSON body or in
// X-Xunara-Machine-Key/X-Xunara-Node-Key. The keys are verified either way.
func (a agentRequest) withHeaders(req *http.Request) agentRequest {
	if a.MachineKey == "" {
		a.MachineKey = req.Header.Get("X-Xunara-Machine-Key")
	}
	if a.NodeKey == "" {
		a.NodeKey = req.Header.Get("X-Xunara-Node-Key")
	}
	return a
}

// agentHeartbeatRequest is the body of POST /api/agent/v1/heartbeat.
type agentHeartbeatRequest struct {
	agentRequest
	Hostname  string   `json:"hostname,omitempty"`
	Endpoints []string `json:"endpoints,omitempty"`
	// AgentVersion is reported into the node's host info alongside the
	// hostname, so the console can show what the agent runs.
	AgentVersion string `json:"agent_version,omitempty"`
}

// agentRouter mounts the native client's protocol.
func (s *Server) agentRouter() http.Handler {
	r := chi.NewRouter()
	r.Post("/enroll", s.handleAgentEnroll)
	r.Post("/netmap", s.handleAgentNetmap)
	r.Post("/heartbeat", s.handleAgentHeartbeat)
	r.Get("/events", s.handleAgentEvents)
	r.Post("/services", s.handleAgentServices)
	r.Post("/services/health", s.handleAgentServiceHealth)
	if s.flux != nil {
		r.Post("/flux/transfers", s.handleFluxCreate)
		r.Get("/flux/transfers", s.handleFluxList)
		r.Post("/flux/transfers/{id}/accept", s.handleFluxAccept)
		r.Post("/flux/transfers/{id}/deny", s.handleFluxDeny)
		r.Post("/flux/transfers/{id}/cancel", s.handleFluxCancel)
		r.Put("/flux/transfers/{id}/content", s.handleFluxUpload)
		r.Get("/flux/transfers/{id}/content", s.handleFluxDownload)
		r.Post("/flux/transfers/{id}/complete", s.handleFluxComplete)
		r.Post("/flux/transfers/{id}/fail", s.handleFluxFail)
	}
	if s.cfg.ReachEnabled {
		r.Post("/reach/sessions", s.handleReachCreate)
		r.Get("/reach/sessions", s.handleReachList)
		r.Get("/reach/sessions/{id}", s.handleReachGet)
		r.Post("/reach/sessions/{id}/accept", s.handleReachAccept)
		r.Post("/reach/sessions/{id}/deny", s.handleReachDeny)
		r.Post("/reach/sessions/{id}/start", s.handleReachStart)
		r.Post("/reach/sessions/{id}/chunks", s.handleReachChunks)
		r.Get("/reach/sessions/{id}/chunks", s.handleReachChunksRead)
		r.Post("/reach/sessions/{id}/finish", s.handleReachFinish)
		r.Post("/reach/sessions/{id}/cancel", s.handleReachCancel)
	}
	return r
}

// handleAgentEnroll implements POST /api/agent/v1/enroll: it authorizes a
// machine (pre-auth key or pending device approval) and issues the agent
// credential.
func (s *Server) handleAgentEnroll(w http.ResponseWriter, req *http.Request) {
	var enroll agentEnrollRequest
	if err := json.NewDecoder(req.Body).Decode(&enroll); err != nil {
		httpError(w, err)
		return
	}
	if enroll.Version != 0 && enroll.Version != agentProtocolVersion {
		httpError(w, NewHTTPError(http.StatusBadRequest,
			fmt.Sprintf("unsupported agent protocol version %d", enroll.Version), nil))
		return
	}

	machineKey, err := parseMachineKey(enroll.MachineKey)
	if err != nil {
		httpError(w, NewHTTPError(http.StatusBadRequest, err.Error(), nil))
		return
	}
	nodeKey, err := parseNodeKey(enroll.NodeKey)
	if err != nil {
		httpError(w, NewHTTPError(http.StatusBadRequest, err.Error(), nil))
		return
	}

	resp := s.agentEnroll(req, enroll, machineKey, nodeKey)
	status := http.StatusOK
	if resp.Status == "rejected" {
		status = http.StatusForbidden
	}
	writeJSON(w, status, resp)
}

// agentEnroll is the transport-independent enrollment decision.
func (s *Server) agentEnroll(req *http.Request, enroll agentEnrollRequest, machineKey key.MachinePublic, nodeKey key.NodePublic) agentEnrollResponse {
	// An already-registered node re-enrolls after an agent restart: both keys
	// must match, so possession of the node key alone is not enough.
	if node, ok := s.store.GetNodeByNodeKey(nodeKey); ok {
		if node.MachineKey != machineKey {
			return agentEnrollResponse{Status: "rejected", Error: "machine key does not match the registered node"}
		}
		return s.authorizeAgent(node)
	}

	if enroll.AuthKey != "" {
		hostinfo := &tailcfg.Hostinfo{
			Hostname:   enroll.Hostname,
			OS:         enroll.OS,
			IPNVersion: enroll.AgentVersion,
		}
		regResp, err := s.handleRegister(req.Context(), tailcfg.RegisterRequest{
			Version:   tailcfg.CurrentCapabilityVersion,
			NodeKey:   nodeKey,
			Auth:      &tailcfg.RegisterResponseAuth{AuthKey: enroll.AuthKey},
			Hostinfo:  hostinfo,
			Ephemeral: enroll.Ephemeral,
		}, machineKey)
		if err != nil {
			return agentEnrollResponse{Status: "rejected", Error: errorMessage(err)}
		}
		if regResp.AuthURL != "" {
			return agentEnrollResponse{Status: "pending", AuthURL: regResp.AuthURL}
		}
		node, ok := s.store.GetNodeByNodeKey(nodeKey)
		if !ok {
			return agentEnrollResponse{Status: "rejected", Error: "registration did not create a node"}
		}
		return s.authorizeAgent(node)
	}

	// Interactive: reuse the durable device authorization the browser flow
	// writes, so approval works across instances and the console page is the
	// same one official clients use.
	if da, ok := s.identity.GetDeviceAuthorizationByNodeKey(nodeKey.String()); ok {
		if da.MachineKey != machineKey.String() {
			return agentEnrollResponse{Status: "rejected", Error: "machine key does not match the pending registration"}
		}
		switch {
		case da.State == identity.DeviceDenied:
			return agentEnrollResponse{Status: "rejected", Error: "registration denied"}
		case da.State == identity.DeviceApproved:
			if node, ok := s.store.GetNodeByNodeKey(nodeKey); ok {
				return s.authorizeAgent(node)
			}
		case da.Pending() && !da.Expired(time.Now()):
			return agentEnrollResponse{Status: "pending", AuthURL: s.authURL(da.ID)}
		}
	}

	regResp, err := s.handleRegister(req.Context(), tailcfg.RegisterRequest{
		Version:  tailcfg.CurrentCapabilityVersion,
		NodeKey:  nodeKey,
		Hostinfo: &tailcfg.Hostinfo{Hostname: enroll.Hostname, OS: enroll.OS, IPNVersion: enroll.AgentVersion},
	}, machineKey)
	if err != nil {
		return agentEnrollResponse{Status: "rejected", Error: errorMessage(err)}
	}
	return agentEnrollResponse{Status: "pending", AuthURL: regResp.AuthURL}
}

// authorizeAgent issues (rotating any previous) credential for a node.
func (s *Server) authorizeAgent(node state.Node) agentEnrollResponse {
	if err := s.identity.RevokeAgentTokensForNode(int64(node.ID)); err != nil {
		s.log.Error("revoking previous agent tokens", "node_id", int(node.ID), "err", err)
		return agentEnrollResponse{Status: "rejected", Error: "could not rotate the agent credential"}
	}

	_, token, err := s.identity.CreateAgentToken(identity.NewAgentTokenOptions{
		NodeID:     int64(node.ID),
		MachineKey: node.MachineKey.String(),
		NodeKey:    node.NodeKey.String(),
	})
	if err != nil {
		s.log.Error("creating agent token", "node_id", int(node.ID), "err", err)
		return agentEnrollResponse{Status: "rejected", Error: "could not issue the agent credential"}
	}

	s.audit(nodeActor(node), identity.AuditAgentEnrolled, nodeTarget(node), "native client enrolled")

	return agentEnrollResponse{
		Status:   "authorized",
		NodeID:   int64(node.ID),
		StableID: node.StableID,
		Token:    token,
	}
}

// handleAgentNetmap implements POST /api/agent/v1/netmap: the authenticated
// native client fetches the same netmap an official client receives, as JSON.
func (s *Server) handleAgentNetmap(w http.ResponseWriter, req *http.Request) {
	var body agentRequest
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		httpError(w, err)
		return
	}

	node, _, err := s.authenticateAgent(req, body)
	if err != nil {
		httpError(w, err)
		return
	}

	s.markAgentSeen(node.ID)

	resp := s.fullMap(node, tailcfg.MapRequest{Version: tailcfg.CurrentCapabilityVersion})
	writeJSON(w, http.StatusOK, resp)
}

// handleAgentHeartbeat implements POST /api/agent/v1/heartbeat: liveness plus
// the host facts an official client would report on its map session.
func (s *Server) handleAgentHeartbeat(w http.ResponseWriter, req *http.Request) {
	var body agentHeartbeatRequest
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		httpError(w, err)
		return
	}

	node, _, err := s.authenticateAgent(req, body.agentRequest)
	if err != nil {
		httpError(w, err)
		return
	}

	var endpoints []netip.AddrPort
	for _, raw := range body.Endpoints {
		addr, err := netip.ParseAddrPort(strings.TrimSpace(raw))
		if err != nil {
			httpError(w, NewHTTPError(http.StatusBadRequest,
				fmt.Sprintf("invalid endpoint %q", raw), err))
			return
		}
		endpoints = append(endpoints, addr)
	}

	// Reuse the map-request persistence path: the same change detection,
	// PreferredDERP adoption and watcher wakeups official clients get.
	var hostinfo *tailcfg.Hostinfo
	if body.Hostname != "" || body.AgentVersion != "" {
		existing := tailcfg.Hostinfo{}
		if node.Hostinfo != nil {
			existing = *node.Hostinfo
		}
		if body.Hostname != "" {
			existing.Hostname = body.Hostname
		}
		if body.AgentVersion != "" {
			existing.IPNVersion = body.AgentVersion
		}
		hostinfo = &existing
	}

	s.recordMapRequest(node, tailcfg.MapRequest{
		Version:   tailcfg.CurrentCapabilityVersion,
		NodeKey:   node.NodeKey,
		Endpoints: endpoints,
		Hostinfo:  hostinfo,
	})
	s.markAgentSeen(node.ID)

	w.WriteHeader(http.StatusNoContent)
}

// agentEventHeartbeat is how often an idle event stream sends a keepalive
// comment, so middleboxes do not drop the connection and the client can
// detect a stalled server.
const agentEventHeartbeat = 25 * time.Second

// handleAgentEvents implements GET /api/agent/v1/events: a Server-Sent Events
// stream that pushes a fresh full netmap whenever the tailnet changes.
//
// The same identity rules as the polling endpoints apply, with the request
// body's place taken by headers (a GET has no body): a bearer agent token plus
// the machine and node keys the token is bound to. The stream ends when the
// node is deleted or its credential is revoked; the client re-enrolls then.
func (s *Server) handleAgentEvents(w http.ResponseWriter, req *http.Request) {
	body := agentRequest{
		MachineKey: req.Header.Get("X-Xunara-Machine-Key"),
		NodeKey:    req.Header.Get("X-Xunara-Node-Key"),
	}
	node, _, err := s.authenticateAgent(req, body)
	if err != nil {
		httpError(w, err)
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		httpError(w, NewHTTPError(http.StatusInternalServerError,
			"streaming is not supported by this server", nil))
		return
	}

	// SSE headers. "Connection: keep-alive" is deliberately absent: it is a
	// protocol error under HTTP/2, and HTTP/1.1 keeps the connection open by
	// default between frames.
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	io.WriteString(w, "retry: 3000\n\n")
	flusher.Flush()

	changes, cancelWatch := s.watch()
	defer cancelWatch()

	// send writes one netmap frame. It returns false when the node is gone or
	// the client disconnected; the caller ends the stream then.
	send := func() bool {
		self, ok := s.store.GetNodeByID(node.ID)
		if !ok {
			return false
		}
		resp := s.fullMap(self, tailcfg.MapRequest{Version: tailcfg.CurrentCapabilityVersion})
		payload, err := json.Marshal(resp)
		if err != nil {
			s.log.Error("encoding agent netmap event", "node_id", int(node.ID), "err", err)
			return false
		}
		if _, err := fmt.Fprintf(w, "event: netmap\ndata: %s\n\n", payload); err != nil {
			return false
		}
		flusher.Flush()
		s.markAgentSeen(self.ID)
		return true
	}

	if !send() {
		return
	}

	heartbeat := time.NewTicker(agentEventHeartbeat)
	defer heartbeat.Stop()

	for {
		select {
		case <-req.Context().Done():
			return
		case <-changes:
			if !send() {
				return
			}
		case <-heartbeat.C:
			if _, err := io.WriteString(w, ": keepalive\n\n"); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}

// authenticateAgent resolves a bearer agent token and re-checks the machine
// and node keys the request repeats against the stored node.
func (s *Server) authenticateAgent(req *http.Request, body agentRequest) (state.Node, identity.AgentToken, error) {
	token, ok := bearerToken(req)
	if !ok {
		return state.Node{}, identity.AgentToken{}, NewHTTPError(http.StatusUnauthorized,
			"missing agent token", nil)
	}

	credential, err := s.identity.GetAgentTokenByToken(token)
	if err != nil {
		return state.Node{}, identity.AgentToken{}, NewHTTPError(http.StatusUnauthorized,
			"invalid agent token", nil)
	}

	node, ok := s.store.GetNodeByID(state.NodeID(credential.NodeID))
	if !ok {
		// The node was deleted: the credential dies with it.
		return state.Node{}, identity.AgentToken{}, NewHTTPError(http.StatusUnauthorized,
			"agent node is no longer registered", nil)
	}
	if !node.Expiry.IsZero() && node.Expiry.Before(time.Now()) {
		return state.Node{}, identity.AgentToken{}, NewHTTPError(http.StatusUnauthorized,
			"node key expired", nil)
	}

	// MachineKey and NodeKey bind the token to this node (AGENTS.md section
	// 11); a token alone is not machine identity.
	machineKey, err := parseMachineKey(body.MachineKey)
	if err != nil {
		return state.Node{}, identity.AgentToken{}, NewHTTPError(http.StatusBadRequest, err.Error(), nil)
	}
	nodeKey, err := parseNodeKey(body.NodeKey)
	if err != nil {
		return state.Node{}, identity.AgentToken{}, NewHTTPError(http.StatusBadRequest, err.Error(), nil)
	}
	if node.MachineKey != machineKey || node.NodeKey != nodeKey ||
		credential.MachineKey != node.MachineKey.String() || credential.NodeKey != node.NodeKey.String() {
		return state.Node{}, identity.AgentToken{}, NewHTTPError(http.StatusForbidden,
			"agent credential does not match the node's keys", nil)
	}

	if err := s.identity.TouchAgentToken(credential.ID, time.Now().UTC()); err != nil {
		// Last-used bookkeeping must not block requests.
		s.log.Warn("touching agent token", "token_id", credential.ID, "err", err)
	}
	return node, credential, nil
}

// markAgentSeen records that a native client is currently connected. Heartbeat
// liveness is advisory: it feeds the console and platform API, never a
// security decision.
func (s *Server) markAgentSeen(id state.NodeID) {
	s.sessMu.Lock()
	defer s.sessMu.Unlock()
	if s.agentSeen == nil {
		s.agentSeen = make(map[state.NodeID]time.Time)
	}
	s.agentSeen[id] = time.Now()
}

// parseMachineKey parses a "mkey:..." machine public key.
func parseMachineKey(raw string) (key.MachinePublic, error) {
	var mk key.MachinePublic
	if err := mk.UnmarshalText([]byte(strings.TrimSpace(raw))); err != nil {
		return key.MachinePublic{}, errors.New("invalid machine key")
	}
	return mk, nil
}

// parseNodeKey parses a "nodekey:..." node public key.
func parseNodeKey(raw string) (key.NodePublic, error) {
	var nk key.NodePublic
	if err := nk.UnmarshalText([]byte(strings.TrimSpace(raw))); err != nil {
		return key.NodePublic{}, errors.New("invalid node key")
	}
	return nk, nil
}

// errorMessage renders an error for the agent without leaking internals: an
// HTTPError's message is safe to show, anything else is generic.
func errorMessage(err error) string {
	var he HTTPError
	if errors.As(err, &he) {
		return he.Msg
	}
	return "enrollment failed"
}
