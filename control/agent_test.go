package control

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"path"
	"strings"
	"testing"
	"time"

	"tailscale.com/tailcfg"
	"tailscale.com/types/key"

	"github.com/xunara-net/xunara-server/state"
)

// agentPost performs a JSON request against /api/agent/v1 and returns the body
// and status.
func agentPost(t *testing.T, client *http.Client, base, path, token string, req any) ([]byte, int) {
	t.Helper()

	raw, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshalling %s: %v", path, err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, base+path, bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("building %s: %v", path, err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if token != "" {
		httpReq.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := client.Do(httpReq)
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	defer resp.Body.Close()

	out, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	return out, resp.StatusCode
}

// enrollAgent walks a fresh agent through enrollment with a pre-auth key.
func enrollAgent(t *testing.T, client *http.Client, base string, machineKey key.MachinePrivate, nodeKey key.NodePrivate, authKey string) agentEnrollResponse {
	t.Helper()

	body, status := agentPost(t, client, base, "/api/agent/v1/enroll", "", agentEnrollRequest{
		Version:      agentProtocolVersion,
		AuthKey:      authKey,
		MachineKey:   machineKey.Public().String(),
		NodeKey:      nodeKey.Public().String(),
		Hostname:     "agent-node",
		OS:           "linux",
		AgentVersion: "xunara-agent/0.1.0",
	})
	if status != http.StatusOK {
		t.Fatalf("enroll status = %d (%s)", status, body)
	}

	var resp agentEnrollResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("decoding enroll response: %v", err)
	}
	return resp
}

// TestAgentEnrollPreAuthAndNetmap covers the whole native-client happy path:
// enrollment with a pre-auth key, netmap fetch, heartbeat, credential rotation
// and the key bindings.
func TestAgentEnrollPreAuthAndNetmap(t *testing.T) {
	s := newServerWithConfig(t, Config{Domain: "example.com"})
	hs := newTestHTTPServer(t, s)
	client := hs.Client()

	secret := seedPreAuthKey(t, s, state.PreAuthKey{})
	machineKey := key.NewMachine()
	nodeKey := key.NewNode()

	resp := enrollAgent(t, client, hs.URL, machineKey, nodeKey, secret)
	if resp.Status != "authorized" || resp.Token == "" || resp.NodeID == 0 {
		t.Fatalf("enroll = %+v, want authorized with a token", resp)
	}
	if node, ok := s.Store().GetNodeByNodeKey(nodeKey.Public()); !ok {
		t.Fatal("enrollment did not create the node")
	} else if node.MachineKey != machineKey.Public() || node.Hostname != "agent-node" {
		t.Errorf("node = %+v, want the agent's keys and hostname", node)
	}

	// The netmap endpoint returns the same shape official clients get.
	body, status := agentPost(t, client, hs.URL, "/api/agent/v1/netmap", resp.Token, agentRequest{
		MachineKey: machineKey.Public().String(),
		NodeKey:    nodeKey.Public().String(),
	})
	if status != http.StatusOK {
		t.Fatalf("netmap status = %d (%s)", status, body)
	}
	var netmap tailcfg.MapResponse
	if err := json.Unmarshal(body, &netmap); err != nil {
		t.Fatalf("decoding netmap: %v", err)
	}
	if netmap.Node == nil || !strings.HasPrefix(netmap.Node.Name, "agent-node.") {
		t.Fatalf("netmap self = %+v, want agent-node", netmap.Node)
	}

	// A netmap fetch counts as liveness.
	if node, ok := s.Store().GetNodeByNodeKey(nodeKey.Public()); !ok || !s.isOnline(node.ID) {
		t.Error("agent is not reported online after the netmap fetch")
	}

	// Heartbeat accepts host facts and endpoints.
	body, status = agentPost(t, client, hs.URL, "/api/agent/v1/heartbeat", resp.Token, agentHeartbeatRequest{
		agentRequest: agentRequest{
			MachineKey: machineKey.Public().String(),
			NodeKey:    nodeKey.Public().String(),
		},
		Hostname:     "renamed-agent",
		Endpoints:    []string{"192.0.2.7:41641"},
		AgentVersion: "xunara-agent/0.1.1",
	})
	if status != http.StatusNoContent {
		t.Fatalf("heartbeat status = %d (%s)", status, body)
	}
	node, _ := s.Store().GetNodeByNodeKey(nodeKey.Public())
	if node.Hostinfo == nil || node.Hostinfo.Hostname != "renamed-agent" ||
		node.Hostinfo.IPNVersion != "xunara-agent/0.1.1" {
		t.Errorf("hostinfo = %+v, want the heartbeat's facts", node.Hostinfo)
	}
	if len(node.Endpoints) != 1 || node.Endpoints[0].String() != "192.0.2.7:41641" {
		t.Errorf("endpoints = %v, want the reported endpoint", node.Endpoints)
	}

	// Bad endpoints are refused before any state is written.
	if _, status := agentPost(t, client, hs.URL, "/api/agent/v1/heartbeat", resp.Token, agentHeartbeatRequest{
		agentRequest: agentRequest{
			MachineKey: machineKey.Public().String(),
			NodeKey:    nodeKey.Public().String(),
		},
		Endpoints: []string{"not-an-address"},
	}); status != http.StatusBadRequest {
		t.Errorf("invalid endpoint status = %d, want 400", status)
	}

	// Enrollment again rotates the credential: the old token dies.
	rotated := enrollAgent(t, client, hs.URL, machineKey, nodeKey, "")
	if rotated.Status != "authorized" || rotated.Token == resp.Token {
		t.Fatalf("rotated enroll = %+v, want a new token", rotated)
	}
	if body, status := agentPost(t, client, hs.URL, "/api/agent/v1/netmap", resp.Token, agentRequest{
		MachineKey: machineKey.Public().String(),
		NodeKey:    nodeKey.Public().String(),
	}); status != http.StatusUnauthorized {
		t.Errorf("old token status = %d (%s), want 401", status, body)
	}

	// Wrong keys with a valid token are refused (machine identity binding).
	otherMachine := key.NewMachine()
	if body, status := agentPost(t, client, hs.URL, "/api/agent/v1/netmap", rotated.Token, agentRequest{
		MachineKey: otherMachine.Public().String(),
		NodeKey:    nodeKey.Public().String(),
	}); status != http.StatusForbidden {
		t.Errorf("foreign machine key status = %d (%s), want 403", status, body)
	}

	// Missing token.
	if _, status := agentPost(t, client, hs.URL, "/api/agent/v1/netmap", "", agentRequest{
		MachineKey: machineKey.Public().String(),
		NodeKey:    nodeKey.Public().String(),
	}); status != http.StatusUnauthorized {
		t.Errorf("missing token status = %d, want 401", status)
	}

	// Deleting the node kills the credential.
	if err := s.Store().DeleteNode(node.ID); err != nil {
		t.Fatalf("DeleteNode: %v", err)
	}
	if _, status := agentPost(t, client, hs.URL, "/api/agent/v1/netmap", rotated.Token, agentRequest{
		MachineKey: machineKey.Public().String(),
		NodeKey:    nodeKey.Public().String(),
	}); status != http.StatusUnauthorized {
		t.Errorf("deleted node status = %d, want 401", status)
	}
}

// TestAgentEnrollInteractiveApproval covers the browser-approval path: pending
// enrollment, approval through the existing device flow, then authorization.
func TestAgentEnrollInteractiveApproval(t *testing.T) {
	s := newServerWithConfig(t, Config{})
	hs := newTestHTTPServer(t, s)
	client := hs.Client()

	machineKey := key.NewMachine()
	nodeKey := key.NewNode()

	body, status := agentPost(t, client, hs.URL, "/api/agent/v1/enroll", "", agentEnrollRequest{
		Version:    agentProtocolVersion,
		MachineKey: machineKey.Public().String(),
		NodeKey:    nodeKey.Public().String(),
		Hostname:   "interactive-agent",
	})
	if status != http.StatusOK {
		t.Fatalf("enroll status = %d (%s)", status, body)
	}
	var pending agentEnrollResponse
	if err := json.Unmarshal(body, &pending); err != nil {
		t.Fatalf("decoding enroll response: %v", err)
	}
	if pending.Status != "pending" || !strings.HasPrefix(pending.AuthURL, "http") {
		t.Fatalf("enroll = %+v, want pending with an auth URL", pending)
	}

	authID := path.Base(pending.AuthURL)
	if err := s.ApproveRegistration(authID); err != nil {
		t.Fatalf("ApproveRegistration: %v", err)
	}

	// Polling again after approval authorizes the agent.
	approved := enrollAgent(t, client, hs.URL, machineKey, nodeKey, "")
	if approved.Status != "authorized" || approved.Token == "" {
		t.Fatalf("post-approval enroll = %+v, want authorized", approved)
	}

	// Denied registrations are reported as rejected, and a mismatched machine
	// key never adopts another node's pending registration.
	otherMachine, otherNode := key.NewMachine(), key.NewNode()
	body, _ = agentPost(t, client, hs.URL, "/api/agent/v1/enroll", "", agentEnrollRequest{
		Version:    agentProtocolVersion,
		MachineKey: otherMachine.Public().String(),
		NodeKey:    otherNode.Public().String(),
		Hostname:   "denied-agent",
	})
	var otherPending agentEnrollResponse
	if err := json.Unmarshal(body, &otherPending); err != nil {
		t.Fatalf("decoding second enroll: %v", err)
	}

	_, status = agentPost(t, client, hs.URL, "/api/agent/v1/enroll", "", agentEnrollRequest{
		Version:    agentProtocolVersion,
		MachineKey: machineKey.Public().String(),
		NodeKey:    otherNode.Public().String(),
	})
	if status != http.StatusForbidden {
		t.Errorf("mismatched machine key status = %d, want 403", status)
	}

	if _, err := s.denyDevice(path.Base(otherPending.AuthURL), state.DefaultUserID, "test"); err != nil {
		t.Fatalf("denyDevice: %v", err)
	}
	body, status = agentPost(t, client, hs.URL, "/api/agent/v1/enroll", "", agentEnrollRequest{
		Version:    agentProtocolVersion,
		MachineKey: otherMachine.Public().String(),
		NodeKey:    otherNode.Public().String(),
		Hostname:   "denied-agent",
	})
	if status != http.StatusForbidden || !strings.Contains(string(body), "denied") {
		t.Errorf("denied enroll status = %d (%s), want 403 denied", status, body)
	}
}

// TestAgentEnrollRejectsBadInput pins the fail-closed input validation.
func TestAgentEnrollRejectsBadInput(t *testing.T) {
	s := newServerWithConfig(t, Config{})
	hs := newTestHTTPServer(t, s)
	client := hs.Client()

	validMachine, validNode := key.NewMachine().Public().String(), key.NewNode().Public().String()

	cases := []struct {
		name string
		req  agentEnrollRequest
	}{
		{"bad machine key", agentEnrollRequest{Version: 1, MachineKey: "not-a-key", NodeKey: validNode}},
		{"bad node key", agentEnrollRequest{Version: 1, MachineKey: validMachine, NodeKey: "not-a-key"}},
		{"future protocol", agentEnrollRequest{Version: 99, MachineKey: validMachine, NodeKey: validNode}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, status := agentPost(t, client, hs.URL, "/api/agent/v1/enroll", "", tc.req); status != http.StatusBadRequest {
				t.Errorf("status = %d, want 400", status)
			}
		})
	}

	// An invalid pre-auth key is refused without creating anything.
	s2 := newServerWithConfig(t, Config{})
	hs2 := newTestHTTPServer(t, s2)
	body, status := agentPost(t, hs2.Client(), hs2.URL, "/api/agent/v1/enroll", "", agentEnrollRequest{
		Version:    agentProtocolVersion,
		AuthKey:    "xunara_authkey_nope",
		MachineKey: validMachine,
		NodeKey:    validNode,
	})
	if status != http.StatusForbidden || !strings.Contains(string(body), "invalid pre-auth key") {
		t.Errorf("invalid auth key status = %d (%s), want 403", status, body)
	}
	if nodes := len(s2.Store().ListNodes()); nodes != 0 {
		t.Errorf("nodes = %d, want 0", nodes)
	}
}

// agentEventsGet opens the native-client event stream.
func agentEventsGet(t *testing.T, client *http.Client, base, token string, keys agentRequest) *http.Response {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/api/agent/v1/events", nil)
	if err != nil {
		t.Fatalf("building events request: %v", err)
	}
	req.Header.Set("Accept", "text/event-stream")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if keys.MachineKey != "" {
		req.Header.Set("X-Xunara-Machine-Key", keys.MachineKey)
	}
	if keys.NodeKey != "" {
		req.Header.Set("X-Xunara-Node-Key", keys.NodeKey)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET /api/agent/v1/events: %v", err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

// readNetmapEvent reads one SSE data frame and decodes it as a MapResponse.
func readNetmapEvent(t *testing.T, r *bufio.Reader) *tailcfg.MapResponse {
	t.Helper()

	var data []string
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			t.Fatalf("reading event stream: %v", err)
		}
		line = strings.TrimRight(line, "\n")
		switch {
		case line == "":
			if len(data) == 0 {
				continue
			}
			var resp tailcfg.MapResponse
			if err := json.Unmarshal([]byte(strings.Join(data, "\n")), &resp); err != nil {
				t.Fatalf("decoding netmap event: %v", err)
			}
			return &resp
		case strings.HasPrefix(line, "data: "):
			data = append(data, strings.TrimPrefix(line, "data: "))
		}
	}
}

// TestAgentEventStreamPushesNetmapChanges covers the SSE stream: an enrolled
// agent receives its netmap immediately and a fresh one when the tailnet
// changes.
func TestAgentEventStreamPushesNetmapChanges(t *testing.T) {
	s := newServerWithConfig(t, Config{Domain: "example.com"})
	hs := newTestHTTPServer(t, s)
	client := hs.Client()

	secret := seedPreAuthKey(t, s, state.PreAuthKey{})
	machineKey := key.NewMachine()
	nodeKey := key.NewNode()
	enrolled := enrollAgent(t, client, hs.URL, machineKey, nodeKey, secret)
	if enrolled.Token == "" {
		t.Fatalf("enrollment = %+v", enrolled)
	}

	resp := agentEventsGet(t, client, hs.URL, enrolled.Token, agentRequest{
		MachineKey: machineKey.Public().String(),
		NodeKey:    nodeKey.Public().String(),
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("events status = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "text/event-stream" {
		t.Fatalf("Content-Type = %q, want text/event-stream", ct)
	}
	if cc := resp.Header.Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", cc)
	}

	reader := bufio.NewReader(resp.Body)
	first := readNetmapEvent(t, reader)
	if first.Node == nil || !strings.HasPrefix(first.Node.Name, "agent-node.") {
		t.Fatalf("first netmap self = %+v, want the agent's node", first.Node)
	}
	if len(first.Peers) != 0 {
		t.Fatalf("first netmap has %d peers, want 0", len(first.Peers))
	}

	// A second device joining the tailnet wakes the stream.
	otherSecret := seedPreAuthKey(t, s, state.PreAuthKey{})
	conn, _, _ := registerPreAuthedNode(t, hs, "stream-peer", otherSecret)
	defer conn.Close()

	pushed := readNetmapEvent(t, reader)
	if len(pushed.Peers) != 1 {
		t.Fatalf("pushed netmap has %d peers, want 1", len(pushed.Peers))
	}
	if pushed.Peers[0].Name != "stream-peer.example.com." {
		t.Errorf("pushed peer = %q, want stream-peer.example.com.", pushed.Peers[0].Name)
	}
}

// TestAgentEventStreamRequiresCredential checks the stream's identity rules.
func TestAgentEventStreamRequiresCredential(t *testing.T) {
	s := newServerWithConfig(t, Config{Domain: "example.com"})
	hs := newTestHTTPServer(t, s)
	client := hs.Client()

	secret := seedPreAuthKey(t, s, state.PreAuthKey{})
	machineKey := key.NewMachine()
	nodeKey := key.NewNode()
	enrolled := enrollAgent(t, client, hs.URL, machineKey, nodeKey, secret)
	if enrolled.Token == "" {
		t.Fatalf("enrollment = %+v", enrolled)
	}

	// No token.
	if resp := agentEventsGet(t, client, hs.URL, "", agentRequest{}); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("anonymous events status = %d, want 401", resp.StatusCode)
	}

	// Valid token, wrong node key: the credential is bound to the keys.
	other := key.NewNode()
	if resp := agentEventsGet(t, client, hs.URL, enrolled.Token, agentRequest{
		MachineKey: machineKey.Public().String(),
		NodeKey:    other.Public().String(),
	}); resp.StatusCode != http.StatusForbidden {
		t.Errorf("mismatched keys status = %d, want 403", resp.StatusCode)
	}
}
