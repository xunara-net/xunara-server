package daemon

import (
	"context"
	"errors"
	"net/http/httptest"
	"path"
	"strings"
	"testing"
	"time"

	"github.com/xunara-net/xunara-server/client/protocol"
	"github.com/xunara-net/xunara-server/control"
	"github.com/xunara-net/xunara-server/state"
)

// startControlServer brings up a real control plane for the native-client
// tests.
func startControlServer(t *testing.T) (*control.Server, *httptest.Server) {
	t.Helper()

	srv, err := control.New(control.Config{
		StateDir:  t.TempDir(),
		ServerURL: "http://login.test",
		Domain:    "example.com",
	})
	if err != nil {
		t.Fatalf("control.New: %v", err)
	}
	t.Cleanup(func() { srv.Close() })

	hs := httptest.NewServer(srv.Handler())
	t.Cleanup(hs.Close)
	return srv, hs
}

// seedPreAuthKey creates a pre-auth key on the control plane.
func seedPreAuthKey(t *testing.T, srv *control.Server) string {
	t.Helper()

	secret, err := state.NewPreAuthKeySecret()
	if err != nil {
		t.Fatalf("NewPreAuthKeySecret: %v", err)
	}
	key := state.PreAuthKey{Key: secret, UserID: state.DefaultUserID}
	if err := srv.Store().CreatePreAuthKey(&key); err != nil {
		t.Fatalf("CreatePreAuthKey: %v", err)
	}
	return secret
}

// heartbeatFor builds the heartbeat body for a node identity.
func heartbeatFor(t *testing.T, keys protocol.Keys) protocol.HeartbeatRequest {
	t.Helper()
	return protocol.HeartbeatRequest{
		MachineKey:   keys.Machine.Public().String(),
		NodeKey:      keys.Node.Public().String(),
		Hostname:     "e2e-agent",
		AgentVersion: Version,
	}
}

// TestAgentEndToEndEnrollHeartbeatStatus drives the native client against a
// real control plane: enrollment, heartbeat, status (netmap) and the node's
// presence in the server store.
func TestAgentEndToEndEnrollHeartbeatStatus(t *testing.T) {
	srv, hs := startControlServer(t)
	secret := seedPreAuthKey(t, srv)

	stateDir := t.TempDir()
	state, err := Enroll(context.Background(), EnrollOptions{
		ServerURL: hs.URL,
		StateDir:  stateDir,
		AuthKey:   secret,
		Hostname:  "e2e-agent",
	})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if state.NodeID == 0 || state.StableID == "" {
		t.Fatalf("enrolled state = %+v", state)
	}

	nodes := srv.Store().ListNodes()
	if len(nodes) != 1 {
		t.Fatalf("control plane has %d nodes, want 1", len(nodes))
	}
	if nodes[0].Hostname != "e2e-agent" {
		t.Errorf("node hostname = %q, want e2e-agent", nodes[0].Hostname)
	}

	agent, err := NewAgent(state, nil, nil)
	if err != nil {
		t.Fatalf("NewAgent: %v", err)
	}

	status, err := agent.Status(context.Background())
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if !strings.HasPrefix(status.Name, "e2e-agent.") {
		t.Errorf("status name = %q, want the MagicDNS name", status.Name)
	}
	if status.NodeID != state.NodeID {
		t.Errorf("status node ID = %d, want %d", status.NodeID, state.NodeID)
	}

	// A heartbeat reports liveness; the control plane must show the node
	// online even though it holds no Noise session.
	keys, err := state.Keys()
	if err != nil {
		t.Fatalf("state keys: %v", err)
	}
	if err := agent.Client.Heartbeat(context.Background(), state.Token, heartbeatFor(t, keys)); err != nil {
		t.Fatalf("Heartbeat: %v", err)
	}
	if !srv.IsNodeOnline(nodes[0].ID) {
		t.Error("node is not online after the agent heartbeat")
	}

	// Re-enrolling after the node was deleted fails closed: the state is gone
	// from the control plane and the agent must start over.
	if err := srv.Store().DeleteNode(nodes[0].ID); err != nil {
		t.Fatalf("DeleteNode: %v", err)
	}
	if err := agent.Client.Heartbeat(context.Background(), state.Token, heartbeatFor(t, keys)); err == nil {
		t.Error("heartbeat with a deleted node succeeded")
	}
}

// TestAgentEndToEndInteractiveApproval drives the browser-approval path
// against the real device authorization store.
func TestAgentEndToEndInteractiveApproval(t *testing.T) {
	srv, hs := startControlServer(t)

	stateDir := t.TempDir()
	_, err := Enroll(context.Background(), EnrollOptions{
		ServerURL: hs.URL,
		StateDir:  stateDir,
		Hostname:  "approval-agent",
	})
	var pending *PendingApprovalError
	if !errors.As(err, &pending) {
		t.Fatalf("Enroll error = %v, want PendingApprovalError", err)
	}

	authID := path.Base(pending.AuthURL)
	if err := srv.ApproveRegistration(authID); err != nil {
		t.Fatalf("ApproveRegistration: %v", err)
	}

	state, err := Enroll(context.Background(), EnrollOptions{
		ServerURL: hs.URL,
		StateDir:  stateDir,
		Hostname:  "approval-agent",
	})
	if err != nil {
		t.Fatalf("post-approval Enroll: %v", err)
	}
	if state.Token == "" || state.NodeID == 0 {
		t.Fatalf("post-approval state = %+v", state)
	}

	agent, err := NewAgent(state, nil, nil)
	if err != nil {
		t.Fatalf("NewAgent: %v", err)
	}
	if _, err := agent.Status(context.Background()); err != nil {
		t.Fatalf("Status after approval: %v", err)
	}
}

// TestAgentEndToEndEventStream checks the push path: a running agent receives
// netmaps over the server's SSE stream when the tailnet changes, without
// waiting for a poll.
func TestAgentEndToEndEventStream(t *testing.T) {
	srv, hs := startControlServer(t)
	secret := seedPreAuthKey(t, srv)

	stateDir := t.TempDir()
	state, err := Enroll(context.Background(), EnrollOptions{
		ServerURL: hs.URL,
		StateDir:  stateDir,
		AuthKey:   secret,
		Hostname:  "stream-agent",
	})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}

	agent, err := NewAgent(state, protocol.New(hs.URL), nil)
	if err != nil {
		t.Fatalf("NewAgent: %v", err)
	}
	// The heartbeat/poll interval is deliberately far beyond the test's
	// deadline: a netmap that arrives in this test can only have been pushed.
	agent.Interval = 10 * time.Minute

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- agent.Run(ctx) }()

	// Wait until the stream delivered its initial frame (the bring-up fetch is
	// the first netmap; the stream frame is the second).
	waitForNetmaps(t, agent, 2)

	// A second device joins through the interactive flow; the approval wakes
	// the stream.
	otherDir := t.TempDir()
	_, err = Enroll(context.Background(), EnrollOptions{
		ServerURL: hs.URL,
		StateDir:  otherDir,
		Hostname:  "second-agent",
	})
	var pending *PendingApprovalError
	if !errors.As(err, &pending) {
		t.Fatalf("second Enroll error = %v, want PendingApprovalError", err)
	}
	if err := srv.ApproveRegistration(path.Base(pending.AuthURL)); err != nil {
		t.Fatalf("ApproveRegistration: %v", err)
	}
	if _, err := Enroll(context.Background(), EnrollOptions{
		ServerURL: hs.URL,
		StateDir:  otherDir,
		Hostname:  "second-agent",
	}); err != nil {
		t.Fatalf("post-approval Enroll: %v", err)
	}

	// The pushed netmap must carry the new peer.
	deadline := time.Now().Add(10 * time.Second)
	for {
		_, latest := agent.netmapStats()
		if latest != nil && len(latest.Peers) == 1 {
			if latest.Peers[0].Name != "second-agent.example.com." {
				t.Errorf("pushed peer = %q, want second-agent.example.com.", latest.Peers[0].Name)
			}
			break
		}
		if time.Now().After(deadline) {
			peers := 0
			if latest != nil {
				peers = len(latest.Peers)
			}
			t.Fatalf("pushed netmap has %d peers, want 1", peers)
		}
		time.Sleep(10 * time.Millisecond)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not stop after cancellation")
	}
}

// waitForNetmaps waits until the agent has applied at least want netmaps.
func waitForNetmaps(t *testing.T, agent *Agent, want int) {
	t.Helper()

	deadline := time.Now().Add(10 * time.Second)
	for {
		if applied, _ := agent.netmapStats(); applied >= want {
			return
		}
		if time.Now().After(deadline) {
			applied, _ := agent.netmapStats()
			t.Fatalf("agent applied %d netmaps, want at least %d", applied, want)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
