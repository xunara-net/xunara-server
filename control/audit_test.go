package control

import (
	"context"
	"fmt"
	"testing"
	"time"

	"tailscale.com/tailcfg"
	"tailscale.com/types/key"

	"github.com/xunara-net/xunara-server/identity"
	"github.com/xunara-net/xunara-server/state"
)

// auditEvents returns the server's audit log.
func auditEvents(t *testing.T, s *Server) []identity.AuditEvent {
	t.Helper()
	return s.Identity().ListAudit(0)
}

// findAudit returns the first event with the given action.
func findAudit(t *testing.T, s *Server, action string) (identity.AuditEvent, bool) {
	t.Helper()
	for _, e := range auditEvents(t, s) {
		if e.Action == action {
			return e, true
		}
	}
	return identity.AuditEvent{}, false
}

func TestInteractiveRegistrationIsAudited(t *testing.T) {
	s := newTestServer(t)
	hs := newTestHTTPServer(t, s)
	conn, _, _ := registerNode(t, s, hs, "node-a")
	defer conn.Close()

	event, ok := findAudit(t, s, identity.AuditNodeApproved)
	if !ok {
		t.Fatalf("audit log has no %s event: %+v", identity.AuditNodeApproved, auditEvents(t, s))
	}
	if event.Actor != "admin" {
		t.Errorf("actor = %q, want admin", event.Actor)
	}
	if event.Target == "" {
		t.Error("approved event has no target")
	}
}

func TestAuthKeyRegistrationIsAudited(t *testing.T) {
	s := newTestServer(t)
	secret := seedPreAuthKey(t, s, state.PreAuthKey{})
	preauth, ok := s.Store().GetPreAuthKey(secret)
	if !ok {
		t.Fatal("seeded pre-auth key not found")
	}

	nodeKey := key.NewNode()
	if _, err := s.handleRegister(context.Background(), tailcfg.RegisterRequest{
		Version: tailcfg.CurrentCapabilityVersion,
		NodeKey: nodeKey.Public(),
		Auth:    &tailcfg.RegisterResponseAuth{AuthKey: secret},
	}, key.NewMachine().Public()); err != nil {
		t.Fatalf("handleRegister: %v", err)
	}

	event, ok := findAudit(t, s, identity.AuditNodeRegistered)
	if !ok {
		t.Fatalf("audit log has no %s event: %+v", identity.AuditNodeRegistered, auditEvents(t, s))
	}
	if want := fmt.Sprintf("preauthkey:%d", preauth.ID); event.Actor != want {
		t.Errorf("actor = %q, want %q", event.Actor, want)
	}

	node, ok := s.Store().GetNodeByNodeKey(nodeKey.Public())
	if !ok {
		t.Fatal("registered node not found")
	}
	if want := "node:" + node.StableID; event.Target != want {
		t.Errorf("target = %q, want %q", event.Target, want)
	}
}

func TestLogoutIsAudited(t *testing.T) {
	s := newTestServer(t)
	secret := seedPreAuthKey(t, s, state.PreAuthKey{})
	machineKey := key.NewMachine()
	nodeKey := key.NewNode()

	req := tailcfg.RegisterRequest{
		Version: tailcfg.CurrentCapabilityVersion,
		NodeKey: nodeKey.Public(),
		Auth:    &tailcfg.RegisterResponseAuth{AuthKey: secret},
	}
	if _, err := s.handleRegister(context.Background(), req, machineKey.Public()); err != nil {
		t.Fatalf("handleRegister: %v", err)
	}
	node, ok := s.Store().GetNodeByNodeKey(nodeKey.Public())
	if !ok {
		t.Fatal("registered node not found")
	}

	req.Auth = nil
	req.Expiry = time.Now().Add(-time.Minute)
	if _, err := s.handleRegister(context.Background(), req, machineKey.Public()); err != nil {
		t.Fatalf("logout: %v", err)
	}

	event, ok := findAudit(t, s, identity.AuditNodeDeleted)
	if !ok {
		t.Fatalf("audit log has no %s event: %+v", identity.AuditNodeDeleted, auditEvents(t, s))
	}
	if want := "node:" + node.StableID; event.Target != want {
		t.Errorf("target = %q, want %q", event.Target, want)
	}
	if _, ok := s.Store().GetNodeByID(node.ID); ok {
		t.Error("logged-out node is still registered")
	}
}

func TestEphemeralReapIsAudited(t *testing.T) {
	s := newServerWithConfig(t, Config{EphemeralInactivityTimeout: time.Hour})

	stale := state.Node{
		NodeKey:   key.NewNode().Public(),
		Ephemeral: true,
		Created:   time.Now().Add(-2 * time.Hour),
	}
	if err := s.Store().CreateNode(&stale); err != nil {
		t.Fatalf("CreateNode: %v", err)
	}
	if got := s.ReapEphemeral(time.Now()); got != 1 {
		t.Fatalf("reaped = %d, want 1", got)
	}

	event, ok := findAudit(t, s, identity.AuditNodeReaped)
	if !ok {
		t.Fatalf("audit log has no %s event: %+v", identity.AuditNodeReaped, auditEvents(t, s))
	}
	if event.Actor != "system" {
		t.Errorf("actor = %q, want system", event.Actor)
	}
	if want := "node:" + stale.StableID; event.Target != want {
		t.Errorf("target = %q, want %q", event.Target, want)
	}
}

func TestSetDNSIsAudited(t *testing.T) {
	s := newDNSAuthServer(t)
	hs := newTestHTTPServer(t, s)

	conn, client, nodeKey := registerNode(t, s, hs, "node-a")
	defer conn.Close()

	postRaw(t, client, "/machine/set-dns", tailcfg.SetDNSRequest{
		Version: tailcfg.CurrentCapabilityVersion,
		NodeKey: nodeKey.Public(),
		Name:    "notes.node-a.xunara.test.",
		Type:    "TXT",
		Value:   "hello",
	})

	event, ok := findAudit(t, s, identity.AuditDNSRecordSet)
	if !ok {
		t.Fatalf("audit log has no %s event: %+v", identity.AuditDNSRecordSet, auditEvents(t, s))
	}
	if event.Target != "dns:notes.node-a.xunara.test/TXT" {
		t.Errorf("target = %q", event.Target)
	}
	// The record value may be an ACME challenge secret and must not be
	// copied into the audit log.
	if event.Detail == "challenge-token" {
		t.Error("audit detail contains the DNS record value")
	}
}
