package control

import (
	"context"
	"errors"
	"net/http"
	"path"
	"strings"
	"testing"
	"time"

	"tailscale.com/tailcfg"
	"tailscale.com/types/key"

	"github.com/xunara-net/xunara-server/identity"
	"github.com/xunara-net/xunara-server/state"
)

func TestHandleRegisterInteractiveApproveThenReRegister(t *testing.T) {
	s := newTestServer(t)
	mk := key.NewMachine().Public()
	nk := key.NewNode().Public()

	req := tailcfg.RegisterRequest{
		Version:  tailcfg.CurrentCapabilityVersion,
		NodeKey:  nk,
		Hostinfo: &tailcfg.Hostinfo{Hostname: "n1"},
	}

	resp, err := s.handleRegister(context.Background(), req, mk)
	if err != nil {
		t.Fatalf("handleRegister: %v", err)
	}
	if resp.MachineAuthorized {
		t.Fatal("first registration should not be authorized")
	}
	if resp.AuthURL == "" {
		t.Fatal("expected an AuthURL for interactive login")
	}

	if err := s.ApproveRegistration(path.Base(resp.AuthURL)); err != nil {
		t.Fatalf("ApproveRegistration: %v", err)
	}

	req.Followup = resp.AuthURL
	resp2, err := s.handleRegister(context.Background(), req, mk)
	if err != nil {
		t.Fatalf("follow-up handleRegister: %v", err)
	}
	if !resp2.MachineAuthorized {
		t.Fatalf("follow-up not authorized: %+v", resp2)
	}

	node, ok := s.store.GetNodeByNodeKey(nk)
	if !ok {
		t.Fatal("node was not created on approval")
	}
	if node.Hostname != "n1" {
		t.Errorf("hostname = %q, want n1", node.Hostname)
	}
	if node.MachineKey != mk {
		t.Error("node machine key does not match the registering session")
	}

	// A client restart re-registers with neither Auth nor Followup.
	resp3, err := s.handleRegister(context.Background(), tailcfg.RegisterRequest{
		Version: tailcfg.CurrentCapabilityVersion,
		NodeKey: nk,
	}, mk)
	if err != nil {
		t.Fatalf("re-register: %v", err)
	}
	if !resp3.MachineAuthorized {
		t.Fatalf("re-register not authorized: %+v", resp3)
	}
}

func TestHandleRegisterMachineKeyMismatch(t *testing.T) {
	s := newTestServer(t)

	nk := key.NewNode().Public()
	node := state.Node{
		MachineKey: key.NewMachine().Public(),
		NodeKey:    nk,
		Method:     state.RegisterMethodInteractive,
	}
	if err := s.store.CreateNode(&node); err != nil {
		t.Fatalf("seeding node: %v", err)
	}

	_, err := s.handleRegister(context.Background(), tailcfg.RegisterRequest{
		Version: tailcfg.CurrentCapabilityVersion,
		NodeKey: nk,
	}, key.NewMachine().Public())

	var he HTTPError
	if !errors.As(err, &he) || he.Code != http.StatusUnauthorized {
		t.Fatalf("err = %v, want 401 HTTPError", err)
	}
}

func TestHandleRegisterLogout(t *testing.T) {
	s := newTestServer(t)
	mk := key.NewMachine().Public()
	nk := key.NewNode().Public()

	node := state.Node{MachineKey: mk, NodeKey: nk, Method: state.RegisterMethodInteractive}
	if err := s.store.CreateNode(&node); err != nil {
		t.Fatalf("seeding node: %v", err)
	}

	resp, err := s.handleRegister(context.Background(), tailcfg.RegisterRequest{
		Version: tailcfg.CurrentCapabilityVersion,
		NodeKey: nk,
		Expiry:  time.Now().Add(-time.Hour),
	}, mk)
	if err != nil {
		t.Fatalf("logout handleRegister: %v", err)
	}
	if resp.NodeKeyExpired && !resp.MachineAuthorized && resp.Error != "" {
		t.Fatalf("unexpected error response: %+v", resp)
	}
	if _, ok := s.store.GetNodeByNodeKey(nk); ok {
		t.Fatal("node should be removed after logout")
	}
}

func TestRegisterWithPreAuthKey(t *testing.T) {
	s := newTestServer(t)

	secret := seedPreAuthKey(t, s, state.PreAuthKey{Ephemeral: true})

	machineKey := key.NewMachine().Public()
	nodeKey := key.NewNode().Public()

	resp, err := s.handleRegister(context.Background(), tailcfg.RegisterRequest{
		Version:  tailcfg.CurrentCapabilityVersion,
		NodeKey:  nodeKey,
		Auth:     &tailcfg.RegisterResponseAuth{AuthKey: secret},
		Hostinfo: &tailcfg.Hostinfo{Hostname: "pak-node"},
	}, machineKey)
	if err != nil {
		t.Fatalf("handleRegister: %v", err)
	}
	if !resp.MachineAuthorized {
		t.Fatalf("node was not authorized: %+v", resp)
	}

	node, ok := s.store.GetNodeByNodeKey(nodeKey)
	if !ok {
		t.Fatal("node was not created")
	}
	if node.Method != state.RegisterMethodAuthKey {
		t.Errorf("method = %q, want %q", node.Method, state.RegisterMethodAuthKey)
	}
	if !node.Ephemeral {
		t.Error("ephemeral flag from the key was not applied")
	}
	if node.Hostname != "pak-node" {
		t.Errorf("hostname = %q, want pak-node", node.Hostname)
	}

	// The key is single-use by default: a second node must be turned away.
	_, err = s.handleRegister(context.Background(), tailcfg.RegisterRequest{
		Version: tailcfg.CurrentCapabilityVersion,
		NodeKey: key.NewNode().Public(),
		Auth:    &tailcfg.RegisterResponseAuth{AuthKey: secret},
	}, key.NewMachine().Public())

	var he HTTPError
	if !errors.As(err, &he) || he.Code != http.StatusUnauthorized {
		t.Fatalf("second registration err = %v, want 401 HTTPError", err)
	}
}

func TestRegisterWithReusablePreAuthKey(t *testing.T) {
	s := newTestServer(t)

	secret := seedPreAuthKey(t, s, state.PreAuthKey{Reusable: true})

	for range 2 {
		if _, err := s.handleRegister(context.Background(), tailcfg.RegisterRequest{
			Version: tailcfg.CurrentCapabilityVersion,
			NodeKey: key.NewNode().Public(),
			Auth:    &tailcfg.RegisterResponseAuth{AuthKey: secret},
		}, key.NewMachine().Public()); err != nil {
			t.Fatalf("handleRegister: %v", err)
		}
	}

	if got := len(s.store.ListNodes()); got != 2 {
		t.Errorf("nodes = %d, want 2", got)
	}
}

func TestRegisterRejectsBadPreAuthKeys(t *testing.T) {
	s := newTestServer(t)

	expired := seedPreAuthKey(t, s, state.PreAuthKey{Expiry: time.Now().Add(-time.Hour)})

	tests := map[string]string{
		"unknown": "tskey-auth-0000000000000000000000000",
		"expired": expired,
	}

	for name, secret := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := s.handleRegister(context.Background(), tailcfg.RegisterRequest{
				Version: tailcfg.CurrentCapabilityVersion,
				NodeKey: key.NewNode().Public(),
				Auth:    &tailcfg.RegisterResponseAuth{AuthKey: secret},
			}, key.NewMachine().Public())

			var he HTTPError
			if !errors.As(err, &he) || he.Code != http.StatusUnauthorized {
				t.Fatalf("err = %v, want 401 HTTPError", err)
			}
		})
	}
}

// seedPreAuthKey stores a pre-auth key with a generated secret.
func seedPreAuthKey(t *testing.T, s *Server, template state.PreAuthKey) string {
	t.Helper()

	secret, err := state.NewPreAuthKeySecret()
	if err != nil {
		t.Fatalf("NewPreAuthKeySecret: %v", err)
	}

	template.Key = secret
	if template.UserID == 0 {
		template.UserID = state.DefaultUserID
	}
	if err := s.store.CreatePreAuthKey(&template); err != nil {
		t.Fatalf("CreatePreAuthKey: %v", err)
	}
	return secret
}

// TestRegisterReportsExpiredNodeKey checks the NodeKeyExpired signal the
// official client uses to regenerate its node key without waiting for a netmap
// (controlclient doLoginOrRegen). The machine stays authorized: only the key
// expired.
func TestRegisterReportsExpiredNodeKey(t *testing.T) {
	s := newServerWithConfig(t, Config{NodeKeyExpiry: time.Hour})
	mk := key.NewMachine().Public()
	nk := key.NewNode().Public()

	secret := seedPreAuthKey(t, s, state.PreAuthKey{})
	resp, err := s.handleRegister(context.Background(), tailcfg.RegisterRequest{
		Version:  tailcfg.CurrentCapabilityVersion,
		NodeKey:  nk,
		Hostinfo: &tailcfg.Hostinfo{Hostname: "expiring"},
		Auth:     &tailcfg.RegisterResponseAuth{AuthKey: secret},
	}, mk)
	if err != nil {
		t.Fatalf("handleRegister: %v", err)
	}
	if resp.NodeKeyExpired {
		t.Errorf("a fresh registration reports an expired node key: %+v", resp)
	}

	node, ok := s.store.GetNodeByNodeKey(nk)
	if !ok {
		t.Fatal("node was not created")
	}
	node.Expiry = time.Now().Add(-time.Minute)
	if err := s.store.UpdateNode(node); err != nil {
		t.Fatalf("UpdateNode: %v", err)
	}

	// A client restart re-registers with the expired key: the server must ask
	// for a replacement instead of silently keeping the dead key.
	resp2, err := s.handleRegister(context.Background(), tailcfg.RegisterRequest{
		Version: tailcfg.CurrentCapabilityVersion,
		NodeKey: nk,
	}, mk)
	if err != nil {
		t.Fatalf("re-register: %v", err)
	}
	if !resp2.NodeKeyExpired {
		t.Errorf("re-register with an expired key does not report it: %+v", resp2)
	}
	if !resp2.MachineAuthorized {
		t.Errorf("only the key expired, the machine stays authorized: %+v", resp2)
	}
	if resp2.AuthURL != "" {
		t.Errorf("an expired key must not silently turn into a new interactive login: %+v", resp2)
	}
}

// TestExpiredNodeKeyRegenerationRotatesInPlace walks the flow an official
// client performs after NodeKeyExpired: it generates a new node key, names the
// old one in OldNodeKey, and the human authorizes the login. The node keeps its
// identity (ID, stable ID, machine key) and gets a fresh expiry.
func TestExpiredNodeKeyRegenerationRotatesInPlace(t *testing.T) {
	s := newTestServer(t)
	mk := key.NewMachine().Public()
	oldKey := key.NewNode().Public()

	secret := seedPreAuthKey(t, s, state.PreAuthKey{})
	if _, err := s.handleRegister(context.Background(), tailcfg.RegisterRequest{
		Version:  tailcfg.CurrentCapabilityVersion,
		NodeKey:  oldKey,
		Hostinfo: &tailcfg.Hostinfo{Hostname: "rotating"},
		Auth:     &tailcfg.RegisterResponseAuth{AuthKey: secret},
	}, mk); err != nil {
		t.Fatalf("handleRegister: %v", err)
	}

	node, ok := s.store.GetNodeByNodeKey(oldKey)
	if !ok {
		t.Fatal("node was not created")
	}
	node.Expiry = time.Now().Add(-time.Minute)
	if err := s.store.UpdateNode(node); err != nil {
		t.Fatalf("UpdateNode: %v", err)
	}

	newKey := key.NewNode().Public()
	pending, err := s.handleRegister(context.Background(), tailcfg.RegisterRequest{
		Version:    tailcfg.CurrentCapabilityVersion,
		NodeKey:    newKey,
		OldNodeKey: oldKey,
	}, mk)
	if err != nil {
		t.Fatalf("regenerated registration: %v", err)
	}
	if pending.AuthURL == "" {
		t.Fatalf("the regenerated key is not registered, a login is needed: %+v", pending)
	}

	if err := s.ApproveRegistration(path.Base(pending.AuthURL)); err != nil {
		t.Fatalf("ApproveRegistration: %v", err)
	}

	rotated, ok := s.store.GetNodeByNodeKey(newKey)
	if !ok {
		t.Fatal("approval did not register the new node key")
	}
	if rotated.ID != node.ID || rotated.StableID != node.StableID || rotated.MachineKey != mk {
		t.Errorf("rotation changed the node identity: %+v, want id %d stable %s", rotated, node.ID, node.StableID)
	}
	if _, ok := s.store.GetNodeByNodeKey(oldKey); ok {
		t.Error("the old node key is still registered")
	}
	if rotated.Expired(time.Now()) {
		t.Errorf("the rotated node is still expired: %v", rotated.Expiry)
	}

	// The follow-up the client sends after approval authorizes the new key and
	// no longer asks for another one.
	follow, err := s.handleRegister(context.Background(), tailcfg.RegisterRequest{
		Version:  tailcfg.CurrentCapabilityVersion,
		NodeKey:  newKey,
		Followup: pending.AuthURL,
	}, mk)
	if err != nil {
		t.Fatalf("follow-up: %v", err)
	}
	if !follow.MachineAuthorized || follow.NodeKeyExpired {
		t.Errorf("follow-up = %+v, want authorized with a usable key", follow)
	}
}

// TestRegisterShortensNodeKeyExpiry covers the client-requested expiry change
// (upstream LocalBackend.SetExpirySooner): a node may only ever shorten its own
// key expiry, never extend it, and a node whose key never expires cannot opt
// into one.
func TestRegisterShortensNodeKeyExpiry(t *testing.T) {
	s := newServerWithConfig(t, Config{NodeKeyExpiry: 30 * 24 * time.Hour})
	mk := key.NewMachine().Public()
	nk := key.NewNode().Public()

	secret := seedPreAuthKey(t, s, state.PreAuthKey{})
	if _, err := s.handleRegister(context.Background(), tailcfg.RegisterRequest{
		Version:  tailcfg.CurrentCapabilityVersion,
		NodeKey:  nk,
		Hostinfo: &tailcfg.Hostinfo{Hostname: "short-lived"},
		Auth:     &tailcfg.RegisterResponseAuth{AuthKey: secret},
	}, mk); err != nil {
		t.Fatalf("handleRegister: %v", err)
	}

	node, ok := s.store.GetNodeByNodeKey(nk)
	if !ok {
		t.Fatal("node was not created")
	}
	original := node.Expiry
	if original.IsZero() {
		t.Fatal("the test needs a node with a finite expiry")
	}

	// Shortening is applied and audited.
	shorter := time.Now().Add(time.Hour).Round(time.Second)
	resp, err := s.handleRegister(context.Background(), tailcfg.RegisterRequest{
		Version: tailcfg.CurrentCapabilityVersion,
		NodeKey: nk,
		Expiry:  shorter,
	}, mk)
	if err != nil {
		t.Fatalf("shortening register: %v", err)
	}
	if !resp.MachineAuthorized {
		t.Errorf("shortening must not deauthorize the node: %+v", resp)
	}
	updated, ok := s.store.GetNodeByNodeKey(nk)
	if !ok {
		t.Fatal("node disappeared")
	}
	if !updated.Expiry.Equal(shorter) {
		t.Errorf("expiry = %v, want %v", updated.Expiry, shorter)
	}
	event, ok := findAudit(t, s, identity.AuditNodeExpiryShortened)
	if !ok {
		t.Fatal("shortening was not audited")
	}
	if event.Target != nodeTarget(updated) || !strings.Contains(event.Detail, shorter.UTC().Format(time.RFC3339)) {
		t.Errorf("audit event = %+v", event)
	}

	// Extending is refused instead of silently ignored.
	_, err = s.handleRegister(context.Background(), tailcfg.RegisterRequest{
		Version: tailcfg.CurrentCapabilityVersion,
		NodeKey: nk,
		Expiry:  time.Now().Add(365 * 24 * time.Hour),
	}, mk)
	var he HTTPError
	if !errors.As(err, &he) || he.Code != http.StatusBadRequest {
		t.Fatalf("extending error = %v, want 400 HTTPError", err)
	}
	after, ok := s.store.GetNodeByNodeKey(nk)
	if !ok {
		t.Fatal("node disappeared after a refused extension")
	}
	if !after.Expiry.Equal(shorter) {
		t.Errorf("expiry changed to %v after a refused extension, want %v", after.Expiry, shorter)
	}

	// A node whose key never expires cannot switch to one that does: its
	// lifetime is decided by tag ownership or by the deployment policy.
	forever := seedAPIMachine(t, s, "forever", []string{"tag:server"})
	if !forever.Expiry.IsZero() {
		t.Fatalf("tagged node expiry = %v, want zero", forever.Expiry)
	}
	_, err = s.handleRegister(context.Background(), tailcfg.RegisterRequest{
		Version: tailcfg.CurrentCapabilityVersion,
		NodeKey: forever.NodeKey,
		Expiry:  time.Now().Add(time.Hour),
	}, forever.MachineKey)
	if !errors.As(err, &he) || he.Code != http.StatusBadRequest {
		t.Fatalf("never-expiring node error = %v, want 400 HTTPError", err)
	}
}
