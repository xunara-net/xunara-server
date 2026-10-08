package control

import (
	"context"
	"errors"
	"net/http"
	"path"
	"testing"

	"tailscale.com/tailcfg"
	"tailscale.com/types/key"

	"github.com/xunara-net/xunara-server/identity"
	"github.com/xunara-net/xunara-server/state"
)

// registerWithKey drives the auth-key registration path.
func registerWithKey(t *testing.T, s *Server, mk key.MachinePublic, nk key.NodePublic, secret, hostname string) (*tailcfg.RegisterResponse, error) {
	t.Helper()
	return s.handleRegister(context.Background(), tailcfg.RegisterRequest{
		Version:  tailcfg.CurrentCapabilityVersion,
		NodeKey:  nk,
		Auth:     &tailcfg.RegisterResponseAuth{AuthKey: secret},
		Hostinfo: &tailcfg.Hostinfo{Hostname: hostname},
	}, mk)
}

// TestRegisterWithAuthKeyRotatesNodeKeyInPlace checks that a machine
// re-registering with the same machine key but a new node key updates the
// existing node instead of registering a duplicate peer.
func TestRegisterWithAuthKeyRotatesNodeKeyInPlace(t *testing.T) {
	s := newTestServer(t)
	mk := key.NewMachine().Public()
	nk1 := key.NewNode().Public()

	secret := seedPreAuthKey(t, s, state.PreAuthKey{Reusable: true})

	resp, err := registerWithKey(t, s, mk, nk1, secret, "rotator")
	if err != nil {
		t.Fatalf("first registration: %v", err)
	}
	if !resp.MachineAuthorized {
		t.Fatalf("first registration not authorized: %+v", resp)
	}
	first, ok := s.store.GetNodeByNodeKey(nk1)
	if !ok {
		t.Fatal("first node was not created")
	}

	nk2 := key.NewNode().Public()
	resp, err = registerWithKey(t, s, mk, nk2, secret, "rotator")
	if err != nil {
		t.Fatalf("rotation registration: %v", err)
	}
	if !resp.MachineAuthorized {
		t.Fatalf("rotation not authorized: %+v", resp)
	}

	rotated, ok := s.store.GetNodeByNodeKey(nk2)
	if !ok {
		t.Fatal("node key rotation did not bind the new node key")
	}
	if rotated.ID != first.ID || rotated.StableID != first.StableID {
		t.Errorf("rotation changed node identity: ID %d→%d StableID %q→%q",
			first.ID, rotated.ID, first.StableID, rotated.StableID)
	}
	if rotated.IPv4 != first.IPv4 || rotated.IPv6 != first.IPv6 {
		t.Errorf("rotation changed addresses: %v/%v → %v/%v",
			first.IPv4, first.IPv6, rotated.IPv4, rotated.IPv6)
	}
	if _, ok := s.store.GetNodeByNodeKey(nk1); ok {
		t.Error("the superseded node key still resolves to a node")
	}
	if nodes := s.store.ListNodes(); len(nodes) != 1 {
		t.Errorf("node count = %d, want 1 (rotation must not duplicate)", len(nodes))
	}
	if _, ok := findAudit(t, s, identity.AuditNodeKeyRotated); !ok {
		t.Error("node.key_rotated audit event missing")
	}
}

// TestRegisterWithAuthKeyRotationRequiresValidKey checks that a spent
// single-use key cannot rotate a node key, and that the failure leaves the
// existing node untouched.
func TestRegisterWithAuthKeyRotationRequiresValidKey(t *testing.T) {
	s := newTestServer(t)
	mk := key.NewMachine().Public()
	nk1 := key.NewNode().Public()

	secret := seedPreAuthKey(t, s, state.PreAuthKey{})

	if _, err := registerWithKey(t, s, mk, nk1, secret, "rotator"); err != nil {
		t.Fatalf("first registration: %v", err)
	}

	nk2 := key.NewNode().Public()
	_, err := registerWithKey(t, s, mk, nk2, secret, "rotator")
	var he HTTPError
	if !errors.As(err, &he) || he.Code != http.StatusUnauthorized {
		t.Fatalf("spent key rotation err = %v, want 401", err)
	}

	if _, ok := s.store.GetNodeByNodeKey(nk1); !ok {
		t.Error("the existing node key stopped resolving after a rejected rotation")
	}
	if _, ok := s.store.GetNodeByNodeKey(nk2); ok {
		t.Error("rejected rotation still bound the new node key")
	}
	if nodes := s.store.ListNodes(); len(nodes) != 1 {
		t.Errorf("node count = %d, want 1", len(nodes))
	}
	if _, ok := findAudit(t, s, identity.AuditNodeKeyRotated); ok {
		t.Error("rejected rotation must not be audited as a rotation")
	}
}

// TestRegisterWithAuthKeyRotationTags covers the tag rules: a tagged key
// replaces the node's tags, an untagged key preserves them.
func TestRegisterWithAuthKeyRotationTags(t *testing.T) {
	s := newTestServer(t)
	mk := key.NewMachine().Public()

	tagged, err := state.NormalizeTags([]string{"tag:server"})
	if err != nil {
		t.Fatalf("NormalizeTags: %v", err)
	}
	firstKey := seedPreAuthKey(t, s, state.PreAuthKey{Reusable: true, Tags: tagged})
	untaggedKey := seedPreAuthKey(t, s, state.PreAuthKey{Reusable: true})

	nk1 := key.NewNode().Public()
	if _, err := registerWithKey(t, s, mk, nk1, firstKey, "tagged"); err != nil {
		t.Fatalf("tagged registration: %v", err)
	}
	node, _ := s.store.GetNodeByNodeKey(nk1)
	if len(node.Tags) != 1 || node.Tags[0] != "tag:server" {
		t.Fatalf("node tags = %v, want [tag:server]", node.Tags)
	}

	// An untagged key re-registering the tagged machine preserves its tags.
	nk2 := key.NewNode().Public()
	if _, err := registerWithKey(t, s, mk, nk2, untaggedKey, "tagged"); err != nil {
		t.Fatalf("untagged rotation: %v", err)
	}
	node, ok := s.store.GetNodeByNodeKey(nk2)
	if !ok {
		t.Fatal("rotation with untagged key did not bind the new node key")
	}
	if len(node.Tags) != 1 || node.Tags[0] != "tag:server" {
		t.Errorf("untagged key cleared tags: %v", node.Tags)
	}
}

// TestRegisterInteractiveRotatesNodeKeyInPlace checks the approval flow: a
// relogin on the same machine with a new node key keeps the node identity.
func TestRegisterInteractiveRotatesNodeKeyInPlace(t *testing.T) {
	s := newTestServer(t)
	mk := key.NewMachine().Public()

	nk1 := key.NewNode().Public()
	resp, err := s.handleRegister(context.Background(), tailcfg.RegisterRequest{
		Version:  tailcfg.CurrentCapabilityVersion,
		NodeKey:  nk1,
		Hostinfo: &tailcfg.Hostinfo{Hostname: "relogin"},
	}, mk)
	if err != nil {
		t.Fatalf("first interactive registration: %v", err)
	}
	if err := s.ApproveRegistration(path.Base(resp.AuthURL)); err != nil {
		t.Fatalf("ApproveRegistration: %v", err)
	}
	first, ok := s.store.GetNodeByNodeKey(nk1)
	if !ok {
		t.Fatal("first node was not created")
	}

	nk2 := key.NewNode().Public()
	resp2, err := s.handleRegister(context.Background(), tailcfg.RegisterRequest{
		Version:  tailcfg.CurrentCapabilityVersion,
		NodeKey:  nk2,
		Hostinfo: &tailcfg.Hostinfo{Hostname: "relogin"},
	}, mk)
	if err != nil {
		t.Fatalf("relogin registration: %v", err)
	}
	if resp2.AuthURL == "" {
		t.Fatalf("relogin must go through device approval, got %+v", resp2)
	}
	if err := s.ApproveRegistration(path.Base(resp2.AuthURL)); err != nil {
		t.Fatalf("approving relogin: %v", err)
	}

	rotated, ok := s.store.GetNodeByNodeKey(nk2)
	if !ok {
		t.Fatal("relogin did not bind the new node key")
	}
	if rotated.ID != first.ID || rotated.StableID != first.StableID {
		t.Errorf("relogin changed node identity: ID %d→%d StableID %q→%q",
			first.ID, rotated.ID, first.StableID, rotated.StableID)
	}
	if _, ok := s.store.GetNodeByNodeKey(nk1); ok {
		t.Error("the superseded node key still resolves after relogin")
	}
	if nodes := s.store.ListNodes(); len(nodes) != 1 {
		t.Errorf("node count = %d, want 1", len(nodes))
	}
	if _, ok := findAudit(t, s, identity.AuditNodeKeyRotated); !ok {
		t.Error("node.key_rotated audit event missing")
	}
}

// TestRegisterRotationRefusesAmbiguousOwnership seeds a machine key bound to
// two nodes (tagged plus user-owned) and checks that rotation is refused
// rather than picking one arbitrarily.
func TestRegisterRotationRefusesAmbiguousOwnership(t *testing.T) {
	s := newTestServer(t)
	mk := key.NewMachine().Public()

	tagged, err := state.NormalizeTags([]string{"tag:server"})
	if err != nil {
		t.Fatalf("NormalizeTags: %v", err)
	}
	secret := seedPreAuthKey(t, s, state.PreAuthKey{Reusable: true, Tags: tagged})

	first, err := registerWithKey(t, s, mk, key.NewNode().Public(), secret, "one")
	if err != nil || !first.MachineAuthorized {
		t.Fatalf("seeding tagged node: %v %+v", err, first)
	}

	// A second node for the same machine, user-owned, as a corrupt/legacy
	// store could hold it.
	second := state.Node{
		MachineKey: mk,
		NodeKey:    key.NewNode().Public(),
		UserID:     state.DefaultUserID,
		Method:     state.RegisterMethodInteractive,
	}
	if err := s.store.CreateNode(&second); err != nil {
		t.Fatalf("seeding second node: %v", err)
	}

	_, err = registerWithKey(t, s, mk, key.NewNode().Public(), secret, "ambiguous")
	var he HTTPError
	if !errors.As(err, &he) || he.Code != http.StatusConflict {
		t.Fatalf("ambiguous rotation err = %v, want 409", err)
	}
	if nodes := s.store.ListNodes(); len(nodes) != 2 {
		t.Errorf("node count = %d, want 2 (no node created, none rotated)", len(nodes))
	}
}
