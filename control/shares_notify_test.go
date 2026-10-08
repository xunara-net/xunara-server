package control

import (
	"testing"
	"time"

	"tailscale.com/tailcfg"
	"tailscale.com/types/key"

	"github.com/xunara-net/xunara-server/state"
)

// assertWoken fails when no watch notification arrives.
func assertWoken(t *testing.T, ch <-chan struct{}, msg string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(2 * time.Second):
		t.Fatal(msg)
	}
}

// assertNotWoken fails when a notification is pending. Watch sends are
// synchronous and non-blocking, so a notification that should not happen is
// already visible when the assertion runs.
func assertNotWoken(t *testing.T, ch <-chan struct{}, msg string) {
	t.Helper()
	select {
	case <-ch:
		t.Fatal(msg)
	default:
	}
}

// TestShareNodeChangeWakesPeers pins spec section 38.6: node state visible to
// the other side of an accepted share wakes that side's netmap watchers, and
// nothing else does.
func TestShareNodeChangeWakesPeers(t *testing.T) {
	f := newShareFixture(t)

	acmeWake, cancelAcme := f.acme.watch()
	defer cancelAcme()

	// A purely local notification does not cross the organization boundary.
	f.globex.notifyWatchers()
	assertNotWoken(t, acmeWake, "a local notification woke a foreign organization")

	// Neither does an unrelated node of the sharee's organization.
	local := state.Node{
		MachineKey: key.NewMachine().Public(),
		NodeKey:    key.NewNode().Public(),
		UserID:     4242,
		Hostname:   "unrelated",
	}
	if err := f.globex.store.CreateNode(&local); err != nil {
		t.Fatalf("CreateNode(unrelated): %v", err)
	}
	f.globex.notifyNodePeers(local)
	assertNotWoken(t, acmeWake, "an unrelated node woke a foreign organization")

	// The sharee's node changes: the shared machine's organization is woken.
	f.globex.recordMapRequest(f.x, tailcfg.MapRequest{Version: f.x.CapVer + 1})
	assertWoken(t, acmeWake, "sharee node change did not wake the source organization")

	// The shared machine changes: the sharee's organization is woken.
	globexWake, cancelGlobex := f.globex.watch()
	defer cancelGlobex()
	f.acme.recordMapRequest(f.y, tailcfg.MapRequest{Version: f.y.CapVer + 1})
	assertWoken(t, globexWake, "shared machine change did not wake the target organization")
}

// TestShareNodeDeletionWakesPeers checks the deletion half: the remote side is
// woken and the peer is gone from a freshly built netmap.
func TestShareNodeDeletionWakesPeers(t *testing.T) {
	f := newShareFixture(t)

	globexWake, cancel := f.globex.watch()
	defer cancel()

	if err := f.acme.store.DeleteNode(f.y.ID); err != nil {
		t.Fatalf("DeleteNode: %v", err)
	}
	f.acme.notifyNodePeers(f.y)
	assertWoken(t, globexWake, "deleting a shared machine did not wake the target organization")

	if peers := f.globex.sharePeersFor(f.x); peers != nil {
		t.Fatalf("deleted machine still in the sharee netmap: %+v", peers.nodes)
	}
}

// TestShareDeleteWakesPeerWithoutSharing exercises the plain deployment path:
// notifyNodePeers must behave exactly like notifyWatchers when the server has
// no share registry.
func TestShareDeleteWakesPeerWithoutSharing(t *testing.T) {
	s := newServerWithConfig(t, Config{Domain: "example.com"})
	node := seedAPIMachine(t, s, "laptop", nil)

	wake, cancel := s.watch()
	defer cancel()
	s.notifyNodePeers(node)
	assertWoken(t, wake, "a local node change did not wake local watchers")
}
