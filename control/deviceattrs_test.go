package control

import (
	"context"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"tailscale.com/tailcfg"
	"tailscale.com/types/key"

	"github.com/xunara-net/xunara-server/identity"
	"github.com/xunara-net/xunara-server/state"
)

// setDeviceAttrs sends one PATCH to the inner endpoint and returns the status.
func setDeviceAttrs(t *testing.T, client *http.Client, nodeKey key.NodePublic, update tailcfg.AttrUpdate) ([]byte, int) {
	t.Helper()

	return doRaw(t, client, http.MethodPatch, "/machine/set-device-attr", tailcfg.SetDeviceAttributesRequest{
		Version: tailcfg.CurrentCapabilityVersion,
		NodeKey: nodeKey,
		Update:  update,
	})
}

// storedDeviceAttrs reads a node's attributes straight from the store.
func storedDeviceAttrs(t *testing.T, s *Server, nodeKey key.NodePublic) map[string]any {
	t.Helper()

	node := storedNode(t, s, nodeKey)
	attrs, err := s.store.NodeDeviceAttrs(node.ID)
	if err != nil {
		t.Fatalf("NodeDeviceAttrs: %v", err)
	}
	return attrs
}

// deviceAttrStores returns one fresh store of each implementation, for tests
// that check behaviour both must share.
func deviceAttrStores(t *testing.T) map[string]state.Store {
	t.Helper()

	sqlite, err := state.OpenSQLite(context.Background(), filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("OpenSQLite: %v", err)
	}
	t.Cleanup(func() { sqlite.Close() })

	return map[string]state.Store{"memory": state.NewMemoryStore(), "sqlite": sqlite}
}

// TestSetDeviceAttrsRoundTrip checks the happy path: an update is stored,
// merges with what is already there, deletes with a null value, and is
// auditable without writing the values anywhere durable.
func TestSetDeviceAttrsRoundTrip(t *testing.T) {
	s := newServerWithConfig(t, Config{})
	hs := newTestHTTPServer(t, s)

	conn, client, nodeKey := registerNode(t, s, hs, "posture")
	defer conn.Close()

	if body, status := setDeviceAttrs(t, client, nodeKey.Public(), tailcfg.AttrUpdate{
		"os_version":   "15.2",
		"disk_encrypt": true,
		"score":        float64(7.5),
	}); status != http.StatusOK {
		t.Fatalf("set-device-attr status = %d (%s), want 200", status, body)
	}

	attrs := storedDeviceAttrs(t, s, nodeKey.Public())
	if len(attrs) != 3 || attrs["os_version"] != "15.2" || attrs["disk_encrypt"] != true || attrs["score"] != float64(7.5) {
		t.Fatalf("stored attributes = %#v", attrs)
	}

	// An update only touches the attributes it names.
	if _, status := setDeviceAttrs(t, client, nodeKey.Public(), tailcfg.AttrUpdate{"os_version": "15.3"}); status != http.StatusOK {
		t.Fatalf("second update status = %d, want 200", status)
	}
	attrs = storedDeviceAttrs(t, s, nodeKey.Public())
	if len(attrs) != 3 || attrs["os_version"] != "15.3" || attrs["disk_encrypt"] != true {
		t.Fatalf("attributes after update = %#v", attrs)
	}

	// A null value removes the attribute; the rest survives.
	if _, status := setDeviceAttrs(t, client, nodeKey.Public(), tailcfg.AttrUpdate{"disk_encrypt": nil}); status != http.StatusOK {
		t.Fatalf("delete status = %d, want 200", status)
	}
	attrs = storedDeviceAttrs(t, s, nodeKey.Public())
	if _, ok := attrs["disk_encrypt"]; ok || len(attrs) != 2 {
		t.Fatalf("attributes after delete = %#v", attrs)
	}

	// Deleting an attribute that does not exist is a no-op, and an empty
	// update is accepted.
	for _, update := range []tailcfg.AttrUpdate{{"never_set": nil}, {}} {
		if _, status := setDeviceAttrs(t, client, nodeKey.Public(), update); status != http.StatusOK {
			t.Fatalf("no-op update status = %d, want 200", status)
		}
	}
	if attrs := storedDeviceAttrs(t, s, nodeKey.Public()); len(attrs) != 2 {
		t.Errorf("no-op updates changed the set: %#v", attrs)
	}

	// The audit log names the attributes that changed, never their values.
	var (
		found  bool
		detail strings.Builder
	)
	for _, event := range s.identity.ListAudit(0) {
		if event.Action != identity.AuditDeviceAttrsUpdated {
			continue
		}
		found = true
		detail.WriteString(event.Detail)
		detail.WriteString("\n")
	}
	if !found {
		t.Fatalf("no %s audit event was recorded", identity.AuditDeviceAttrsUpdated)
	}
	if !strings.Contains(detail.String(), "os_version") || !strings.Contains(detail.String(), "disk_encrypt") {
		t.Errorf("audit details do not name the changed attributes:\n%s", detail.String())
	}
	for _, value := range []string{"15.2", "15.3", "7.5"} {
		if strings.Contains(detail.String(), value) {
			t.Errorf("audit details contain the value %q:\n%s", value, detail.String())
		}
	}
}

// TestSetDeviceAttrsIsNodeBound checks that a node can only write its own
// attributes: another node's key on a registered session, and an unregistered
// session, both fail.
func TestSetDeviceAttrsIsNodeBound(t *testing.T) {
	s := newServerWithConfig(t, Config{})
	hs := newTestHTTPServer(t, s)

	conn, client, nodeKey := registerNode(t, s, hs, "owner")
	defer conn.Close()
	otherConn, _, otherKey := registerNode(t, s, hs, "other")
	defer otherConn.Close()

	if body, status := setDeviceAttrs(t, client, otherKey.Public(), tailcfg.AttrUpdate{"spoofed": "yes"}); status != http.StatusNotFound {
		t.Fatalf("cross-node update status = %d (%s), want 404", status, body)
	}
	if attrs := storedDeviceAttrs(t, s, otherKey.Public()); len(attrs) != 0 {
		t.Errorf("cross-node update stored %#v", attrs)
	}

	strangerConn := dialNoise(t, hs, key.NewMachine())
	defer strangerConn.Close()
	if _, status := setDeviceAttrs(t, h2Client(strangerConn), nodeKey.Public(), tailcfg.AttrUpdate{"spoofed": "yes"}); status != http.StatusNotFound {
		t.Errorf("unregistered session status = %d, want 404", status)
	}

	// The version gate applies before anything is stored.
	if _, status := doRaw(t, client, http.MethodPatch, "/machine/set-device-attr", tailcfg.SetDeviceAttributesRequest{
		Version: MinSupportedCapabilityVersion - 1,
		NodeKey: nodeKey.Public(),
		Update:  tailcfg.AttrUpdate{"x": "y"},
	}); status != http.StatusBadRequest {
		t.Errorf("unsupported version status = %d, want 400", status)
	}
	if attrs := storedDeviceAttrs(t, s, nodeKey.Public()); len(attrs) != 0 {
		t.Errorf("rejected requests stored %#v", attrs)
	}
}

// TestSetDeviceAttrsValidation checks that anything this build cannot store is
// refused with 400 instead of being silently dropped.
func TestSetDeviceAttrsValidation(t *testing.T) {
	s := newServerWithConfig(t, Config{})
	hs := newTestHTTPServer(t, s)

	conn, client, nodeKey := registerNode(t, s, hs, "validation")
	defer conn.Close()

	for name, update := range map[string]tailcfg.AttrUpdate{
		"empty name":        {"": "x"},
		"name with space":   {"os version": "x"},
		"name with newline": {"os\nversion": "x"},
		"name too long":     {strings.Repeat("a", maxDeviceAttrNameLen+1): "x"},
		"value too long":    {"os_version": strings.Repeat("a", maxDeviceAttrValueLen+1)},
		"value with NULL":   {"os_version": "a\x00b"},
		"object value":      {"nested": map[string]any{"a": "b"}},
		"array value":       {"list": []any{"a"}},
	} {
		body, status := setDeviceAttrs(t, client, nodeKey.Public(), update)
		if status != http.StatusBadRequest {
			t.Errorf("%s status = %d (%s), want 400", name, status, body)
			continue
		}
		if attrs := storedDeviceAttrs(t, s, nodeKey.Public()); len(attrs) != 0 {
			t.Errorf("%s stored %#v", name, attrs)
		}
	}

	// An update that would grow the set past the limit is refused as a whole:
	// attributes are not partially applied.
	full := make(tailcfg.AttrUpdate, maxDeviceAttrs)
	for i := range maxDeviceAttrs {
		full[string(rune('a'+i%26))+strings.Repeat("x", i/26)] = float64(i)
	}
	if _, status := setDeviceAttrs(t, client, nodeKey.Public(), full); status != http.StatusOK {
		t.Fatalf("filling the set status = %d, want 200", status)
	}
	if _, status := setDeviceAttrs(t, client, nodeKey.Public(), tailcfg.AttrUpdate{"one_more": "x"}); status != http.StatusBadRequest {
		t.Errorf("overflowing update status = %d, want 400", status)
	}
	// Deleting while over the limit is fine (that is how a node gets back
	// under it).
	if _, status := setDeviceAttrs(t, client, nodeKey.Public(), tailcfg.AttrUpdate{"a": nil}); status != http.StatusOK {
		t.Errorf("deleting from a full set status = %d, want 200", status)
	}

	// The encoded size of the whole set is bounded too.
	s2 := newServerWithConfig(t, Config{})
	hs2 := newTestHTTPServer(t, s2)
	conn2, client2, nodeKey2 := registerNode(t, s2, hs2, "bulk")
	defer conn2.Close()

	bulk := make(tailcfg.AttrUpdate, 32)
	for i := range 32 {
		bulk[string(rune('a'+i%26))+strings.Repeat("y", i/26)] = strings.Repeat("v", maxDeviceAttrValueLen)
	}
	if _, status := setDeviceAttrs(t, client2, nodeKey2.Public(), bulk); status != http.StatusBadRequest {
		t.Errorf("oversized set status = %d, want 400", status)
	}

	// A single update cannot carry an arbitrary number of entries, even when
	// they are all deletions that would leave the set small.
	huge := make(tailcfg.AttrUpdate, maxDeviceAttrUpdateEntries+1)
	for i := range maxDeviceAttrUpdateEntries + 1 {
		huge[string(rune('a'+i%26))+strings.Repeat("z", i/26)] = nil
	}
	if _, status := setDeviceAttrs(t, client2, nodeKey2.Public(), huge); status != http.StatusBadRequest {
		t.Errorf("oversized update status = %d, want 400", status)
	}
}

// TestSetDeviceAttrsAuditsKeysOnly checks the detail format directly, without
// going through a session.
func TestDeviceAttrAuditDetail(t *testing.T) {
	got := deviceAttrAuditDetail(tailcfg.AttrUpdate{"b": "1", "a": true, "gone": nil})
	if got != "set a, b; deleted gone" {
		t.Errorf("detail = %q, want sorted set/delete lists", got)
	}
	got = deviceAttrAuditDetail(tailcfg.AttrUpdate{"only": nil})
	if got != "deleted only" {
		t.Errorf("detail = %q", got)
	}
	if got := deviceAttrAuditDetail(nil); got != "" {
		t.Errorf("detail of an empty update = %q, want empty", got)
	}
}

// TestNodeDeletionDropsDeviceAttrs checks the store contract: attributes
// belong to the node and disappear with it.
func TestNodeDeletionDropsDeviceAttrs(t *testing.T) {
	for name, store := range deviceAttrStores(t) {
		t.Run(name, func(t *testing.T) {
			node := state.Node{Hostname: "attrs", NodeKey: key.NewNode().Public()}
			if err := store.CreateNode(&node); err != nil {
				t.Fatalf("CreateNode: %v", err)
			}
			if err := store.SetNodeDeviceAttrs(node.ID, map[string]any{"a": "1", "b": true}); err != nil {
				t.Fatalf("SetNodeDeviceAttrs: %v", err)
			}
			if err := store.SetNodeDeviceAttrs(node.ID, map[string]any{"a": nil}); err != nil {
				t.Fatalf("SetNodeDeviceAttrs(delete): %v", err)
			}
			attrs, err := store.NodeDeviceAttrs(node.ID)
			if err != nil {
				t.Fatalf("NodeDeviceAttrs: %v", err)
			}
			if len(attrs) != 1 || attrs["b"] != true {
				t.Fatalf("attributes = %#v", attrs)
			}
			counts, err := store.NodeDeviceAttrCounts()
			if err != nil {
				t.Fatalf("NodeDeviceAttrCounts: %v", err)
			}
			if counts[node.ID] != 1 {
				t.Errorf("counts = %#v, want 1 for node %d", counts, node.ID)
			}

			if err := store.DeleteNode(node.ID); err != nil {
				t.Fatalf("DeleteNode: %v", err)
			}
			if attrs, err := store.NodeDeviceAttrs(node.ID); err != nil || len(attrs) != 0 {
				t.Errorf("attributes after node deletion = %#v (err %v)", attrs, err)
			}
			counts, err = store.NodeDeviceAttrCounts()
			if err != nil {
				t.Fatalf("NodeDeviceAttrCounts: %v", err)
			}
			if counts[node.ID] != 0 {
				t.Errorf("counts after node deletion = %#v", counts)
			}
		})
	}
}

// TestSetDeviceAttrsUnknownNode checks the store's own guard: the HTTP path
// validates the node first, so this is the boundary a future caller hits.
func TestSetDeviceAttrsUnknownNode(t *testing.T) {
	for name, store := range deviceAttrStores(t) {
		t.Run(name, func(t *testing.T) {
			if err := store.SetNodeDeviceAttrs(state.NodeID(99), map[string]any{"a": "1"}); err == nil {
				t.Error("SetNodeDeviceAttrs accepted an unknown node")
			}
		})
	}
}
