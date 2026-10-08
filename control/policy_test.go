package control

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"tailscale.com/tailcfg"

	"github.com/xunara-net/xunara-server/identity"
)

// writePolicy writes an ACL document and returns its path.
func writePolicy(t *testing.T, dir, doc string) string {
	t.Helper()

	path := filepath.Join(dir, "policy.hujson")
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatalf("writing policy: %v", err)
	}
	return path
}

// TestPolicyReplacesAllowAll checks that a tailnet with a policy document sends
// the compiled rules instead of the default allow-all filter.
func TestPolicyReplacesAllowAll(t *testing.T) {
	dir := t.TempDir()
	path := writePolicy(t, dir, `{
		// only HTTPS to the whole tailnet
		"acls": [{"action": "accept", "src": ["*"], "dst": ["*:443"]}],
	}`)

	s := newServerWithConfig(t, Config{PolicyPath: path})
	hs := newTestHTTPServer(t, s)

	conn, client, nodeKey := registerNode(t, s, hs, "node-a")
	defer conn.Close()

	msg := decodeMapResponse(t, postRaw(t, client, "/machine/map", tailcfg.MapRequest{
		Version: tailcfg.CurrentCapabilityVersion,
		NodeKey: nodeKey.Public(),
	}), "")

	rules, ok := msg.PacketFilters["base"]
	if !ok {
		t.Fatalf("PacketFilters = %v, want a base entry", msg.PacketFilters)
	}
	if len(rules) != 1 {
		t.Fatalf("rules = %+v, want one", rules)
	}
	if rules[0].SrcIPs[0] != "*" {
		t.Errorf("SrcIPs = %v, want [*]", rules[0].SrcIPs)
	}
	if got := rules[0].DstPorts[0].Ports; got.First != 443 || got.Last != 443 {
		t.Errorf("ports = %+v, want 443", got)
	}
}

// TestPolicyReloadIsPushed checks that editing the policy file re-pushes the
// netmap, and that a policy which grants nothing clears the filter explicitly.
func TestPolicyReloadIsPushed(t *testing.T) {
	dir := t.TempDir()
	path := writePolicy(t, dir, `{"acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}]}`)

	s := newServerWithConfig(t, Config{PolicyPath: path})
	hs := newTestHTTPServer(t, s)

	conn, client, nodeKey := registerNode(t, s, hs, "node-a")
	defer conn.Close()

	sess := openMapSession(t, client, nodeKey.Public())
	defer sess.Body.Close()

	frames := mapFrames(sess.Body)
	view := newNetmapView()

	first := waitForNetmapFrame(t, frames, view, func(*netmapView) bool { return true })
	if rules := first.PacketFilters["base"]; len(rules) != 1 {
		t.Fatalf("initial rules = %+v, want the allow-all rule", rules)
	}

	// Deny everything, with a modification time clearly newer than the first
	// write (filesystem timestamps can be coarse).
	if err := os.WriteFile(path, []byte(`{}`), 0o600); err != nil {
		t.Fatalf("rewriting policy: %v", err)
	}
	future := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(path, future, future); err != nil {
		t.Fatalf("touching policy: %v", err)
	}

	update := waitForNetmapFrame(t, frames, view, func(*netmapView) bool { return true })
	rules, ok := update.PacketFilters["base"]
	if !ok {
		t.Fatalf("update has no base filter: %+v", update.PacketFilters)
	}
	if rules == nil {
		t.Error("an empty policy must be sent as an empty list, not null (null deletes the entry)")
	}
	if len(rules) != 0 {
		t.Errorf("rules = %+v, want none after the policy was emptied", rules)
	}

	if _, ok := findAudit(t, s, identity.AuditPolicyReloaded); !ok {
		t.Errorf("audit log has no %s event: %+v", identity.AuditPolicyReloaded, auditEvents(t, s))
	}
}

// TestBrokenPolicyKeepsTheOldRules checks the failure mode: a policy file that
// no longer parses must not silently open the tailnet.
func TestBrokenPolicyKeepsTheOldRules(t *testing.T) {
	dir := t.TempDir()
	path := writePolicy(t, dir, `{"acls": [{"action": "accept", "src": ["*"], "dst": ["*:443"]}]}`)

	s := newServerWithConfig(t, Config{PolicyPath: path})
	hs := newTestHTTPServer(t, s)

	conn, client, nodeKey := registerNode(t, s, hs, "node-a")
	defer conn.Close()

	if err := os.WriteFile(path, []byte(`{"acls": [{"action": "accept"`), 0o600); err != nil {
		t.Fatalf("rewriting policy: %v", err)
	}
	future := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(path, future, future); err != nil {
		t.Fatalf("touching policy: %v", err)
	}

	if err := s.loadPolicy(); err == nil {
		t.Fatal("expected an error loading a broken policy")
	}

	msg := decodeMapResponse(t, postRaw(t, client, "/machine/map", tailcfg.MapRequest{
		Version: tailcfg.CurrentCapabilityVersion,
		NodeKey: nodeKey.Public(),
	}), "")
	rules := msg.PacketFilters["base"]
	if len(rules) != 1 || rules[0].DstPorts[0].Ports.First != 443 {
		t.Errorf("rules = %+v, want the last valid policy to stay in force", rules)
	}
}

// TestInvalidPolicyFailsStartup checks that a policy rejected at load time
// stops the server from starting at all.
func TestInvalidPolicyFailsStartup(t *testing.T) {
	dir := t.TempDir()
	path := writePolicy(t, dir, `{"acls": [{"action": "accept", "src": ["group:nope"], "dst": ["*:*"]}]}`)

	if _, err := New(Config{StateDir: t.TempDir(), PolicyPath: path}); err == nil {
		t.Fatal("expected New to fail for a policy with an unknown group")
	}
}
