package control

import (
	"encoding/json"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xunara-net/xunara-server/identity"
	"github.com/xunara-net/xunara-server/state"
)

// decodeSecurity decodes GET /api/v2/security.
func decodeSecurity(t *testing.T, resp *http.Response) securityView {
	t.Helper()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("security status = %d, want 200", resp.StatusCode)
	}
	var view securityView
	if err := json.NewDecoder(resp.Body).Decode(&view); err != nil {
		t.Fatalf("decoding security view: %v", err)
	}
	return view
}

// findingIDs returns the findings' IDs in order.
func findingIDs(view securityView) []string {
	ids := make([]string, 0, len(view.Findings))
	for _, f := range view.Findings {
		ids = append(ids, f.ID)
	}
	return ids
}

// TestAPIV2SecuritySnapshot seeds every posture dimension and checks the
// counts, the findings and their deterministic order.
func TestAPIV2SecuritySnapshot(t *testing.T) {
	s := newTestServer(t)
	hs := newTestHTTPServer(t, s)
	client := noRedirectClient()

	if resp := apiRequest(t, client, http.MethodGet, hs.URL+"/api/v2/security", "", nil); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("anonymous security status = %d, want 401", resp.StatusCode)
	}
	_, token := seedAPIKey(t, s, identity.ScopeRead)

	now := time.Now().UTC()
	online := seedAPIMachine(t, s, "online", nil)
	online.Expiry = now.Add(10 * 24 * time.Hour)
	if err := s.store.UpdateNode(online); err != nil {
		t.Fatalf("UpdateNode(online): %v", err)
	}
	s.markOnline(online)
	defer s.markOffline(online)

	expired := seedAPIMachine(t, s, "expired", nil)
	expired.Expiry = now.Add(-time.Hour)
	if err := s.store.UpdateNode(expired); err != nil {
		t.Fatalf("UpdateNode(expired): %v", err)
	}
	seedAPIMachine(t, s, "tagged", []string{"tag:prod"})
	ephemeral := seedAPIMachine(t, s, "ephemeral", nil)
	ephemeral.Ephemeral = true
	if err := s.store.UpdateNode(ephemeral); err != nil {
		t.Fatalf("UpdateNode(ephemeral): %v", err)
	}
	exit := seedAPIMachine(t, s, "exit", nil)
	exit.ApprovedRoutes = []netip.Prefix{state.ExitRouteV4}
	if err := s.store.UpdateNode(exit); err != nil {
		t.Fatalf("UpdateNode(exit): %v", err)
	}

	// A pending device and a durable auth key, including one expired secret
	// that must never appear in the response.
	if _, err := s.Identity().CreateDeviceAuthorization(identity.NewDeviceAuthorizationOptions{
		MachineKey: "machine-pending", NodeKey: "node-pending",
	}); err != nil {
		t.Fatalf("CreateDeviceAuthorization: %v", err)
	}
	const authKeySecret = "tskey-auth-security-secret"
	past := now.Add(-time.Hour)
	unused := state.PreAuthKey{Key: authKeySecret, UserID: state.DefaultUserID, Expiry: past}
	if err := s.store.CreatePreAuthKey(&unused); err != nil {
		t.Fatalf("CreatePreAuthKey: %v", err)
	}

	resp := apiRequest(t, client, http.MethodGet, hs.URL+"/api/v2/security", token, nil)
	raw := bodyString(t, resp)
	if strings.Contains(raw, authKeySecret) {
		t.Fatalf("security response leaks an auth key:\n%s", raw)
	}
	if strings.Contains(raw, "node-pending") {
		t.Fatalf("security response leaks device metadata:\n%s", raw)
	}
	var view securityView
	if err := json.Unmarshal([]byte(raw), &view); err != nil {
		t.Fatalf("decoding security view: %v", err)
	}

	if view.GeneratedAt.IsZero() {
		t.Error("generatedAt missing")
	}
	if view.Nodes.Total != 5 || view.Nodes.Online != 1 || view.Nodes.Expired != 1 ||
		view.Nodes.ExpiringSoon != 1 || view.Nodes.Tagged != 1 || view.Nodes.Untagged != 4 ||
		view.Nodes.Ephemeral != 1 || view.Nodes.ExitNodes != 1 || view.Nodes.Unsigned != 5 {
		t.Errorf("node counts = %+v", view.Nodes)
	}
	if view.Devices.Pending != 1 {
		t.Errorf("pending devices = %d, want 1", view.Devices.Pending)
	}
	if view.AuthKeys.Total != 1 || view.AuthKeys.Expired != 1 || view.AuthKeys.Unused != 1 {
		t.Errorf("auth key counts = %+v", view.AuthKeys)
	}
	if view.APIKeys.Live != 1 || view.APIKeys.NeverExpires != 1 || view.APIKeys.Total != 1 {
		t.Errorf("api key counts = %+v", view.APIKeys)
	}
	if !view.Policy.Configured {
		// The bare server has no policy document; the open-policy finding must
		// say so.
		want := []string{"policy.absent", "nodes.expired_keys", "apikeys.never_expires", "nodes.keys_expiring", "devices.pending"}
		got := findingIDs(view)
		if len(got) != len(want) {
			t.Fatalf("findings = %v, want %v", got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("findings = %v, want %v", got, want)
			}
		}
	} else {
		t.Errorf("bare server reports a configured policy: %+v", view.Policy)
	}
	for _, f := range view.Findings {
		if f.Severity != securitySeverityHigh && f.Severity != securitySeverityMedium &&
			f.Severity != securitySeverityLow && f.Severity != securitySeverityInfo {
			t.Errorf("finding %s has unknown severity %q", f.ID, f.Severity)
		}
		if f.Title == "" || f.Detail == "" {
			t.Errorf("finding %s lacks text: %+v", f.ID, f)
		}
	}
	if view.Sharing.Enabled || view.Sharing.OutgoingPending != 0 || view.Sharing.IncomingAccepted != 0 {
		t.Errorf("sharing on a bare server = %+v, want disabled with zero counts", view.Sharing)
	}
	if view.Webhooks.Enabled || view.Webhooks.Configured != 0 {
		t.Errorf("webhooks = %+v, want disabled", view.Webhooks)
	}
}

// TestSecurityPolicyLoadError checks that a broken policy file is a high
// finding while the last good document stays in force.
func TestSecurityPolicyLoadError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.hujson")
	if err := os.WriteFile(path, []byte(`{"acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}]}`), 0o600); err != nil {
		t.Fatalf("writing policy: %v", err)
	}
	s := newServerWithConfig(t, Config{PolicyPath: path})

	if view := s.securityView(); !view.Policy.Configured || view.Policy.RuleCount != 1 || view.Policy.LoadError != "" {
		t.Fatalf("healthy policy view = %+v", view.Policy)
	}
	if err := os.WriteFile(path, []byte("{ this is not hujson"), 0o600); err != nil {
		t.Fatalf("breaking the policy: %v", err)
	}
	view := s.securityView()
	if !view.Policy.Configured || view.Policy.LoadError == "" {
		t.Fatalf("broken policy view = %+v", view.Policy)
	}
	if !strings.Contains(view.Policy.LoadError, "hujson") && !strings.Contains(view.Policy.LoadError, "parsing") {
		t.Errorf("load error is not a parse failure: %q", view.Policy.LoadError)
	}
	if len(view.Findings) == 0 || view.Findings[0].ID != "policy.load_error" || view.Findings[0].Severity != securitySeverityHigh {
		t.Errorf("findings = %+v, want policy.load_error first", view.Findings)
	}
}

// TestSecurityTailnetLockFinding checks the unsigned-node finding appears
// while lock is enforced and disappears once every node is signed.
func TestSecurityTailnetLockFinding(t *testing.T) {
	s := newTestServer(t)
	node := seedAPIMachine(t, s, "locked", nil)

	adminKey, genesis := newTestTKAKey(t)
	if err := s.tka.initBegin(genesis); err != nil {
		t.Fatalf("initBegin: %v", err)
	}
	if err := s.tka.enable(nil); err != nil {
		t.Fatalf("enable: %v", err)
	}
	view := s.securityView()
	if !view.TailnetLock.Enabled || view.TailnetLock.Nodes.Unsigned != 1 {
		t.Fatalf("lock counts = %+v", view.TailnetLock)
	}
	found := false
	for _, f := range view.Findings {
		if f.ID == "tka.unsigned_nodes" && f.Severity == securitySeverityHigh {
			found = true
		}
	}
	if !found {
		t.Errorf("findings = %v, want tka.unsigned_nodes", findingIDs(view))
	}

	stored := storedNode(t, s, node.NodeKey)
	stored.KeySignature = signTestNodeKey(t, adminKey, stored.NodeKey)
	if err := s.store.UpdateNode(stored); err != nil {
		t.Fatalf("UpdateNode: %v", err)
	}
	view = s.securityView()
	if view.TailnetLock.Nodes.Unsigned != 0 {
		t.Errorf("unsigned nodes after signing = %d, want 0", view.TailnetLock.Nodes.Unsigned)
	}
	for _, f := range view.Findings {
		if f.ID == "tka.unsigned_nodes" {
			t.Errorf("finding persisted after every node was signed")
		}
	}
}

// TestSecuritySharingCounts checks the share counters against the registry.
func TestSecuritySharingCounts(t *testing.T) {
	f := newShareFixture(t)

	acme := f.acme.securityView()
	if !acme.Sharing.Enabled || acme.Sharing.OutgoingAccepted != 1 || acme.Sharing.OutgoingPending != 0 ||
		acme.Sharing.IncomingAccepted != 0 || acme.Sharing.IncomingPending != 0 {
		t.Errorf("source sharing counts = %+v", acme.Sharing)
	}
	globex := f.globex.securityView()
	if !globex.Sharing.Enabled || globex.Sharing.IncomingAccepted != 1 || globex.Sharing.OutgoingAccepted != 0 {
		t.Errorf("target sharing counts = %+v", globex.Sharing)
	}
}

// TestConsoleSecurityPage checks the read-only page renders the snapshot and
// findings for any role, with no write surface.
func TestConsoleSecurityPage(t *testing.T) {
	s := newTestServer(t)
	hs := newTestHTTPServer(t, s)
	client := noRedirectClient()

	// Unauthenticated requests go to the login page.
	if resp := getRequest(t, client, hs.URL+"/console/security", nil); resp.StatusCode != http.StatusFound {
		t.Errorf("anonymous console status = %d, want 302", resp.StatusCode)
	}

	cookie := loginLocal(t, client, hs.URL, "/console/security")
	page := bodyString(t, getRequest(t, client, hs.URL+"/console/security", cookie))
	for _, want := range []string{"Security", "Findings", "policy.absent", "Node keys", "not configured (allow-all)"} {
		if !strings.Contains(page, want) {
			t.Errorf("security page lacks %q:\n%s", want, page)
		}
	}
	if strings.Contains(page, `action="/console/security"`) {
		t.Errorf("security page renders a form:\n%s", page)
	}

	// A member can read it too: security posture is not administration.
	member := seedRoleUser(t, s, "member@example.com", identity.RoleMember)
	memberCookie, _ := seedUserSession(t, s, member)
	resp := getRequest(t, client, hs.URL+"/console/security", memberCookie)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("member console status = %d, want 200", resp.StatusCode)
	}
	if !strings.Contains(bodyString(t, resp), "read-only") {
		t.Error("member page lacks the read-only banner")
	}
}
