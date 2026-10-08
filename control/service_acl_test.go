package control

import (
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/xunara-net/xunara-server/state"
)

// aclVisibilityPolicy grants the engineering group the production port, the
// whole organization 443, and everyone internet access (which must never leak
// into tailnet reachability).
const aclVisibilityPolicy = `{
	"groups": {"group:eng": ["eng@example.com"]},
	"tagOwners": {"tag:prod": ["eng@example.com"]},
	"acls": [
		{"action": "accept", "src": ["group:eng"], "dst": ["tag:prod:8080"]},
		{"action": "accept", "src": ["group:eng"], "dst": ["tag:prod:9090"], "proto": "tcp"},
		{"action": "accept", "src": ["*"], "dst": ["*:443"]},
		{"action": "accept", "src": ["*"], "dst": ["autogroup:internet:*"]}
	],
}`

// aclVisibilityFixture is a server with one tagged publisher and two clients:
// one in the engineering group, one outside it.
type aclVisibilityFixture struct {
	server *Server
	prod   state.Node
	eng    state.Node
	other  state.Node
}

func newACLVisibilityFixture(t *testing.T, doc string) *aclVisibilityFixture {
	t.Helper()

	cfg := Config{Domain: "example.com"}
	if doc != "" {
		cfg.PolicyPath = policyFile(t, doc)
	}
	s := newServerWithConfig(t, cfg)

	f := &aclVisibilityFixture{server: s}
	f.prod = seedAPIMachine(t, s, "prod-1", []string{"tag:prod"})

	engID := seedExternalUser(t, s, "eng@example.com", "test", "eng")
	f.eng = seedAPIMachine(t, s, "eng-laptop", nil)
	f.eng.UserID = engID
	if err := s.store.UpdateNode(f.eng); err != nil {
		t.Fatalf("UpdateNode(eng): %v", err)
	}
	f.other = seedAPIMachine(t, s, "other-phone", nil)
	return f
}

// TestACLDerivedVisibilityFiltersDNS checks the whole evaluation: a service
// that derives visibility from the ACL is discovered exactly by the nodes the
// packet filter would let connect.
func TestACLDerivedVisibilityFiltersDNS(t *testing.T) {
	f := newACLVisibilityFixture(t, aclVisibilityPolicy)
	publishStoreServices(t, f.server, f.prod.ID, []state.Service{
		{Name: "api", Protocol: "tcp", Port: 8080, VisibilityFromACL: true},
		{Name: "web", Protocol: "tcp", Port: 443, VisibilityFromACL: true},
		{Name: "metrics", Protocol: "udp", Port: 9090, VisibilityFromACL: true},
		{Name: "admin", Protocol: "tcp", Port: 9090, VisibilityFromACL: true},
	})

	// The publisher keeps its own services, whatever the ACL says.
	if names := serviceRecordNames(t, f.server, f.prod); len(names) != 4 {
		t.Errorf("publisher records = %v, want all four", names)
	}
	// The engineering group reaches 8080 and both 9090 protocols are bound by
	// protocol: the udp service is not reachable, the tcp one is. 443 is
	// granted to everyone.
	engNames := serviceRecordNames(t, f.server, f.eng)
	if !equalNameSet(engNames, []string{"api.example.com", "web.example.com", "admin.example.com"}) {
		t.Errorf("engineering records = %v, want api, web and admin", engNames)
	}
	// A node outside the group only gets the wildcard grant; internet access
	// never grants tailnet reachability.
	otherNames := serviceRecordNames(t, f.server, f.other)
	if !equalNameSet(otherNames, []string{"web.example.com"}) {
		t.Errorf("outsider records = %v, want only web", otherNames)
	}
}

// TestACLDerivedVisibilityFollowsPolicyAndNodes checks cache invalidation:
// both a policy reload and a node change (which identity it belongs to) must
// change the answer.
func TestACLDerivedVisibilityFollowsPolicyAndNodes(t *testing.T) {
	f := newACLVisibilityFixture(t, aclVisibilityPolicy)
	publishStoreServices(t, f.server, f.prod.ID, []state.Service{
		{Name: "api", Protocol: "tcp", Port: 8080, VisibilityFromACL: true},
	})

	if names := serviceRecordNames(t, f.server, f.other); len(names) != 0 {
		t.Fatalf("outsider records = %v, want none", names)
	}
	// Moving the node into the engineering user grants it the connection, and
	// therefore discovery.
	f.other.UserID = f.eng.UserID
	if err := f.server.store.UpdateNode(f.other); err != nil {
		t.Fatalf("UpdateNode(other): %v", err)
	}
	if names := serviceRecordNames(t, f.server, f.other); len(names) != 1 {
		t.Fatalf("records after the node joined the group = %v, want the service", names)
	}

	// Reloading a policy that no longer grants the port withdraws discovery.
	restricted := `{"groups": {"group:eng": ["eng@example.com"]}, "tagOwners": {"tag:prod": ["eng@example.com"]}, "acls": []}`
	if err := os.WriteFile(f.server.cfg.PolicyPath, []byte(restricted), 0o600); err != nil {
		t.Fatalf("writing policy: %v", err)
	}
	if err := f.server.loadPolicy(); err != nil {
		t.Fatalf("loadPolicy: %v", err)
	}
	if names := serviceRecordNames(t, f.server, f.eng); len(names) != 0 {
		t.Errorf("records after the policy stopped granting the port = %v, want none", names)
	}
}

// TestACLDerivedVisibilityWithoutPolicy checks the allow-all default: with no
// document every node reaches every node, so ACL-derived discovery is the
// organization default.
func TestACLDerivedVisibilityWithoutPolicy(t *testing.T) {
	f := newACLVisibilityFixture(t, "")
	publishStoreServices(t, f.server, f.prod.ID, []state.Service{
		{Name: "api", Protocol: "tcp", Port: 8080, VisibilityFromACL: true},
	})

	for _, self := range []state.Node{f.prod, f.eng, f.other} {
		if names := serviceRecordNames(t, f.server, self); len(names) != 1 {
			t.Errorf("records for %s without a policy = %v, want the service", self.Hostname, names)
		}
	}
}

// TestACLDerivedVisibilityPublishValidation checks the publish rules: the two
// visibility axes are mutually exclusive, and the accepted flag is reported on
// every read surface.
func TestACLDerivedVisibilityPublishValidation(t *testing.T) {
	s := newServerWithConfig(t, Config{Domain: "example.com", PolicyPath: policyFile(t, aclVisibilityPolicy)})
	hs := newTestHTTPServer(t, s)
	agent := enrollServiceAgent(t, s, hs, "prod-1")

	_, status, raw := publishServices(t, s, hs, agent, []agentService{
		{Name: "api", Protocol: "tcp", Port: 8080, VisibilityFromACL: true, Visibility: []string{"tag:prod"}},
	}, nil)
	if status != http.StatusBadRequest || !strings.Contains(raw, "cannot be combined") {
		t.Fatalf("mixed visibility status = %d (%s), want 400", status, raw)
	}
	if _, ok := s.store.GetServiceByName("api"); ok {
		t.Error("a rejected publish stored a service")
	}

	resp, status, raw := publishServices(t, s, hs, agent, []agentService{
		{Name: "api", Protocol: "tcp", Port: 8080, VisibilityFromACL: true},
	}, nil)
	if status != http.StatusOK {
		t.Fatalf("publish status = %d (%s)", status, raw)
	}
	if len(resp.Services) != 1 || !resp.Services[0].VisibilityFromACL {
		t.Errorf("published view = %+v, want visibilityFromACL", resp.Services)
	}
}

// equalNameSet compares two name/record lists as sets.
func equalNameSet(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	seen := make(map[string]bool, len(got))
	for _, name := range got {
		seen[name] = true
	}
	for _, name := range want {
		if !seen[name] {
			return false
		}
	}
	return true
}
