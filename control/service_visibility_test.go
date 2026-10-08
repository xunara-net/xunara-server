package control

import (
	"net/http"
	"slices"
	"strings"
	"testing"

	"tailscale.com/tailcfg"

	"github.com/xunara-net/xunara-server/identity"
	"github.com/xunara-net/xunara-server/state"
)

// visibilityPolicy declares the tags service visibility selectors may
// reference: tag:app is claimed by the built-in local user.
const visibilityPolicy = `{
	"tagOwners": {"tag:app": ["local"]},
	"acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}],
}`

// serviceRecordNames lists the A records MagicDNS publishes for one node.
func serviceRecordNames(t *testing.T, s *Server, self state.Node) []string {
	t.Helper()
	var names []string
	for _, record := range s.extraDNSRecordsFor(self) {
		if record.Type == "A" {
			names = append(names, record.Name)
		}
	}
	return names
}

// TestServiceVisibilityFiltersDNS is the core of section 46: a service that
// declared selectors resolves only for the nodes those selectors name, while
// an unrestricted service keeps the v1 behavior (the whole organization).
func TestServiceVisibilityFiltersDNS(t *testing.T) {
	s := newServerWithConfig(t, Config{Domain: "example.com", PolicyPath: policyFile(t, visibilityPolicy)})
	hs := newTestHTTPServer(t, s)
	publisher := enrollServiceAgent(t, s, hs, "prod-1")
	allowed := seedAPIMachine(t, s, "app-1", []string{"tag:app"})
	other := seedAPIMachine(t, s, "other-1", nil)

	if _, status, raw := publishServices(t, s, hs, publisher, []agentService{
		{Name: "restricted", Protocol: "tcp", Port: 8443, Visibility: []string{"tag:app"}},
		{Name: "public", Protocol: "tcp", Port: 8080},
	}, nil); status != http.StatusOK {
		t.Fatalf("publish: %d (%s)", status, raw)
	}

	for _, tt := range []struct {
		name string
		self state.Node
		want []string
	}{
		{name: "publisher sees its own service", self: publisher.node, want: []string{"public.example.com", "restricted.example.com"}},
		{name: "selectors name the viewer", self: allowed, want: []string{"public.example.com", "restricted.example.com"}},
		{name: "unrelated node sees only the default", self: other, want: []string{"public.example.com"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got := serviceRecordNames(t, s, tt.self)
			if len(got) != len(tt.want) {
				t.Fatalf("records for %s = %v, want %v", tt.self.Hostname, got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Fatalf("records for %s = %v, want %v", tt.self.Hostname, got, tt.want)
				}
			}
		})
	}

	// The same filtering reaches the wire through the full netmap.
	full := s.fullMap(allowed, tailcfg.MapRequest{Version: tailcfg.CurrentCapabilityVersion})
	if names := dnsRecordNames(full); !slices.Contains(names, "restricted.example.com") {
		t.Errorf("allowed node netmap DNS = %v, want the restricted record", names)
	}
	full = s.fullMap(other, tailcfg.MapRequest{Version: tailcfg.CurrentCapabilityVersion})
	if names := dnsRecordNames(full); slices.Contains(names, "restricted.example.com") {
		t.Errorf("unrelated node netmap DNS = %v, must not contain the restricted record", names)
	}

	// Administration still sees the stored declaration, including its
	// selectors: visibility narrows discovery, it does not hide the service
	// from its owner.
	_, token := seedAPIKey(t, s, identity.ScopeRead)
	resp := apiRequest(t, noRedirectClient(), http.MethodGet, hs.URL+"/api/v2/services", token, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/v2/services = %d", resp.StatusCode)
	}
	body := bodyString(t, resp)
	if !strings.Contains(body, `"visibility":["tag:app"]`) {
		t.Errorf("admin view lacks the declared visibility: %s", body)
	}
	if !strings.Contains(body, `"visibility":["*"]`) {
		t.Errorf("admin view lacks the default visibility: %s", body)
	}
}

// dnsRecordNames lists the record names of a netmap response.
func dnsRecordNames(resp *tailcfg.MapResponse) []string {
	if resp.DNSConfig == nil {
		return nil
	}
	var names []string
	for _, record := range resp.DNSConfig.ExtraRecords {
		// Wire names are fully qualified; the control-plane view is not.
		names = append(names, strings.TrimSuffix(record.Name, "."))
	}
	slices.Sort(names)
	return names
}

// TestServiceVisibilityValidation pins the publish-time rules: selectors are
// checked against the loaded policy document, and a deployment without one
// accepts only the default.
func TestServiceVisibilityValidation(t *testing.T) {
	for _, tt := range []struct {
		name    string
		policy  string
		service agentService
		wantErr string
	}{
		{
			name:    "undeclared tag",
			policy:  visibilityPolicy,
			service: agentService{Name: "api", Protocol: "tcp", Port: 1, Visibility: []string{"tag:db"}},
			wantErr: "tag \"tag:db\" is not declared",
		},
		{
			name:    "undeclared group",
			policy:  visibilityPolicy,
			service: agentService{Name: "api", Protocol: "tcp", Port: 1, Visibility: []string{"group:eng"}},
			wantErr: "group \"group:eng\" is not declared",
		},
		{
			name:    "internet is not a source",
			policy:  visibilityPolicy,
			service: agentService{Name: "api", Protocol: "tcp", Port: 1, Visibility: []string{"autogroup:internet"}},
			wantErr: "only valid as a destination",
		},
		{
			name:    "empty selector",
			policy:  visibilityPolicy,
			service: agentService{Name: "api", Protocol: "tcp", Port: 1, Visibility: []string{" "}},
			wantErr: "selector is empty",
		},
		{
			name:    "selectors need a policy document",
			service: agentService{Name: "api", Protocol: "tcp", Port: 1, Visibility: []string{"tag:app"}},
			wantErr: "require a policy document",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Config{Domain: "example.com"}
			if tt.policy != "" {
				cfg.PolicyPath = policyFile(t, tt.policy)
			}
			s := newServerWithConfig(t, cfg)
			hs := newTestHTTPServer(t, s)
			agent := enrollServiceAgent(t, s, hs, "host")

			_, status, raw := publishServices(t, s, hs, agent, []agentService{tt.service}, nil)
			if status != http.StatusBadRequest {
				t.Fatalf("publish status = %d (%s), want 400", status, raw)
			}
			if !strings.Contains(raw, tt.wantErr) {
				t.Errorf("publish error = %s, want %q", raw, tt.wantErr)
			}
			if _, ok := s.store.GetServiceByName("api"); ok {
				t.Error("a rejected publish stored a service")
			}
		})
	}
}

// TestServiceVisibilityFailsClosedWithoutPolicy checks the upgrade path: a
// restricted service outlives the policy document that could resolve its
// selectors, and must not silently widen again.
func TestServiceVisibilityFailsClosedWithoutPolicy(t *testing.T) {
	s := newServerWithConfig(t, Config{Domain: "example.com", PolicyPath: policyFile(t, visibilityPolicy)})
	hs := newTestHTTPServer(t, s)
	publisher := enrollServiceAgent(t, s, hs, "prod-1")
	allowed := seedAPIMachine(t, s, "app-1", []string{"tag:app"})

	if _, status, raw := publishServices(t, s, hs, publisher, []agentService{
		{Name: "restricted", Protocol: "tcp", Port: 8443, Visibility: []string{"tag:app"}},
	}, nil); status != http.StatusOK {
		t.Fatalf("publish: %d (%s)", status, raw)
	}
	if names := serviceRecordNames(t, s, allowed); len(names) != 1 {
		t.Fatalf("records while the policy is loaded = %v, want the service", names)
	}

	// The watcher replaces the engine when the document is removed; simulate
	// that by dropping the compiled policy.
	s.policy.Store(nil)

	if names := serviceRecordNames(t, s, allowed); len(names) != 0 {
		t.Errorf("records without a policy = %v, want none (fail closed)", names)
	}
	if names := serviceRecordNames(t, s, publisher.node); len(names) != 1 {
		t.Errorf("publisher records without a policy = %v, want its own service", names)
	}
}
