package control

import (
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"

	"tailscale.com/tailcfg"

	"github.com/xunara-net/xunara-server/identity"
	"github.com/xunara-net/xunara-server/state"
)

// servePolicy authorizes HTTPS serving for tag:server.
const servePolicy = `{
	"tagOwners": {"tag:server": ["local"]},
	"nodeAttrs": [{"target": ["tag:server"], "attr": ["https"]}],
}`

// serveFixture seeds the three postures the page has to tell apart: an
// authorized server, a device reporting Funnel, and a device asking for
// ingress wiring.
type serveFixture struct {
	server *Server
	serve  state.Node
	funnel state.Node
	wire   state.Node
}

func newServeFixture(t *testing.T, cfg Config) *serveFixture {
	t.Helper()

	cfg.PolicyPath = policyFile(t, servePolicy)
	if cfg.Domain == "" {
		cfg.Domain = "tailnet.test"
	}
	s := newServerWithConfig(t, cfg)
	f := &serveFixture{server: s}

	withHostinfo := func(node state.Node, info *tailcfg.Hostinfo) state.Node {
		t.Helper()
		node.Hostinfo = info
		if err := s.store.UpdateNode(node); err != nil {
			t.Fatalf("UpdateNode(%s): %v", node.Hostname, err)
		}
		return node
	}

	f.serve = withHostinfo(seedAPIMachine(t, s, "serve", []string{"tag:server"}),
		&tailcfg.Hostinfo{Hostname: "serve"})
	f.funnel = withHostinfo(seedAPIMachine(t, s, "funnel", nil),
		&tailcfg.Hostinfo{Hostname: "funnel", IngressEnabled: true})
	f.wire = withHostinfo(seedAPIMachine(t, s, "wire", nil),
		&tailcfg.Hostinfo{Hostname: "wire", WireIngress: true})
	seedAPIMachine(t, s, "plain", nil)
	return f
}

// TestServeView checks the join between the https grant, certificate domains
// and the Funnel/ingress reports.
func TestServeView(t *testing.T) {
	f := newServeFixture(t, Config{
		DNSProvider: &fakeDNSProvider{},
		CertDomains: []string{"serve.example.com"},
	})

	view := f.server.serveView()
	if !view.Certificates {
		t.Error("certificates = false with a DNS provider configured")
	}
	if view.FunnelSupported {
		t.Error("funnelSupported = true; this build runs no public ingress")
	}
	if !slices.Equal(view.CertDomains, []string{"serve.example.com"}) {
		t.Errorf("certDomains = %v, want the extra domain", view.CertDomains)
	}

	got := make([]string, 0, len(view.Nodes))
	for _, node := range view.Nodes {
		got = append(got, node.Hostname)
	}
	if want := []string{"serve", "funnel", "wire"}; !slices.Equal(got, want) {
		t.Fatalf("nodes = %v, want %v", got, want)
	}

	serve := view.Nodes[0]
	if !serve.Serve || serve.Funnel || serve.WantsIngress {
		t.Errorf("serve node = %+v, want only serve granted", serve)
	}
	wantDomains := []string{"serve.example.com", "serve.tailnet.test"}
	if !slices.Equal(serve.CertDomains, wantDomains) {
		t.Errorf("serve certDomains = %v, want %v", serve.CertDomains, wantDomains)
	}

	if funnel := view.Nodes[1]; funnel.Serve || !funnel.Funnel || funnel.WantsIngress {
		t.Errorf("funnel node = %+v, want funnel reported without a grant", funnel)
	}
	if wire := view.Nodes[2]; wire.Serve || wire.Funnel || !wire.WantsIngress {
		t.Errorf("wire node = %+v, want ingress wanted", wire)
	}
}

// TestServeViewWithoutCertificates checks that without a DNS provider the
// view says so and nodes report no certificate domains.
func TestServeViewWithoutCertificates(t *testing.T) {
	f := newServeFixture(t, Config{})

	view := f.server.serveView()
	if view.Certificates {
		t.Error("certificates = true without a DNS provider")
	}
	for _, node := range view.Nodes {
		if len(node.CertDomains) != 0 {
			t.Errorf("node %s certDomains = %v, want none", node.Hostname, node.CertDomains)
		}
	}
}

// TestAPIV2Serve checks the read-only HTTP surface.
func TestAPIV2Serve(t *testing.T) {
	f := newServeFixture(t, Config{DNSProvider: &fakeDNSProvider{}})
	hs := newTestHTTPServer(t, f.server)
	client := noRedirectClient()

	if resp := apiRequest(t, client, http.MethodGet, hs.URL+"/api/v2/serve", "", nil); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("anonymous status = %d, want 401", resp.StatusCode)
	}

	_, token := seedAPIKey(t, f.server, identity.ScopeRead)
	resp := apiRequest(t, client, http.MethodGet, hs.URL+"/api/v2/serve", token, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var view serveView
	if err := json.NewDecoder(resp.Body).Decode(&view); err != nil {
		t.Fatalf("decoding serve: %v", err)
	}
	if len(view.Nodes) != 3 || view.FunnelSupported {
		t.Errorf("view = %+v", view)
	}

	member := seedRoleUser(t, f.server, "member@example.com", identity.RoleMember)
	memberToken := seedAPIKeyForUser(t, f.server, member, identity.ScopeRead)
	if resp := apiRequest(t, client, http.MethodGet, hs.URL+"/api/v2/serve", memberToken, nil); resp.StatusCode != http.StatusOK {
		t.Errorf("member status = %d, want 200", resp.StatusCode)
	}
}

// TestConsoleServe checks the console page renders the postures, explains the
// Funnel decision and stays read-only for every role.
func TestConsoleServe(t *testing.T) {
	f := newServeFixture(t, Config{DNSProvider: &fakeDNSProvider{}})
	hs := newTestHTTPServer(t, f.server)
	client := noRedirectClient()
	cookie := loginLocal(t, client, hs.URL, "/console/serve")

	page := bodyString(t, getRequest(t, client, hs.URL+"/console/serve", cookie))
	for _, want := range []string{
		"Serve", "DNS provider configured", "not supported", "https granted",
		"funnel reported", "requests ingress wiring", "serve.tailnet.test",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("serve page lacks %q:\n%s", want, page)
		}
	}
	if strings.Contains(page, `action="/console/serve"`) {
		t.Errorf("page renders a form:\n%s", page)
	}

	member := seedRoleUser(t, f.server, "member@example.com", identity.RoleMember)
	memberCookie, _ := seedUserSession(t, f.server, member)
	if resp := getRequest(t, client, hs.URL+"/console/serve", memberCookie); resp.StatusCode != http.StatusOK {
		t.Errorf("member page status = %d, want 200", resp.StatusCode)
	}
}
