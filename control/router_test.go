package control

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"tailscale.com/control/controlhttp"
	"tailscale.com/control/ts2021"
	"tailscale.com/net/dnscache"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"

	"github.com/xunara-net/xunara-server/state"
)

// TestMain keeps a developer's HTTP proxy out of the way. The router tests
// dial fake login-server hostnames ("login.acme.example.com") at an httptest
// listener; without this, net/http's proxy resolution would send those
// requests to the ambient proxy instead of the test server. NO_PROXY is read
// once per process, so it has to be set before any test runs.
func TestMain(m *testing.M) {
	const fakeDomains = "example.com,example.net"
	if noProxy := os.Getenv("NO_PROXY"); !strings.Contains(noProxy, fakeDomains) {
		if noProxy != "" {
			noProxy += ","
		}
		os.Setenv("NO_PROXY", noProxy+fakeDomains)
	}
	os.Exit(m.Run())
}

// newTestRouter builds a Router and closes it when the test ends.
func newTestRouter(t *testing.T, cfg RouterConfig) *Router {
	t.Helper()

	r, err := NewRouter(cfg)
	if err != nil {
		t.Fatalf("NewRouter: %v", err)
	}
	t.Cleanup(func() { r.Close() })
	return r
}

// requestAtHost performs a GET with an explicit Host header, standing in for
// DNS pointing a login-server URL at this router.
func requestAtHost(t *testing.T, hs *httptest.Server, host, path string) *http.Response {
	t.Helper()

	req, err := http.NewRequest(http.MethodGet, hs.URL+path, nil)
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	req.Host = host

	resp, err := hs.Client().Do(req)
	if err != nil {
		t.Fatalf("GET %s (host %s): %v", path, host, err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

// fetchKeyAtHost retrieves the Noise public key served for one host.
func fetchKeyAtHost(t *testing.T, hs *httptest.Server, host string) key.MachinePublic {
	t.Helper()

	resp := requestAtHost(t, hs, host, "/key?v="+strconv.Itoa(int(tailcfg.CurrentCapabilityVersion)))
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("GET /key (host %s) status = %d (%s)", host, resp.StatusCode, body)
	}

	var pk tailcfg.OverTLSPublicKeyResponse
	if err := json.NewDecoder(resp.Body).Decode(&pk); err != nil {
		t.Fatalf("decoding /key response: %v", err)
	}
	return pk.PublicKey
}

// dialNoiseAtHost is dialNoise with the Host header of a known organization:
// the dialer still connects to the test listener, but the request carries the
// organization's login-server hostname, exactly like a real client.
func dialNoiseAtHost(t *testing.T, hs *httptest.Server, host string, machineKey key.MachinePrivate) net.Conn {
	t.Helper()

	u, err := url.Parse(hs.URL)
	if err != nil {
		t.Fatalf("parsing test server URL: %v", err)
	}

	d := &controlhttp.Dialer{
		Hostname:        host,
		MachineKey:      machineKey,
		ControlKey:      fetchKeyAtHost(t, hs, host),
		ProtocolVersion: uint16(tailcfg.CurrentCapabilityVersion),
		HTTPPort:        u.Port(),
		HTTPSPort:       controlhttp.NoPort,
		// The fake login-server hostname does not resolve; pin it to the test
		// listener (the custom Dialer below ignores the address anyway).
		DNSCache: &dnscache.Resolver{
			SingleHost:             host,
			SingleHostStaticResult: []netip.Addr{netip.MustParseAddr("127.0.0.1")},
		},
		Dialer: func(context.Context, string, string) (net.Conn, error) {
			return net.Dial("tcp", hs.Listener.Addr().String())
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := d.Dial(ctx)
	if err != nil {
		t.Fatalf("noise dial (host %s): %v", host, err)
	}

	nc := ts2021.NewConn(conn.Conn, func() {})
	if _, err := nc.GetEarlyPayload(ctx); err != nil {
		t.Fatalf("reading early noise payload: %v", err)
	}
	return nc
}

// registerPreAuthedNodeAtHost registers a node through one organization's
// login-server hostname.
func registerPreAuthedNodeAtHost(t *testing.T, hs *httptest.Server, host, hostname, secret string) (net.Conn, *http.Client, key.NodePrivate) {
	t.Helper()

	machineKey := key.NewMachine()
	nodeKey := key.NewNode()

	conn := dialNoiseAtHost(t, hs, host, machineKey)
	t.Cleanup(func() { conn.Close() })
	client := h2Client(conn)

	resp := decodeJSON[tailcfg.RegisterResponse](t, postRaw(t, client, "/machine/register", tailcfg.RegisterRequest{
		Version:  tailcfg.CurrentCapabilityVersion,
		NodeKey:  nodeKey.Public(),
		Auth:     &tailcfg.RegisterResponseAuth{AuthKey: secret},
		Hostinfo: &tailcfg.Hostinfo{Hostname: hostname},
	}))
	if !resp.MachineAuthorized {
		t.Fatalf("pre-authed registration was not authorized: %+v", resp)
	}
	return conn, client, nodeKey
}

// TestRouterDispatchesAndIsolatesOrganizations registers a node through one
// organization's host and checks it never appears in the other's store or
// netmap: tenant isolation is by construction, not by filtering.
func TestRouterDispatchesAndIsolatesOrganizations(t *testing.T) {
	acme := newServerWithConfig(t, Config{Domain: "acme.example.com"})
	globex := newServerWithConfig(t, Config{Domain: "globex.example.com"})

	router := newTestRouter(t, RouterConfig{Orgs: []OrgSite{
		{ID: "acme", Name: "Acme", Domains: []string{"login.acme.example.com"}, Server: acme},
		{ID: "globex", Name: "Globex", Domains: []string{"*.globex.example.com"}, Server: globex},
	}})
	hs := httptest.NewServer(router.Handler())
	t.Cleanup(hs.Close)

	acmeKey := fetchKeyAtHost(t, hs, "login.acme.example.com")
	if acmeKey != acme.NoisePublicKey() {
		t.Errorf("acme host served the wrong noise key")
	}
	wildcardKey := fetchKeyAtHost(t, hs, "login.globex.example.com")
	if wildcardKey != globex.NoisePublicKey() {
		t.Errorf("wildcard host served the wrong noise key")
	}
	if acmeKey == globex.NoisePublicKey() {
		t.Error("organizations share a noise key; they must not")
	}

	// Unknown hosts are refused with a non-enumerating 404.
	resp := requestAtHost(t, hs, "attacker.example.net", "/key")
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("unknown host status = %d, want 404", resp.StatusCode)
	}

	// Register a node in acme only.
	secret := seedPreAuthKey(t, acme, state.PreAuthKey{})
	_, client, nodeKey := registerPreAuthedNodeAtHost(t, hs, "login.acme.example.com", "acme-node", secret)

	if n := len(acme.Store().ListNodes()); n != 1 {
		t.Fatalf("acme nodes = %d, want 1", n)
	}
	if n := len(globex.Store().ListNodes()); n != 0 {
		t.Fatalf("globex nodes = %d, want 0 (tenant leak)", n)
	}
	if _, ok := globex.Store().GetNodeByNodeKey(nodeKey.Public()); ok {
		t.Fatal("acme's node key resolved in globex's store")
	}

	// The node's netmap works on its own host.
	netmap := decodeMapResponse(t, postRaw(t, client, "/machine/map", tailcfg.MapRequest{
		Version: tailcfg.CurrentCapabilityVersion,
		NodeKey: nodeKey.Public(),
	}), "")
	if netmap.Node == nil || !strings.HasPrefix(netmap.Node.Name, "acme-node.") {
		t.Errorf("acme netmap self = %+v, want acme-node", netmap.Node)
	}
}

// TestRouterSingleOrgFallback checks that a one-organization deployment without
// configured domains keeps serving every host, preserving single-tenant
// behaviour.
func TestRouterSingleOrgFallback(t *testing.T) {
	only := newServerWithConfig(t, Config{})
	router := newTestRouter(t, RouterConfig{Orgs: []OrgSite{{ID: "default", Name: "Default", Server: only}}})
	hs := httptest.NewServer(router.Handler())
	t.Cleanup(hs.Close)

	if got := fetchKeyAtHost(t, hs, "anything.example.test"); got != only.NoisePublicKey() {
		t.Error("single-org fallback served the wrong noise key")
	}

	// Process-level endpoints answer regardless of host.
	resp := requestAtHost(t, hs, "anything.example.test", "/health")
	if resp.StatusCode != http.StatusOK {
		t.Errorf("/health status = %d, want 200", resp.StatusCode)
	}
}

// TestNewRouterValidation rejects ambiguous or broken organization tables.
func TestNewRouterValidation(t *testing.T) {
	srv := newServerWithConfig(t, Config{})

	cases := []struct {
		name string
		cfg  RouterConfig
	}{
		{"no orgs", RouterConfig{}},
		{"missing id", RouterConfig{Orgs: []OrgSite{{Server: srv}}}},
		{"missing server", RouterConfig{Orgs: []OrgSite{{ID: "a", Domains: []string{"a.example.com"}}}}},
		{"duplicate id", RouterConfig{Orgs: []OrgSite{
			{ID: "a", Domains: []string{"a.example.com"}, Server: srv},
			{ID: "a", Domains: []string{"b.example.com"}, Server: srv},
		}}},
		{"duplicate domain", RouterConfig{Orgs: []OrgSite{
			{ID: "a", Domains: []string{"login.example.com"}, Server: srv},
			{ID: "b", Domains: []string{"LOGIN.example.com."}, Server: srv},
		}}},
		{"second org without domains", RouterConfig{Orgs: []OrgSite{
			{ID: "a", Domains: []string{"a.example.com"}, Server: srv},
			{ID: "b", Server: srv},
		}}},
		{"bad domain", RouterConfig{Orgs: []OrgSite{
			{ID: "a", Domains: []string{"https://a.example.com"}, Server: srv},
		}}},
		{"bare hostname domain", RouterConfig{Orgs: []OrgSite{
			{ID: "a", Domains: []string{"localhost"}, Server: srv},
		}}},
		{"wildcard with extra label", RouterConfig{Orgs: []OrgSite{
			{ID: "a", Domains: []string{"*.*.example.com"}, Server: srv},
		}}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewRouter(tc.cfg); err == nil {
				t.Fatal("NewRouter accepted an invalid configuration")
			}
		})
	}
}

// TestMatchRouterDomain pins the host-matching rules.
func TestMatchRouterDomain(t *testing.T) {
	cases := []struct {
		pattern string
		host    string
		want    bool
	}{
		{"login.example.com", "login.example.com", true},
		{"login.example.com", "other.example.com", false},
		{"*.example.com", "login.example.com", true},
		{"*.example.com", "example.com", false},
		{"*.example.com", "a.b.example.com", false},
		{"*.example.com", "login.example.com.evil.net", false},
	}
	for _, tc := range cases {
		if got := matchRouterDomain(tc.pattern, tc.host); got != tc.want {
			t.Errorf("matchRouterDomain(%q, %q) = %v, want %v", tc.pattern, tc.host, got, tc.want)
		}
	}
}

// TestNormalizeRouterHost pins Host-header canonicalization.
func TestNormalizeRouterHost(t *testing.T) {
	cases := map[string]string{
		"Login.Example.COM":     "login.example.com",
		"login.example.com:443": "login.example.com",
		"login.example.com.":    "login.example.com",
		"":                      "",
	}
	for in, want := range cases {
		if got := normalizeRouterHost(in); got != want {
			t.Errorf("normalizeRouterHost(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestPlatformAPI checks the cross-organization API: fail-closed when
// disabled, bearer-token auth, and org statistics.
func TestPlatformAPI(t *testing.T) {
	acme := newServerWithConfig(t, Config{Domain: "acme.example.com"})
	globex := newServerWithConfig(t, Config{})

	orgs := []OrgSite{
		{ID: "acme", Name: "Acme", Domains: []string{"login.acme.example.com"}, Server: acme},
		{ID: "globex", Name: "Globex", Domains: []string{"*.globex.example.com"}, Server: globex},
	}

	// Disabled: no platform token configured.
	disabled := newTestRouter(t, RouterConfig{Orgs: orgs})
	hsDisabled := httptest.NewServer(disabled.Handler())
	t.Cleanup(hsDisabled.Close)
	if resp := requestAtHost(t, hsDisabled, "login.acme.example.com", "/api/platform/v1/organizations"); resp.StatusCode != http.StatusForbidden {
		t.Errorf("disabled platform API status = %d, want 403", resp.StatusCode)
	}

	// Enabled: token required, wrong or org-scoped credentials rejected.
	router := newTestRouter(t, RouterConfig{Orgs: orgs, PlatformAdminToken: "platform-secret"})
	hs := httptest.NewServer(router.Handler())
	t.Cleanup(hs.Close)

	get := func(auth string) *http.Response {
		t.Helper()
		req, err := http.NewRequest(http.MethodGet, hs.URL+"/api/platform/v1/organizations", nil)
		if err != nil {
			t.Fatalf("building request: %v", err)
		}
		req.Host = "login.acme.example.com"
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		resp, err := hs.Client().Do(req)
		if err != nil {
			t.Fatalf("GET platform API: %v", err)
		}
		t.Cleanup(func() { resp.Body.Close() })
		return resp
	}

	if resp := get(""); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("no token status = %d, want 401", resp.StatusCode)
	}
	if resp := get("Bearer wrong"); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("wrong token status = %d, want 401", resp.StatusCode)
	}
	if resp := get("Bearer platform-secret"); resp.StatusCode != http.StatusOK {
		t.Errorf("valid token status = %d, want 200", resp.StatusCode)
	}

	// A session cookie from an organization's console must not unlock the
	// platform API (tenant-scoped credential).
	adminID := seedRoleUser(t, acme, "root", "owner")
	cookie, _ := seedUserSession(t, acme, adminID)
	req, err := http.NewRequest(http.MethodGet, hs.URL+"/api/platform/v1/organizations", nil)
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	req.Host = "login.acme.example.com"
	req.AddCookie(cookie)
	resp, err := hs.Client().Do(req)
	if err != nil {
		t.Fatalf("GET platform API with cookie: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("org session cookie status = %d, want 401", resp.StatusCode)
	}

	// Stats reflect the organization's own store.
	secret := seedPreAuthKey(t, acme, state.PreAuthKey{})
	registerPreAuthedNodeAtHost(t, hs, "login.acme.example.com", "platform-node", secret)

	resp = get("Bearer platform-secret")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list organizations status = %d", resp.StatusCode)
	}
	var list struct {
		Organizations []PlatformOrg `json:"organizations"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		t.Fatalf("decoding organizations: %v", err)
	}
	if len(list.Organizations) != 2 {
		t.Fatalf("organizations = %d, want 2", len(list.Organizations))
	}
	if got := list.Organizations[0]; got.ID != "acme" || got.Stats.Nodes != 1 || got.Stats.Users < 1 {
		t.Errorf("acme platform view = %+v, want 1 node and at least 1 user", got)
	}
	if got := list.Organizations[1]; got.ID != "globex" || got.Stats.Nodes != 0 {
		t.Errorf("globex platform view = %+v, want no nodes", got)
	}
}
