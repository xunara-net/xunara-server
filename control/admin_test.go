package control

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"

	"tailscale.com/types/key"

	"github.com/xunara-net/xunara-server/netspace"
	"github.com/xunara-net/xunara-server/plan"
	"github.com/xunara-net/xunara-server/state"
)

// newAdminTestRouter builds a router with one organization, a plan registry
// and the platform token, plus the config paths needed to talk to it.
func newAdminTestRouter(t *testing.T) (*Router, *PlanRegistry, string) {
	t.Helper()

	ctx := context.Background()
	dir := t.TempDir()

	const token = "test-platform-token"
	registry, err := OpenOrgRegistry(ctx, OrgRegistryConfig{
		Path:      dir + "/platform.db",
		StateRoot: dir + "/orgs",
		NewServer: func(org ManagedOrg, stateDir string) (*Server, error) {
			return New(Config{ServerURL: org.ServerURL, Domain: org.Domain, StateDir: stateDir})
		},
	})
	if err != nil {
		t.Fatalf("OpenOrgRegistry: %v", err)
	}
	t.Cleanup(func() { registry.Close() })

	pool, err := netspace.NewPool(netip.MustParsePrefix("100.100.0.0/24"), 24)
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}
	plans, err := OpenPlanRegistry(ctx, PlanRegistryConfig{Path: dir + "/plans.db", Pool: pool})
	if err != nil {
		t.Fatalf("OpenPlanRegistry: %v", err)
	}
	t.Cleanup(func() { plans.Close() })

	router, err := NewRouter(RouterConfig{
		ListenAddr:         "127.0.0.1:0",
		Orgs:               []OrgSite{{ID: "acme", Name: "Acme", Domains: []string{"login.acme.test"}, Server: newTestServer(t)}},
		PlatformAdminToken: token,
		Registry:           registry,
		Plans:              plans,
	})
	if err != nil {
		t.Fatalf("NewRouter: %v", err)
	}
	t.Cleanup(func() { router.Close() })
	return router, plans, token
}

// adminSignIn signs the test client in and returns its cookie jar.
func adminSignIn(t *testing.T, handler http.Handler, token string) *jar {
	t.Helper()
	recorder := httptest.NewRecorder()
	form := url.Values{"token": {token}}
	req := httptest.NewRequest(http.MethodPost, "http://platform.test/admin/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusFound {
		t.Fatalf("admin login = %d, want 302 (%s)", recorder.Code, recorder.Body.String())
	}
	jar := newJar()
	for _, cookie := range recorder.Result().Cookies() {
		jar.set(cookie)
	}
	return jar
}

// jar is a minimal cookie jar: the standard library's is in net/http/cookiejar,
// which the console tests already avoid pulling into every file.
type jar struct{ cookies map[string]*http.Cookie }

func newJar() *jar { return &jar{cookies: map[string]*http.Cookie{}} }

func (j *jar) set(cookie *http.Cookie) { j.cookies[cookie.Name] = cookie }

func (j *jar) apply(req *http.Request) {
	for _, cookie := range j.cookies {
		req.AddCookie(cookie)
	}
}

func TestAdminConsoleRequiresThePlatformToken(t *testing.T) {
	router, _, token := newAdminTestRouter(t)
	handler := router.Handler()

	// No session: every page redirects to the sign-in page.
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "http://platform.test/admin/", nil))
	if recorder.Code != http.StatusFound || recorder.Header().Get("Location") != "/admin/login" {
		t.Fatalf("unauthenticated /admin/ = %d %q, want a redirect to /admin/login", recorder.Code, recorder.Header().Get("Location"))
	}

	// A wrong token is refused.
	recorder = httptest.NewRecorder()
	form := url.Values{"token": {"not-the-token"}}
	req := httptest.NewRequest(http.MethodPost, "http://platform.test/admin/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("wrong token = %d, want 401", recorder.Code)
	}

	// A tenant session cookie is not a platform session.
	recorder = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "http://platform.test/admin/", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "tenant-session-token"})
	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusFound {
		t.Fatalf("tenant cookie on /admin/ = %d, want a redirect", recorder.Code)
	}

	// The right token signs in.
	jar := adminSignIn(t, handler, token)
	recorder = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "http://platform.test/admin/", nil)
	jar.apply(req)
	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("authenticated /admin/ = %d, want 200 (%s)", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "Acme") {
		t.Fatal("the overview does not list the hosted tenant")
	}
}

func TestAdminConsoleChangesAPlanAndNetwork(t *testing.T) {
	router, plans, token := newAdminTestRouter(t)
	handler := router.Handler()
	jar := adminSignIn(t, handler, token)

	csrf := ""

	// Load the tenants page to read the session's CSRF token.
	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://platform.test/admin/tenants", nil)
	jar.apply(req)
	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("tenants page = %d", recorder.Code)
	}
	for _, line := range strings.Split(recorder.Body.String(), "\n") {
		if strings.Contains(line, `name="csrf"`) {
			csrf = between(line, `value="`, `"`)
			break
		}
	}
	if csrf == "" {
		t.Fatal("the tenants page carries no CSRF token")
	}

	post := func(path string, values url.Values) *httptest.ResponseRecorder {
		values.Set("csrf", csrf)
		recorder := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "http://platform.test"+path, strings.NewReader(values.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		jar.apply(req)
		handler.ServeHTTP(recorder, req)
		return recorder
	}

	// A write without the token is refused.
	recorder = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "http://platform.test/admin/tenants/plan",
		strings.NewReader(url.Values{"org": {"acme"}, "plan": {plan.ProID}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	jar.apply(req)
	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("write without CSRF = %d, want 403", recorder.Code)
	}

	if got := post("/admin/tenants/plan", url.Values{"org": {"acme"}, "plan": {plan.ProID}}); got.Code != http.StatusFound {
		t.Fatalf("changing the plan = %d, want 302", got.Code)
	}
	if assigned := plans.Plan(context.Background(), "acme"); assigned.ID != plan.ProID {
		t.Fatalf("plan after the change = %q, want %q", assigned.ID, plan.ProID)
	}

	if got := post("/admin/tenants/network", url.Values{"org": {"acme"}, "network_prefix": {"100.101.44.0/24"}}); got.Code != http.StatusFound {
		t.Fatalf("setting the network = %d, want 302", got.Code)
	}
	prefix, ok := plans.NetworkPrefix(context.Background(), "acme")
	if !ok || prefix.String() != "100.101.44.0/24" {
		t.Fatalf("network after the change = %s (%v)", prefix, ok)
	}

	// The running control plane allocates from the new range.
	server := router.serverFor("acme")
	node := addTestNode(t, server)
	if !prefix.Contains(node.IPv4) {
		t.Fatalf("the tenant's next device got %s, outside %s", node.IPv4, prefix)
	}

	// An invalid range is reported, not stored.
	if got := post("/admin/tenants/network", url.Values{"org": {"acme"}, "network_prefix": {"127.0.0.0/24"}}); got.Code != http.StatusFound {
		t.Fatalf("invalid network = %d, want a redirect with a notice", got.Code)
	}
	if after, _ := plans.NetworkPrefix(context.Background(), "acme"); after != prefix {
		t.Fatalf("an invalid range rewrote the tenant's network to %s", after)
	}
}

func TestAdminConsolePlanEditor(t *testing.T) {
	router, plans, token := newAdminTestRouter(t)
	handler := router.Handler()
	jar := adminSignIn(t, handler, token)

	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://platform.test/admin/plans", nil)
	jar.apply(req)
	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("plans page = %d", recorder.Code)
	}
	body := recorder.Body.String()
	if !strings.Contains(body, "Plan editor") {
		t.Fatal("the plans page has no editor")
	}
	csrf := ""
	for _, line := range strings.Split(body, "\n") {
		if strings.Contains(line, `name="csrf"`) {
			csrf = between(line, `value="`, `"`)
			break
		}
	}

	form := url.Values{
		"csrf": {csrf}, "id": {"pro-plus"}, "name": {"Pro Plus"},
		"price_cents": {"2990"}, "currency": {"CNY"}, "billing_cycle": {"month"},
		"max_devices": {"80"}, "max_users": {"8"}, "max_routes": {""}, "max_auth_keys": {"40"},
		"allow_custom_cidr": {"on"}, "allow_exit_node": {"on"}, "allow_subnet_router": {"on"},
		"allow_api": {"on"}, "allow_acl": {"on"}, "allow_audit_log": {"on"}, "allow_multi_member": {"on"},
	}
	recorder = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "http://platform.test/admin/plans/save", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	jar.apply(req)
	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusFound {
		t.Fatalf("saving a plan = %d, want 302 (%s)", recorder.Code, recorder.Body.String())
	}

	stored, ok := plans.Catalog().Get("pro-plus")
	if !ok {
		t.Fatal("the new plan is not in the catalog")
	}
	if stored.MaxDevices != 80 || stored.MaxRoutes != plan.Unlimited || !stored.AllowExitNode {
		t.Fatalf("stored plan = %#v", stored)
	}

	// The editor's plan survives a restart: it is stored, not just in memory.
	plans.Close()
	reopened, err := OpenPlanRegistry(context.Background(), PlanRegistryConfig{
		Path: plans.cfg.Path, Pool: netspace.Pool{}, Reserved: nil,
	})
	if err != nil {
		t.Fatalf("reopening the registry: %v", err)
	}
	defer reopened.Close()
	if _, ok := reopened.Catalog().Get("pro-plus"); !ok {
		t.Fatal("the edited plan did not survive a reopen")
	}

	// The default plan cannot be deleted, and a plan without tenants can.
	if err := reopened.DeletePlan(context.Background(), plan.FreeID); !errors.Is(err, plan.ErrDefaultPlan) {
		t.Fatalf("deleting the default plan = %v, want ErrDefaultPlan", err)
	}
	if err := reopened.DeletePlan(context.Background(), "pro-plus"); err != nil {
		t.Fatalf("deleting an unused stored plan = %v, want success", err)
	}
}

// addTestNode registers one device directly in the store.
func addTestNode(t *testing.T, server *Server) state.Node {
	t.Helper()
	node := state.Node{
		NodeKey:    key.NewNode().Public(),
		MachineKey: key.NewMachine().Public(),
		Hostname:   "platform-node",
	}
	if err := server.store.CreateNode(&node); err != nil {
		t.Fatalf("CreateNode: %v", err)
	}
	return node
}

// between returns the text between two markers.
func between(s, start, end string) string {
	i := strings.Index(s, start)
	if i < 0 {
		return ""
	}
	s = s[i+len(start):]
	j := strings.Index(s, end)
	if j < 0 {
		return ""
	}
	return s[:j]
}
