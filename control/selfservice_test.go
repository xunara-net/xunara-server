package control

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/xunara-net/xunara-server/identity"
	"github.com/xunara-net/xunara-server/netspace"
	"github.com/xunara-net/xunara-server/plan"
	"github.com/xunara-net/xunara-server/state"
	"tailscale.com/tailcfg"
)

// selfServiceRouter builds the hosted shape: a front door at app.xunara.test,
// another tenant at acme.xunara.test, platform-managed organizations and a
// plan catalog with a network pool behind them.
func selfServiceRouter(t *testing.T, cfg *SelfServiceConfig, prepare ...func(*PlanRegistry)) (*Router, *PlanRegistry) {
	t.Helper()
	return selfServiceRouterWith(t, selfServiceTestOptions{cfg: cfg}, prepare...)
}

// selfServiceTestOptions lets one test widen the front door (several domains)
// without complicating every other caller.
type selfServiceTestOptions struct {
	cfg           *SelfServiceConfig
	frontDomains  []string
	sharedDERPMap *tailcfg.DERPMap
	prepareTenant func(*Server) error
}

func selfServiceRouterWith(t *testing.T, options selfServiceTestOptions, prepare ...func(*PlanRegistry)) (*Router, *PlanRegistry) {
	t.Helper()

	cfg := options.cfg
	frontDomains := options.frontDomains
	if len(frontDomains) == 0 {
		frontDomains = []string{"app.xunara.test"}
	}

	ctx := context.Background()
	dir := t.TempDir()

	registry, err := OpenOrgRegistry(ctx, OrgRegistryConfig{
		Path:      dir + "/platform.db",
		StateRoot: dir + "/orgs",
		NewServer: func(org ManagedOrg, stateDir string) (*Server, error) {
			server, err := New(Config{ServerURL: org.ServerURL, StateDir: stateDir, DERPMap: options.sharedDERPMap.Clone()})
			if err != nil {
				return nil, err
			}
			if options.prepareTenant != nil {
				if err := options.prepareTenant(server); err != nil {
					server.Close()
					return nil, err
				}
			}
			return server, nil
		},
	})
	if err != nil {
		t.Fatalf("OpenOrgRegistry: %v", err)
	}
	t.Cleanup(func() { registry.Close() })

	pool, err := netspace.NewPool(netip.MustParsePrefix("100.100.0.0/16"), 24)
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}
	plans, err := OpenPlanRegistry(ctx, PlanRegistryConfig{Path: dir + "/plans.db", Pool: pool})
	if err != nil {
		t.Fatalf("OpenPlanRegistry: %v", err)
	}
	t.Cleanup(func() { plans.Close() })

	for _, prep := range prepare {
		prep(plans)
	}

	// The sign-up desk is public by definition, so the front door runs in
	// open registration mode (enableSelfServiceLocked refuses anything else).
	front := newServerWithConfig(t, Config{
		StateDir:     dir + "/portal",
		ServerURL:    "https://app.xunara.test",
		Registration: RegistrationOpen,
	})
	if cfg != nil {
		cfg.Site = "portal"
	}
	router, err := NewRouter(RouterConfig{
		ListenAddr: "127.0.0.1:0",
		Orgs: []OrgSite{
			{ID: "portal", Name: "Xunara Cloud", Domains: frontDomains, Server: front},
			{ID: "acme", Name: "Acme", Domains: []string{"acme.xunara.test"}, Server: newTestServer(t)},
		},
		PlatformAdminToken: "self-service-platform-token",
		Registry:           registry,
		Plans:              plans,
		SelfService:        cfg,
		SharedDERPMap:      options.sharedDERPMap,
	})
	if err != nil {
		t.Fatalf("NewRouter: %v", err)
	}
	t.Cleanup(func() { router.Close() })
	return router, plans
}

// postJSONAtHost posts a JSON body with an explicit Host header, standing in
// for DNS pointing a name at the deployment.
func postJSONAtHost(t *testing.T, handler http.Handler, host, path string, body any) *httptest.ResponseRecorder {
	t.Helper()

	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshalling the body: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "http://"+host+path, bytes.NewReader(raw))
	req.Host = host
	req.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	return recorder
}

func TestSelfServiceSignupCreatesTenant(t *testing.T) {
	router, plans := selfServiceRouter(t, &SelfServiceConfig{
		DomainSuffix: "xunara.test",
		Scheme:       "https",
		CookieDomain: "xunara.test",
	})
	handler := router.Handler()

	recorder := postJSONAtHost(t, handler, "app.xunara.test", selfServiceSignupPath, map[string]string{
		"login":        "alice",
		"display_name": "Alice",
		"email":        "alice@example.com",
		"password":     "correct horse battery staple",
	})
	if recorder.Code != http.StatusCreated {
		t.Fatalf("self-service signup = %d (%s), want 201", recorder.Code, recorder.Body.String())
	}

	var payload struct {
		Authenticated bool `json:"authenticated"`
		Handoff       bool `json:"handoff"`
		Organization  struct {
			ID     string `json:"id"`
			Domain string `json:"domain"`
			URL    string `json:"url"`
		} `json:"organization"`
		User struct {
			LoginName string `json:"login_name"`
			Role      string `json:"role"`
		} `json:"user"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decoding the response: %v", err)
	}
	if !payload.Authenticated || !payload.Handoff {
		t.Fatalf("payload = %+v, want an authenticated sign-up with a cookie hand-off", payload)
	}
	if payload.Organization.ID != "alice" || payload.Organization.Domain != "alice.xunara.test" ||
		payload.Organization.URL != "https://alice.xunara.test" {
		t.Fatalf("organization = %+v, want the tenant alice.xunara.test", payload.Organization)
	}
	if payload.User.LoginName != "alice" || payload.User.Role != string(identity.RoleOwner) {
		t.Fatalf("user = %+v, want alice as the tenant owner", payload.User)
	}

	// The session is scoped to the shared parent domain, so the browser
	// carries it to the tenant's own host.
	var session *http.Cookie
	for _, cookie := range recorder.Result().Cookies() {
		if cookie.Name == sessionCookieName {
			session = cookie
		}
	}
	if session == nil {
		t.Fatal("the sign-up returned no session cookie")
	}
	if session.Domain != "xunara.test" {
		t.Fatalf("session cookie domain = %q, want xunara.test", session.Domain)
	}

	// Every new tenant is on a plan and owns a network block from the pool.
	prefix, ok := plans.NetworkPrefix(context.Background(), "alice")
	if !ok || !prefix.IsValid() {
		t.Fatalf("the new tenant has no network block (%v, %v)", prefix, ok)
	}
	if !netip.MustParsePrefix("100.100.0.0/24").Contains(prefix.Addr()) {
		t.Fatalf("network block %s is outside the pool", prefix)
	}

	// The tenant's own host serves its console: the session works there, and
	// the account is the owner of that organization.
	sessionReq := httptest.NewRequest(http.MethodGet, "http://alice.xunara.test/api/v1/auth/session", nil)
	sessionReq.Host = "alice.xunara.test"
	sessionReq.AddCookie(session)
	sessionRecorder := httptest.NewRecorder()
	handler.ServeHTTP(sessionRecorder, sessionReq)
	if sessionRecorder.Code != http.StatusOK {
		t.Fatalf("session probe on the tenant host = %d, want 200", sessionRecorder.Code)
	}
	var sessionPayload struct {
		Authenticated bool `json:"authenticated"`
		User          struct {
			LoginName string `json:"login_name"`
			Role      string `json:"role"`
		} `json:"user"`
		Plan struct {
			ID string `json:"id"`
		} `json:"plan"`
	}
	if err := json.Unmarshal(sessionRecorder.Body.Bytes(), &sessionPayload); err != nil {
		t.Fatalf("decoding the session: %v", err)
	}
	if !sessionPayload.Authenticated || sessionPayload.User.Role != string(identity.RoleOwner) {
		t.Fatalf("tenant session = %+v, want the owner signed in", sessionPayload)
	}
	if sessionPayload.Plan.ID == "" {
		t.Fatalf("tenant session reports no plan: %+v", sessionPayload)
	}

	// The front door advertises the desk so the console posts here.
	providersReq := httptest.NewRequest(http.MethodGet, "http://app.xunara.test/api/v1/auth/providers", nil)
	providersReq.Host = "app.xunara.test"
	providersRecorder := httptest.NewRecorder()
	handler.ServeHTTP(providersRecorder, providersReq)
	var providers struct {
		SelfService *SelfServiceInfo `json:"self_service"`
	}
	if err := json.Unmarshal(providersRecorder.Body.Bytes(), &providers); err != nil {
		t.Fatalf("decoding the providers payload: %v", err)
	}
	if providers.SelfService == nil || providers.SelfService.Endpoint != selfServiceSignupPath {
		t.Fatalf("providers = %+v, want the self-service endpoint", providers.SelfService)
	}
}

func TestSelfServiceFrontDoorCannotCreateLocalMembers(t *testing.T) {
	router, _ := selfServiceRouter(t, &SelfServiceConfig{DomainSuffix: "xunara.test"})
	front := router.orgByID("portal").site.Server
	usersBefore := len(front.identity.ListUsers())

	recorder := postJSONAtHost(t, router.Handler(), "app.xunara.test", "/api/v1/auth/signup", map[string]string{
		"login": "outsider", "password": "correct horse battery staple",
	})
	if recorder.Code != http.StatusForbidden || !strings.Contains(recorder.Body.String(), "TENANT_SIGNUP_REQUIRED") {
		t.Fatalf("local API signup = %d (%s), want tenant registration required", recorder.Code, recorder.Body.String())
	}

	form := url.Values{
		"login": {"outsider"}, "password": {"correct horse battery staple"}, "confirm": {"correct horse battery staple"},
		"_csrf": {front.newFormToken(formPurposeSignup)},
	}
	request := httptest.NewRequest(http.MethodPost, "https://app.xunara.test/signup", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	recorder = httptest.NewRecorder()
	router.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("local HTML signup = %d, want 403", recorder.Code)
	}
	if len(front.identity.ListUsers()) != usersBefore {
		t.Fatal("signup added a member to the public front door")
	}
	if _, exists := front.identity.GetUserByLoginName("outsider"); exists {
		t.Fatal("the rejected signup created an account")
	}
	if len(recorder.Result().Cookies()) != 0 {
		t.Fatal("the rejected signup established a session")
	}

	request = httptest.NewRequest(http.MethodGet, "https://app.xunara.test/signup", nil)
	recorder = httptest.NewRecorder()
	router.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusSeeOther || recorder.Header().Get("Location") != "/register" {
		t.Fatalf("signup page = %d (%s), want the registration console", recorder.Code, recorder.Header().Get("Location"))
	}
}

func TestSelfServiceClientsReceiveSharedDERPAndStayIsolated(t *testing.T) {
	sharedMap := &tailcfg.DERPMap{
		OmitDefaultRegions: true,
		Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{
			900: {
				RegionID: 900, RegionCode: "public", RegionName: "Public relay",
				Nodes: []*tailcfg.DERPNode{{
					Name: "900a", RegionID: 900, HostName: "relay.example.com", DERPPort: 9091, STUNPort: -1,
					CertName: "sha256-raw:" + strings.Repeat("a", 64),
				}},
			},
		},
	}
	router, plans := selfServiceRouterWith(t, selfServiceTestOptions{
		cfg: &SelfServiceConfig{DomainSuffix: "example.com"}, sharedDERPMap: sharedMap,
	})
	for _, login := range []string{"alice", "bob"} {
		recorder := postJSONAtHost(t, router.Handler(), "app.xunara.test", selfServiceSignupPath, map[string]string{
			"login": login, "password": "correct horse battery staple",
		})
		if recorder.Code != http.StatusCreated {
			t.Fatalf("signup %s = %d, want 201", login, recorder.Code)
		}
	}
	hs := httptest.NewServer(router.Handler())
	t.Cleanup(hs.Close)
	alice := router.orgByID("alice").site.Server
	bob := router.orgByID("bob").site.Server
	aliceKey := seedPreAuthKey(t, alice, state.PreAuthKey{Reusable: true})
	bobKey := seedPreAuthKey(t, bob, state.PreAuthKey{Reusable: true})
	_, aliceClient, aliceNode := registerPreAuthedNodeAtHost(t, hs, "alice.example.com", "alice-laptop", aliceKey)
	registerPreAuthedNodeAtHost(t, hs, "alice.example.com", "alice-phone", aliceKey)
	_, bobClient, bobNode := registerPreAuthedNodeAtHost(t, hs, "bob.example.com", "bob-laptop", bobKey)

	aliceMap := decodeMapResponse(t, postRaw(t, aliceClient, "/machine/map", tailcfg.MapRequest{
		Version: tailcfg.CurrentCapabilityVersion, NodeKey: aliceNode.Public(),
	}), "")
	bobMap := decodeMapResponse(t, postRaw(t, bobClient, "/machine/map", tailcfg.MapRequest{
		Version: tailcfg.CurrentCapabilityVersion, NodeKey: bobNode.Public(),
	}), "")
	if !reflect.DeepEqual(aliceMap.DERPMap, sharedMap) || !reflect.DeepEqual(bobMap.DERPMap, sharedMap) {
		t.Fatal("the upstream Noise client did not receive the shared map with its port and certificate pin")
	}
	if len(aliceMap.Peers) != 1 || len(bobMap.Peers) != 0 {
		t.Fatalf("peer counts alice=%d bob=%d, want 1 and 0", len(aliceMap.Peers), len(bobMap.Peers))
	}
	for login, networkMap := range map[string]*tailcfg.MapResponse{"alice": aliceMap, "bob": bobMap} {
		prefix, ok := plans.NetworkPrefix(context.Background(), login)
		if !ok || networkMap.Node == nil || !networkMap.Node.MachineAuthorized || len(networkMap.Node.Addresses) == 0 {
			t.Fatalf("%s has no authorized node or assigned network", login)
		}
		if !prefix.Contains(networkMap.Node.Addresses[0].Addr()) {
			t.Fatalf("%s node address is outside its allocated network", login)
		}
		if len(networkMap.UserProfiles) == 0 || networkMap.UserProfiles[0].LoginName != login {
			t.Fatalf("%s received another tenant's user profile", login)
		}
	}
	if _, exists := bob.store.GetNodeByNodeKey(aliceNode.Public()); exists {
		t.Fatal("alice's machine resolved in bob's state store")
	}
	if alice.NoisePublicKey() == bob.NoisePublicKey() {
		t.Fatal("new tenants share the control-plane key")
	}
	for _, nodeKey := range []tailcfg.DERPAdmitClientRequest{{NodePublic: aliceNode.Public()}, {NodePublic: bobNode.Public()}} {
		recorder := postJSONAtHost(t, router.Handler(), "127.0.0.1", relayAdmissionPath, nodeKey)
		var admission tailcfg.DERPAdmitClientResponse
		if err := json.Unmarshal(recorder.Body.Bytes(), &admission); err != nil {
			t.Fatal(err)
		}
		if recorder.Code != http.StatusOK || !admission.Allow {
			t.Fatal("a managed tenant's authorized node was refused by the shared relay")
		}
	}
}

// A deployment reachable only on a non-standard port hands new owners the
// URL that actually answers: the port is part of the tenant URL, not a
// silently dropped detail.
func TestSelfServiceSignupCarriesThePublicPort(t *testing.T) {
	router, _ := selfServiceRouter(t, &SelfServiceConfig{
		DomainSuffix: "115.192.161.121.nip.io",
		Scheme:       "http",
		Port:         "9090",
	})

	recorder := postJSONAtHost(t, router.Handler(), "app.xunara.test", selfServiceSignupPath, map[string]string{
		"login":    "carol",
		"password": "correct horse battery staple",
	})
	if recorder.Code != http.StatusCreated {
		t.Fatalf("self-service signup = %d (%s), want 201", recorder.Code, recorder.Body.String())
	}

	var payload struct {
		Organization struct {
			Domain string `json:"domain"`
			URL    string `json:"url"`
		} `json:"organization"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decoding the response: %v", err)
	}
	if payload.Organization.URL != "http://carol.115.192.161.121.nip.io:9090" {
		t.Fatalf("tenant URL = %q, want it to carry the public port", payload.Organization.URL)
	}
	if payload.Organization.Domain != "carol.115.192.161.121.nip.io" {
		t.Fatalf("tenant domain = %q, want the bare host without a port", payload.Organization.Domain)
	}
}

// A front door with several names cannot share a cookie with every one of
// them: when the request arrives on a host outside the cookie domain the
// session stays host-only and the answer must not claim a hand-off.
func TestSelfServiceSignupOutsideCookieCoverageSkipsHandoff(t *testing.T) {
	router, _ := selfServiceRouterWith(t, selfServiceTestOptions{
		cfg: &SelfServiceConfig{
			DomainSuffix: "tailnet.xunara.test",
			CookieDomain: "xunara.test",
		},
		frontDomains: []string{"app.xunara.test", "portal.other.test"},
	})

	recorder := postJSONAtHost(t, router.Handler(), "portal.other.test", selfServiceSignupPath, map[string]string{
		"login":    "dana",
		"password": "correct horse battery staple",
	})
	if recorder.Code != http.StatusCreated {
		t.Fatalf("self-service signup = %d (%s), want 201", recorder.Code, recorder.Body.String())
	}

	var payload struct {
		Handoff bool `json:"handoff"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decoding the response: %v", err)
	}
	if payload.Handoff {
		t.Fatal("hand-off was claimed for a host the cookie domain does not cover")
	}
	for _, cookie := range recorder.Result().Cookies() {
		if cookie.Name == sessionCookieName && cookie.Domain != "" {
			t.Fatalf("session cookie domain = %q, want a host-only cookie", cookie.Domain)
		}
	}
}

// A second account with the same login name gets its own tenant with a
// derived ID: the login name is tenant-scoped, the domain is not.
func TestSelfServiceSignupDerivesUniqueOrganization(t *testing.T) {
	router, _ := selfServiceRouter(t, &SelfServiceConfig{DomainSuffix: "xunara.test"})
	handler := router.Handler()

	first := postJSONAtHost(t, handler, "app.xunara.test", selfServiceSignupPath, map[string]string{
		"login": "bob", "password": "correct horse battery staple",
	})
	if first.Code != http.StatusCreated {
		t.Fatalf("first signup = %d (%s), want 201", first.Code, first.Body.String())
	}
	second := postJSONAtHost(t, handler, "app.xunara.test", selfServiceSignupPath, map[string]string{
		"login": "bob", "password": "correct horse battery staple",
	})
	if second.Code != http.StatusCreated {
		t.Fatalf("second signup = %d (%s), want 201", second.Code, second.Body.String())
	}

	var orgIDs []string
	for _, body := range []*httptest.ResponseRecorder{first, second} {
		var payload struct {
			Organization struct {
				ID string `json:"id"`
			} `json:"organization"`
		}
		if err := json.Unmarshal(body.Body.Bytes(), &payload); err != nil {
			t.Fatalf("decoding: %v", err)
		}
		orgIDs = append(orgIDs, payload.Organization.ID)
	}
	if orgIDs[0] == orgIDs[1] {
		t.Fatalf("both sign-ups landed in tenant %q, want one tenant each", orgIDs[0])
	}
	if !strings.HasPrefix(orgIDs[1], "bob") {
		t.Fatalf("second tenant = %q, want a derived ID that still reads as bob", orgIDs[1])
	}
}

// The desk answers only on its own hosts: anywhere else the request belongs
// to that organization, which has no such endpoint.
func TestSelfServiceSignupIsScopedToTheFrontDoor(t *testing.T) {
	router, _ := selfServiceRouter(t, &SelfServiceConfig{DomainSuffix: "xunara.test"})
	handler := router.Handler()

	recorder := postJSONAtHost(t, handler, "acme.xunara.test", selfServiceSignupPath, map[string]string{
		"login": "mallory", "password": "correct horse battery staple",
	})
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("signup on a tenant host = %d (%s), want 404", recorder.Code, recorder.Body.String())
	}
}

// A sign-up that fails leaves no tenant behind, and the plan's member quota
// is the rule that can stop it.
func TestSelfServiceSignupRollsBackOnQuota(t *testing.T) {
	// New tenants start on a plan that allows no members, so not even the
	// owner account can be created: the commercial rule stops the sign-up and
	// the tenant must not survive it.
	router, _ := selfServiceRouter(t,
		&SelfServiceConfig{DomainSuffix: "xunara.test", Plan: "nobody"},
		func(plans *PlanRegistry) {
			if _, err := plans.UpsertPlan(context.Background(), plan.Plan{
				ID: "nobody", Name: "Nobody", Currency: "CNY",
				MaxDevices: plan.Unlimited, MaxUsers: 0, MaxRoutes: plan.Unlimited, MaxAuthKeys: plan.Unlimited,
			}); err != nil {
				t.Fatalf("UpsertPlan: %v", err)
			}
		})
	handler := router.Handler()

	recorder := postJSONAtHost(t, handler, "app.xunara.test", selfServiceSignupPath, map[string]string{
		"login": "carol", "password": "correct horse battery staple",
	})
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("signup on a plan without members = %d (%s), want 403", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "USER_LIMIT_REACHED") {
		t.Fatalf("signup rejection = %s, want USER_LIMIT_REACHED", recorder.Body.String())
	}

	// The tenant must not survive its failed sign-up.
	for _, org := range router.orgSnapshot() {
		if strings.HasPrefix(org.site.ID, "carol") {
			t.Fatalf("a rolled-back tenant is still served: %+v", org.site.ID)
		}
	}
}

func TestSelfServiceRejectsBadConfiguration(t *testing.T) {
	cases := []struct {
		name         string
		cfg          *SelfServiceConfig
		registration RegistrationMode
	}{
		{"no domain suffix", &SelfServiceConfig{Scheme: "https"}, RegistrationOpen},
		{"unknown site", &SelfServiceConfig{Site: "nope", DomainSuffix: "xunara.test"}, RegistrationOpen},
		{"cookie domain outside the front door", &SelfServiceConfig{DomainSuffix: "xunara.test", CookieDomain: "elsewhere.test"}, RegistrationOpen},
		{"unknown plan", &SelfServiceConfig{DomainSuffix: "xunara.test", Plan: "platinum"}, RegistrationOpen},
		{"bad port", &SelfServiceConfig{DomainSuffix: "xunara.test", Port: "http"}, RegistrationOpen},
		{"port out of range", &SelfServiceConfig{DomainSuffix: "xunara.test", Port: "70000"}, RegistrationOpen},
		// The desk hands out accounts to anyone, so a front door that is not
		// open would contradict what it does.
		{"invite-only front door", &SelfServiceConfig{DomainSuffix: "xunara.test"}, RegistrationInvite},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			dir := t.TempDir()
			registry, err := OpenOrgRegistry(ctx, OrgRegistryConfig{
				Path:      dir + "/platform.db",
				StateRoot: dir + "/orgs",
				NewServer: func(org ManagedOrg, stateDir string) (*Server, error) {
					return New(Config{ServerURL: org.ServerURL, StateDir: stateDir})
				},
			})
			if err != nil {
				t.Fatalf("OpenOrgRegistry: %v", err)
			}
			t.Cleanup(func() { registry.Close() })
			plans, err := OpenPlanRegistry(ctx, PlanRegistryConfig{Path: dir + "/plans.db"})
			if err != nil {
				t.Fatalf("OpenPlanRegistry: %v", err)
			}
			t.Cleanup(func() { plans.Close() })

			front := newServerWithConfig(t, Config{
				StateDir:     dir + "/portal",
				Registration: tc.registration,
			})

			_, err = NewRouter(RouterConfig{
				ListenAddr: "127.0.0.1:0",
				Orgs:       []OrgSite{{ID: "portal", Name: "Portal", Domains: []string{"app.xunara.test"}, Server: front}},
				Registry:   registry,
				Plans:      plans,
				SelfService: func() *SelfServiceConfig {
					cfg := *tc.cfg
					if cfg.Site == "" {
						cfg.Site = "portal"
					}
					return &cfg
				}(),
			})
			if err == nil {
				t.Fatal("NewRouter accepted a broken self-service configuration")
			}
		})
	}
}
