package control

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/xunara-net/xunara-server/identity"
	"github.com/xunara-net/xunara-server/state"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

func nativeTestRouter(test *testing.T) *Router {
	test.Helper()
	router, _ := selfServiceRouter(test, &SelfServiceConfig{DomainSuffix: "xunara.test", ConsoleURL: "https://app.xunara.test", NativeGateway: true})
	response := postJSONAtHost(test, router.Handler(), "app.xunara.test", selfServiceSignupPath,
		map[string]string{"login": "alice", "password": testLocalPassword})
	if response.Code != http.StatusCreated {
		test.Fatalf("signup: %d %s", response.Code, response.Body.String())
	}
	return router
}

func nativeBrowserLogin(test *testing.T, router *Router, flowID, login, password string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	test.Helper()
	values := url.Values{"_csrf": {router.nativeGateway.front.newFormToken("native-login:" + flowID)}, "login": {login}, "password": {password}}
	request := httptest.NewRequest(http.MethodPost, "https://app.xunara.test/device/"+flowID+"/login", strings.NewReader(values.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, cookie := range cookies {
		request.AddCookie(cookie)
	}
	response := httptest.NewRecorder()
	router.Handler().ServeHTTP(response, request)
	return response
}

func TestNativeGatewayTS2021AccountApprovalIsolation(test *testing.T) {
	router := nativeTestRouter(test)
	front := router.orgByID("portal").site.Server
	tenant := router.orgByID("alice").site.Server
	host := httptest.NewServer(router.Handler())
	defer host.Close()
	machine, node := key.NewMachine(), key.NewNode()
	connection := dialNoiseAtHost(test, host, "app.xunara.test", machine)
	defer connection.Close()
	client := h2Client(connection)
	registration := tailcfg.RegisterRequest{Version: tailcfg.CurrentCapabilityVersion, NodeKey: node.Public(), Hostinfo: &tailcfg.Hostinfo{Hostname: "account-laptop"}}
	first := decodeJSON[tailcfg.RegisterResponse](test, postRaw(test, client, "/machine/register", registration))
	if first.MachineAuthorized || !strings.HasPrefix(first.AuthURL, "https://app.xunara.test/device/") {
		test.Fatalf("new device was authorized or misrouted: %+v", first)
	}
	flowID := strings.TrimPrefix(first.AuthURL, "https://app.xunara.test/device/")
	_, adminToken, err := front.identity.CreateSession(identity.NewSessionOptions{UserID: 1, TTL: time.Hour})
	if err != nil {
		test.Fatal(err)
	}
	adminCookie := &http.Cookie{Name: sessionCookieName, Value: adminToken}
	pageRequest := httptest.NewRequest(http.MethodGet, first.AuthURL, nil)
	pageRequest.AddCookie(adminCookie)
	page := httptest.NewRecorder()
	router.Handler().ServeHTTP(page, pageRequest)
	if page.Code != http.StatusOK || strings.Contains(page.Body.String(), "网络标识") || strings.Contains(page.Body.String(), "登录范围") {
		test.Fatal("enrollment must use ordinary account login, never a network chooser")
	}
	if len(front.identity.ListPendingDeviceAuthorizations(time.Now())) != 0 || len(tenant.identity.ListPendingDeviceAuthorizations(time.Now())) != 0 {
		test.Fatal("anonymous device created a default-tenant approval")
	}
	response := nativeBrowserLogin(test, router, flowID, "alice", testLocalPassword, adminCookie)
	location := response.Header().Get("Location")
	if response.Code != http.StatusSeeOther || !strings.HasPrefix(location, "https://app.xunara.test/t/alice/register/") {
		test.Fatalf("account login: %d %s %s", response.Code, location, response.Body.String())
	}
	authID := strings.TrimPrefix(location, "https://app.xunara.test/t/alice/register/")
	var tenantCookie *http.Cookie
	for _, cookie := range response.Result().Cookies() {
		if cookie.Name == tenantCookieName(sessionCookieName, "alice") {
			tenantCookie = cookie
		}
	}
	if tenantCookie == nil || tenantCookie.Path != "/t/alice/" || !tenantCookie.Secure {
		test.Fatal("account session did not receive a tenant-specific cookie")
	}
	approval := httptest.NewRequest(http.MethodGet, location, nil)
	approval.AddCookie(adminCookie)
	anonymous := httptest.NewRecorder()
	router.Handler().ServeHTTP(anonymous, approval)
	relogin, err := url.Parse(anonymous.Header().Get("Location"))
	if err != nil || anonymous.Code != http.StatusFound || relogin.Path != "/login" || relogin.Query().Get("return_to") != approval.URL.Path {
		test.Fatal("default administrator cookie authenticated a tenant approval")
	}
	approval.AddCookie(tenantCookie)
	signedIn := httptest.NewRecorder()
	router.Handler().ServeHTTP(signedIn, approval)
	if signedIn.Code != http.StatusOK || !strings.Contains(signedIn.Body.String(), location+"/approve") {
		test.Fatalf("scoped approval form: %d %s", signedIn.Code, signedIn.Body.String())
	}
	values := url.Values{"csrf": {csrfTokenFor(tenantCookie.Value)}}
	decision := httptest.NewRequest(http.MethodPost, location+"/approve", strings.NewReader(values.Encode()))
	decision.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	decision.AddCookie(tenantCookie)
	approved := httptest.NewRecorder()
	router.Handler().ServeHTTP(approved, decision)
	if approved.Code != http.StatusOK {
		test.Fatalf("approval: %d %s", approved.Code, approved.Body.String())
	}
	registration.Followup = first.AuthURL
	completed := decodeJSON[tailcfg.RegisterResponse](test, postRaw(test, client, "/machine/register", registration))
	if !completed.MachineAuthorized || completed.Login.LoginName != "alice" {
		test.Fatalf("registration entered wrong account: %+v", completed)
	}
	netmap := decodeMapResponse(test, postRaw(test, client, "/machine/map", tailcfg.MapRequest{Version: tailcfg.CurrentCapabilityVersion, NodeKey: node.Public()}), "")
	if netmap.Node == nil || netmap.Node.Key != node.Public() || len(netmap.Peers) != 0 {
		test.Fatal("scoped native map is missing its node or leaked peers")
	}
	if nodes, err := front.networkNodes(test.Context()); err != nil || len(nodes) != 0 {
		test.Fatal("device entered the default administrator's network")
	}
	if authorization, err := tenant.identity.LookupDeviceAuthorization(test.Context(), authID); err != nil || authorization.State != identity.DeviceApproved {
		test.Fatal("approved device was not committed in its own tenant")
	}
	// 相同 Noise 连接的其他端点也必须属于同一设备，不能退回默认租户。
	wrongNode := key.NewNode()
	_, status := postRawStatus(test, client, "/machine/map", tailcfg.MapRequest{Version: tailcfg.CurrentCapabilityVersion, NodeKey: wrongNode.Public()})
	if status != http.StatusUnauthorized {
		test.Fatalf("unknown node map = %d", status)
	}
}

func TestNativeGatewayRejectsWrongKeyHintTokenAndOldPending(test *testing.T) {
	router := nativeTestRouter(test)
	front := router.nativeGateway.front
	machine, node := key.NewMachine(), key.NewNode()
	legacy, err := front.identity.CreateDeviceAuthorization(identity.NewDeviceAuthorizationOptions{MachineKey: machine.Public().String(), NodeKey: node.Public().String()})
	if err != nil {
		test.Fatal(err)
	}
	if err := front.ApproveRegistration(legacy.ID); err == nil {
		test.Fatal("unscoped legacy request was approved by the default owner")
	}
	connection := &noiseServer{server: front, machineKey: machine.Public(), clientIP: "127.0.0.1"}
	for _, hints := range []bool{false, true} {
		registration := tailcfg.RegisterRequest{Version: tailcfg.CurrentCapabilityVersion, NodeKey: node.Public()}
		if !hints {
			registration.Auth = &tailcfg.RegisterResponseAuth{AuthKey: "invalid-auth-key"}
		}
		raw, _ := json.Marshal(registration)
		request := httptest.NewRequest(http.MethodPost, "http://noise/machine/register", bytes.NewReader(raw))
		if hints {
			request.Header.Set(tailcfg.LBHeader, key.NewNode().Public().String())
		}
		response := httptest.NewRecorder()
		router.nativeGateway.noiseHandler(connection).ServeHTTP(response, request)
		var result tailcfg.RegisterResponse
		if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil || result.Error == "" || result.AuthURL != "" || result.MachineAuthorized {
			test.Fatalf("unsafe registration fallback: %d %s", response.Code, response.Body.String())
		}
	}
}

func TestNativeBindingCannotInheritRecreatedTenant(test *testing.T) {
	router := nativeTestRouter(test)
	machine, node := key.NewMachine(), key.NewNode()
	old := router.orgByID("alice").site.Server
	if err := router.cfg.Registry.bindNative(test.Context(), machine.Public().String(), node.Public().String(), "alice", old.noiseKey.Public().String()); err != nil {
		test.Fatal(err)
	}
	if _, err := router.DeleteManagedOrg(test.Context(), "alice"); err != nil {
		test.Fatal(err)
	}
	recreated := postJSONAtHost(test, router.Handler(), "app.xunara.test", selfServiceSignupPath,
		map[string]string{"login": "ALICE", "password": testLocalPassword})
	if recreated.Code != http.StatusCreated {
		test.Fatalf("deleted account cannot register again: %d %s", recreated.Code, recreated.Body.String())
	}
	current := router.orgByID("alice").site.Server
	if current.noiseKey.Public() == old.noiseKey.Public() {
		test.Fatal("new account inherited old Noise identity")
	}
	if _, found, err := router.nativeGateway.boundOrg(test.Context(), machine.Public(), node.Public()); !found || err == nil {
		test.Fatal("old device routing inherited a recreated account")
	}
	if nodes, err := current.networkNodes(test.Context()); err != nil || len(nodes) != 0 {
		test.Fatal("new account inherited old devices")
	}
}

func TestNativeGatewayTokenAndAuxiliaryEndpointsKeepExactTenant(test *testing.T) {
	router := nativeTestRouter(test)
	created := postJSONAtHost(test, router.Handler(), "app.xunara.test", selfServiceSignupPath,
		map[string]string{"login": "bob", "password": testLocalPassword})
	if created.Code != http.StatusCreated {
		test.Fatal(created.Body.String())
	}
	host := httptest.NewServer(router.Handler())
	defer host.Close()
	machine := key.NewMachine()
	connection := dialNoiseAtHost(test, host, "app.xunara.test", machine)
	defer connection.Close()
	client := h2Client(connection)
	nodes := make(map[string]key.NodePublic)
	for _, orgID := range []string{"alice", "bob"} {
		tenant := router.orgByID(orgID).site.Server
		secret := seedPreAuthKey(test, tenant, state.PreAuthKey{})
		node := key.NewNode().Public()
		nodes[orgID] = node
		registered := decodeJSON[tailcfg.RegisterResponse](test, postRaw(test, client, "/machine/register", tailcfg.RegisterRequest{
			Version: tailcfg.CurrentCapabilityVersion, NodeKey: node, Hostinfo: &tailcfg.Hostinfo{Hostname: orgID},
			Auth: &tailcfg.RegisterResponseAuth{AuthKey: secret},
		}))
		if !registered.MachineAuthorized || registered.Login.LoginName != orgID {
			test.Fatalf("token crossed tenant: %+v", registered)
		}
		retried := decodeJSON[tailcfg.RegisterResponse](test, postRaw(test, client, "/machine/register", tailcfg.RegisterRequest{
			Version: tailcfg.CurrentCapabilityVersion, NodeKey: node, Hostinfo: &tailcfg.Hostinfo{Hostname: orgID},
			Auth: &tailcfg.RegisterResponseAuth{AuthKey: secret},
		}))
		if !retried.MachineAuthorized || retried.Login.LoginName != orgID {
			test.Fatal("lost registration reply cannot be retried with its consumed one-time token")
		}
		reused := decodeJSON[tailcfg.RegisterResponse](test, postRaw(test, client, "/machine/register", tailcfg.RegisterRequest{
			Version: tailcfg.CurrentCapabilityVersion, NodeKey: key.NewNode().Public(),
			Auth: &tailcfg.RegisterResponseAuth{AuthKey: secret},
		}))
		if reused.MachineAuthorized || reused.AuthURL != "" || reused.Error == "" {
			test.Fatal("one-time token admitted another device or fell back to a browser")
		}
	}
	for _, orgID := range []string{"alice", "bob"} {
		netmap := decodeMapResponse(test, postRaw(test, client, "/machine/map", tailcfg.MapRequest{Version: tailcfg.CurrentCapabilityVersion, NodeKey: nodes[orgID]}), "")
		if netmap.Node == nil || netmap.Node.Key != nodes[orgID] || len(netmap.Peers) != 0 {
			test.Fatal("same MachineKey leaked nodes across tenants")
		}
		feature := decodeJSON[tailcfg.QueryFeatureResponse](test, postRaw(test, client, "/machine/feature/query", tailcfg.QueryFeatureRequest{
			NodeKey: nodes[orgID], Feature: "serve",
		}))
		if feature.Complete {
			test.Fatal("feature inherited another tenant's capabilities")
		}
	}
	request, err := http.NewRequest(http.MethodGet, "http://xunara.test/machine/whoami", nil)
	if err != nil {
		test.Fatal(err)
	}
	response, err := client.Do(request)
	if err != nil {
		test.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		test.Fatal("ambiguous machine-only auxiliary request chose a default tenant")
	}
}
