package control

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/xunara-net/xunara-server/identity"
	"github.com/xunara-net/xunara-server/plan"
	"github.com/xunara-net/xunara-server/state"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

func readRouteView(test *testing.T, server *Server, node state.Node, cookie *http.Cookie) routeManagementView {
	test.Helper()
	response := accountRequest(test, server, http.MethodGet, "/api/v2/machines/"+node.StableID+"/routes", nil, cookie, nil)
	var view routeManagementView
	if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &view) != nil {
		test.Fatal("route configuration not read")
	}
	if response.Header().Get("Cache-Control") != "no-store" {
		test.Fatal("private route configuration may be cached")
	}
	for _, forbidden := range []string{"machineKey", "nodeKey", "discoKey", "hostinfo", "private-log"} {
		if strings.Contains(response.Body.String(), forbidden) {
			test.Fatal("private key or raw report leaked")
		}
	}
	return view
}

func seedManagedRoutes(test *testing.T, server *Server, hostname string, routes []netip.Prefix) state.Node {
	test.Helper()
	node := seedAPIMachine(test, server, hostname, nil)
	node.Hostinfo = advertisedHostinfo(hostname, routes...)
	node.Hostinfo.FrontendLogID = "private-log"
	if err := server.store.UpdateNode(node); err != nil {
		test.Fatal(err)
	}
	return node
}

func TestRouteManagementAuthorizationCASAndUnannouncedRejection(test *testing.T) {
	server := newTestServer(test)
	node := seedManagedRoutes(test, server, "route-managed", []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")})
	cookie, token := seedUserSession(test, server, state.DefaultUserID)
	view := readRouteView(test, server, node, cookie)
	endpoint := "/api/v2/machines/" + node.StableID + "/routes"
	body := map[string]any{"revision": view.Revision, "approve": []string{"10.20.0.0/16"}}
	headers := map[string]string{"X-CSRF-Token": csrfTokenFor(token)}
	for _, attempt := range []struct {
		cookie   *http.Cookie
		headers  map[string]string
		expected int
	}{
		{nil, headers, 401}, {cookie, nil, 403}, {cookie, headers, 200},
	} {
		response := accountRequest(test, server, http.MethodPost, endpoint, body, attempt.cookie, attempt.headers)
		if response.Code != attempt.expected {
			test.Fatalf("authorization status %d, want %d", response.Code, attempt.expected)
		}
	}
	if response := accountRequest(test, server, http.MethodPost, endpoint, body, cookie, headers); response.Code != 409 {
		test.Fatal("stale approval succeeded")
	}
	view = readRouteView(test, server, node, cookie)
	body = map[string]any{"revision": view.Revision, "approve": []string{"192.168.250.0/24"}}
	if response := accountRequest(test, server, http.MethodPost, endpoint, body, cookie, headers); response.Code != 409 {
		test.Fatal("unannounced route approved")
	}
	node, _ = server.store.GetNodeByID(node.ID)
	node.NodeKey = key.NewNode().Public()
	if err := server.store.UpdateNode(node); err != nil {
		test.Fatal(err)
	}
	if response := accountRequest(test, server, http.MethodPost, endpoint, map[string]any{"revision": view.Revision, "unapprove": []string{"10.20.0.0/16"}}, cookie, headers); response.Code != 409 {
		test.Fatal("old node identity mutated a rotated device")
	}
	member := seedRoleUser(test, server, "routes-member", identity.RoleMember)
	memberCookie, memberToken := seedUserSession(test, server, member)
	memberView := readRouteView(test, server, node, memberCookie)
	if memberView.CanManage {
		test.Fatal("member granted route management")
	}
	if response := accountRequest(test, server, http.MethodPost, endpoint, map[string]any{"revision": memberView.Revision, "unapprove": []string{"10.20.0.0/16"}}, memberCookie, map[string]string{"X-CSRF-Token": csrfTokenFor(memberToken)}); response.Code != 403 {
		test.Fatal("member wrote approval")
	}
}

func TestRouteManagementIndependentPlanFeaturesAndCleanup(test *testing.T) {
	entitlement := plan.UnlimitedPlan()
	entitlement.AllowSubnetRouter = false
	server := planServer(test, entitlement)
	node := seedManagedRoutes(test, server, "exit-only", []netip.Prefix{state.ExitRouteV4, state.ExitRouteV6, netip.MustParsePrefix("10.0.0.0/8")})
	cookie, token := seedUserSession(test, server, state.DefaultUserID)
	headers := map[string]string{"X-CSRF-Token": csrfTokenFor(token)}
	view := readRouteView(test, server, node, cookie)
	endpoint := "/api/v2/machines/" + node.StableID + "/routes"
	response := accountRequest(test, server, http.MethodPost, endpoint, map[string]any{"revision": view.Revision, "approve": []string{"0.0.0.0/0", "::/0"}}, cookie, headers)
	if response.Code != 200 {
		test.Fatalf("exit-only entitlement denied: %d", response.Code)
	}
	view = readRouteView(test, server, node, cookie)
	if response := accountRequest(test, server, http.MethodPost, endpoint, map[string]any{"revision": view.Revision, "approve": []string{"10.0.0.0/8"}}, cookie, headers); response.Code != 403 {
		test.Fatal("subnet route bypassed its independent gate")
	}
	server.setPlanSource(func(string) plan.Plan { return freePlan(test) })
	if response := accountRequest(test, server, http.MethodPost, endpoint, map[string]any{"revision": view.Revision, "unapprove": []string{"0.0.0.0/0", "::/0"}}, cookie, headers); response.Code != 200 {
		test.Fatal("downgraded account cannot clean up old approvals")
	}
}

func TestRouteManagementBadRequestsBoundsAndReadFailures(test *testing.T) {
	server := newTestServer(test)
	node := seedAPIMachine(test, server, "route-bound", nil)
	cookie, token := seedUserSession(test, server, state.DefaultUserID)
	view := readRouteView(test, server, node, cookie)
	for _, body := range []map[string]any{
		{"approve": []string{"10.0.0.0/8"}},
		{"revision": view.Revision, "approve": []string{"invalid"}},
		{"revision": view.Revision, "approve": []string{"10.0.0.0/8"}, "unapprove": []string{"10.0.0.0/8"}},
		{"revision": view.Revision, "unknown": "field"},
	} {
		response := accountRequest(test, server, http.MethodPost, "/api/v2/machines/"+node.StableID+"/routes", body, cookie, map[string]string{"X-CSRF-Token": csrfTokenFor(token)})
		if response.Code != 400 {
			test.Fatal("invalid route change was accepted")
		}
	}
	advertised := make([]netip.Prefix, routeManagementLimit+1)
	for index := range advertised {
		advertised[index] = netip.PrefixFrom(netip.AddrFrom4([4]byte{10, byte(index >> 8), byte(index), 0}), 24)
	}
	node.Hostinfo = &tailcfg.Hostinfo{RoutableIPs: advertised}
	if err := server.store.UpdateNode(node); err != nil {
		test.Fatal(err)
	}
	if response := accountRequest(test, server, http.MethodGet, "/api/v2/routes/configuration", nil, cookie, nil); response.Code != 413 || strings.Contains(response.Body.String(), `"items"`) {
		test.Fatal("oversized snapshot became a partial/empty success")
	}
	database := server.store.(*state.SQLiteStore).DB()
	if _, err := database.ExecContext(test.Context(), "ALTER TABLE nodes RENAME TO nodes_unavailable"); err != nil {
		test.Fatal(err)
	}
	if response := accountRequest(test, server, http.MethodGet, "/api/v2/machines/"+node.StableID+"/routes", nil, cookie, nil); response.Code != 503 {
		test.Fatal("storage outage became missing device")
	}
	if response := accountRequest(test, server, http.MethodGet, "/api/v2/exit-nodes", nil, cookie, nil); response.Code != 503 {
		test.Fatal("storage outage became zero exit nodes")
	}
}

func TestRouteManagementSnapshotBoundPrecedesCommit(test *testing.T) {
	server := newTestServer(test)
	node := seedAPIMachine(test, server, "large-old-approval", nil)
	for index := range routeManagementLimit + 2 {
		node.ApprovedRoutes = append(node.ApprovedRoutes, netip.PrefixFrom(netip.AddrFrom4([4]byte{10, byte(index >> 8), byte(index), 0}), 24))
	}
	if err := server.store.UpdateNode(node); err != nil {
		test.Fatal(err)
	}
	cookie, token := seedUserSession(test, server, state.DefaultUserID)
	before := server.store.ConfigRevision()
	response := accountRequest(test, server, http.MethodPost, "/api/v2/machines/"+node.StableID+"/routes",
		map[string]any{"revision": state.RouteApprovalRevision(node), "unapprove": []string{node.ApprovedRoutes[0].String()}},
		cookie, map[string]string{"X-CSRF-Token": csrfTokenFor(token)})
	stored, _ := server.store.GetNodeByID(node.ID)
	if response.Code != 413 || !reflect.DeepEqual(stored.ApprovedRoutes, node.ApprovedRoutes) || server.store.ConfigRevision() != before {
		test.Fatal("oversized response was rejected only after committing a write")
	}
}

func TestRouteManagementServiceScopesAndTenantIsolation(test *testing.T) {
	first, second := newTestServer(test), newTestServer(test)
	node := seedManagedRoutes(test, first, "first-route", []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")})
	secondNode := seedManagedRoutes(test, second, "second-route", node.AnnouncedRoutes())
	router := newTestRouter(test, RouterConfig{Orgs: []OrgSite{
		{ID: "first", Domains: []string{"first.test"}, Server: first}, {ID: "second", Domains: []string{"second.test"}, Server: second},
	}})
	requestAt := func(host, method, endpoint, token string, body any) *httptest.ResponseRecorder {
		encoded, err := json.Marshal(body)
		if err != nil {
			test.Fatal(err)
		}
		request := httptest.NewRequest(method, "https://"+host+endpoint, strings.NewReader(string(encoded)))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Authorization", "Bearer "+token)
		recorder := httptest.NewRecorder()
		router.Handler().ServeHTTP(recorder, request)
		return recorder
	}
	_, readToken := seedAPIKey(test, first, identity.ScopeRead)
	_, writeToken := seedAPIKey(test, first, identity.ScopeRead, identity.ScopeWrite)
	endpoint := "/api/v2/machines/" + node.StableID + "/routes"
	body := map[string]any{"revision": state.RouteApprovalRevision(node), "approve": []string{"10.0.0.0/8"}}
	if response := requestAt("first.test", http.MethodPost, endpoint, readToken, body); response.Code != 403 {
		test.Fatal("read key changed routes")
	}
	if response := requestAt("second.test", http.MethodPost, "/api/v2/machines/"+secondNode.StableID+"/routes", writeToken, body); response.Code != 401 {
		test.Fatal("first tenant key authenticated at second tenant")
	}
	if response := requestAt("first.test", http.MethodGet, "/api/v2/machines/"+secondNode.StableID+"/routes", writeToken, nil); response.Code != 404 {
		test.Fatal("foreign stable node resolved inside first tenant")
	}
	if response := requestAt("first.test", http.MethodPost, endpoint, writeToken, body); response.Code != 200 {
		test.Fatal("authorized service write was rejected")
	}
	first.setPlanSource(func(string) plan.Plan { return freePlan(test) })
	if response := requestAt("first.test", http.MethodPost, endpoint, writeToken, body); response.Code != 403 {
		test.Fatal("API entitlement bypassed")
	}
	if response := requestAt("first.test", http.MethodGet, endpoint, writeToken, nil); response.Code != 200 || strings.Contains(response.Body.String(), `"can_manage":true`) {
		test.Fatal("disabled service writer advertised management")
	}
	stored, _ := second.store.GetNodeByID(secondNode.ID)
	if len(stored.ApprovedRoutes) != 0 {
		test.Fatal("foreign tenant was mutated")
	}
}

func TestRouteManagementLegacyEndpointsShareAtomicAudit(test *testing.T) {
	for _, source := range []string{"api-v1", "html"} {
		test.Run(source, func(test *testing.T) {
			server := newTestServer(test)
			node := seedManagedRoutes(test, server, "legacy-router", []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")})
			cookie, token := seedUserSession(test, server, state.DefaultUserID)
			database := server.store.(*state.SQLiteStore).DB()
			if _, err := database.ExecContext(test.Context(), "CREATE TRIGGER missing_route_audit BEFORE INSERT ON audit_events WHEN NEW.action = 'route.approved' BEGIN SELECT RAISE(IGNORE); END"); err != nil {
				test.Fatal(err)
			}
			before := server.store.ConfigRevision()
			if source == "api-v1" {
				response := accountRequest(test, server, http.MethodPost, "/api/v1/machines/"+node.StableID+"/routes",
					map[string]any{"approve": []string{"10.0.0.0/8"}}, cookie, map[string]string{"X-CSRF-Token": csrfTokenFor(token)})
				if response.Code != 503 {
					test.Fatal("legacy API acknowledged unrecorded audit")
				}
			} else {
				host := newTestHTTPServer(test, server)
				response := postForm(test, noRedirectClient(), host.URL+"/console/machines/"+node.StableID+"/routes",
					url.Values{"csrf": {csrfTokenFor(token)}, "action": {"approve-all"}}, cookie)
				if response.StatusCode != 503 {
					test.Fatal("HTML acknowledged unrecorded audit")
				}
			}
			stored, _ := server.store.GetNodeByID(node.ID)
			if len(stored.ApprovedRoutes) != 0 || server.store.ConfigRevision() != before {
				test.Fatal("legacy workflow left partial state")
			}
		})
	}
}

func TestRouteManagementNoisePublicationAndStaleTelemetry(test *testing.T) {
	server := newTestServer(test)
	host := newTestHTTPServer(test, server)
	connection, client, nodeKey := registerNode(test, server, host, "route-wire")
	defer connection.Close()
	subnet := netip.MustParsePrefix("10.25.0.0/16")
	request := tailcfg.MapRequest{Version: tailcfg.CurrentCapabilityVersion, NodeKey: nodeKey.Public(),
		Hostinfo: advertisedHostinfo("route-wire", subnet, state.ExitRouteV4, state.ExitRouteV6)}
	decodeMapResponse(test, postRaw(test, client, "/machine/map", request), "")
	stale, _ := server.store.GetNodeByNodeKey(nodeKey.Public())
	cookie, token := seedUserSession(test, server, state.DefaultUserID)
	view := readRouteView(test, server, stale, cookie)
	response := accountRequest(test, server, http.MethodPost, "/api/v2/machines/"+stale.StableID+"/routes",
		map[string]any{"revision": view.Revision, "approve": []string{subnet.String(), "0.0.0.0/0", "::/0"}}, cookie, map[string]string{"X-CSRF-Token": csrfTokenFor(token)})
	if response.Code != 200 {
		test.Fatal("route approval failed")
	}
	updated := server.recordMapRequest(stale, tailcfg.MapRequest{DiscoKey: key.NewDisco().Public()})
	if len(updated.ApprovedRoutes) != 3 {
		test.Fatal("old map request undid committed approval")
	}
	result := decodeMapResponse(test, postRaw(test, client, "/machine/map", request), "")
	for _, route := range []netip.Prefix{subnet, state.ExitRouteV4, state.ExitRouteV6} {
		if !containsPrefix(result.Node.AllowedIPs, route) {
			test.Fatal("approved route missing from upstream map")
		}
	}
	if !reflect.DeepEqual(result.Node.PrimaryRoutes, []netip.Prefix{subnet}) {
		test.Fatal("default routes wrongly elected as subnet primaries")
	}
	view = readRouteView(test, server, stale, cookie)
	response = accountRequest(test, server, http.MethodPost, "/api/v2/machines/"+stale.StableID+"/routes",
		map[string]any{"revision": view.Revision, "unapprove": []string{subnet.String(), "0.0.0.0/0", "::/0"}}, cookie, map[string]string{"X-CSRF-Token": csrfTokenFor(token)})
	if response.Code != 200 {
		test.Fatal("withdrawal failed")
	}
	result = decodeMapResponse(test, postRaw(test, client, "/machine/map", request), "")
	if containsPrefix(result.Node.AllowedIPs, subnet) || len(result.Node.PrimaryRoutes) != 0 {
		test.Fatal("withdrawal not published")
	}
}
