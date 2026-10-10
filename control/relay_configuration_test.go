package control

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/xunara-net/xunara-server/identity"
	"github.com/xunara-net/xunara-server/networkconfig"
	"github.com/xunara-net/xunara-server/state"
)

func seedConfigurationRelay(test *testing.T, server *Server) string {
	test.Helper()
	secret, err := state.NewRelayTokenSecret()
	if err != nil {
		test.Fatal(err)
	}
	if err := server.store.CreateRelay(state.Relay{ID: "relay-history", RegionName: "原始地区"}, secret); err != nil {
		test.Fatal(err)
	}
	return secret
}

func TestRelayConfigurationHTTPPreconditionsHistoryAndAuthorization(test *testing.T) {
	server := newTestServer(test)
	secret := seedConfigurationRelay(test, server)
	cookie, token := seedUserSession(test, server, state.DefaultUserID)
	headers := map[string]string{"X-CSRF-Token": csrfTokenFor(token)}
	endpoint := "/api/v2/relays/relay-history"
	for _, scenario := range []struct {
		name   string
		body   any
		status int
	}{
		{"missing version", map[string]any{"desired_state": "online"}, 428},
		{"stale version", map[string]any{"config_version": 2, "desired_state": "online"}, 409},
		{"invalid state", map[string]any{"config_version": 1, "desired_state": "bad"}, 400},
		{"negative bandwidth", map[string]any{"config_version": 1, "bandwidth_limit": -2}, 400},
		{"unsafe bandwidth", map[string]any{"config_version": 1, "bandwidth_limit": 1 << 53}, 400},
		{"invalid region", map[string]any{"config_version": 1, "region_name": "injected\nline"}, 400},
		{"empty update", map[string]any{"config_version": 1}, 400},
		{"mixed restore", map[string]any{"config_version": 1, "restore_from": 1, "region_name": "changed"}, 400},
		{"missing history", map[string]any{"config_version": 1, "restore_from": 99}, 404},
	} {
		test.Run(scenario.name, func(test *testing.T) {
			response := accountRequest(test, server, http.MethodPatch, endpoint, scenario.body, cookie, headers)
			if response.Code != scenario.status {
				test.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
		})
	}
	response := accountRequest(test, server, http.MethodPatch, endpoint, map[string]any{"config_version": 1, "desired_state": "maintenance"}, cookie, nil)
	if response.Code != http.StatusForbidden {
		test.Fatal("cookie write did not require CSRF")
	}
	memberID := seedRoleUser(test, server, "read-only", identity.RoleMember)
	memberCookie, memberToken := seedUserSession(test, server, memberID)
	response = accountRequest(test, server, http.MethodPatch, endpoint, map[string]any{"config_version": 1, "desired_state": "maintenance"}, memberCookie, map[string]string{"X-CSRF-Token": csrfTokenFor(memberToken)})
	if response.Code != http.StatusForbidden {
		test.Fatal("member changed configuration")
	}
	response = accountRequest(test, server, http.MethodPatch, endpoint, map[string]any{"config_version": 1, "desired_state": "maintenance"}, cookie, headers)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"configVersion":2`) {
		test.Fatalf("save: %d %s", response.Code, response.Body.String())
	}
	response = accountRequest(test, server, http.MethodGet, endpoint+"/history", nil, memberCookie, nil)
	var history struct {
		Items []networkconfig.RelayHistoryItem `json:"items"`
	}
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &history) != nil || len(history.Items) != 2 || strings.Contains(response.Body.String(), secret) {
		test.Fatal("history read failed or exposed credentials")
	}
	response = accountRequest(test, server, http.MethodPatch, endpoint, map[string]any{"config_version": 2, "restore_from": 1}, cookie, headers)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"configVersion":3`) {
		test.Fatalf("restore: %d %s", response.Code, response.Body.String())
	}
	for _, scenario := range []struct {
		header string
		status int
	}{{"", 428}, {"*", 400}, {"2", 409}, {`"3"`, 204}} {
		deleteHeaders := map[string]string{"X-CSRF-Token": csrfTokenFor(token), "If-Match": scenario.header}
		response = accountRequest(test, server, http.MethodDelete, endpoint, nil, cookie, deleteHeaders)
		if response.Code != scenario.status {
			test.Fatalf("delete precondition=%q status=%d", scenario.header, response.Code)
		}
	}
	response = accountRequest(test, server, http.MethodGet, endpoint+"/history", nil, cookie, nil)
	if response.Code != http.StatusNotFound {
		test.Fatal("deleted service had recoverable history")
	}
}

func TestRelayConfigurationPlatformAndTenantUseOneVersionChain(test *testing.T) {
	first, second := newTestServer(test), newTestServer(test)
	seedConfigurationRelay(test, first)
	router, err := NewRouter(RouterConfig{PlatformAdminToken: "isolated-platform-credential", Orgs: []OrgSite{
		{ID: "one", Domains: []string{"one.test"}, Server: first},
		{ID: "two", Domains: []string{"two.test"}, Server: second},
	}})
	if err != nil {
		test.Fatal(err)
	}
	host := httptest.NewServer(router.Handler())
	test.Cleanup(host.Close)
	endpoint := host.URL + "/api/platform/v1/organizations/one/relays/relay-history"
	response := apiRequest(test, host.Client(), http.MethodPatch, endpoint, "isolated-platform-credential", map[string]any{"config_version": 1, "region_name": "平台配置"})
	if response.StatusCode != http.StatusOK {
		test.Fatalf("platform save: %d", response.StatusCode)
	}
	for _, suffix := range []string{"", "/history"} {
		if response := apiRequest(test, host.Client(), http.MethodGet, endpoint+suffix, "isolated-platform-credential", nil); response.StatusCode != http.StatusOK {
			test.Fatalf("platform read: %d", response.StatusCode)
		}
	}
	foreign := host.URL + "/api/platform/v1/organizations/two/relays/relay-history/history"
	if response := apiRequest(test, host.Client(), http.MethodGet, foreign, "isolated-platform-credential", nil); response.StatusCode != http.StatusNotFound {
		test.Fatal("platform history confused tenant IDs")
	}
	_, key := seedAPIKey(test, first, identity.ScopeRead, identity.ScopeWrite)
	if response := apiRequest(test, host.Client(), http.MethodGet, endpoint, key, nil); response.StatusCode != http.StatusUnauthorized {
		test.Fatal("tenant key authenticated as platform")
	}
	cookie, token := seedUserSession(test, first, state.DefaultUserID)
	result := accountRequest(test, first, http.MethodPatch, "/api/v2/relays/relay-history", map[string]any{"config_version": 1, "desired_state": "disabled"}, cookie, map[string]string{"X-CSRF-Token": csrfTokenFor(token)})
	if result.Code != http.StatusConflict {
		test.Fatal("tenant overwrote a platform edit")
	}
	response = apiRequest(test, host.Client(), http.MethodPatch, endpoint, "isolated-platform-credential", map[string]any{"config_version": 2, "restore_from": 1})
	if response.StatusCode != http.StatusOK {
		test.Fatal("platform restore failed")
	}
	history, err := first.networkConfig.RelayHistory(test.Context(), "relay-history")
	if err != nil || len(history) != 3 || history[0].Actor != "platform:one" {
		test.Fatal("platform history source missing")
	}
	if err := first.store.(*state.SQLiteStore).DB().Close(); err != nil {
		test.Fatal(err)
	}
	if response := apiRequest(test, host.Client(), http.MethodGet, host.URL+"/api/platform/v1/relays", "isolated-platform-credential", nil); response.StatusCode != http.StatusServiceUnavailable {
		test.Fatal("storage failure reported as empty platform list")
	}
}
