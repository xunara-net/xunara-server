package control

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"

	"tailscale.com/tailcfg"

	"github.com/xunara-net/xunara-server/identity"
	"github.com/xunara-net/xunara-server/plan"
	"github.com/xunara-net/xunara-server/policy"
	"github.com/xunara-net/xunara-server/state"
)

type consolePolicyConfiguration struct {
	Revision uint64 `json:"revision"`
	BaseHash string `json:"base_hash"`
	Content  string `json:"content"`
	Source   string `json:"source"`
}

func consolePolicy(t *testing.T, server *Server, cookie *http.Cookie) consolePolicyConfiguration {
	t.Helper()
	response := accountRequest(t, server, http.MethodGet, "/api/v2/policy/configuration", nil, cookie, nil)
	if response.Code != http.StatusOK {
		t.Fatalf("configuration: %d %s", response.Code, response.Body.String())
	}
	var configuration consolePolicyConfiguration
	if err := json.Unmarshal(response.Body.Bytes(), &configuration); err != nil {
		t.Fatal(err)
	}
	return configuration
}

func policyBody(configuration consolePolicyConfiguration, content string) map[string]any {
	return map[string]any{"revision": configuration.Revision, "base_hash": configuration.BaseHash, "content": content}
}

func TestNetworkConsolePolicyPublicationHistoryRestartAndCAS(t *testing.T) {
	path := policyFile(t, `{"acls":[{"src":["*"],"dst":["*:*"]}]}`)
	server := newServerWithConfig(t, Config{PolicyPath: path})
	cookie, token := seedUserSession(t, server, state.DefaultUserID)
	source := seedAPIMachine(t, server, "laptop", nil)
	destination := seedAPIMachine(t, server, "nas", nil)
	before := consolePolicy(t, server, cookie)
	content := fmt.Sprintf(`{"acls":[{"src":[%q],"dst":[%q],"proto":"tcp"}],"tests":[{"src":%q,"accept":[%q],"deny":[%q]}]}`, source.IPv4.String(), destination.IPv4.String()+":443", source.IPv4.String(), destination.IPv4.String()+":443", destination.IPv4.String()+":22")
	body := policyBody(before, content)
	response := accountRequest(t, server, http.MethodPost, "/api/v2/policy/validate", body, cookie, nil)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"publishable":true`) {
		t.Fatalf("preview: %d %s", response.Code, response.Body.String())
	}
	if server.policy.Load().Document().ACLs[0].Dst[0] != "*:*" {
		t.Fatal("preview modified live permissions")
	}
	response = accountRequest(t, server, http.MethodPut, "/api/v2/policy/configuration", body, cookie, map[string]string{"X-CSRF-Token": csrfTokenFor(token)})
	if response.Code != http.StatusOK {
		t.Fatalf("publication: %d %s", response.Code, response.Body.String())
	}
	nodes := server.store.ListNodes()
	if !policy.AllowsIngress(server.packetFilterFor(destination), destination, source, "tcp", 443) || policy.AllowsIngress(server.packetFilterFor(destination), destination, source, "tcp", 22) {
		t.Fatal("published permissions did not reach the real compiler")
	}
	if len(nodes) != 2 {
		t.Fatal("publication altered devices")
	}
	response = accountRequest(t, server, http.MethodPut, "/api/v2/policy/configuration", body, cookie, map[string]string{"X-CSRF-Token": csrfTokenFor(token)})
	if response.Code != http.StatusConflict {
		t.Fatalf("stale CAS accepted: %d", response.Code)
	}
	if err := os.WriteFile(path, []byte(`malformed deployment file`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := server.refreshManagedConfiguration(t.Context()); err != nil {
		t.Fatalf("file overwrote managed policy: %v", err)
	}
	current := consolePolicy(t, server, cookie)
	if current.Revision != 1 || current.Source != "database" {
		t.Fatalf("managed authority: %+v", current)
	}
	restarted, err := New(server.cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { restarted.Close() })
	if restarted.policyConfig.Load().Revision != 1 || policy.AllowsIngress(restarted.packetFilterFor(destination), destination, source, "tcp", 22) {
		t.Fatal("restart lost published permissions")
	}
	response = accountRequest(t, restarted, http.MethodPut, "/api/v2/policy/configuration", map[string]any{"revision": current.Revision, "base_hash": current.BaseHash, "restore_from": 0}, cookie, map[string]string{"X-CSRF-Token": csrfTokenFor(token)})
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"revision":2`) {
		t.Fatalf("restore: %d %s", response.Code, response.Body.String())
	}
	if err := server.refreshManagedConfiguration(t.Context()); err != nil {
		t.Fatal(err)
	}
	if !policy.AllowsIngress(server.packetFilterFor(destination), destination, source, "tcp", 22) {
		t.Fatal("second instance did not reload restored permissions")
	}
	response = accountRequest(t, server, http.MethodGet, "/api/v2/policy/history", nil, cookie, nil)
	var history struct {
		Items []consolePolicyConfiguration `json:"items"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &history); err != nil || len(history.Items) != 3 {
		t.Fatalf("history: %s %v", response.Body.String(), err)
	}
}

func TestNetworkConsolePolicyRejectsInvalidTestsAndUnconfirmedPublication(t *testing.T) {
	server := newTestServer(t)
	cookie, token := seedUserSession(t, server, state.DefaultUserID)
	before := consolePolicy(t, server, cookie)
	for _, content := range []string{`{"acls":[{"src":["group:missing"],"dst":["*:443"]}]}`, `{"ACLs":[]}`, `{"acls":[],"acls":[]}`} {
		response := accountRequest(t, server, http.MethodPut, "/api/v2/policy/configuration", policyBody(before, content), cookie, map[string]string{"X-CSRF-Token": csrfTokenFor(token)})
		if response.Code != http.StatusBadRequest {
			t.Fatalf("invalid policy: %d %s", response.Code, response.Body.String())
		}
	}
	failedTests := `{"tests":[{"src":"100.64.0.1","accept":["100.64.0.2:22"]}]}`
	response := accountRequest(t, server, http.MethodPost, "/api/v2/policy/validate", policyBody(before, failedTests), cookie, nil)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"publishable":false`) {
		t.Fatal("unexecuted assertions were reported publishable")
	}
	seedAPIMachine(t, server, "source", nil)
	seedAPIMachine(t, server, "destination", nil)
	response = accountRequest(t, server, http.MethodPut, "/api/v2/policy/configuration", policyBody(before, failedTests), cookie, map[string]string{"X-CSRF-Token": csrfTokenFor(token)})
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "POLICY_TEST_FAILED") {
		t.Fatalf("failed assertions: %d %s", response.Code, response.Body.String())
	}
	response = accountRequest(t, server, http.MethodPut, "/api/v2/policy/configuration", policyBody(before, `{}`), cookie, nil)
	if response.Code != http.StatusForbidden || !strings.Contains(response.Body.String(), "CSRF_INVALID") {
		t.Fatal("session publication without CSRF succeeded")
	}
	if current := consolePolicy(t, server, cookie); current.Revision != 0 || current.Content != before.Content {
		t.Fatal("rejected draft changed permissions")
	}
}

func TestNetworkConsolePolicySimulationAndMatrixUseSameEngine(t *testing.T) {
	server := newTestServer(t)
	cookie, _ := seedUserSession(t, server, state.DefaultUserID)
	source := seedAPIMachine(t, server, "source", nil)
	destination := seedAPIMachine(t, server, "destination", nil)
	content := fmt.Sprintf(`{"grants":[{"src":[%q],"dst":[%q],"ip":["tcp:443"]}]}`, source.IPv4.String(), destination.IPv4.String())
	for _, port := range []int{443, 22} {
		response := accountRequest(t, server, http.MethodPost, "/api/v2/policy/simulate", map[string]any{"source": source.ID, "destination": destination.ID, "protocol": "tcp", "port": port, "content": content}, cookie, nil)
		var explanation policy.Explanation
		if err := json.Unmarshal(response.Body.Bytes(), &explanation); err != nil || response.Code != http.StatusOK || explanation.Allowed != (port == 443) {
			t.Fatalf("simulation: %d %s %v", response.Code, response.Body.String(), err)
		}
		if port == 443 && (len(explanation.Matches) != 1 || explanation.Matches[0].Sources[0] != source.IPv4.String()) {
			t.Fatal("explanation did not refer to the tested draft")
		}
		response = accountRequest(t, server, http.MethodPost, "/api/v2/policy/matrix", map[string]any{"sources": []state.NodeID{source.ID}, "destinations": []state.NodeID{destination.ID}, "protocol": "tcp", "port": port, "content": content}, cookie, nil)
		var matrix struct {
			Items []struct {
				Allowed bool `json:"allowed"`
			} `json:"items"`
		}
		if err := json.Unmarshal(response.Body.Bytes(), &matrix); err != nil || response.Code != http.StatusOK || len(matrix.Items) != 1 || matrix.Items[0].Allowed != explanation.Allowed {
			t.Fatalf("matrix drift: %d %s %v", response.Code, response.Body.String(), err)
		}
	}
	response := accountRequest(t, server, http.MethodPost, "/api/v2/policy/simulate", map[string]any{"source": source.ID, "destination": 9999, "protocol": "tcp", "port": 443}, cookie, nil)
	if response.Code != http.StatusBadRequest {
		t.Fatal("unknown tenant-local device was accepted")
	}
	other := newTestServer(t)
	response = accountRequest(t, other, http.MethodGet, "/api/v2/policy/history", nil, cookie, nil)
	if response.Code != http.StatusUnauthorized {
		t.Fatal("a foreign tenant session could read history")
	}
}

func TestNetworkConsoleWriterRolePlanAndStorageBoundaries(t *testing.T) {
	server := newServerWithConfig(t, Config{Domain: "xunara.test", PlanSource: func(string) plan.Plan { return plan.Plan{ID: "limited", AllowACL: true, MaxRelays: 1} }})
	cookie, token := seedUserSession(t, server, state.DefaultUserID)
	before := consolePolicy(t, server, cookie)
	member := seedRoleUser(t, server, "member", identity.RoleMember)
	memberCookie, memberToken := seedUserSession(t, server, member)
	response := accountRequest(t, server, http.MethodPut, "/api/v2/policy/configuration", policyBody(before, `{}`), memberCookie, map[string]string{"X-CSRF-Token": csrfTokenFor(memberToken)})
	if response.Code != http.StatusForbidden {
		t.Fatal("member changed policy")
	}
	_, serviceToken := seedAPIKey(t, server, identity.ScopeRead, identity.ScopeWrite)
	for _, endpoint := range []string{"/api/v2/policy/configuration", "/api/v2/relays/enroll-tokens"} {
		response = accountRequest(t, server, http.MethodPost, endpoint, map[string]any{}, nil, map[string]string{"Authorization": "Bearer " + serviceToken})
		if endpoint == "/api/v2/policy/configuration" {
			response = accountRequest(t, server, http.MethodPut, endpoint, policyBody(before, `{}`), nil, map[string]string{"Authorization": "Bearer " + serviceToken})
		}
		if response.Code != http.StatusForbidden {
			t.Fatalf("API entitlement bypass: %s %d", endpoint, response.Code)
		}
	}
	response = accountRequest(t, server, http.MethodPut, "/api/v2/policy/configuration", policyBody(before, `{"grants":[{"src":["*"],"dst":["*"],"ip":["tcp:443"]}]}`), cookie, map[string]string{"X-CSRF-Token": csrfTokenFor(token)})
	if response.Code != http.StatusForbidden {
		t.Fatal("grants entitlement bypass")
	}
	response = accountRequest(t, server, http.MethodPost, "/api/v2/dns/records", map[string]string{"name": "nas.xunara.test", "type": "A", "value": "100.64.0.2"}, cookie, map[string]string{"X-CSRF-Token": csrfTokenFor(token)})
	if response.Code != http.StatusForbidden {
		t.Fatal("DNS entitlement bypass")
	}
	core := server.store.(*state.SQLiteStore)
	if _, err := core.DB().ExecContext(t.Context(), "CREATE TRIGGER deny_policy_audit BEFORE INSERT ON audit_events BEGIN SELECT RAISE(ABORT, 'injected outage'); END"); err != nil {
		t.Fatal(err)
	}
	response = accountRequest(t, server, http.MethodPut, "/api/v2/policy/configuration", policyBody(before, `{}`), cookie, map[string]string{"X-CSRF-Token": csrfTokenFor(token)})
	if response.Code != http.StatusServiceUnavailable || server.policyConfig.Load().Revision != 0 || server.policy.Load() != nil {
		t.Fatalf("partial publication: %d %s", response.Code, response.Body.String())
	}
	if _, err := core.DB().ExecContext(t.Context(), "ALTER TABLE nodes RENAME TO unavailable_nodes"); err != nil {
		t.Fatal(err)
	}
	response = accountRequest(t, server, http.MethodPost, "/api/v2/policy/simulate", map[string]any{"source": 1, "destination": 2, "protocol": "tcp", "port": 443}, cookie, nil)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("device storage outage was misreported as policy denial: %d", response.Code)
	}
}

func TestNetworkConsoleDNSRecordCRUDAndLegacyProtection(t *testing.T) {
	server := newServerWithConfig(t, Config{Domain: "xunara.test"})
	cookie, token := seedUserSession(t, server, state.DefaultUserID)
	headers := map[string]string{"X-CSRF-Token": csrfTokenFor(token)}
	response := accountRequest(t, server, http.MethodPost, "/api/v2/dns/records", map[string]string{"name": "nas.xunara.test", "type": "A", "value": "100.64.0.20"}, cookie, headers)
	var record struct {
		ID       uint64 `json:"id"`
		Revision uint64 `json:"revision"`
	}
	if response.Code != http.StatusCreated || json.Unmarshal(response.Body.Bytes(), &record) != nil || record.ID == 0 || record.Revision != 1 {
		t.Fatalf("record creation: %d %s", response.Code, response.Body.String())
	}
	endpoint := "/api/v2/dns/records/" + strconv.FormatUint(record.ID, 10)
	response = accountRequest(t, server, http.MethodPut, endpoint, map[string]any{"name": "nas.xunara.test", "type": "A", "value": "100.64.0.21", "revision": 1}, cookie, headers)
	if response.Code != http.StatusOK {
		t.Fatalf("record edit: %d %s", response.Code, response.Body.String())
	}
	headers["If-Match"] = "1"
	response = accountRequest(t, server, http.MethodDelete, endpoint, nil, cookie, headers)
	if response.Code != http.StatusConflict {
		t.Fatal("stale DNS deletion succeeded")
	}
	headers["If-Match"] = "2"
	response = accountRequest(t, server, http.MethodDelete, endpoint, nil, cookie, headers)
	if response.Code != http.StatusNoContent {
		t.Fatal("confirmed DNS deletion failed")
	}
	protected := state.DNSRecord{Name: "_acme-challenge.nas.xunara.test", Type: "TXT", Value: "not-a-secret", NodeID: 1}
	if err := server.store.UpsertDNSRecord(&protected); err != nil {
		t.Fatal(err)
	}
	response = accountRequest(t, server, http.MethodDelete, "/api/v1/dns/"+strconv.FormatUint(protected.ID, 10), nil, cookie, headers)
	if response.Code != http.StatusForbidden || !strings.Contains(response.Body.String(), "DNS_RECORD_PROTECTED") {
		t.Fatal("legacy API bypassed protected-record rules")
	}
	for _, body := range []map[string]string{{"name": "nas.outside.test", "type": "A", "value": "100.64.0.2"}, {"name": "nas.xunara.test", "type": "CNAME", "value": "node.xunara.test"}, {"name": "nas.xunara.test", "type": "AAAA", "value": "100.64.0.2"}} {
		response = accountRequest(t, server, http.MethodPost, "/api/v2/dns/records", body, cookie, headers)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("unsupported record accepted: %d", response.Code)
		}
	}
}

func TestNetworkConsolePublishedDNSAndPolicyReachNoiseStream(t *testing.T) {
	server := newServerWithConfig(t, Config{Domain: "xunara.test"})
	host := newTestHTTPServer(t, server)
	connection, client, nodeKey := registerNode(t, server, host, "laptop")
	defer connection.Close()
	stream := openMapSession(t, client, nodeKey.Public())
	defer stream.Body.Close()
	frames, view := mapFrames(stream.Body), newNetmapView()
	waitForNetmapFrame(t, frames, view, func(*netmapView) bool { return true })
	cookie, token := seedUserSession(t, server, state.DefaultUserID)
	headers := map[string]string{"X-CSRF-Token": csrfTokenFor(token)}
	response := accountRequest(t, server, http.MethodGet, "/api/v2/dns/configuration", nil, cookie, nil)
	var dnsConfiguration struct {
		Revision uint64 `json:"revision"`
		BaseHash string `json:"base_hash"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &dnsConfiguration); err != nil {
		t.Fatal(err)
	}
	settings := dnsSettings{MagicDNS: false, Nameservers: []string{"1.1.1.1"}, SearchDomains: []string{"corp.example.test"}, SplitDNS: map[string][]string{"office.example.test": {"10.0.0.53:5353"}}}
	response = accountRequest(t, server, http.MethodPut, "/api/v2/dns/configuration", map[string]any{"revision": dnsConfiguration.Revision, "base_hash": dnsConfiguration.BaseHash, "settings": settings}, cookie, headers)
	if response.Code != http.StatusOK {
		t.Fatalf("DNS publish: %d %s", response.Code, response.Body.String())
	}
	var dnsUpdate *tailcfg.MapResponse
	for dnsUpdate == nil || dnsUpdate.DNSConfig == nil {
		dnsUpdate = waitForNetmapFrame(t, frames, view, func(*netmapView) bool { return true })
	}
	if dnsUpdate.DNSConfig.Proxied || dnsUpdate.DNSConfig.Resolvers[0].Addr != "1.1.1.1" || dnsUpdate.DNSConfig.Domains[0] != "corp.example.test" || dnsUpdate.DNSConfig.Routes["office.example.test"][0].Addr != "10.0.0.53:5353" {
		t.Fatalf("DNS wire mismatch: %+v", dnsUpdate.DNSConfig)
	}
	configuration := consolePolicy(t, server, cookie)
	response = accountRequest(t, server, http.MethodPut, "/api/v2/policy/configuration", policyBody(configuration, `{}`), cookie, headers)
	if response.Code != http.StatusOK {
		t.Fatalf("policy publish: %d %s", response.Code, response.Body.String())
	}
	var filterUpdate *tailcfg.MapResponse
	for filterUpdate == nil || filterUpdate.PacketFilters["base"] == nil {
		filterUpdate = waitForNetmapFrame(t, frames, view, func(*netmapView) bool { return true })
	}
	if len(filterUpdate.PacketFilters["base"]) != 0 {
		t.Fatal("empty policy was not sent as an explicit deny-all filter")
	}
}

func TestNetworkConsoleClearsPreviouslyManagedDNS(t *testing.T) {
	server := newTestServer(t)
	cookie, token := seedUserSession(t, server, state.DefaultUserID)
	headers := map[string]string{"X-CSRF-Token": csrfTokenFor(token)}
	for _, resolvers := range [][]string{{"1.1.1.1"}, {}} {
		response := accountRequest(t, server, http.MethodGet, "/api/v2/dns/configuration", nil, cookie, nil)
		var configuration struct {
			Revision uint64 `json:"revision"`
			BaseHash string `json:"base_hash"`
		}
		if err := json.Unmarshal(response.Body.Bytes(), &configuration); err != nil {
			t.Fatal(err)
		}
		response = accountRequest(t, server, http.MethodPut, "/api/v2/dns/configuration", map[string]any{"revision": configuration.Revision, "base_hash": configuration.BaseHash, "settings": dnsSettings{Nameservers: resolvers}}, cookie, headers)
		if response.Code != http.StatusOK {
			t.Fatalf("DNS publish: %d %s", response.Code, response.Body.String())
		}
	}
	if actual := server.dnsConfigFor(state.Node{}); actual == nil || len(actual.Resolvers) != 0 || actual.Proxied {
		t.Fatalf("nil would retain old client DNS: %+v", actual)
	}
}
