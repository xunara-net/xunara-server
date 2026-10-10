package control

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"tailscale.com/tailcfg"

	"github.com/xunara-net/xunara-server/identity"
	"github.com/xunara-net/xunara-server/state"
)

func externalMapFixture(identifier tailcfg.DERPRegionID) *tailcfg.DERPMap {
	return &tailcfg.DERPMap{Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{identifier: {
		RegionID: identifier, RegionCode: "public", RegionName: "外部公共中继",
		Nodes: []*tailcfg.DERPNode{{Name: "external-" + identifier.String(), RegionID: identifier, HostName: "relay.example.test", DERPPort: 8443, STUNPort: -1, CertName: "sha256-raw:" + strings.Repeat("a", 64)}},
	}}}
}

func TestExternalDERPPublicationDefaultVisibilityHistoryRestartAndDeletion(t *testing.T) {
	base := externalMapFixture(1)
	server := newServerWithConfig(t, Config{DERPMap: base})
	cookie, token := seedUserSession(t, server, state.DefaultUserID)
	headers := map[string]string{"X-CSRF-Token": csrfTokenFor(token)}
	body := map[string]any{"revision": 0, "map": externalMapFixture(900)}
	response := accountRequest(t, server, http.MethodPut, "/api/v2/derp/configuration", body, cookie, headers)
	if response.Code != http.StatusOK {
		t.Fatalf("map publication: %d %s", response.Code, response.Body.String())
	}
	if len(server.DERPMap().Regions) != 2 || base.Regions[900] != nil || len(server.store.ListRelays()) != 0 {
		t.Fatal("external publication overwrote defaults or manufactured a managed identity")
	}
	view, _ := server.derpStatus()
	if view.Regions[0].Source != "deployment" || view.Regions[1].Source != "external" || view.Regions[1].Nodes[0].STUNPort != -1 || view.Regions[1].Nodes[0].DERPPort != 8443 {
		t.Fatal("map status hid sources or lost complete port configuration")
	}
	if response := accountRequest(t, server, http.MethodPut, "/api/v2/derp/configuration", body, cookie, headers); response.Code != http.StatusConflict {
		t.Fatal("stale map version accepted")
	}
	restarted, err := New(server.cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { restarted.Close() })
	if restarted.DERPMap().Regions[900] == nil {
		t.Fatal("external map disappeared on restart")
	}
	response = accountRequest(t, restarted, http.MethodPut, "/api/v2/derp/configuration", map[string]any{"revision": 1, "restore_from": 0}, cookie, headers)
	if response.Code != http.StatusOK || len(restarted.DERPMap().Regions) != 1 {
		t.Fatal("restore did not retain deployment default")
	}
	response = accountRequest(t, restarted, http.MethodGet, "/api/v2/derp/history", nil, cookie, nil)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"revision":2`) {
		t.Fatal("external map history missing")
	}
	other := newTestServer(t)
	if response := accountRequest(t, other, http.MethodGet, "/api/v2/derp/configuration", nil, cookie, nil); response.Code != http.StatusUnauthorized {
		t.Fatal("foreign tenant session read external configuration")
	}
}

func TestExternalDERPAuthorityCollisionAndPolicy(t *testing.T) {
	server := newServerWithConfig(t, Config{DERPMap: externalMapFixture(1), DERPPolicy: DERPPolicy{Mode: DERPPolicyNone}})
	cookie, token := seedUserSession(t, server, state.DefaultUserID)
	body := map[string]any{"revision": 0, "map": externalMapFixture(900)}
	if response := accountRequest(t, server, http.MethodPut, "/api/v2/derp/configuration", body, cookie, nil); response.Code != http.StatusForbidden {
		t.Fatal("map publication lacked CSRF")
	}
	member := seedRoleUser(t, server, "member", identity.RoleMember)
	memberCookie, memberToken := seedUserSession(t, server, member)
	if response := accountRequest(t, server, http.MethodPut, "/api/v2/derp/configuration", body, memberCookie, map[string]string{"X-CSRF-Token": csrfTokenFor(memberToken)}); response.Code != http.StatusForbidden {
		t.Fatal("member changed external map")
	}
	headers := map[string]string{"X-CSRF-Token": csrfTokenFor(token)}
	body["map"] = externalMapFixture(1)
	if response := accountRequest(t, server, http.MethodPut, "/api/v2/derp/configuration", body, cookie, headers); response.Code != http.StatusConflict {
		t.Fatal("default region overwritten")
	}
	body["map"] = externalMapFixture(900)
	if response := accountRequest(t, server, http.MethodPut, "/api/v2/derp/configuration", body, cookie, headers); response.Code != http.StatusOK {
		t.Fatalf("publication: %d %s", response.Code, response.Body.String())
	}
	if len(server.DERPMap().Regions) != 0 || !server.DERPMap().OmitDefaultRegions {
		t.Fatal("external map bypassed tenant DERP policy")
	}
	host, _, operator := managedRelayFixture(t, server, 40001, "managed.example.test", "", 443)
	body["revision"], body["map"] = 1, externalMapFixture(40001)
	if response := accountRequest(t, server, http.MethodPut, "/api/v2/derp/configuration", body, cookie, headers); response.Code != http.StatusConflict {
		t.Fatal("offline managed region overwritten")
	}
	enrollment, _ := issueRelayEnrollToken(t, host, operator, "private")
	response := enrollRelay(t, host, enrollment, map[string]any{"hostname": "another.example.test", "region_id": 900, "node_key": "nodekey:" + strings.Repeat("b", 64), "derp_port": 443, "stun_port": 3478})
	if response.StatusCode != http.StatusConflict {
		t.Fatalf("external/enrollment collision: %d %s", response.StatusCode, readBody(t, response))
	}
	if record, err := server.store.LookupRelayEnrollmentToken(t.Context(), enrollment); err != nil || record.Used() {
		t.Fatal("collision consumed one-time relay credential")
	}
}

type externalMapTransport func(*http.Request) (*http.Response, error)

func (transport externalMapTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	return transport(request)
}

func TestOfficialDERPImportHasFixedSourceBoundedResponseAndNoRedirect(t *testing.T) {
	content, err := json.Marshal(externalMapFixture(1))
	if err != nil {
		t.Fatal(err)
	}
	for _, sample := range []struct {
		name   string
		status int
		body   string
		valid  bool
	}{
		{"valid", 200, string(content), true}, {"redirect", 302, "", false}, {"failure", 503, "private upstream details", false}, {"oversized", 200, strings.Repeat(" ", externalDERPMaxBytes+1), false}, {"unknown field", 200, `{"Regions":{},"Unknown":true}`, false}, {"test override", 200, `{"Regions":{"1":{"RegionID":1,"Nodes":[{"Name":"unsafe","RegionID":1,"HostName":"relay.example.test","InsecureForTests":true}]}}}`, false},
	} {
		t.Run(sample.name, func(t *testing.T) {
			calls := 0
			transport := externalMapTransport(func(request *http.Request) (*http.Response, error) {
				calls++
				if request.URL.String() != officialDERPMapURL || request.Header.Get("Authorization") != "" || request.Context() == nil {
					t.Fatal("import did not enforce fixed source/context/no credential")
				}
				return &http.Response{StatusCode: sample.status, Header: http.Header{"Location": []string{"http://127.0.0.1/secret"}}, Body: io.NopCloser(strings.NewReader(sample.body)), Request: request}, nil
			})
			value, err := fetchOfficialDERPMap(t.Context(), transport)
			if calls != 1 || (err == nil) != sample.valid || sample.valid && value.Regions[1] == nil {
				t.Fatalf("import result: calls=%d map=%v err=%v", calls, value, err)
			}
		})
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := fetchOfficialDERPMap(ctx, nil); err == nil {
		t.Fatal("cancelled fetch succeeded")
	}
}
