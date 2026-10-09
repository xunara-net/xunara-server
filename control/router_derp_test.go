package control

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

func TestSharedDERPAdmitEnforcesEachTenantPolicy(t *testing.T) {
	sharedMap := derpTestMap()
	privateMap := sharedMap.Clone()
	for _, region := range privateMap.Regions {
		for _, node := range region.Nodes {
			node.HostName = "private.example.com"
		}
	}
	cases := []struct {
		name    string
		config  Config
		expired bool
		want    bool
	}{
		{name: "shared", config: Config{DERPMap: sharedMap}, want: true},
		{name: "expired", config: Config{DERPMap: sharedMap}, expired: true},
		{name: "disabled", config: Config{DERPMap: sharedMap, DERPPolicy: DERPPolicy{Mode: DERPPolicyNone}}},
		{name: "private with colliding region IDs", config: Config{DERPMap: privateMap}},
		{name: "no configured map", config: Config{}},
		{name: "restricted shared region", config: Config{DERPMap: sharedMap, DERPPolicy: DERPPolicy{Mode: DERPPolicyRegions, Regions: []int{1}}}, want: true},
	}
	var sites []OrgSite
	var requests []struct {
		name    string
		nodeKey key.NodePublic
		want    bool
	}
	for index, testCase := range cases {
		server := newServerWithConfig(t, testCase.config)
		node := seedTestNode(t, server)
		if testCase.expired {
			node.Expiry = time.Now().Add(-time.Hour)
			if err := server.store.UpdateNode(node); err != nil {
				t.Fatal(err)
			}
		}
		id := "tenant-" + string(rune('a'+index))
		sites = append(sites, OrgSite{ID: id, Domains: []string{id + ".example.com"}, Server: server})
		requests = append(requests, struct {
			name    string
			nodeKey key.NodePublic
			want    bool
		}{testCase.name, node.NodeKey, testCase.want})
	}
	router := newTestRouter(t, RouterConfig{Orgs: sites, SharedDERPMap: sharedMap})
	for _, testCase := range requests {
		t.Run(testCase.name, func(t *testing.T) {
			recorder := postJSONAtHost(t, router.Handler(), "127.0.0.1", relayAdmissionPath, tailcfg.DERPAdmitClientRequest{NodePublic: testCase.nodeKey})
			var response tailcfg.DERPAdmitClientResponse
			if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
				t.Fatal(err)
			}
			if recorder.Code != http.StatusOK || response.Allow != testCase.want {
				t.Fatalf("admission status=%d allow=%v, want 200/%v", recorder.Code, response.Allow, testCase.want)
			}
		})
	}
	for _, nodeKey := range []key.NodePublic{{}, key.NewNode().Public()} {
		recorder := postJSONAtHost(t, router.Handler(), "127.0.0.1", relayAdmissionPath, tailcfg.DERPAdmitClientRequest{NodePublic: nodeKey})
		var response tailcfg.DERPAdmitClientResponse
		if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
			t.Fatal(err)
		}
		if recorder.Code != http.StatusOK || response.Allow {
			t.Fatal("unknown or zero node key was admitted")
		}
	}
}

func TestSharedDERPAdmitRequiresConfigurationAndRejectsBadBodies(t *testing.T) {
	server := newTestServer(t)
	plain := newTestRouter(t, RouterConfig{Orgs: []OrgSite{{ID: "plain", Server: server}}})
	recorder := postJSONAtHost(t, plain.Handler(), "127.0.0.1", relayAdmissionPath, tailcfg.DERPAdmitClientRequest{})
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("unconfigured shared admission = %d, want 404", recorder.Code)
	}
	router := newTestRouter(t, RouterConfig{
		Orgs: []OrgSite{{ID: "shared", Server: newTestServer(t)}}, SharedDERPMap: derpTestMap(),
	})
	for _, body := range []string{"", "{", "{} {}", strings.Repeat(" ", maxDERPAdmitRequestBytes) + "{}"} {
		request := httptest.NewRequest(http.MethodPost, "http://127.0.0.1"+relayAdmissionPath, strings.NewReader(body))
		recorder := httptest.NewRecorder()
		router.Handler().ServeHTTP(recorder, request)
		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("invalid admission body = %d, want 400", recorder.Code)
		}
	}
}
