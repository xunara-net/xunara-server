package control

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"tailscale.com/derp/derphttp"
	"tailscale.com/net/netmon"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"

	"github.com/xunara-net/xunara-server/identity"
	"github.com/xunara-net/xunara-server/state"
)

func managedRelayFixture(t *testing.T, server *Server, region int, hostname, certificate string, port int) (*httptest.Server, relayEnrollResponse, string) {
	t.Helper()
	host := newTestHTTPServer(t, server)
	_, apiToken := seedAPIKey(t, server, identity.ScopeRead, identity.ScopeWrite)
	enrollment, _ := issueRelayEnrollToken(t, host, apiToken, "private")
	response := enrollRelay(t, host, enrollment, map[string]any{
		"hostname": hostname, "region_code": "private", "region_name": "Private region",
		"region_id": region, "cert_name": certificate, "node_key": key.NewNode().Public().String(), "derp_port": port, "stun_port": 3478,
	})
	if response.StatusCode != http.StatusOK {
		t.Fatalf("managed enrollment: %d %s", response.StatusCode, readBody(t, response))
	}
	var credential relayEnrollResponse
	decodeTestBody(t, response, &credential)
	return host, credential, apiToken
}

func TestManagedRelayMapTracksHealthSteeringExpiryAndDeletion(t *testing.T) {
	static := &tailcfg.DERPMap{Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{1: {RegionID: 1, RegionCode: "static", Nodes: []*tailcfg.DERPNode{{Name: "static", RegionID: 1, HostName: "static.example.test"}}}}}
	server := newServerWithConfig(t, Config{DERPMap: static})
	host, credential, operator := managedRelayFixture(t, server, 40001, "relay.example.test", "sha256-raw:"+strings.Repeat("a", 64), 443)
	if server.DERPMap().Regions[40001] != nil {
		t.Fatal("unhealthy, never-heartbeating relay was advertised")
	}
	response := apiRequest(t, host.Client(), http.MethodPost, host.URL+relayHeartbeatPath, credential.RelayToken, map[string]any{"healthy": true})
	if response.StatusCode != http.StatusOK {
		t.Fatalf("heartbeat: %d", response.StatusCode)
	}
	if server.DERPMap().Regions[40001] == nil || server.DERPMap().Regions[1] == nil || static.Regions[40001] != nil {
		t.Fatal("managed map lost static regions or mutated deployment config")
	}
	if !server.derpRegionKnown(40001) || server.derpRegionsServed() != 2 {
		t.Fatal("placement and metadata did not use the served map")
	}
	response = apiRequest(t, host.Client(), http.MethodPatch, host.URL+"/api/v2/relays/"+credential.RelayID, operator, map[string]any{"config_version": 1, "desired_state": "disabled"})
	if response.StatusCode != http.StatusOK || server.DERPMap().Regions[40001] != nil {
		t.Fatal("disabled relay remained in the map")
	}
	response = apiRequest(t, host.Client(), http.MethodPatch, host.URL+"/api/v2/relays/"+credential.RelayID, operator, map[string]any{"config_version": 2, "desired_state": "online"})
	if response.StatusCode != http.StatusOK || server.DERPMap().Regions[40001] == nil {
		t.Fatal("re-enabled healthy relay was not served")
	}
	core := server.store.(*state.SQLiteStore)
	if _, err := core.DB().ExecContext(t.Context(), "UPDATE relays SET last_seen = ? WHERE id = ?", time.Now().Add(-relayOnlineWindow-time.Second).UnixNano(), credential.RelayID); err != nil {
		t.Fatal(err)
	}
	if err := server.refreshRelayMap(t.Context()); err != nil {
		t.Fatal(err)
	}
	if server.DERPMap().Regions[40001] != nil {
		t.Fatal("stale relay remained in the map")
	}
	response = apiRequest(t, host.Client(), http.MethodDelete, host.URL+"/api/v2/relays/"+credential.RelayID, operator, nil, map[string]string{"If-Match": "3"})
	if response.StatusCode != http.StatusNoContent || len(server.DERPMap().Regions) != 1 {
		t.Fatal("deletion changed static regions")
	}
}

func TestManagedRelayMapIsTenantLocalAndRemovesLastRegionExplicitly(t *testing.T) {
	server := newServerWithConfig(t, Config{DERPMap: &tailcfg.DERPMap{}})
	host, credential, operator := managedRelayFixture(t, server, 40001, "relay.example.test", "", 443)
	response := apiRequest(t, host.Client(), http.MethodPost, host.URL+relayHeartbeatPath, credential.RelayToken, map[string]any{"healthy": true})
	if response.StatusCode != http.StatusOK || server.DERPMap().Regions[40001] == nil {
		t.Fatal("map with nil Regions did not accept managed region")
	}
	other := newTestServer(t)
	if other.DERPMap() != nil || other.derpRegionKnown(40001) {
		t.Fatal("another tenant inherited a private relay")
	}
	session, err := newMapSession()
	if err != nil {
		t.Fatal(err)
	}
	session.initial(&tailcfg.MapResponse{DERPMap: server.DERPMap()})
	response = apiRequest(t, host.Client(), http.MethodDelete, host.URL+"/api/v2/relays/"+credential.RelayID, operator, nil, map[string]string{"If-Match": "1"})
	if response.StatusCode != http.StatusNoContent {
		t.Fatal("relay deletion failed")
	}
	update := &tailcfg.MapResponse{}
	if !session.syncDERP(update, server.DERPMap()) || update.DERPMap == nil || len(update.DERPMap.Regions) != 0 {
		t.Fatal("nil delta would leave the deleted relay on clients")
	}
	if session.syncDERP(&tailcfg.MapResponse{}, server.DERPMap()) {
		t.Fatal("unchanged map produced duplicate updates")
	}
}

func TestManagedRelayEnrollmentValidatesRegionsCertificatesAndHostnames(t *testing.T) {
	server := newTestServer(t)
	host := newTestHTTPServer(t, server)
	_, operator := seedAPIKey(t, server)
	enrollment, _ := issueRelayEnrollToken(t, host, operator, "private")
	for _, fields := range []map[string]any{
		{"region_id": 70000}, {"region_id": -1}, {"cert_name": "sha256-raw:bad"},
		{"region_id": 40001, "node_key": "nodekey:not-a-key"}, {"hostname": "name:443"}, {"hostname": "bad_underscore.example.test"},
	} {
		body := map[string]any{"hostname": "relay.example.test", "region_id": 40001, "node_key": key.NewNode().Public().String()}
		for name, value := range fields {
			body[name] = value
		}
		response := enrollRelay(t, host, enrollment, body)
		if response.StatusCode != http.StatusBadRequest {
			t.Fatalf("invalid enrollment accepted: %d", response.StatusCode)
		}
	}
	if token, err := server.store.LookupRelayEnrollmentToken(t.Context(), enrollment); err != nil || token.Used() {
		t.Fatal("rejected enrollment consumed its token")
	}
	response := enrollRelay(t, host, enrollment, map[string]any{"hostname": "relay.example.test", "region_id": 40001, "node_key": key.NewNode().Public().String()})
	if response.StatusCode != http.StatusOK {
		t.Fatal("valid enrollment failed")
	}
	second, _ := issueRelayEnrollToken(t, host, operator, "private")
	response = enrollRelay(t, host, second, map[string]any{"hostname": "second.example.test", "region_id": 40001, "node_key": key.NewNode().Public().String()})
	if response.StatusCode != http.StatusConflict {
		t.Fatal("duplicate region accepted")
	}
}

func TestManagedRelayEnrollmentCannotOverrideTokenVisibility(testCase *testing.T) {
	for _, visibility := range []string{state.RelayVisibilityPrivate, state.RelayVisibilityOrganization, state.RelayVisibilityPublic} {
		testCase.Run(visibility, func(testCase *testing.T) {
			server := newTestServer(testCase)
			host := newTestHTTPServer(testCase, server)
			_, secret, err := server.createRelayEnrollmentToken("visibility", visibility, time.Hour, "test")
			if err != nil {
				testCase.Fatal(err)
			}
			for _, requested := range []string{state.RelayVisibilityPrivate, state.RelayVisibilityOrganization, state.RelayVisibilityPublic} {
				if requested == visibility {
					continue
				}
				response := enrollRelay(testCase, host, secret, map[string]any{
					"hostname": "relay.example.test", "node_key": key.NewNode().Public().String(), "visibility": requested,
				})
				if response.StatusCode != http.StatusForbidden {
					testCase.Fatalf("visibility override accepted: %d", response.StatusCode)
				}
				record, err := server.store.LookupRelayEnrollmentToken(testCase.Context(), secret)
				if err != nil || record.Used() || len(server.store.ListRelays()) != 0 {
					testCase.Fatal("rejected visibility changed enrollment state")
				}
			}
			response := enrollRelay(testCase, host, secret, map[string]any{
				"hostname": "relay.example.test", "node_key": key.NewNode().Public().String(),
			})
			if response.StatusCode != http.StatusOK || server.store.ListRelays()[0].Visibility != visibility {
				testCase.Fatal("omitted visibility did not inherit token authorization")
			}
		})
	}
}

func TestManagedRelayPolicyAndStorageFailuresDoNotWidenTheMap(t *testing.T) {
	server := newServerWithConfig(t, Config{DERPPolicy: DERPPolicy{Mode: DERPPolicyNone}})
	host, credential, _ := managedRelayFixture(t, server, 40001, "relay.example.test", "", 443)
	response := apiRequest(t, host.Client(), http.MethodPost, host.URL+relayHeartbeatPath, credential.RelayToken, map[string]any{"healthy": true})
	if response.StatusCode != http.StatusOK || len(server.DERPMap().Regions) != 0 {
		t.Fatal("private relay bypassed DERP policy")
	}
	core := server.store.(*state.SQLiteStore)
	previous := server.managedDERP.Load()
	if _, err := core.DB().ExecContext(t.Context(), "UPDATE relays SET cert_name = 'invalid-pin'"); err != nil {
		t.Fatal(err)
	}
	if err := server.refreshRelayMap(t.Context()); err == nil || server.managedDERP.Load() != previous {
		t.Fatal("invalid map replaced the last valid snapshot")
	}
	if _, err := core.DB().ExecContext(t.Context(), "ALTER TABLE relays RENAME TO unavailable_relays"); err != nil {
		t.Fatal(err)
	}
	if err := server.refreshRelayMap(t.Context()); err == nil || server.managedDERP.Load() != previous {
		t.Fatal("storage outage became an empty/default map")
	}
}

func TestManagedRelayMapCertificateWorksWithOfficialDERPClient(t *testing.T) {
	tlsServer := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) { writer.WriteHeader(http.StatusOK) }))
	defer tlsServer.Close()
	hostname, portValue, err := net.SplitHostPort(tlsServer.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portValue)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(tlsServer.Certificate().Raw)
	pin := "sha256-raw:" + hex.EncodeToString(digest[:])
	server := newTestServer(t)
	host, credential, _ := managedRelayFixture(t, server, 40001, hostname, pin, port)
	response := apiRequest(t, host.Client(), http.MethodPost, host.URL+relayHeartbeatPath, credential.RelayToken, map[string]any{"healthy": true})
	if response.StatusCode != http.StatusOK {
		t.Fatal("healthy heartbeat failed")
	}
	region := server.DERPMap().Regions[40001]
	client := derphttp.NewRegionClient(key.NewNode(), t.Logf, netmon.NewStatic(), func() *tailcfg.DERPRegion { return region })
	defer client.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	connection, closer, node, err := client.DialRegionTLS(ctx, region)
	if err != nil {
		t.Fatalf("official TLS client rejected published pin: %v", err)
	}
	if !connection.ConnectionState().HandshakeComplete || node.CertName != pin || node.InsecureForTests {
		t.Fatal("map disabled verification instead of authenticating TLS")
	}
	closer.Close()
	incorrect := region.Clone()
	incorrect.Nodes[0].CertName = "sha256-raw:" + strings.Repeat("0", 64)
	if _, _, _, err := client.DialRegionTLS(ctx, incorrect); err == nil {
		t.Fatal("official client accepted a mismatched certificate pin")
	}
	if regionID, ok := server.singleDERPRegion(); !ok || regionID != tailcfg.DERPRegionID(40001) {
		t.Fatalf("single-region placement did not use managed map: %+v", server.DERPMap())
	}
}
