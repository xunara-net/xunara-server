package control

import (
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"tailscale.com/tailcfg"

	"github.com/xunara-net/xunara-server/identity"
	"github.com/xunara-net/xunara-server/state"
)

func TestMachineConnectionReportWhitelistAndUnits(test *testing.T) {
	server := newServerWithConfig(test, Config{DERPMap: derpTestMap()})
	lastSeen := time.Now().UTC().Add(-time.Hour)
	node := state.Node{StableID: "connection-device", HomeDERP: 2, LastSeen: &lastSeen,
		Endpoints: []netip.AddrPort{netip.MustParseAddrPort("192.0.2.2:41641"), netip.MustParseAddrPort("[2001:db8::1]:1234")},
		Hostinfo: &tailcfg.Hostinfo{FrontendLogID: "private-frontend", BackendLogID: "private-backend", PushDeviceToken: "private-push",
			NetInfo: &tailcfg.NetInfo{PreferredDERP: 1, WorkingUDP: "false", WorkingIPv6: "true", LinkType: "wifi",
				DERPLatency: map[string]float64{"2-v6": .035, "1-v4": .01234, "2-v4": 0, "99-v4": .001,
					"private.example:3478": .01, "01-v4": .01, "1-v5": .01, "1-v6": -1, "3-v4": math.Inf(1), "4-v4": math.NaN()}}}}
	view := server.machineConnectionView(node)
	if view.HomeRegion == nil || view.HomeRegion.ID != 2 || view.HomeRegion.Name != "Singapore" || !view.HomeRegion.Advertised || view.ReportedRegionID != 1 || !view.ReportedRegionAdvertised {
		test.Fatal("client preference and effective home were not kept separate")
	}
	if !view.ReportAvailable || view.Network == nil || view.Network.UDP == nil || *view.Network.UDP || view.Network.IPv6 == nil || !*view.Network.IPv6 || view.Network.UPnP != nil {
		test.Fatal("unknown network facts were confused with explicit false")
	}
	if len(view.Latencies) != 3 || view.Latencies[0].RegionID != 1 || view.Latencies[0].Milliseconds != 12.34 || view.Latencies[1].Milliseconds != 0 || view.Latencies[2].AddressFamily != "ipv6" {
		test.Fatalf("unexpected filtered/sorted measurements: %+v", view.Latencies)
	}
	if view.HomeRegion.Servers[0].DERPPort != 443 || view.HomeRegion.Servers[0].STUNPort != 3478 {
		test.Fatal("upstream default ports were not applied")
	}
	encoded, err := json.Marshal(view)
	if err != nil {
		test.Fatal(err)
	}
	for _, forbidden := range []string{"private-", "private.example", "machineKey", "nodeKey", "discoKey", "hostinfo", "connectionType", "reportTime"} {
		if strings.Contains(string(encoded), forbidden) {
			test.Fatalf("connection DTO leaks or invents %q", forbidden)
		}
	}
	view.Endpoints[0] = "changed"
	view.HomeRegion.Servers[0].Hostname = "changed"
	*view.LastControlSeenAt = time.Time{}
	if node.Endpoints[0].String() != "192.0.2.2:41641" || node.LastSeen.IsZero() || server.DERPMap().Regions[2].Nodes[0].HostName == "changed" {
		test.Fatal("presentation mutated stored metadata")
	}
}

func TestMachineConnectionMissingAndUnservedReports(test *testing.T) {
	for _, mode := range []DERPPolicyMode{"", DERPPolicyNone, DERPPolicyRegions} {
		policy := DERPPolicy{Mode: mode}
		if mode == DERPPolicyRegions {
			policy.Regions = []int{1}
		}
		server := newServerWithConfig(test, Config{DERPMap: derpTestMap(), DERPPolicy: policy})
		view := server.machineConnectionView(state.Node{HomeDERP: 99})
		if view.ReportAvailable || view.Network != nil || view.HomeRegion == nil || view.HomeRegion.Advertised || view.HomeRegion.Name != "" || len(view.HomeRegion.Servers) != 0 || len(view.Latencies) != 0 {
			test.Fatal("missing report or hidden region became a successful connection")
		}
	}
	server := newTestServer(test)
	view := server.machineConnectionView(state.Node{})
	if view.MapConfigured || view.HomeRegion != nil || view.ReportedRegionID != 0 || view.Endpoints == nil || view.Latencies == nil {
		test.Fatal("no configured map was confused with a disabled or populated map")
	}
}

func TestMachineConnectionResponseLimits(test *testing.T) {
	regions := map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{}
	report := &tailcfg.NetInfo{DERPLatency: map[string]float64{}}
	node := state.Node{HomeDERP: 1, Hostinfo: &tailcfg.Hostinfo{NetInfo: report}}
	for index := 1; index <= 140; index++ {
		identifier := tailcfg.DERPRegionID(index)
		regions[identifier] = &tailcfg.DERPRegion{RegionID: identifier, RegionName: "test-region"}
		report.DERPLatency[strconv.Itoa(index)+"-v4"] = .02
		node.Endpoints = append(node.Endpoints, netip.AddrPortFrom(netip.MustParseAddr("192.0.2.1"), uint16(index)))
		regions[1].Nodes = append(regions[1].Nodes, &tailcfg.DERPNode{Name: strconv.Itoa(index), HostName: "test.example.com"})
	}
	server := newServerWithConfig(test, Config{DERPMap: &tailcfg.DERPMap{Regions: regions}})
	view := server.machineConnectionView(node)
	if len(view.Endpoints) != 32 || view.EndpointCount != 140 || !view.EndpointsTruncated || len(view.Latencies) != 128 || !view.LatenciesTruncated || len(view.HomeRegion.Servers) != 32 || !view.HomeRegion.ServersTruncated {
		test.Fatal("diagnostic response was not bounded")
	}
}

func TestAPIMachineConnectionAuthorizationAndReadOnly(test *testing.T) {
	server := newServerWithConfig(test, Config{DERPMap: derpTestMap()})
	host := newTestHTTPServer(test, server)
	node := seedAPIMachine(test, server, "connection-test", nil)
	_, readToken := seedAPIKey(test, server, identity.ScopeRead)
	_, writeToken := seedAPIKey(test, server, identity.ScopeWrite)
	endpoint := host.URL + "/api/v1/machines/" + strconv.FormatUint(uint64(node.ID), 10) + "/connection"
	for _, attempt := range []struct {
		token  string
		status int
	}{{"", 401}, {writeToken, 403}, {readToken, 200}} {
		response := apiRequest(test, host.Client(), http.MethodGet, endpoint, attempt.token, nil)
		if response.StatusCode != attempt.status || response.Header.Get("Cache-Control") != "no-store" {
			test.Fatalf("status/cache = %d/%s", response.StatusCode, response.Header.Get("Cache-Control"))
		}
		readBody(test, response)
	}
	response := apiRequest(test, host.Client(), http.MethodGet, host.URL+"/api/v1/machines/"+node.StableID+"/connection", readToken, nil)
	var view machineConnectionView
	if err := json.Unmarshal(readBody(test, response), &view); err != nil || view.StableID != node.StableID {
		test.Fatal("stable ID connection lookup failed")
	}
	stored, exists := server.store.GetNodeByID(node.ID)
	if !exists || !reflect.DeepEqual(node, stored) {
		test.Fatal("diagnostic read modified the machine")
	}
	response = apiRequest(test, host.Client(), http.MethodGet, host.URL+"/api/v1/machines/missing/connection", readToken, nil)
	if response.StatusCode != 404 {
		test.Fatal("unknown machine not refused")
	}
	readBody(test, response)
}

func TestMachineConnectionSnapshotConcurrentRefresh(test *testing.T) {
	server := newTestServer(test)
	snapshots := []*derpMapSnapshot{
		{Map: &tailcfg.DERPMap{Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{7: {RegionID: 7, RegionName: "first"}}}, Sources: map[tailcfg.DERPRegionID]string{7: "deployment"}},
		{Map: &tailcfg.DERPMap{Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{7: {RegionID: 7, RegionName: "second"}}}, Sources: map[tailcfg.DERPRegionID]string{7: "managed"}},
	}
	server.managedDERP.Store(snapshots[0])
	var workers sync.WaitGroup
	workers.Add(2)
	go func() {
		defer workers.Done()
		for index := 0; index < 500; index++ {
			server.managedDERP.Store(snapshots[index%2])
		}
	}()
	go func() {
		defer workers.Done()
		for index := 0; index < 500; index++ {
			view := server.machineConnectionView(state.Node{HomeDERP: 7})
			if (view.HomeRegion.Name == "first") != (view.HomeRegion.Source == "deployment") {
				test.Error("mixed relay map/source snapshots")
				return
			}
		}
	}()
	workers.Wait()
}

func TestAPIMachineConnectionTenantIsolation(test *testing.T) {
	first := newServerWithConfig(test, Config{DERPMap: derpTestMap()})
	second := newTestServer(test)
	firstNode := seedAPIMachine(test, first, "first-tenant", nil)
	secondNode := seedAPIMachine(test, second, "second-tenant", nil)
	_, firstToken := seedAPIKey(test, first, identity.ScopeRead)
	_, secondToken := seedAPIKey(test, second, identity.ScopeRead)
	router := newTestRouter(test, RouterConfig{Orgs: []OrgSite{
		{ID: "first", Domains: []string{"first.example.com"}, Server: first},
		{ID: "second", Domains: []string{"second.example.com"}, Server: second},
	}})
	host := httptest.NewServer(router.Handler())
	defer host.Close()
	endpoint := host.URL + "/api/v1/machines/" + strconv.FormatUint(uint64(firstNode.ID), 10) + "/connection"
	for _, attempt := range []struct {
		hostname, token string
		expected        int
	}{
		{"first.example.com", firstToken, 200}, {"second.example.com", firstToken, 401}, {"second.example.com", secondToken, 200},
	} {
		request, err := http.NewRequest(http.MethodGet, endpoint, nil)
		if err != nil {
			test.Fatal(err)
		}
		request.Host = attempt.hostname
		request.Header.Set("Authorization", "Bearer "+attempt.token)
		response, err := host.Client().Do(request)
		if err != nil {
			test.Fatal(err)
		}
		body := readBody(test, response)
		if response.StatusCode != attempt.expected {
			test.Fatalf("tenant status = %d", response.StatusCode)
		}
		if attempt.hostname == "second.example.com" && attempt.expected == 200 {
			var view machineConnectionView
			if json.Unmarshal(body, &view) != nil || view.StableID != secondNode.StableID || view.MapConfigured {
				test.Fatal("another tenant's device or relay map leaked")
			}
		}
	}
}

func TestMachineConnectionUsesPersistedMapRequest(test *testing.T) {
	server := newServerWithConfig(test, Config{DERPMap: derpTestMap()})
	node := seedTestNode(test, server)
	node = server.recordMapRequest(node, tailcfg.MapRequest{
		Hostinfo:  &tailcfg.Hostinfo{NetInfo: &tailcfg.NetInfo{PreferredDERP: 2, WorkingUDP: "false", WorkingIPv6: "true", DERPLatency: map[string]float64{"2-v4": .01234}}},
		Endpoints: []netip.AddrPort{netip.MustParseAddrPort("192.0.2.20:41641")},
	})
	node = server.recordMapRequest(node, tailcfg.MapRequest{Hostinfo: &tailcfg.Hostinfo{Hostname: "report-retained"}})
	stored, found := server.store.GetNodeByID(node.ID)
	if !found {
		test.Fatal("reported node was not persisted")
	}
	view := server.machineConnectionView(stored)
	if view.HomeRegion == nil || view.HomeRegion.ID != 2 || !view.ReportAvailable || view.Network.UDP == nil || *view.Network.UDP || len(view.Latencies) != 1 || view.Latencies[0].Milliseconds != 12.34 {
		test.Fatal("connection details lost persisted upstream report or confused unknown and false")
	}
}
