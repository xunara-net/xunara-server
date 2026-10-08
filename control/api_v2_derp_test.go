package control

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"tailscale.com/tailcfg"

	xunarav2 "github.com/xunara-net/xunara-server/api/gen/xunara/v2"
	"github.com/xunara-net/xunara-server/identity"
)

// derpTestMap is a two-region DERP map; region 2 has two relays.
func derpTestMap() *tailcfg.DERPMap {
	return &tailcfg.DERPMap{Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{
		1: {
			RegionID:   1,
			RegionCode: "fra",
			RegionName: "Frankfurt",
			Nodes:      []*tailcfg.DERPNode{{Name: "1a", HostName: "veil1.example.com:443"}},
		},
		2: {
			RegionID:   2,
			RegionCode: "sin",
			RegionName: "Singapore",
			Nodes: []*tailcfg.DERPNode{
				{Name: "2b", HostName: "veil2b.example.com:443"},
				{Name: "2a", HostName: "veil2a.example.com:443"},
				{Name: "2a-dup", HostName: "veil2a.example.com:443"},
			},
		},
	}}
}

// seedDERPNode stores a machine homed to region (0 = none chosen).
func seedDERPNode(t *testing.T, s *Server, hostname string, region tailcfg.DERPRegionID) {
	t.Helper()
	node := seedAPIMachine(t, s, hostname, nil)
	node.HomeDERP = region
	if err := s.store.UpdateNode(node); err != nil {
		t.Fatalf("homin %s to region %d: %v", hostname, region, err)
	}
}

// decodeDERPStatus reads one management response.
func decodeDERPStatus(t *testing.T, raw []byte) derpStatusView {
	t.Helper()
	var view derpStatusView
	if err := json.Unmarshal(raw, &view); err != nil {
		t.Fatalf("decoding the DERP status: %v (%s)", err, raw)
	}
	return view
}

// TestAPIV2DERPStatus drives GET /api/v2/derp: served regions with their
// public relay hosts, and the node placement counters.
func TestAPIV2DERPStatus(t *testing.T) {
	s := newServerWithConfig(t, Config{DERPMap: derpTestMap()})
	hs := newTestHTTPServer(t, s)
	client := noRedirectClient()
	_, readToken := seedAPIKey(t, s, identity.ScopeRead)
	_, writeToken := seedAPIKey(t, s, identity.ScopeWrite)

	seedDERPNode(t, s, "derp-fra", 1)
	seedDERPNode(t, s, "derp-sin-a", 2)
	seedDERPNode(t, s, "derp-sin-b", 2)
	seedDERPNode(t, s, "derp-nohome", 0)

	base := hs.URL + "/api/v2/derp"
	if resp := apiRequest(t, client, http.MethodGet, base, "", nil); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("anonymous status = %d, want 401", resp.StatusCode)
	}
	if resp := apiRequest(t, client, http.MethodGet, base, writeToken, nil); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("write-only status = %d, want 403", resp.StatusCode)
	}

	resp := apiRequest(t, client, http.MethodGet, base, readToken, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if cc := resp.Header.Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", cc)
	}
	view := decodeDERPStatus(t, readBody(t, resp))
	if view.PolicyMode != "inherit" || len(view.PolicyRegions) != 0 {
		t.Errorf("policy = %q %v, want inherit with no allowlist", view.PolicyMode, view.PolicyRegions)
	}
	if !view.MapConfigured || view.RegionsServed != 2 || len(view.Regions) != 2 {
		t.Fatalf("map/regions = %+v", view)
	}
	if view.NodesWithoutHome != 1 || view.NodesWithUnservedHome != 0 {
		t.Errorf("placement counters = %+v", view)
	}
	fra, sin := view.Regions[0], view.Regions[1]
	if fra.ID != 1 || fra.Code != "fra" || fra.Name != "Frankfurt" || fra.NodeCount != 1 ||
		len(fra.Hosts) != 1 || fra.Hosts[0] != "veil1.example.com:443" {
		t.Errorf("region 1 = %+v", fra)
	}
	// Hosts are deduplicated and sorted; the count follows the nodes.
	if sin.ID != 2 || sin.NodeCount != 2 || len(sin.Hosts) != 2 ||
		sin.Hosts[0] != "veil2a.example.com:443" || sin.Hosts[1] != "veil2b.example.com:443" {
		t.Errorf("region 2 = %+v", sin)
	}
}

// TestAPIV2DERPPolicyStates checks the three policy outcomes: an allowlist
// leaves a stale home visibly unserved, "none" serves an explicit empty map,
// and no configured map is a different answer from an empty one.
func TestAPIV2DERPPolicyStates(t *testing.T) {
	client := noRedirectClient()

	t.Run("regions", func(t *testing.T) {
		s := newServerWithConfig(t, Config{
			DERPMap:    derpTestMap(),
			DERPPolicy: DERPPolicy{Mode: DERPPolicyRegions, Regions: []int{2}},
		})
		hs := newTestHTTPServer(t, s)
		_, readToken := seedAPIKey(t, s, identity.ScopeRead)
		seedDERPNode(t, s, "derp-fra", 1)
		seedDERPNode(t, s, "derp-sin", 2)

		view := decodeDERPStatus(t, readBody(t,
			apiRequest(t, client, http.MethodGet, hs.URL+"/api/v2/derp", readToken, nil)))
		if view.PolicyMode != string(DERPPolicyRegions) || len(view.PolicyRegions) != 1 || view.PolicyRegions[0] != 2 {
			t.Errorf("policy = %q %v", view.PolicyMode, view.PolicyRegions)
		}
		if view.RegionsServed != 1 || len(view.Regions) != 1 || view.Regions[0].ID != 2 {
			t.Errorf("regions = %+v", view.Regions)
		}
		// The node homed to the filtered-out region is waiting to be re-homed.
		if view.NodesWithUnservedHome != 1 || view.Regions[0].NodeCount != 1 {
			t.Errorf("placement = %+v", view)
		}
	})

	t.Run("none", func(t *testing.T) {
		s := newServerWithConfig(t, Config{DERPMap: derpTestMap(), DERPPolicy: DERPPolicy{Mode: DERPPolicyNone}})
		hs := newTestHTTPServer(t, s)
		_, readToken := seedAPIKey(t, s, identity.ScopeRead)

		view := decodeDERPStatus(t, readBody(t,
			apiRequest(t, client, http.MethodGet, hs.URL+"/api/v2/derp", readToken, nil)))
		if !view.MapConfigured || view.RegionsServed != 0 || len(view.Regions) != 0 {
			t.Errorf("none = %+v, want a configured map serving nothing", view)
		}
	})

	t.Run("no map", func(t *testing.T) {
		s := newTestServer(t)
		hs := newTestHTTPServer(t, s)
		_, readToken := seedAPIKey(t, s, identity.ScopeRead)

		view := decodeDERPStatus(t, readBody(t,
			apiRequest(t, client, http.MethodGet, hs.URL+"/api/v2/derp", readToken, nil)))
		if view.MapConfigured || view.RegionsServed != 0 || len(view.Regions) != 0 {
			t.Errorf("no map = %+v, want mapConfigured false", view)
		}
	})
}

// TestPlatformGRPCDERPStatus mirrors the HTTP surface on the typed API.
func TestPlatformGRPCDERPStatus(t *testing.T) {
	s := newServerWithConfig(t, Config{
		DERPMap:    derpTestMap(),
		DERPPolicy: DERPPolicy{Mode: DERPPolicyRegions, Regions: []int{2}},
	})
	_, readToken := seedAPIKey(t, s, identity.ScopeRead)
	seedDERPNode(t, s, "derp-sin", 2)
	client := startGRPCTestServer(t, s.RegisterPlatformGRPC)

	if _, err := client.GetDERPStatus(context.Background(), &xunarav2.GetDERPStatusRequest{}); status.Code(err) != codes.Unauthenticated {
		t.Errorf("anonymous error = %v, want Unauthenticated", err)
	}
	_, writeToken := seedAPIKey(t, s, identity.ScopeWrite)
	if _, err := client.GetDERPStatus(grpcCtx(writeToken), &xunarav2.GetDERPStatusRequest{}); status.Code(err) != codes.PermissionDenied {
		t.Errorf("write-only error = %v, want PermissionDenied", err)
	}

	view, err := client.GetDERPStatus(grpcCtx(readToken), &xunarav2.GetDERPStatusRequest{})
	if err != nil {
		t.Fatalf("GetDERPStatus: %v", err)
	}
	if view.GetPolicyMode() != string(DERPPolicyRegions) || len(view.GetPolicyRegions()) != 1 || view.GetPolicyRegions()[0] != 2 {
		t.Errorf("policy = %q %v", view.GetPolicyMode(), view.GetPolicyRegions())
	}
	if !view.GetMapConfigured() || view.GetRegionsServed() != 1 || len(view.GetRegions()) != 1 {
		t.Fatalf("regions = %+v", view.GetRegions())
	}
	region := view.GetRegions()[0]
	if region.GetId() != 2 || region.GetCode() != "sin" || region.GetName() != "Singapore" ||
		region.GetNodeCount() != 1 || len(region.GetHosts()) != 2 {
		t.Errorf("region = %+v", region)
	}
	if view.GetNodesWithUnservedHome() != 0 || view.GetNodesWithoutHome() != 0 {
		t.Errorf("placement = %+v", view)
	}
}
