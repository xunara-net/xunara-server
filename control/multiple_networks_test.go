package control

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"testing"

	"github.com/xunara-net/xunara-server/plan"
	"github.com/xunara-net/xunara-server/state"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

func TestMultipleAddressPoolsMoveDeviceAndRetainRemovedRangeAddresses(t *testing.T) {
	server := planServer(t, proPlan(t))
	cookie, token := seedUserSession(t, server, 1)
	headers := map[string]string{"X-CSRF-Token": csrfTokenFor(token)}
	node := seedAPIMachine(t, server, "segment-device", nil)
	peer := seedAPIMachine(t, server, "segment-peer", nil)
	body := map[string]any{"ipv4_cidr": "100.101.50.0/24", "extra_ipv4_cidrs": []string{"192.168.60.0/24", "10.42.0.0/24"}, "revision": 0}
	for _, operation := range []struct{ method, path string }{{http.MethodPost, "/api/v2/network/addresses/validate"}, {http.MethodPut, "/api/v2/network/addresses"}} {
		response := accountRequest(t, server, operation.method, operation.path, body, cookie, headers)
		if response.Code != http.StatusOK {
			t.Fatalf("pool update: %d %s", response.Code, response.Body.String())
		}
	}
	configuration, err := server.actualAllocation(t.Context())
	if err != nil || len(configuration.ExtraIPv4) != 2 {
		t.Fatal("additional pools were not persisted")
	}
	response := accountRequest(t, server, http.MethodPut, "/api/v2/machines/"+node.StableID+"/ipv4", map[string]string{
		"ipv4": "192.168.60.20", "expected_ipv4": node.IPv4.String(),
	}, cookie, headers)
	if response.Code != http.StatusOK {
		t.Fatalf("secondary pool IP change: %d", response.Code)
	}
	updated, _ := server.store.GetNodeByID(node.ID)
	frame := server.fullMap(peer, tailcfg.MapRequest{Version: tailcfg.CurrentCapabilityVersion})
	found := false
	for _, entry := range frame.Peers {
		if entry.ID == tailcfg.NodeID(updated.ID) && entry.Addresses[0].Addr() == updated.IPv4 && entry.AllowedIPs[0].Bits() == 32 {
			found = true
		}
	}
	if !found {
		t.Fatal("official MapResponse did not project the additional-pool device as a host route")
	}
	body["revision"] = configuration.SourceRevision
	body["extra_ipv4_cidrs"] = []string{}
	response = accountRequest(t, server, http.MethodPut, "/api/v2/network/addresses", body, cookie, headers)
	if response.Code != http.StatusOK {
		t.Fatal("removing an additional pool failed")
	}
	retained, _ := server.store.GetNodeByID(node.ID)
	if retained.IPv4 != updated.IPv4 {
		t.Fatal("pool removal silently renumbered a live device")
	}
	response = accountRequest(t, server, http.MethodPut, "/api/v2/machines/"+node.StableID+"/ipv4", map[string]string{
		"ipv4": "192.168.60.21", "expected_ipv4": retained.IPv4.String(),
	}, cookie, headers)
	if response.Code != http.StatusBadRequest {
		t.Fatal("removed pool still accepted new addresses")
	}
}

func TestAdditionalPoolsReserveAcrossTenantsAndDowngrades(t *testing.T) {
	registry, _ := newTestPlanRegistry(t, t.TempDir())
	for _, orgID := range []string{"first", "second"} {
		if _, err := registry.AssignPlan(t.Context(), orgID, plan.ProID); err != nil {
			t.Fatal(err)
		}
	}
	extra := []netip.Prefix{netip.MustParsePrefix("192.168.60.0/24")}
	if _, err := registry.setNetworks(t.Context(), "first", netip.MustParsePrefix("100.101.50.0/24"), &extra, nil, "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.setNetworks(t.Context(), "second", netip.MustParsePrefix("100.101.51.0/24"), &extra, nil, "test"); !errors.Is(err, ErrNetworkConflict) {
		t.Fatal("another tenant claimed an active additional pool")
	}
	if _, err := registry.AssignPlan(t.Context(), "first", plan.FreeID); err != nil {
		t.Fatal(err)
	}
	version, err := registry.networkVersion(t.Context(), "first")
	if err != nil || len(version.ExtraIPv4) != 0 {
		t.Fatal("downgrade retained editable additional pools")
	}
	if err := registry.validateNetworks(t.Context(), "second", netip.MustParsePrefix("100.101.51.0/24"), extra); !errors.Is(err, ErrNetworkConflict) {
		t.Fatal("downgrade released addresses that old devices can still hold")
	}
}

func TestAdditionalPoolsFreePlanAndOverlapAreRejected(t *testing.T) {
	for _, planValue := range []plan.Plan{freePlan(t), proPlan(t)} {
		server := planServer(t, planValue)
		cookie, token := seedUserSession(t, server, 1)
		response := accountRequest(t, server, http.MethodPut, "/api/v2/network/addresses", map[string]any{
			"revision": 0, "ipv4_cidr": "100.101.50.0/24", "extra_ipv4_cidrs": []string{"100.101.50.0/25"},
		}, cookie, map[string]string{"X-CSRF-Token": csrfTokenFor(token)})
		if response.Code != http.StatusForbidden && response.Code != http.StatusBadRequest {
			t.Fatalf("invalid/unauthorized additional pool accepted: %d", response.Code)
		}
		if allocationRevision(t, server, cookie) != 0 {
			t.Fatal("rejected update changed the durable allocation")
		}
	}
}

func TestDefaultPoolSelectionUsesConfiguredEntitlementAndKeepsFreeDeviceQuota(t *testing.T) {
	router, plans := selfServiceRouter(t, &SelfServiceConfig{DomainSuffix: "xunara.test"})
	response := postJSONAtHost(t, router.Handler(), "app.xunara.test", selfServiceSignupPath, map[string]string{
		"login": "pool-owner", "password": "correct horse battery staple",
	})
	if response.Code != http.StatusCreated {
		t.Fatalf("signup = %d", response.Code)
	}
	server := router.orgByID("pool-owner").site.Server
	cookie, token := seedUserSession(t, server, 1)
	headers := map[string]string{"X-CSRF-Token": csrfTokenFor(token)}
	original, err := server.actualAllocation(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	body := map[string]any{"revision": original.SourceRevision, "ipv4_cidr": original.IPv4.String(), "extra_ipv4_cidrs": []string{"100.104.70.0/24"}}
	if response := accountRequest(t, server, http.MethodPut, "/api/v2/network/addresses", body, cookie, headers); response.Code != http.StatusForbidden {
		t.Fatal("default pool management bypassed a disabled entitlement")
	}
	configured := freePlan(t)
	configured.AllowCustomCIDR = true
	if _, err := plans.UpsertPlan(t.Context(), configured); err != nil {
		t.Fatal(err)
	}
	existing := seedAPIMachine(t, server, "before-default-switch", nil)
	if response := accountRequest(t, server, http.MethodPut, "/api/v2/network/addresses", body, cookie, headers); response.Code != http.StatusOK {
		t.Fatalf("configured Free additional pool = %d (%s)", response.Code, response.Body.String())
	}
	current, err := server.actualAllocation(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	body = map[string]any{"revision": current.SourceRevision, "ipv4_cidr": "100.104.70.0/24", "extra_ipv4_cidrs": []string{original.IPv4.String()}}
	for _, operation := range []struct{ method, path string }{{http.MethodPost, "/api/v2/network/addresses/validate"}, {http.MethodPut, "/api/v2/network/addresses"}} {
		response := accountRequest(t, server, operation.method, operation.path, body, cookie, headers)
		if response.Code != http.StatusOK {
			t.Fatalf("switch default = %d (%s)", response.Code, response.Body.String())
		}
	}
	next, err := server.actualAllocation(t.Context())
	retained, found := server.store.GetNodeByID(existing.ID)
	if err != nil || !found || next.IPv4.String() != "100.104.70.0/24" || len(next.ExtraIPv4) != 1 || next.ExtraIPv4[0] != original.IPv4 || retained.IPv4 != existing.IPv4 {
		t.Fatal("default pool switch changed an existing IP or dropped the old pool")
	}
	if response := accountRequest(t, server, http.MethodPut, "/api/v2/network/addresses", body, cookie, headers); response.Code != http.StatusConflict {
		t.Fatal("stale default pool switch was accepted")
	}
	fillDevices(t, server, 9)
	for _, node := range server.store.ListNodes() {
		if node.ID != existing.ID && !next.IPv4.Contains(node.IPv4) {
			t.Fatal("new device did not use the user's default pool")
		}
		frame := server.fullMap(node, tailcfg.MapRequest{Version: tailcfg.CurrentCapabilityVersion})
		if frame.Node == nil || frame.Node.Addresses[0].Addr() != node.IPv4 || frame.Node.AllowedIPs[0].Bits() != 32 {
			t.Fatal("official MapResponse changed pool addresses into whole-subnet routes")
		}
	}
	_, err = server.handleRegister(context.Background(), tailcfg.RegisterRequest{
		Version: tailcfg.CurrentCapabilityVersion, NodeKey: key.NewNode().Public(),
		Auth: &tailcfg.RegisterResponseAuth{AuthKey: seedPreAuthKey(t, server, state.PreAuthKey{})},
	}, key.NewMachine().Public())
	var refusal HTTPError
	if !errors.As(err, &refusal) || refusal.Code != http.StatusForbidden || len(server.store.ListNodes()) != 10 {
		t.Fatalf("custom default bypassed Free's 10-device quota: %v", err)
	}
}
