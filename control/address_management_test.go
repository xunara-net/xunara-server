package control

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"strconv"
	"testing"

	"tailscale.com/tailcfg"
	"tailscale.com/types/key"

	"github.com/xunara-net/xunara-server/identity"
	"github.com/xunara-net/xunara-server/plan"
	"github.com/xunara-net/xunara-server/state"
)

func allocationRevision(t *testing.T, server *Server, cookie *http.Cookie) uint64 {
	t.Helper()
	response := accountRequest(t, server, http.MethodGet, "/api/v2/network/addresses", nil, cookie, nil)
	var view struct {
		Revision uint64 `json:"revision"`
	}
	if response.Code != http.StatusOK {
		t.Fatalf("allocation read: %d %s", response.Code, response.Body.String())
	}
	if err := json.Unmarshal(response.Body.Bytes(), &view); err != nil {
		t.Fatal(err)
	}
	return view.Revision
}

func TestAddressManagementPreviewSaveRestartAndDeviceChange(t *testing.T) {
	for _, example := range []struct {
		prefix  string
		address string
	}{
		{"100.101.50.12/24", "100.101.50.20"},
		{"192.168.50.12/24", "192.168.50.20"},
		{"10.42.50.12/8", "10.42.50.20"},
		{"172.31.50.12/12", "172.31.50.20"},
		{"192.168.50.12/29", "192.168.50.13"},
		{"192.168.50.0/30", "192.168.50.2"},
		{"192.168.50.0/31", "192.168.50.1"},
		{"8.8.4.12/24", "8.8.4.20"},
	} {
		t.Run(example.prefix, func(t *testing.T) {
			testAddressManagementChange(t, example.prefix, example.address)
		})
	}
}

func testAddressManagementChange(t *testing.T, customPrefix, address string) {
	t.Helper()
	canonical := netip.MustParsePrefix(customPrefix).Masked()
	server := planServer(t, proPlan(t))
	cookie, token := seedUserSession(t, server, state.DefaultUserID)
	headers := map[string]string{"X-CSRF-Token": csrfTokenFor(token)}
	node := seedAPIMachine(t, server, "existing", nil)
	peer := seedAPIMachine(t, server, "peer", nil)
	initial := server.fullMap(node, tailcfg.MapRequest{Version: 100})
	stream, err := newMapSession()
	if err != nil {
		t.Fatal(err)
	}
	stream.initial(initial)
	body := map[string]any{"revision": allocationRevision(t, server, cookie), "ipv4_cidr": customPrefix}
	response := accountRequest(t, server, http.MethodPost, "/api/v2/network/addresses/validate", body, cookie, headers)
	if response.Code != http.StatusOK {
		t.Fatalf("preview: %d %s", response.Code, response.Body.String())
	}
	if allocationRevision(t, server, cookie) != 0 {
		t.Fatal("preview changed allocation")
	}
	response = accountRequest(t, server, http.MethodPut, "/api/v2/network/addresses", body, cookie, headers)
	if response.Code != http.StatusOK {
		t.Fatalf("save: %d %s", response.Code, response.Body.String())
	}
	retained, _ := server.store.GetNodeByID(node.ID)
	if retained.IPv4 != node.IPv4 {
		t.Fatal("range edit silently renumbered old devices")
	}
	newNode := seedAPIMachine(t, server, "new", nil)
	if !canonical.Contains(newNode.IPv4) {
		t.Fatal("new device used old pool")
	}
	response = accountRequest(t, server, http.MethodPut, "/api/v2/network/addresses", body, cookie, headers)
	if response.Code != http.StatusConflict {
		t.Fatal("stale range version accepted")
	}
	response = accountRequest(t, server, http.MethodPut, "/api/v2/machines/"+node.StableID+"/ipv4", map[string]string{"ipv4": address, "expected_ipv4": node.IPv4.String()}, cookie, headers)
	if response.Code != http.StatusOK {
		t.Fatalf("IP change: %d %s", response.Code, response.Body.String())
	}
	updated, _ := server.store.GetNodeByID(node.ID)
	frame := server.updateMap(updated)
	if !applyFrame(stream, frame, peersOf(frame)) || frame.Node == nil || frame.Node.Addresses[0].Addr() != netip.MustParseAddr(address) {
		t.Fatal("official self delta did not carry changed address")
	}
	peerMap := server.fullMap(peer, tailcfg.MapRequest{Version: 100})
	var advertised bool
	for _, candidate := range peerMap.Peers {
		if candidate.ID == tailcfg.NodeID(node.ID) && candidate.Addresses[0].Addr() == updated.IPv4 && candidate.AllowedIPs[0].Addr() == updated.IPv4 {
			advertised = true
		}
	}
	if !advertised {
		t.Fatal("official peer addresses and AllowedIPs remained stale")
	}
	if err := server.store.UpdateNode(node); err != nil {
		t.Fatal(err)
	}
	restarted, err := New(server.cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { restarted.Close() })
	configuration, err := restarted.actualAllocation(t.Context())
	persisted, _ := restarted.store.GetNodeByID(node.ID)
	if err != nil || configuration.SourceRevision != 1 || configuration.IPv4 != canonical || persisted.IPv4 != updated.IPv4 {
		t.Fatal("restart or heartbeat reverted committed addresses")
	}
}

func TestAddressManagementSingleHostPoolAllowsManualAddressAndReportsExhaustion(t *testing.T) {
	server := planServer(t, proPlan(t))
	cookie, token := seedUserSession(t, server, state.DefaultUserID)
	headers := map[string]string{"X-CSRF-Token": csrfTokenFor(token)}
	existing := seedAPIMachine(t, server, "existing", nil)
	body := map[string]any{"revision": allocationRevision(t, server, cookie), "ipv4_cidr": "192.168.50.20/32"}
	if response := accountRequest(t, server, http.MethodPut, "/api/v2/network/addresses", body, cookie, headers); response.Code != http.StatusOK {
		t.Fatalf("single host pool: %d %s", response.Code, response.Body.String())
	}
	if response := accountRequest(t, server, http.MethodPut, "/api/v2/machines/"+existing.StableID+"/ipv4", map[string]string{"ipv4": "192.168.50.20", "expected_ipv4": existing.IPv4.String()}, cookie, headers); response.Code != http.StatusOK {
		t.Fatalf("single address change: %d %s", response.Code, response.Body.String())
	}
	unallocated := state.Node{NodeKey: key.NewNode().Public(), MachineKey: key.NewMachine().Public()}
	if err := server.store.CreateNode(&unallocated); err == nil {
		t.Fatal("occupied single-host pool was allocated again")
	}
}

func TestAddressManagementAuthorityLimitsAndAtomicFailure(t *testing.T) {
	server := planServer(t, freePlan(t))
	cookie, token := seedUserSession(t, server, state.DefaultUserID)
	headers := map[string]string{"X-CSRF-Token": csrfTokenFor(token)}
	node := seedAPIMachine(t, server, "first", nil)
	other := seedAPIMachine(t, server, "second", nil)
	endpoint := "/api/v2/machines/" + strconv.FormatUint(uint64(node.ID), 10) + "/ipv4"
	body := map[string]string{"ipv4": "100.64.0.20", "expected_ipv4": node.IPv4.String()}
	if response := accountRequest(t, server, http.MethodPut, endpoint, body, cookie, nil); response.Code != http.StatusForbidden {
		t.Fatal("IP write lacked CSRF")
	}
	member := seedRoleUser(t, server, "member", identity.RoleMember)
	memberCookie, memberToken := seedUserSession(t, server, member)
	if response := accountRequest(t, server, http.MethodPut, endpoint, body, memberCookie, map[string]string{"X-CSRF-Token": csrfTokenFor(memberToken)}); response.Code != http.StatusForbidden {
		t.Fatal("member changed IP")
	}
	if response := accountRequest(t, server, http.MethodPut, "/api/v2/network/addresses", map[string]any{"revision": 0, "ipv4_cidr": "100.101.50.0/24"}, cookie, headers); response.Code != http.StatusForbidden {
		t.Fatal("free tenant changed its fixed range")
	}
	for _, value := range []struct {
		address string
		status  int
	}{{other.IPv4.String(), 409}, {"100.100.100.100", 400}, {"100.64.0.0", 400}, {"192.168.1.20", 400}} {
		body["ipv4"] = value.address
		if response := accountRequest(t, server, http.MethodPut, endpoint, body, cookie, headers); response.Code != value.status {
			t.Fatalf("address %s: %d %s", value.address, response.Code, response.Body.String())
		}
	}
	body["ipv4"] = "100.64.0.20"
	core := server.store.(*state.SQLiteStore)
	if _, err := core.DB().ExecContext(t.Context(), "CREATE TRIGGER reject_address_audit BEFORE INSERT ON audit_events BEGIN SELECT RAISE(ABORT, 'injected'); END"); err != nil {
		t.Fatal(err)
	}
	if response := accountRequest(t, server, http.MethodPut, endpoint, body, cookie, headers); response.Code != http.StatusServiceUnavailable {
		t.Fatal("audit failure reported success")
	}
	actual, _ := core.GetNodeByID(node.ID)
	if actual.IPv4 != node.IPv4 {
		t.Fatal("failed audit left address modified")
	}
	if _, err := core.DB().ExecContext(t.Context(), "DROP TRIGGER reject_address_audit"); err != nil {
		t.Fatal(err)
	}
	if response := accountRequest(t, server, http.MethodPut, endpoint, body, cookie, headers); response.Code != http.StatusOK {
		t.Fatalf("free admin IP within fixed pool: %d %s", response.Code, response.Body.String())
	}
}

func TestAddressRegistryRetainsOldLeasesAndReconcilesFailedApplication(t *testing.T) {
	registry, _ := newTestPlanRegistry(t, t.TempDir())
	server := newTestServer(t)
	if _, err := registry.Allocate(t.Context(), "default"); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.AssignPlan(t.Context(), "default", plan.ProID); err != nil {
		t.Fatal(err)
	}
	if err := server.AttachPlanRegistry(t.Context(), registry); err != nil {
		t.Fatal(err)
	}
	cookie, token := seedUserSession(t, server, state.DefaultUserID)
	revision := allocationRevision(t, server, cookie)
	core := server.store.(*state.SQLiteStore)
	if _, err := core.DB().ExecContext(t.Context(), "CREATE TRIGGER reject_address_application BEFORE UPDATE ON address_configuration BEGIN SELECT RAISE(ABORT, 'injected'); END"); err != nil {
		t.Fatal(err)
	}
	response := accountRequest(t, server, http.MethodPut, "/api/v2/network/addresses", map[string]any{"revision": revision, "ipv4_cidr": "100.101.50.0/24"}, cookie, map[string]string{"X-CSRF-Token": csrfTokenFor(token)})
	if response.Code != http.StatusServiceUnavailable {
		t.Fatal("failed actual commit reported applied")
	}
	view, err := server.addressView(accountRequestHTTP(cookie))
	if err != nil || view["pending"] != true || view["ipv4_cidr"] != "100.100.1.0/24" {
		t.Fatalf("desired confused with actual: %+v %v", view, err)
	}
	if _, err := core.DB().ExecContext(t.Context(), "DROP TRIGGER reject_address_application"); err != nil {
		t.Fatal(err)
	}
	if err := server.refreshAddressAllocation(t.Context()); err != nil {
		t.Fatal(err)
	}
	if allocationRevision(t, server, cookie) != revision+1 {
		t.Fatal("pending allocation did not converge")
	}
	if _, err := registry.AssignPlan(t.Context(), "other", plan.ProID); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.SetNetwork(t.Context(), "other", netip.MustParsePrefix("100.100.1.0/24")); !errors.Is(err, ErrNetworkConflict) {
		t.Fatalf("old pool was released: %v", err)
	}
	version, err := registry.networkVersion(t.Context(), "default")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := registry.setNetwork(t.Context(), "default", netip.MustParsePrefix(version.Prefix), &version.Revision, "different:no-op"); err != nil {
		t.Fatal(err)
	}
	unchanged, err := registry.networkVersion(t.Context(), "default")
	if err != nil || unchanged.Actor != version.Actor || unchanged.Revision != version.Revision {
		t.Fatal("no-op rewrote immutable network history")
	}
}

func accountRequestHTTP(cookie *http.Cookie) *http.Request {
	request, _ := http.NewRequest(http.MethodGet, "http://login.test/api/v2/network/addresses", nil)
	request.AddCookie(cookie)
	return request
}
