package control

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/xunara-net/xunara-server/identity"
	"github.com/xunara-net/xunara-server/netspace"
	"github.com/xunara-net/xunara-server/plan"
	"github.com/xunara-net/xunara-server/state"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

func TestBrowserDeviceLegacyAddressPoolRepair(test *testing.T) {
	registry, _ := newTestPlanRegistry(test, test.TempDir())
	transaction, err := registry.db.BeginTx(test.Context(), nil)
	if err != nil {
		test.Fatal(err)
	}
	defer transaction.Rollback()
	// 复现旧部署导入的自动网段；现行注册已跳过此保留段，不能只测全新租户。
	now := time.Now().UTC()
	err = upsertTenantPlanTx(test.Context(), transaction, TenantPlan{
		OrgID: "demo", PlanID: plan.FreeID, NetworkPrefix: "100.100.0.0/24", CreatedAt: now, UpdatedAt: now,
	}, "system:import")
	if err != nil {
		test.Fatal(err)
	}
	if err := transaction.Commit(); err != nil {
		test.Fatal(err)
	}
	peer, err := registry.Allocate(test.Context(), "peer")
	if err != nil {
		test.Fatal(err)
	}
	server := newTestServer(test)
	router := newTestRouter(test, RouterConfig{
		Orgs: []OrgSite{{ID: "demo", Server: server}}, Plans: registry, PlatformAdminToken: "pool-repair-test-token",
	})
	platform := httptest.NewServer(router.Handler())
	test.Cleanup(platform.Close)
	host := newTestHTTPServer(test, server)
	connection, client, nodeKey, id := startRegistration(test, host, "android-NX769J")
	defer connection.Close()
	cookie, token := seedUserSession(test, server, state.DefaultUserID)
	headers := map[string]string{"X-CSRF-Token": csrfTokenFor(token)}
	auditCount, revision := len(server.identity.ListAudit(0)), server.store.ConfigRevision()
	for _, endpoint := range []string{
		"/api/v1/browser/device-authorizations/" + id + "/approve",
		"/api/v2/devices/" + id + "/approve",
	} {
		response := accountRequest(test, server, http.MethodPost, endpoint, map[string]any{}, cookie, headers)
		if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), "ADDRESS_POOL_EXHAUSTED:") {
			test.Fatalf("exhausted address pool: %d %s", response.Code, response.Body.String())
		}
	}
	authorization, err := server.identity.LookupDeviceAuthorization(test.Context(), id)
	if err != nil || authorization.State != identity.DevicePending || len(server.store.ListNodes()) != 0 ||
		len(server.identity.ListAudit(0)) != auditCount || server.store.ConfigRevision() != revision {
		test.Fatal("failed allocation left a partial approval")
	}
	// 通过现有平台接口修复，保留历史预留、租户套餐及其他租户，不直改数据库。
	response := apiRequest(test, platform.Client(), http.MethodPatch,
		platform.URL+"/api/platform/v1/organizations/demo/plan", "pool-repair-test-token", map[string]string{"network_prefix": ""})
	if response.StatusCode != http.StatusOK {
		test.Fatalf("pool repair: %d %s", response.StatusCode, bodyString(test, response))
	}
	response.Body.Close()
	allocation, err := server.actualAllocation(test.Context())
	if err != nil || allocation.IPv4.String() != "100.100.2.0/24" || allocation.SourceRevision != 2 {
		test.Fatalf("repaired allocation: %+v %v", allocation, err)
	}
	peerAfter, err := registry.Assignment(test.Context(), "peer")
	if err != nil || peerAfter != peer || server.Plan().ID != plan.FreeID {
		test.Fatal("pool repair changed another tenant or the plan")
	}
	var retained int
	if err := registry.db.QueryRowContext(test.Context(),
		"SELECT COUNT(*) FROM tenant_network_reservations WHERE org_id=? AND prefix=?", "demo", "100.100.0.0/24").Scan(&retained); err != nil || retained != 1 {
		test.Fatal("pool repair released the historical reservation")
	}
	current, err := server.identity.LookupDeviceAuthorization(test.Context(), id)
	if err != nil || current != authorization || len(server.store.ListNodes()) != 0 {
		test.Fatal("repair implicitly approved or changed a device")
	}
	for range 2 {
		response := accountRequest(test, server, http.MethodPost, "/api/v1/browser/device-authorizations/"+id+"/approve", map[string]any{}, cookie, headers)
		if response.Code != http.StatusOK {
			test.Fatalf("approval after repair: %d %s", response.Code, response.Body.String())
		}
	}
	registered := decodeJSON[tailcfg.RegisterResponse](test, postRaw(test, client, "/machine/register", tailcfg.RegisterRequest{
		Version: tailcfg.CurrentCapabilityVersion, NodeKey: nodeKey.Public(), Followup: server.authURL(id),
	}))
	node, found := server.store.GetNodeByNodeKey(nodeKey.Public())
	if !registered.MachineAuthorized || registered.AuthURL != "" || !found || node.UserID != state.DefaultUserID ||
		node.MachineKey.String() != authorization.MachineKey || !allocation.ContainsIPv4(node.IPv4) ||
		netspace.IsClientReservedIPv4(node.IPv4) || len(server.store.ListNodes()) != 1 {
		test.Fatal("repaired approval lost identity, duplicated the device or broke official follow-up")
	}
}

func TestAuthKeyAddressExhaustionDoesNotConsumeKey(test *testing.T) {
	for _, family := range []string{"IPv4", "IPv6"} {
		test.Run(family, func(test *testing.T) {
			server := newTestServer(test)
			ipv4, ipv6 := netip.MustParsePrefix("192.168.50.0/24"), netip.MustParsePrefix("fd7a:115c:a1e0::/64")
			if family == "IPv4" {
				ipv4 = netip.MustParsePrefix("192.168.50.20/32")
			} else {
				ipv6 = netip.MustParsePrefix("fd7a:115c:a1e0::/127")
			}
			if err := server.store.SetAddressPrefixes(ipv4, ipv6); err != nil {
				test.Fatal(err)
			}
			existing := seedAPIMachine(test, server, "existing", nil)
			secret := seedPreAuthKey(test, server, state.PreAuthKey{})
			machine := key.NewMachine().Public()
			request := tailcfg.RegisterRequest{Version: tailcfg.CurrentCapabilityVersion, NodeKey: key.NewNode().Public(),
				Auth: &tailcfg.RegisterResponseAuth{AuthKey: secret}}
			auditCount, revision := len(server.identity.ListAudit(0)), server.store.ConfigRevision()
			_, err := server.handleRegister(test.Context(), request, machine)
			var failure HTTPError
			if !errors.As(err, &failure) || !errors.Is(err, state.ErrAddressExhausted) || failure.Code != http.StatusConflict || !strings.HasPrefix(failure.Msg, "ADDRESS_POOL_EXHAUSTED:") {
				test.Fatalf("exhausted %s enrollment: %v", family, err)
			}
			credential, found := server.store.GetPreAuthKey(secret)
			if !found || credential.Used || len(server.store.ListNodes()) != 1 ||
				len(server.identity.ListAudit(0)) != auditCount || server.store.ConfigRevision() != revision {
				test.Fatal("failed allocation consumed a key or left partial writes")
			}
			if err := server.store.SetAddressPrefixes(netip.MustParsePrefix("192.168.51.0/24"), netip.MustParsePrefix("fd7a:115c:a1e0:1::/64")); err != nil {
				test.Fatal(err)
			}
			response, err := server.handleRegister(test.Context(), request, machine)
			if err != nil || !response.MachineAuthorized || len(server.store.ListNodes()) != 2 {
				test.Fatal("the original one-use key could not retry after pool repair")
			}
			retained, found := server.store.GetNodeByID(existing.ID)
			if !found || retained.IPv4 != existing.IPv4 || retained.IPv6 != existing.IPv6 {
				test.Fatal("pool repair silently renumbered an existing device")
			}
		})
	}
}
