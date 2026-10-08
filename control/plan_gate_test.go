package control

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"strings"
	"testing"

	"tailscale.com/tailcfg"
	"tailscale.com/types/key"

	"github.com/xunara-net/xunara-server/plan"
	"github.com/xunara-net/xunara-server/state"
)

// planServer builds a server whose tenant is on the given plan, the way a
// hosted deployment does: one registry lookup per tenant ID.
func planServer(t *testing.T, p plan.Plan) *Server {
	t.Helper()
	return newServerWithConfig(t, Config{
		PlanSource: func(string) plan.Plan { return p },
	})
}

// freePlan and proPlan are the shipping catalog's first two plans.
func freePlan(t *testing.T) plan.Plan {
	t.Helper()
	p, ok := plan.DefaultCatalog().Get(plan.FreeID)
	if !ok {
		t.Fatal("the default catalog has no free plan")
	}
	return p
}

func proPlan(t *testing.T) plan.Plan {
	t.Helper()
	p, ok := plan.DefaultCatalog().Get(plan.ProID)
	if !ok {
		t.Fatal("the default catalog has no pro plan")
	}
	return p
}

// fillDevices registers exactly n devices through the pre-auth key path.
func fillDevices(t *testing.T, s *Server, n int) {
	t.Helper()
	secret := seedPreAuthKey(t, s, state.PreAuthKey{Reusable: true})
	for i := 0; i < n; i++ {
		_, err := s.handleRegister(context.Background(), tailcfg.RegisterRequest{
			Version: tailcfg.CurrentCapabilityVersion,
			NodeKey: key.NewNode().Public(),
			Auth:    &tailcfg.RegisterResponseAuth{AuthKey: secret},
		}, key.NewMachine().Public())
		if err != nil {
			t.Fatalf("registering device %d: %v", i+1, err)
		}
	}
}

func TestDeviceQuotaBlocksTheEleventhDevice(t *testing.T) {
	s := planServer(t, freePlan(t))
	fillDevices(t, s, 10)

	_, err := s.handleRegister(context.Background(), tailcfg.RegisterRequest{
		Version: tailcfg.CurrentCapabilityVersion,
		NodeKey: key.NewNode().Public(),
		Auth:    &tailcfg.RegisterResponseAuth{AuthKey: seedPreAuthKey(t, s, state.PreAuthKey{})},
	}, key.NewMachine().Public())

	var he HTTPError
	if !errors.As(err, &he) {
		t.Fatalf("registering device 11 = %v, want an HTTPError", err)
	}
	if he.Code != http.StatusForbidden || !strings.HasPrefix(he.Msg, "DEVICE_LIMIT_REACHED") {
		t.Fatalf("registering device 11 = %d %q, want 403 DEVICE_LIMIT_REACHED", he.Code, he.Msg)
	}
	if got := len(s.store.ListNodes()); got != 10 {
		t.Fatalf("the store holds %d devices after the refusal, want 10", got)
	}

	// The limit is on devices, not on talking to the control plane: an
	// existing device still re-registers (and can log out) at the limit.
	existing := s.store.ListNodes()[0]
	resp, err := s.handleRegister(context.Background(), tailcfg.RegisterRequest{
		Version: tailcfg.CurrentCapabilityVersion,
		NodeKey: existing.NodeKey,
	}, existing.MachineKey)
	if err != nil {
		t.Fatalf("re-registering an existing device = %v, want success", err)
	}
	if !resp.MachineAuthorized {
		t.Fatalf("re-registration lost the machine authorization: %+v", resp)
	}
}

func TestDeviceQuotaLiftsWithThePlan(t *testing.T) {
	registry := newTestPlanRegistryForServer(t)

	s := newServerWithConfig(t, Config{
		PlanSource: func(tenantID string) plan.Plan { return registry.Plan(context.Background(), tenantID) },
	})
	fillDevices(t, s, 10)

	// The tenant upgrades; the same control plane must now accept a device.
	if _, err := registry.AssignPlan(context.Background(), s.TenantID(), plan.ProID); err != nil {
		t.Fatalf("AssignPlan: %v", err)
	}
	if _, err := s.handleRegister(context.Background(), tailcfg.RegisterRequest{
		Version: tailcfg.CurrentCapabilityVersion,
		NodeKey: key.NewNode().Public(),
		Auth:    &tailcfg.RegisterResponseAuth{AuthKey: seedPreAuthKey(t, s, state.PreAuthKey{})},
	}, key.NewMachine().Public()); err != nil {
		t.Fatalf("registering after the upgrade = %v, want success", err)
	}
}

func TestDeviceQuotaHoldsPendingApprovals(t *testing.T) {
	s := planServer(t, freePlan(t))
	fillDevices(t, s, 9)

	// A device starts an interactive login while the tenant is one device
	// short of its limit.
	nodeKey := key.NewNode().Public()
	machineKey := key.NewMachine().Public()
	resp, err := s.handleRegister(context.Background(), tailcfg.RegisterRequest{
		Version: tailcfg.CurrentCapabilityVersion,
		NodeKey: nodeKey,
	}, machineKey)
	if err != nil {
		t.Fatalf("starting an interactive registration below the limit = %v", err)
	}
	if resp.AuthURL == "" {
		t.Fatalf("interactive registration returned no auth URL: %+v", resp)
	}
	authID := resp.AuthURL[strings.LastIndex(resp.AuthURL, "/")+1:]

	// Another device takes the last slot.
	fillDevices(t, s, 1)

	if err := s.ApproveRegistration(authID); err == nil {
		t.Fatal("approving the 11th device succeeded despite the device limit")
	} else {
		var he HTTPError
		if !errors.As(err, &he) || he.Code != http.StatusForbidden {
			t.Fatalf("approval = %v, want a 403 HTTPError", err)
		}
	}

	// The pending registration survives the refusal, so an upgrade can still
	// approve the device instead of forcing the user to start over.
	da, ok := s.identity.GetDeviceAuthorization(authID)
	if !ok {
		t.Fatal("the refused approval dropped the device authorization")
	}
	if !da.Pending() {
		t.Fatalf("device authorization is %q after the refusal, want pending", da.State)
	}

	// A client that asks for a new interactive login at the limit is told
	// immediately instead of being sent to an approval page that cannot
	// succeed.
	if _, err := s.handleRegister(context.Background(), tailcfg.RegisterRequest{
		Version: tailcfg.CurrentCapabilityVersion,
		NodeKey: key.NewNode().Public(),
	}, key.NewMachine().Public()); err == nil {
		t.Fatal("a new interactive registration at the limit was accepted")
	} else {
		var he HTTPError
		if !errors.As(err, &he) || he.Code != http.StatusForbidden {
			t.Fatalf("interactive registration at the limit = %v, want a 403 HTTPError", err)
		}
	}
}

func TestPlanGatesWithoutAPlanSourceAreNoOps(t *testing.T) {
	s := newTestServer(t)
	if got := s.Plan().ID; got != "unlimited" {
		t.Fatalf("Plan() without a source = %q, want unlimited", got)
	}
	for name, err := range map[string]error{
		"device":  s.assertDeviceQuota(),
		"authkey": s.assertAuthKeyQuota(),
		"user":    s.assertUserQuota(),
		"api":     s.assertAPIAllowed(),
		"audit":   s.assertAuditLogAllowed(),
		"routes":  s.assertRouteApprovalAllowed([]netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}),
	} {
		if err != nil {
			t.Errorf("%s gate refused an unlimited tenant: %v", name, err)
		}
	}
}

func TestAuthKeyQuotaCountsUsableKeys(t *testing.T) {
	s := planServer(t, freePlan(t))
	limit := freePlan(t).MaxAuthKeys

	for i := 0; i < limit; i++ {
		seedPreAuthKey(t, s, state.PreAuthKey{})
	}
	if err := s.assertAuthKeyQuota(); err == nil {
		t.Fatalf("the %dth auth key was allowed past a limit of %d", limit+1, limit)
	} else if !strings.HasPrefix(err.Error(), "AUTH_KEY_LIMIT_REACHED") {
		t.Fatalf("auth key gate = %v, want AUTH_KEY_LIMIT_REACHED", err)
	}

	// An expired key must not hold a quota slot: the tenant cannot delete it
	// from the console.
	keys := s.store.ListPreAuthKeys()
	if err := s.store.DeletePreAuthKey(keys[0].Key); err != nil {
		t.Fatalf("DeletePreAuthKey: %v", err)
	}
	if err := s.assertAuthKeyQuota(); err != nil {
		t.Fatalf("after deleting a key = %v, want success", err)
	}
}

func TestUserQuotaCountsMembers(t *testing.T) {
	s := planServer(t, freePlan(t))
	// newServerWithConfig seeds one administrator, which is exactly what the
	// free plan allows.
	if err := s.assertUserQuota(); err == nil {
		t.Fatal("a second member was allowed on a one-member plan")
	} else if !strings.HasPrefix(err.Error(), "USER_LIMIT_REACHED") {
		t.Fatalf("user gate = %v, want USER_LIMIT_REACHED", err)
	}

	pro := planServer(t, proPlan(t))
	if err := pro.assertUserQuota(); err != nil {
		t.Fatalf("a five-member plan refused the second member: %v", err)
	}
}

func TestAPIKeyGateFollowsThePlan(t *testing.T) {
	free := planServer(t, freePlan(t))
	if err := free.assertAPIAllowed(); err == nil {
		t.Fatal("the free plan allowed an API key")
	} else if !strings.HasPrefix(err.Error(), "PLAN_FEATURE_DISABLED") {
		t.Fatalf("API gate = %v, want PLAN_FEATURE_DISABLED", err)
	}
	if err := planServer(t, proPlan(t)).assertAPIAllowed(); err != nil {
		t.Fatalf("the pro plan refused an API key: %v", err)
	}
}

func TestRouteGateEnforcesQuotaAndExitNodes(t *testing.T) {
	free := planServer(t, freePlan(t))
	exit := []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("fd7a::/64")}
	if err := free.assertRouteApprovalAllowed(exit); err == nil {
		t.Fatal("the free plan approved an exit node")
	} else if !strings.Contains(err.Error(), "exit nodes") {
		t.Fatalf("exit node gate = %v, want the exit-node message", err)
	}

	routes := []netip.Prefix{
		netip.MustParsePrefix("10.1.0.0/24"),
		netip.MustParsePrefix("10.2.0.0/24"),
		netip.MustParsePrefix("10.3.0.0/24"),
	}
	quota := planServer(t, plan.Plan{ID: "tiny", Name: "Tiny", MaxRoutes: 2, AllowSubnetRouter: true})
	if err := quota.assertRouteApprovalAllowed(routes[:3]); err == nil {
		t.Fatal("a three-route approval was allowed on a two-route plan")
	} else if !strings.HasPrefix(err.Error(), "ROUTE_LIMIT_REACHED") {
		t.Fatalf("route quota gate = %v, want ROUTE_LIMIT_REACHED", err)
	}
	if err := quota.assertRouteApprovalAllowed(routes[:2]); err != nil {
		t.Fatalf("a two-route approval on a two-route plan = %v, want success", err)
	}

	noSubnets := planServer(t, plan.Plan{ID: "plain", Name: "Plain", MaxRoutes: plan.Unlimited})
	if err := noSubnets.assertRouteApprovalAllowed([]netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")}); err == nil {
		t.Fatal("a plan without subnet routers approved a subnet route")
	}
}

func TestAuditLogGateFollowsThePlan(t *testing.T) {
	limited := planServer(t, plan.Plan{ID: "basic", Name: "Basic", AllowAuditLog: false})
	if err := limited.assertAuditLogAllowed(); err == nil {
		t.Fatal("a plan without audit access served the audit log")
	}
	if err := planServer(t, freePlan(t)).assertAuditLogAllowed(); err != nil {
		t.Fatalf("the free plan (audit included) refused the audit log: %v", err)
	}
}

// newTestPlanRegistryForServer opens a plan registry for tests that need a
// live plan source rather than a fixed plan.
func newTestPlanRegistryForServer(t *testing.T) *PlanRegistry {
	t.Helper()
	registry, _ := newTestPlanRegistry(t, t.TempDir())
	return registry
}
