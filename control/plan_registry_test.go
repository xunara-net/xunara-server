package control

import (
	"context"
	"errors"
	"net/netip"
	"path/filepath"
	"testing"

	"github.com/xunara-net/xunara-server/netspace"
	"github.com/xunara-net/xunara-server/plan"
)

// clientError reports whether err is a validation failure the platform API
// returns verbatim (400/409) rather than a server failure.
func clientError(err error) bool {
	var apiErr *orgAPIError
	return errors.As(err, &apiErr)
}

// newTestPlanRegistry opens a registry over the ship's default catalog and a
// /24-block pool, plus the path needed to reopen it.
func newTestPlanRegistry(t *testing.T, dir string) (*PlanRegistry, string) {
	t.Helper()

	pool, err := netspace.NewPool(netip.MustParsePrefix("100.100.0.0/22"), 24)
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}
	path := filepath.Join(dir, "plans.db")
	registry, err := OpenPlanRegistry(context.Background(), PlanRegistryConfig{
		Path:     path,
		Pool:     pool,
		Reserved: []netip.Prefix{netip.MustParsePrefix("100.127.0.0/16")},
	})
	if err != nil {
		t.Fatalf("OpenPlanRegistry: %v", err)
	}
	t.Cleanup(func() { registry.Close() })
	return registry, path
}

func TestPlanRegistryDefaultsToTheCatalogDefault(t *testing.T) {
	ctx := context.Background()
	registry, _ := newTestPlanRegistry(t, t.TempDir())

	assignment, err := registry.Assignment(ctx, "acme")
	if err != nil {
		t.Fatalf("Assignment: %v", err)
	}
	if assignment.PlanID != plan.FreeID {
		t.Fatalf("unassigned tenant plan = %q, want %q", assignment.PlanID, plan.FreeID)
	}
	if assignment.NetworkPrefix != "" {
		t.Fatalf("unassigned tenant network = %q, want empty", assignment.NetworkPrefix)
	}
	if _, ok, err := registry.Get(ctx, "acme"); err != nil || ok {
		t.Fatalf("Get on an unassigned tenant = (%v, %v), want not found", ok, err)
	}
}

func TestPlanRegistryAllocateHandsOutPoolBlocks(t *testing.T) {
	ctx := context.Background()
	registry, _ := newTestPlanRegistry(t, t.TempDir())

	first, err := registry.Allocate(ctx, "acme")
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}
	if first.PlanID != plan.FreeID {
		t.Errorf("Allocate plan = %q, want %q", first.PlanID, plan.FreeID)
	}
	if first.NetworkPrefix != "100.100.1.0/24" {
		t.Errorf("first block = %q, want 100.100.1.0/24", first.NetworkPrefix)
	}

	second, err := registry.Allocate(ctx, "globex")
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}
	if second.NetworkPrefix != "100.100.2.0/24" {
		t.Errorf("second block = %q, want 100.100.2.0/24", second.NetworkPrefix)
	}

	// Idempotent: allocating again must not move a tenant.
	again, err := registry.Allocate(ctx, "acme")
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}
	if again.NetworkPrefix != first.NetworkPrefix {
		t.Errorf("re-allocating acme moved it from %q to %q", first.NetworkPrefix, again.NetworkPrefix)
	}
	if !again.CreatedAt.Equal(first.CreatedAt) {
		t.Errorf("re-allocating acme changed its creation time")
	}

	prefix, ok := registry.NetworkPrefix(ctx, "acme")
	if !ok || prefix.String() != "100.100.1.0/24" {
		t.Fatalf("NetworkPrefix = %s (%v)", prefix, ok)
	}
}

func TestPlanRegistryAssignPlanAndQuotas(t *testing.T) {
	ctx := context.Background()
	registry, _ := newTestPlanRegistry(t, t.TempDir())

	if _, err := registry.AssignPlan(ctx, "acme", "gold"); !errors.Is(err, ErrPlanUnknown) {
		t.Fatalf("AssignPlan with an unknown plan = %v, want ErrPlanUnknown", err)
	}

	assigned, err := registry.AssignPlan(ctx, "acme", plan.ProID)
	if err != nil {
		t.Fatalf("AssignPlan: %v", err)
	}
	if assigned.PlanID != plan.ProID {
		t.Fatalf("assigned plan = %q, want %q", assigned.PlanID, plan.ProID)
	}
	if got := registry.Plan(ctx, "acme"); got.ID != plan.ProID || !got.AllowCustomCIDR {
		t.Fatalf("Plan = %#v, want pro with custom CIDR", got)
	}
	if got := registry.Plan(ctx, "globex"); got.ID != plan.FreeID || got.MaxDevices != 10 {
		t.Fatalf("Plan for an unassigned tenant = %#v, want free/10 devices", got)
	}
}

func TestPlanRegistryCustomNetworkRules(t *testing.T) {
	ctx := context.Background()
	registry, _ := newTestPlanRegistry(t, t.TempDir())

	for _, tc := range []struct{ org, want string }{
		{"acme", "100.100.1.0/24"}, {"globex", "100.100.2.0/24"}, {"initech", "100.100.3.0/24"},
	} {
		got, err := registry.Allocate(ctx, tc.org)
		if err != nil {
			t.Fatalf("Allocate(%s): %v", tc.org, err)
		}
		if got.NetworkPrefix != tc.want {
			t.Fatalf("Allocate(%s) = %q, want %q", tc.org, got.NetworkPrefix, tc.want)
		}
	}

	// A free tenant may not choose a range at all.
	if _, err := registry.SetNetwork(ctx, "globex", netip.MustParsePrefix("192.168.50.0/24")); !errors.Is(err, ErrNetworkNotAllowed) {
		t.Fatalf("free tenant SetNetwork = %v, want ErrNetworkNotAllowed", err)
	}

	for _, org := range []string{"acme", "globex", "initech"} {
		if _, err := registry.AssignPlan(ctx, org, plan.ProID); err != nil {
			t.Fatalf("AssignPlan(%s): %v", org, err)
		}
	}

	// A pro tenant may choose a range, but not onto somebody else's.
	if _, err := registry.SetNetwork(ctx, "globex", netip.MustParsePrefix("100.100.1.0/24")); !errors.Is(err, ErrNetworkConflict) {
		t.Fatalf("SetNetwork onto acme's block = %v, want ErrNetworkConflict", err)
	}

	updated, err := registry.SetNetwork(ctx, "acme", netip.MustParsePrefix("100.101.50.5/24"))
	if err != nil {
		t.Fatalf("SetNetwork: %v", err)
	}
	if updated.NetworkPrefix != "100.101.50.0/24" {
		t.Fatalf("SetNetwork stored %q, want the masked 100.101.50.0/24", updated.NetworkPrefix)
	}
	if _, err := registry.SetNetwork(ctx, "globex", netip.MustParsePrefix("100.101.51.0/25")); err != nil {
		t.Fatalf("a neighboring range must be free: %v", err)
	}
	if _, err := registry.SetNetwork(ctx, "initech", netip.MustParsePrefix("100.101.50.128/25")); !errors.Is(err, ErrNetworkConflict) {
		t.Fatalf("partially overlapping SetNetwork = %v, want ErrNetworkConflict", err)
	}

	// Reserved ranges are refused, and the message says which one.
	if _, err := registry.SetNetwork(ctx, "initech", netip.MustParsePrefix("127.0.0.0/24")); err == nil {
		t.Fatal("SetNetwork accepted the loopback range")
	} else if !clientError(err) {
		t.Fatalf("SetNetwork on loopback = %T, want a client error", err)
	}
	if _, err := registry.SetNetwork(ctx, "initech", netip.MustParsePrefix("100.127.5.0/24")); err == nil {
		t.Fatal("SetNetwork accepted the deployment's reserved share range")
	}

	// Clearing a custom range hands back a pool block.
	cleared, err := registry.SetNetwork(ctx, "acme", netip.Prefix{})
	if err != nil {
		t.Fatalf("clearing the network: %v", err)
	}
	prefix, err := netip.ParsePrefix(cleared.NetworkPrefix)
	if err != nil {
		t.Fatalf("cleared network %q is not a prefix: %v", cleared.NetworkPrefix, err)
	}
	if !registry.Pool().Contains(prefix) {
		t.Fatalf("cleared network %q is not a pool block", prefix)
	}
}

func TestPlanRegistryDowngradeResetsCustomRange(t *testing.T) {
	ctx := context.Background()
	registry, _ := newTestPlanRegistry(t, t.TempDir())

	if _, err := registry.Allocate(ctx, "acme"); err != nil {
		t.Fatalf("Allocate: %v", err)
	}
	if _, err := registry.AssignPlan(ctx, "acme", plan.ProID); err != nil {
		t.Fatalf("AssignPlan: %v", err)
	}
	if _, err := registry.SetNetwork(ctx, "acme", netip.MustParsePrefix("100.101.10.0/24")); err != nil {
		t.Fatalf("SetNetwork: %v", err)
	}

	downgraded, err := registry.AssignPlan(ctx, "acme", plan.FreeID)
	if err != nil {
		t.Fatalf("AssignPlan: %v", err)
	}
	prefix, err := netip.ParsePrefix(downgraded.NetworkPrefix)
	if err != nil {
		t.Fatalf("network after downgrade %q is not a prefix: %v", downgraded.NetworkPrefix, err)
	}
	if !registry.Pool().Contains(prefix) {
		t.Fatalf("downgrade left the custom range %q in place", prefix)
	}
}

func TestPlanRegistryPoolExhaustion(t *testing.T) {
	ctx := context.Background()
	pool, err := netspace.NewPool(netip.MustParsePrefix("100.101.90.0/24"), 24)
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}
	registry, err := OpenPlanRegistry(ctx, PlanRegistryConfig{Path: filepath.Join(t.TempDir(), "plans.db"), Pool: pool})
	if err != nil {
		t.Fatalf("OpenPlanRegistry: %v", err)
	}
	defer registry.Close()

	if _, err := registry.Allocate(ctx, "acme"); err != nil {
		t.Fatalf("Allocate: %v", err)
	}
	if _, err := registry.Allocate(ctx, "globex"); !errors.Is(err, ErrNoNetworkBlock) {
		t.Fatalf("Allocate on an exhausted pool = %v, want ErrNoNetworkBlock", err)
	}
}

func TestPlanRegistrySurvivesReopen(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	registry, path := newTestPlanRegistry(t, dir)

	if _, err := registry.Allocate(ctx, "acme"); err != nil {
		t.Fatalf("Allocate: %v", err)
	}
	if _, err := registry.AssignPlan(ctx, "acme", plan.BusinessID); err != nil {
		t.Fatalf("AssignPlan: %v", err)
	}
	registry.Close()

	reopened, err := OpenPlanRegistry(ctx, PlanRegistryConfig{Path: path})
	if err != nil {
		t.Fatalf("reopening the registry: %v", err)
	}
	defer reopened.Close()

	assignment, ok, err := reopened.Get(ctx, "acme")
	if err != nil || !ok {
		t.Fatalf("Get after reopen = (%v, %v)", ok, err)
	}
	if assignment.PlanID != plan.BusinessID || assignment.NetworkPrefix != "100.100.1.0/24" {
		t.Fatalf("assignment after reopen = %#v", assignment)
	}
}

func TestPlanRegistryStaleAssignmentFallsBackToDefault(t *testing.T) {
	ctx := context.Background()
	registry, _ := newTestPlanRegistry(t, t.TempDir())

	// Simulate a plan that was sold, assigned and later removed from the
	// catalog: the row survives, the plan does not.
	if _, err := registry.db.ExecContext(ctx, `
		INSERT INTO tenant_plans (org_id, plan_id, network_prefix, created_at, updated_at)
		VALUES ('legacy', 'retired', '', 1, 1)`); err != nil {
		t.Fatalf("inserting the stale assignment: %v", err)
	}
	if got := registry.Plan(ctx, "legacy"); got.ID != plan.FreeID {
		t.Fatalf("Plan for a retired assignment = %q, want the catalog default", got.ID)
	}
	assignment, err := registry.Assignment(ctx, "legacy")
	if err != nil {
		t.Fatalf("Assignment: %v", err)
	}
	if assignment.PlanID != "retired" {
		t.Fatalf("Assignment rewrote the stored plan %q", assignment.PlanID)
	}
}

func TestPlanRegistryDeleteReturnsTenantToDefault(t *testing.T) {
	ctx := context.Background()
	registry, _ := newTestPlanRegistry(t, t.TempDir())

	if _, err := registry.AssignPlan(ctx, "acme", plan.BusinessID); err != nil {
		t.Fatalf("AssignPlan: %v", err)
	}
	if err := registry.Delete(ctx, "acme"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, ok, err := registry.Get(ctx, "acme"); err != nil || ok {
		t.Fatalf("Get after Delete = (%v, %v), want not found", ok, err)
	}
	if got := registry.Plan(ctx, "acme"); got.ID != plan.FreeID {
		t.Fatalf("Plan after Delete = %q, want the catalog default", got.ID)
	}
}
