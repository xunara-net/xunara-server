package control

import (
	"context"
	"net/netip"
	"testing"

	"github.com/xunara-net/xunara-server/netspace"
)

// newAdminTestRouter builds a router with one organization, a plan registry
// and the platform token, plus the config paths needed to talk to it.
func newAdminTestRouter(t *testing.T) (*Router, *PlanRegistry, string) {
	t.Helper()

	ctx := context.Background()
	dir := t.TempDir()

	const token = "test-platform-token"
	registry, err := OpenOrgRegistry(ctx, OrgRegistryConfig{
		Path:      dir + "/platform.db",
		StateRoot: dir + "/orgs",
		NewServer: func(org ManagedOrg, stateDir string) (*Server, error) {
			return New(Config{ServerURL: org.ServerURL, Domain: org.Domain, StateDir: stateDir})
		},
	})
	if err != nil {
		t.Fatalf("OpenOrgRegistry: %v", err)
	}
	t.Cleanup(func() { registry.Close() })

	pool, err := netspace.NewPool(netip.MustParsePrefix("100.100.0.0/24"), 24)
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}
	plans, err := OpenPlanRegistry(ctx, PlanRegistryConfig{Path: dir + "/plans.db", Pool: pool})
	if err != nil {
		t.Fatalf("OpenPlanRegistry: %v", err)
	}
	t.Cleanup(func() { plans.Close() })

	router, err := NewRouter(RouterConfig{
		ListenAddr:         "127.0.0.1:0",
		Orgs:               []OrgSite{{ID: "acme", Name: "Acme", Domains: []string{"login.acme.test"}, Server: newTestServer(t)}},
		PlatformAdminToken: token,
		Registry:           registry,
		Plans:              plans,
	})
	if err != nil {
		t.Fatalf("NewRouter: %v", err)
	}
	t.Cleanup(func() { router.Close() })
	return router, plans, token
}
