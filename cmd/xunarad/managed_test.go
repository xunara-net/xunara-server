package main

import (
	"log/slog"
	"testing"

	"github.com/xunara-net/xunara-server/control"
	"tailscale.com/tailcfg"
)

func TestManagedServerConfigPreservesSharedRelayOnRestart(t *testing.T) {
	sharedMap := &tailcfg.DERPMap{Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{
		900: {RegionID: 900, Nodes: []*tailcfg.DERPNode{{Name: "900a", HostName: "relay.example.com", DERPPort: 9091, STUNPort: -1}}},
	}}
	org := control.ManagedOrg{ID: "alice", ServerURL: "https://alice.example.com", Domain: "alice.internal"}
	opts := routerOptions{consoleTimezone: "Asia/Shanghai", trustedProxy: true}
	config := managedServerConfig(org, t.TempDir(), opts, sharedMap, slog.Default())
	if config.ServerURL != org.ServerURL || config.Domain != org.Domain || !config.TrustedProxy {
		t.Fatal("managed server lost its organization identity or deployment settings")
	}
	first, err := control.New(config)
	if err != nil {
		t.Fatal(err)
	}
	publicKey := first.NoisePublicKey()
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	restarted, err := control.New(managedServerConfig(org, config.StateDir, opts, sharedMap, slog.Default()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { restarted.Close() })
	if restarted.NoisePublicKey() != publicKey || restarted.DERPMap().Regions[900].Nodes[0].DERPPort != 9091 {
		t.Fatal("restart changed the tenant key or dropped the public relay")
	}
	config.DERPMap.Regions[900].Nodes[0].HostName = "changed.example.com"
	if sharedMap.Regions[900].Nodes[0].HostName != "relay.example.com" || restarted.DERPMap().Regions[900].Nodes[0].HostName != "relay.example.com" {
		t.Fatal("a tenant mutated another tenant's relay configuration")
	}
}

func TestManagedServerConfigWithoutSharedRelay(t *testing.T) {
	config := managedServerConfig(control.ManagedOrg{ServerURL: "https://alice.example.com"}, t.TempDir(), routerOptions{}, nil, slog.Default())
	if config.DERPMap != nil || config.TrustedProxy {
		t.Fatal("a deployment without managed relay settings inherited another tenant's configuration")
	}
}
