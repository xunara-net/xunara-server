package state

import (
	"net/netip"
	"reflect"
	"testing"
	"time"

	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

func TestRouteRevisionTracksAuthorityNotTelemetry(test *testing.T) {
	node := Node{ID: 1, StableID: "revision-node", UserID: 1, NodeKey: key.NewNode().Public(), MachineKey: key.NewMachine().Public(),
		Hostinfo: &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}}}
	original := RouteApprovalRevision(node)
	node.Hostname = "new-hostname"
	seen := time.Now()
	node.LastSeen = &seen
	if RouteApprovalRevision(node) != original {
		test.Fatal("unrelated telemetry caused a conflict")
	}
	for _, mutate := range []func(*Node){
		func(node *Node) { node.NodeKey = key.NewNode().Public() },
		func(node *Node) { node.MachineKey = key.NewMachine().Public() },
		func(node *Node) { node.UserID++ },
		func(node *Node) { node.ApprovedRoutes = node.AnnouncedRoutes() },
		func(node *Node) { node.Hostinfo = &tailcfg.Hostinfo{} },
	} {
		changed := node
		mutate(&changed)
		if RouteApprovalRevision(changed) == original {
			test.Fatal("authority/approval change was not versioned")
		}
	}
}

func TestTelemetryPreservesCurrentRouteApprovalAndIdentityFacts(test *testing.T) {
	for _, backend := range []string{"sqlite", "memory"} {
		test.Run(backend, func(test *testing.T) {
			var store Store
			if backend == "sqlite" {
				store = openTestSQLite(test, test.TempDir()+"/state.db")
			} else {
				store = NewMemoryStore()
			}
			node := addNode(test, store)
			stale := node
			route := netip.MustParsePrefix("10.50.0.0/16")
			node.ApprovedRoutes = []netip.Prefix{route}
			node.Expiry = time.Now().Add(time.Hour)
			node.Tags = []string{"tag:server"}
			if err := store.UpdateNode(node); err != nil {
				test.Fatal(err)
			}
			stale.Hostname = "updated-telemetry"
			if err := store.UpdateNodeTelemetryWithDNS(&stale); err != nil {
				test.Fatal(err)
			}
			if !reflect.DeepEqual(stale.ApprovedRoutes, node.ApprovedRoutes) || !stale.Expiry.Equal(node.Expiry) || !reflect.DeepEqual(stale.Tags, node.Tags) {
				test.Fatal("telemetry snapshot overwrote administrative state")
			}
			oldKey := stale
			node.NodeKey = key.NewNode().Public()
			if err := store.UpdateNode(node); err != nil {
				test.Fatal(err)
			}
			if err := store.UpdateNodeTelemetryWithDNS(&oldKey); err == nil {
				test.Fatal("obsolete key restored by telemetry")
			}
		})
	}
}
