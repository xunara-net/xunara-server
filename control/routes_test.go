package control

import (
	"net/http/httptest"
	"net/netip"
	"testing"

	"tailscale.com/tailcfg"

	"github.com/xunara-net/xunara-server/state"
)

// advertisedHostinfo returns Hostinfo that advertises the given routes.
func advertisedHostinfo(hostname string, routes ...netip.Prefix) *tailcfg.Hostinfo {
	return &tailcfg.Hostinfo{Hostname: hostname, RoutableIPs: routes}
}

func containsPrefix(prefixes []netip.Prefix, want netip.Prefix) bool {
	for _, p := range prefixes {
		if p == want {
			return true
		}
	}
	return false
}

// TestRoutesRequireApproval drives the route lifecycle through the control API:
// an advertised route is invisible until an administrator approves it, and
// exit routes land in AllowedIPs but never in PrimaryRoutes.
func TestRoutesRequireApproval(t *testing.T) {
	s := newTestServer(t)
	hs := httptest.NewServer(s.Handler())
	defer hs.Close()

	conn, client, nodeKey := registerNode(t, s, hs, "router")
	defer conn.Close()

	subnet := netip.MustParsePrefix("192.168.7.0/24")

	// The client advertises a subnet route and the IPv4 default route.
	msg := decodeMapResponse(t, postRaw(t, client, "/machine/map", tailcfg.MapRequest{
		Version:  tailcfg.CurrentCapabilityVersion,
		NodeKey:  nodeKey.Public(),
		Hostinfo: advertisedHostinfo("router", subnet, state.ExitRouteV4),
	}), "")

	if containsPrefix(msg.Node.AllowedIPs, subnet) {
		t.Fatalf("unapproved route %s is already in AllowedIPs: %v", subnet, msg.Node.AllowedIPs)
	}

	node, ok := s.Store().GetNodeByNodeKey(nodeKey.Public())
	if !ok {
		t.Fatal("node not found after map request")
	}
	if got := node.AnnouncedRoutes(); len(got) != 2 {
		t.Fatalf("announced routes = %v, want the two advertised prefixes", got)
	}

	if err := s.Store().SetNodeApprovedRoutes(node.ID, []netip.Prefix{subnet, state.ExitRouteV4}); err != nil {
		t.Fatalf("SetNodeApprovedRoutes: %v", err)
	}

	msg = decodeMapResponse(t, postRaw(t, client, "/machine/map", tailcfg.MapRequest{
		Version: tailcfg.CurrentCapabilityVersion,
		NodeKey: nodeKey.Public(),
	}), "")

	if !containsPrefix(msg.Node.AllowedIPs, subnet) {
		t.Errorf("approved route %s missing from AllowedIPs %v", subnet, msg.Node.AllowedIPs)
	}
	if !containsPrefix(msg.Node.AllowedIPs, state.ExitRouteV4) {
		t.Errorf("approved exit route missing from AllowedIPs %v", msg.Node.AllowedIPs)
	}
	if !containsPrefix(msg.Node.PrimaryRoutes, subnet) {
		t.Errorf("approved subnet route missing from PrimaryRoutes %v", msg.Node.PrimaryRoutes)
	}
	for _, r := range msg.Node.PrimaryRoutes {
		if state.IsExitRoute(r) {
			t.Errorf("exit route %s must not appear in PrimaryRoutes", r)
		}
	}

	// Withdrawing approval takes the route away again.
	if err := s.Store().SetNodeApprovedRoutes(node.ID, nil); err != nil {
		t.Fatalf("clearing routes: %v", err)
	}
	msg = decodeMapResponse(t, postRaw(t, client, "/machine/map", tailcfg.MapRequest{
		Version: tailcfg.CurrentCapabilityVersion,
		NodeKey: nodeKey.Public(),
	}), "")
	if containsPrefix(msg.Node.AllowedIPs, subnet) {
		t.Errorf("withdrawn route %s is still in AllowedIPs %v", subnet, msg.Node.AllowedIPs)
	}
}

// TestRouteApprovalPushesToConnectedPeers covers the out-of-band approval path:
// the CLI writes approved routes and bumps the configuration revision; running
// servers notice and push an updated netmap.
func TestRouteApprovalPushesToConnectedPeers(t *testing.T) {
	s := newTestServer(t)
	hs := httptest.NewServer(s.Handler())
	defer hs.Close()

	connA, clientA, nodeKeyA := registerNode(t, s, hs, "node-a")
	defer connA.Close()

	sess := openMapSession(t, clientA, nodeKeyA.Public())
	defer sess.Body.Close()

	frames := mapFrames(sess.Body)
	view := newNetmapView()

	waitForNetmap(t, frames, view, func(*netmapView) bool { return true })
	if got := len(view.peerList()); got != 0 {
		t.Fatalf("peers before node B registered = %d, want 0", got)
	}

	connB, clientB, nodeKeyB := registerNode(t, s, hs, "node-b")
	defer connB.Close()

	subnet := netip.MustParsePrefix("10.99.0.0/16")
	postRaw(t, clientB, "/machine/map", tailcfg.MapRequest{
		Version:  tailcfg.CurrentCapabilityVersion,
		NodeKey:  nodeKeyB.Public(),
		Hostinfo: advertisedHostinfo("node-b", subnet),
	})

	waitForNetmap(t, frames, view, func(v *netmapView) bool { return len(v.peerList()) == 1 })
	peer := view.peerList()[0]
	if containsPrefix(peer.AllowedIPs, subnet) {
		t.Fatalf("unapproved route already visible to peers: %v", peer.AllowedIPs)
	}

	nodeB, ok := s.Store().GetNodeByNodeKey(nodeKeyB.Public())
	if !ok {
		t.Fatal("node B not found")
	}
	if err := s.Store().SetNodeApprovedRoutes(nodeB.ID, []netip.Prefix{subnet}); err != nil {
		t.Fatalf("SetNodeApprovedRoutes: %v", err)
	}
	if err := s.Store().BumpConfigRevision(); err != nil {
		t.Fatalf("BumpConfigRevision: %v", err)
	}

	waitForNetmap(t, frames, view, func(v *netmapView) bool {
		peers := v.peerList()
		return len(peers) == 1 && containsPrefix(peers[0].AllowedIPs, subnet)
	})
	if peer := view.peerList()[0]; !containsPrefix(peer.PrimaryRoutes, subnet) {
		t.Errorf("approved route %s missing from peer PrimaryRoutes %v", subnet, peer.PrimaryRoutes)
	}
}

func TestMultipleExitRoutesPushIndependentApprovalAndWithdrawal(test *testing.T) {
	server := newTestServer(test)
	httpServer := httptest.NewServer(server.Handler())
	defer httpServer.Close()

	olderConnection, olderClient, olderKey := registerNode(test, server, httpServer, "older-exit")
	defer olderConnection.Close()
	newerConnection, newerClient, newerKey := registerNode(test, server, httpServer, "newer-exit")
	defer newerConnection.Close()
	consumerConnection, consumerClient, consumerKey := registerNode(test, server, httpServer, "consumer")
	defer consumerConnection.Close()

	postRaw(test, olderClient, "/machine/map", tailcfg.MapRequest{
		Version: tailcfg.CurrentCapabilityVersion, NodeKey: olderKey.Public(),
		Hostinfo: advertisedHostinfo("older-exit", state.ExitRouteV4, state.ExitRouteV6),
	})
	postRaw(test, newerClient, "/machine/map", tailcfg.MapRequest{
		Version: tailcfg.CurrentCapabilityVersion, NodeKey: newerKey.Public(),
		Hostinfo: advertisedHostinfo("newer-exit", state.ExitRouteV4, state.ExitRouteV6),
	})
	older, found := server.Store().GetNodeByNodeKey(olderKey.Public())
	if !found {
		test.Fatal("older exit not found")
	}
	newer, found := server.Store().GetNodeByNodeKey(newerKey.Public())
	if !found {
		test.Fatal("newer exit not found")
	}
	if err := server.Store().SetNodeApprovedRoutes(older.ID, []netip.Prefix{state.ExitRouteV4, state.ExitRouteV6}); err != nil {
		test.Fatal(err)
	}

	session := openMapSession(test, consumerClient, consumerKey.Public())
	defer session.Body.Close()
	frames := mapFrames(session.Body)
	view := newNetmapView()
	exitOptions := func(view *netmapView) map[tailcfg.NodeID]bool {
		options := make(map[tailcfg.NodeID]bool)
		for _, peer := range view.peerList() {
			options[peer.ID] = containsPrefix(peer.AllowedIPs, state.ExitRouteV4) && containsPrefix(peer.AllowedIPs, state.ExitRouteV6)
			if len(peer.PrimaryRoutes) != 0 {
				test.Errorf("exit-only node has primary subnet routes: %v", peer.PrimaryRoutes)
			}
		}
		return options
	}
	waitForNetmap(test, frames, view, func(view *netmapView) bool {
		options := exitOptions(view)
		return len(options) == 2 && options[tailcfg.NodeID(older.ID)] && !options[tailcfg.NodeID(newer.ID)]
	})
	if err := server.Store().SetNodeApprovedRoutes(newer.ID, []netip.Prefix{state.ExitRouteV4, state.ExitRouteV6}); err != nil {
		test.Fatal(err)
	}
	if err := server.Store().BumpConfigRevision(); err != nil {
		test.Fatal(err)
	}
	waitForNetmap(test, frames, view, func(view *netmapView) bool {
		options := exitOptions(view)
		return options[tailcfg.NodeID(older.ID)] && options[tailcfg.NodeID(newer.ID)]
	})
	if err := server.Store().SetNodeApprovedRoutes(older.ID, nil); err != nil {
		test.Fatal(err)
	}
	if err := server.Store().BumpConfigRevision(); err != nil {
		test.Fatal(err)
	}
	waitForNetmap(test, frames, view, func(view *netmapView) bool {
		options := exitOptions(view)
		return !options[tailcfg.NodeID(older.ID)] && options[tailcfg.NodeID(newer.ID)]
	})
}
