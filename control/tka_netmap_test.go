package control

import (
	"net/netip"
	"slices"
	"testing"

	"tailscale.com/tailcfg"

	"github.com/xunara-net/xunara-server/state"
)

// TestRestrictFilterToSignedPeers checks the packet-filter narrowing clients
// require while tailnet lock is enforced: a filter that permits an unsigned
// peer is discarded wholesale by the client, so wildcard sources must be
// expanded to the signed nodes and explicit unsigned sources dropped.
func TestRestrictFilterToSignedPeers(t *testing.T) {
	signed := state.Node{ID: 1, IPv4: netip.MustParseAddr("100.64.0.1")}
	unsigned := state.Node{ID: 2, IPv4: netip.MustParseAddr("100.64.0.2")}
	router := state.Node{
		ID:             3,
		IPv4:           netip.MustParseAddr("100.64.0.3"),
		ApprovedRoutes: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
		Hostinfo: &tailcfg.Hostinfo{
			RoutableIPs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
		},
	}
	nodes := []state.Node{signed, unsigned, router}

	t.Run("no unsigned peers leaves the filter alone", func(t *testing.T) {
		rules := slices.Clone(tailcfg.FilterAllowAll)
		got := restrictFilterToSignedPeers(rules, nil, nodes)
		if !slices.Equal(got[0].SrcIPs, []string{"*"}) {
			t.Errorf("SrcIPs = %v, want the original wildcard", got[0].SrcIPs)
		}
	})

	t.Run("wildcards become the signed nodes", func(t *testing.T) {
		rules := []tailcfg.FilterRule{{SrcIPs: []string{"*"}, DstPorts: []tailcfg.NetPortRange{{IP: "*"}}}}
		got := restrictFilterToSignedPeers(rules, map[state.NodeID]bool{unsigned.ID: true}, nodes)

		want := []string{"10.0.0.0/8", "100.64.0.1/32", "100.64.0.3/32"}
		if !slices.Equal(got[0].SrcIPs, want) {
			t.Errorf("SrcIPs = %v, want %v", got[0].SrcIPs, want)
		}
		for _, src := range got[0].SrcIPs {
			if src == "*" || src == "0.0.0.0/0" || src == "::/0" {
				t.Errorf("SrcIPs still contain a wildcard: %v", got[0].SrcIPs)
			}
		}
	})

	t.Run("rules naming an unsigned peer are dropped", func(t *testing.T) {
		rules := []tailcfg.FilterRule{
			{SrcIPs: []string{"100.64.0.2"}, DstPorts: []tailcfg.NetPortRange{{IP: "*"}}},
			{SrcIPs: []string{"100.64.0.2/32", "100.64.0.1"}, DstPorts: []tailcfg.NetPortRange{{IP: "*"}}},
			{SrcIPs: []string{"100.64.0.1"}, DstPorts: []tailcfg.NetPortRange{{IP: "*"}}},
		}
		got := restrictFilterToSignedPeers(rules, map[state.NodeID]bool{unsigned.ID: true}, nodes)

		if len(got) != 2 {
			t.Fatalf("rules = %+v, want the unsigned-only rule dropped", got)
		}
		if !slices.Equal(got[0].SrcIPs, []string{"100.64.0.1"}) {
			t.Errorf("SrcIPs = %v, want the unsigned source removed", got[0].SrcIPs)
		}
	})

	t.Run("exit routes are never re-permitted", func(t *testing.T) {
		exit := state.Node{
			ID:             4,
			IPv4:           netip.MustParseAddr("100.64.0.4"),
			ApprovedRoutes: []netip.Prefix{state.ExitRouteV4},
			Hostinfo: &tailcfg.Hostinfo{
				RoutableIPs: []netip.Prefix{state.ExitRouteV4},
			},
		}
		rules := []tailcfg.FilterRule{{SrcIPs: []string{"*"}, DstPorts: []tailcfg.NetPortRange{{IP: "*"}}}}
		got := restrictFilterToSignedPeers(rules, map[state.NodeID]bool{unsigned.ID: true}, append(nodes, exit))

		for _, src := range got[0].SrcIPs {
			if src == "0.0.0.0/0" {
				t.Errorf("exit route leaked into the sources: %v", got[0].SrcIPs)
			}
		}
	})
}
