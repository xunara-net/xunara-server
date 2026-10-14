package control

import (
	"net/netip"
	"testing"

	"github.com/xunara-net/xunara-server/identity"
	"github.com/xunara-net/xunara-server/state"
	"go4.org/netipx"
	"tailscale.com/net/packet"
	"tailscale.com/tailcfg"
	"tailscale.com/types/logger"
	"tailscale.com/wgengine/filter"
)

func filterForShareTest(t *testing.T, self state.Node, rules []tailcfg.FilterRule) *filter.Filter {
	t.Helper()
	matches, err := filter.MatchesFromFilterRules(rules)
	if err != nil {
		t.Fatal(err)
	}
	var local netipx.IPSetBuilder
	for _, prefix := range nodePrefixes(self) {
		local.AddPrefix(prefix)
	}
	addresses, err := local.IPSet()
	if err != nil {
		t.Fatal(err)
	}
	return filter.New(matches, nil, addresses, addresses, nil, logger.Discard)
}

func shareUDP(source, target netip.Addr, sourcePort, targetPort uint16) packet.Parsed {
	var content []byte
	if source.Is4() {
		content = packet.Generate(&packet.UDP4Header{IP4Header: packet.IP4Header{Src: source, Dst: target}, SrcPort: sourcePort, DstPort: targetPort}, []byte("share compatibility"))
	} else {
		content = packet.Generate(&packet.UDP6Header{IP6Header: packet.IP6Header{Src: source, Dst: target}, SrcPort: sourcePort, DstPort: targetPort}, []byte("share compatibility"))
	}
	var parsed packet.Parsed
	parsed.Decode(content)
	return parsed
}

func TestShareQuarantineUsesUpstreamStatefulFilter(t *testing.T) {
	fixture := newShareFixture(t)
	incoming := fixture.globex.sharePeersFor(fixture.x).nodes[0]
	rules := fixture.globex.packetFilterFor(fixture.x)
	for _, ipv6 := range []bool{false, true} {
		remote, self := incoming.IPv4, fixture.x.IPv4
		if ipv6 {
			remote, self = incoming.IPv6, fixture.x.IPv6
		}
		clientFilter := filterForShareTest(t, fixture.x, rules)
		unsolicited := shareUDP(remote, self, 8000, 55000)
		if result := clientFilter.RunIn(&unsolicited, 0); result != filter.Drop {
			t.Fatal("shared source can initiate traffic into recipient")
		}
		outgoing := shareUDP(self, remote, 55000, 8000)
		if result, _ := clientFilter.RunOut(&outgoing, 0); result != filter.Accept {
			t.Fatal("recipient cannot initiate")
		}
		if result := clientFilter.RunIn(&unsolicited, 0); result != filter.Accept {
			t.Fatal("quarantine blocks a stateful reply")
		}
	}
	remotePeer := fixture.acme.sharePeersFor(fixture.y).nodes[0]
	sourceFilter := filterForShareTest(t, fixture.y, fixture.acme.packetFilterFor(fixture.y))
	request := shareUDP(remotePeer.IPv4, fixture.y.IPv4, 55000, 8000)
	if sourceFilter.RunIn(&request, 0) != filter.Accept {
		t.Fatal("source denies valid sharee under default policy")
	}
}

func TestMutualSharesDeduplicateAndAuthorizeBothDirections(t *testing.T) {
	fixture := newShareFixture(t)
	user, ok := fixture.acme.identity.GetUser(state.DefaultUserID)
	if !ok {
		t.Fatal("fixture owner missing")
	}
	if err := fixture.acme.identity.LinkExternalIdentity(&identity.ExternalIdentity{ProviderID: "oidc:reverse", Subject: "reverse-owner", UserID: user.ID}); err != nil {
		t.Fatal(err)
	}
	share, err := fixture.globex.createShare(t.Context(), shareTestPrincipal(fixture.user, identity.RoleAdmin), fixture.x.StableID, "acme", "oidc:reverse", "reverse-owner")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.acme.acceptShare(t.Context(), shareTestPrincipal(user.ID, identity.RoleOwner), share.ID); err != nil {
		t.Fatal(err)
	}
	peers := fixture.globex.sharePeersFor(fixture.x)
	if peers == nil || len(peers.nodes) != 1 || !peers.nodes[0].Hostinfo.ShareeNode {
		t.Fatal("mutual sharing duplicates peer IDs or loses reverse authorization")
	}
	clientFilter := filterForShareTest(t, fixture.x, fixture.globex.packetFilterFor(fixture.x))
	request := shareUDP(peers.nodes[0].IPv4, fixture.x.IPv4, 55000, 8000)
	if clientFilter.RunIn(&request, 0) != filter.Accept {
		t.Fatal("mutual sharing still quarantined")
	}
}

func TestShareQuarantineNeverWidensPolicy(t *testing.T) {
	peer := state.Node{StableID: "share:remote:node", IPv4: netip.MustParseAddr("100.127.0.1")}
	local := state.Node{StableID: "local", IPv4: netip.MustParseAddr("100.100.0.1")}
	rules := []tailcfg.FilterRule{{SrcIPs: []string{"100.0.0.0/8"}, DstPorts: []tailcfg.NetPortRange{{IP: "100.100.0.1", Ports: tailcfg.PortRange{First: 22, Last: 22}}}, IPProto: []int{6}}}
	narrowed := restrictShareFilter(rules, []state.Node{local, peer})
	if len(narrowed) != 1 || narrowed[0].DstPorts[0].Ports.Last != 22 || narrowed[0].IPProto[0] != 6 {
		t.Fatal("quarantine widens port or protocol")
	}
	for _, rule := range narrowed {
		for _, raw := range rule.SrcIPs {
			if netip.MustParsePrefix(raw).Contains(peer.IPv4) {
				t.Fatal("quarantine retains blocked source")
			}
		}
	}
	if len(rules[0].SrcIPs) != 1 || rules[0].SrcIPs[0] != "100.0.0.0/8" {
		t.Fatal("shared engine snapshot mutated")
	}
}
