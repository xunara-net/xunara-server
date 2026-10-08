package policy

import (
	"slices"
	"testing"

	"tailscale.com/tailcfg"

	"github.com/xunara-net/xunara-server/state"
)

// TestRelayGrantCompilesToCapGrant pins the wire convention the relay
// management plane reports: an "app" entry for tailscale.com/cap/relay turns a
// grant row into a relay authorization, and the relay node receives the
// reversed relay-target companion cap.
func TestRelayGrantCompilesToCapGrant(t *testing.T) {
	engine := mustEngine(t, `{
		"grants": [{
			"src": ["100.64.0.2/32"],
			"dst": ["100.64.0.1/32"],
			"app": {"tailscale.com/cap/relay": []},
		}],
	}`)

	relay := testNode(1, "relay", "100.64.0.1")
	client := testNode(2, "client", "100.64.0.2")
	nodes := []state.Node{relay, client}

	rules := engine.FilterFor(client, nodes)
	if len(rules) != 2 {
		t.Fatalf("rules = %+v, want the cap grant and its companion", rules)
	}

	grant := rules[0]
	if len(grant.SrcIPs) != 1 || grant.SrcIPs[0] != "100.64.0.2/32" {
		t.Errorf("SrcIPs = %v, want the client", grant.SrcIPs)
	}
	if len(grant.CapGrant) != 1 {
		t.Fatalf("CapGrant = %+v, want one entry", grant.CapGrant)
	}
	if len(grant.CapGrant[0].Dsts) == 0 || grant.CapGrant[0].Dsts[0].String() != "100.64.0.1/32" {
		t.Errorf("CapGrant.Dsts = %v, want the relay node", grant.CapGrant[0].Dsts)
	}
	if _, ok := grant.CapGrant[0].CapMap[tailcfg.PeerCapabilityRelay]; !ok {
		t.Errorf("CapMap = %+v, want the relay capability", grant.CapGrant[0].CapMap)
	}

	companion := rules[1]
	if len(companion.SrcIPs) != 1 || companion.SrcIPs[0] != "100.64.0.1/32" {
		t.Errorf("companion SrcIPs = %v, want the relay node", companion.SrcIPs)
	}
	if len(companion.CapGrant) != 1 {
		t.Fatalf("companion CapGrant = %+v, want one entry", companion.CapGrant)
	}
	if _, ok := companion.CapGrant[0].CapMap[tailcfg.PeerCapabilityRelayTarget]; !ok {
		t.Errorf("companion CapMap = %+v, want the relay-target capability", companion.CapGrant[0].CapMap)
	}

	// Clients only apply rules whose SrcIPs name them, so the rule the relay
	// node matches is the companion (relay-target), never the allocation
	// direction.
	for _, rule := range engine.FilterFor(relay, nodes) {
		if !slices.Contains(rule.SrcIPs, "100.64.0.1/32") {
			continue
		}
		if len(rule.CapGrant) != 1 {
			t.Fatalf("relay rule CapGrant = %+v, want one entry", rule.CapGrant)
		}
		if _, ok := rule.CapGrant[0].CapMap[tailcfg.PeerCapabilityRelayTarget]; !ok {
			t.Errorf("relay CapMap = %+v, want relay-target", rule.CapGrant[0].CapMap)
		}
		if _, ok := rule.CapGrant[0].CapMap[tailcfg.PeerCapabilityRelay]; ok {
			t.Errorf("relay CapMap = %+v, want no allocation capability", rule.CapGrant[0].CapMap)
		}
	}
}

// TestRelayGrantsResolveToNodes checks the management-plane resolver: only
// relay rows are reported, selectors become node IDs, and empty relations are
// dropped.
func TestRelayGrantsResolveToNodes(t *testing.T) {
	engine := mustEngine(t, `{
		"tagOwners": {"tag:relay": ["local"], "tag:client": ["local"], "tag:missing": ["local"]},
		"grants": [
			{"src": ["tag:client"], "dst": ["tag:relay"], "app": {"tailscale.com/cap/relay": []}},
			{"src": ["tag:client"], "dst": ["tag:relay"], "app": {"example.com/cap/other": []}},
			{"src": ["tag:client"], "dst": ["tag:missing"], "app": {"tailscale.com/cap/relay": []}},
		],
	}`)

	relay := testNode(1, "relay", "100.64.0.1")
	relay.Tags = []string{"tag:relay"}
	client := testNode(2, "client", "100.64.0.2")
	client.Tags = []string{"tag:client"}
	plain := testNode(3, "plain", "100.64.0.3")

	grants := engine.RelayGrants([]state.Node{relay, client, plain})
	if len(grants) != 1 {
		t.Fatalf("grants = %+v, want only the relay row", grants)
	}
	if !slices.Equal(grants[0].Sources, []state.NodeID{client.ID}) {
		t.Errorf("sources = %v, want [%d]", grants[0].Sources, client.ID)
	}
	if !slices.Equal(grants[0].Targets, []state.NodeID{relay.ID}) {
		t.Errorf("targets = %v, want [%d]", grants[0].Targets, relay.ID)
	}
}

// TestRelayGrantsSelfOnlyArePerSourceUser checks autogroup:self relay grants:
// each source may use its own user's devices, never another user's.
func TestRelayGrantsSelfOnlyArePerSourceUser(t *testing.T) {
	engine := mustEngine(t, `{
		"grants": [{
			"src": ["autogroup:member"],
			"dst": ["autogroup:self"],
			"app": {"tailscale.com/cap/relay": []},
		}],
	}`)

	aliceA := testNode(1, "alice-a", "100.64.0.1")
	aliceA.UserID = 10
	aliceB := testNode(2, "alice-b", "100.64.0.2")
	aliceB.UserID = 10
	bob := testNode(3, "bob", "100.64.0.3")
	bob.UserID = 11
	tagged := testNode(4, "tagged", "100.64.0.4")
	tagged.UserID = 10
	tagged.Tags = []string{"tag:x"}

	grants := engine.RelayGrants([]state.Node{aliceA, aliceB, bob, tagged})
	if len(grants) != 3 {
		t.Fatalf("grants = %+v, want one row per untagged source", grants)
	}
	if !slices.Equal(grants[0].Sources, []state.NodeID{1}) || !slices.Equal(grants[0].Targets, []state.NodeID{1, 2}) {
		t.Errorf("alice-a grant = %+v, want {[1] [1 2]}", grants[0])
	}
	if !slices.Equal(grants[1].Sources, []state.NodeID{2}) || !slices.Equal(grants[1].Targets, []state.NodeID{1, 2}) {
		t.Errorf("alice-b grant = %+v, want {[2] [1 2]}", grants[1])
	}
	if !slices.Equal(grants[2].Sources, []state.NodeID{3}) || !slices.Equal(grants[2].Targets, []state.NodeID{3}) {
		t.Errorf("bob grant = %+v, want {[3] [3]}", grants[2])
	}
}

// TestRelayGrantsWithoutPolicy checks a document without relay rows reports
// nothing.
func TestRelayGrantsWithoutPolicy(t *testing.T) {
	engine := mustEngine(t, `{"acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}]}`)
	if grants := engine.RelayGrants([]state.Node{testNode(1, "a", "100.64.0.1")}); len(grants) != 0 {
		t.Errorf("grants = %+v, want none", grants)
	}
}
