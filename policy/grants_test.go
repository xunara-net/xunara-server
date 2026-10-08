package policy

import (
	"encoding/json"
	"net/netip"
	"testing"

	"tailscale.com/tailcfg"

	"github.com/xunara-net/xunara-server/state"
)

func TestGrantIPRules(t *testing.T) {
	engine := mustEngine(t, `{
		"tagOwners": {"tag:server": ["local"]},
		"grants": [{
			"src": ["100.64.0.2/32"],
			"dst": ["tag:server"],
			"ip": ["tcp:443", "udp:6000-6100"],
		}],
	}`)

	server := testNode(1, "server", "100.64.0.1")
	server.Tags = []string{"tag:server"}
	client := testNode(2, "client", "100.64.0.2")
	nodes := []state.Node{server, client}

	filter := engine.FilterFor(server, nodes)
	if len(filter) != 2 {
		t.Fatalf("filter = %+v, want one rule per ip entry", filter)
	}

	tcp := filter[0]
	if !slices_EqualInts(tcp.IPProto, []int{6}) {
		t.Errorf("tcp rule IPProto = %v, want [6]", tcp.IPProto)
	}
	if len(tcp.DstPorts) != 2 || tcp.DstPorts[0].IP != "100.64.0.1/32" ||
		tcp.DstPorts[1].IP != "fd7a:115c:a1e0::1/128" ||
		tcp.DstPorts[0].Ports.First != 443 || tcp.DstPorts[0].Ports.Last != 443 {
		t.Errorf("tcp rule DstPorts = %+v, want the tagged server on 443", tcp.DstPorts)
	}
	if len(tcp.SrcIPs) != 1 || tcp.SrcIPs[0] != "100.64.0.2/32" {
		t.Errorf("tcp rule SrcIPs = %v, want the client only", tcp.SrcIPs)
	}

	udp := filter[1]
	if !slices_EqualInts(udp.IPProto, []int{17}) {
		t.Errorf("udp rule IPProto = %v, want [17]", udp.IPProto)
	}
	if len(udp.DstPorts) != 2 || udp.DstPorts[0].Ports.First != 6000 || udp.DstPorts[0].Ports.Last != 6100 {
		t.Errorf("udp rule DstPorts = %+v, want 6000-6100", udp.DstPorts)
	}
}

func TestGrantAppCapGrant(t *testing.T) {
	engine := mustEngine(t, `{
		"grants": [{
			"src": ["*"],
			"dst": ["100.64.0.1/32"],
			"app": {"tailscale.com/cap/kubernetes": [{"impersonate": "group:dev"}]},
		}],
	}`)

	one := testNode(1, "one", "100.64.0.1")
	two := testNode(2, "two", "100.64.0.2")
	nodes := []state.Node{one, two}

	filter := engine.FilterFor(one, nodes)
	if len(filter) != 1 {
		t.Fatalf("filter = %+v, want one cap grant rule", filter)
	}
	rule := filter[0]
	if len(rule.DstPorts) != 0 {
		t.Errorf("cap grant rule DstPorts = %+v, want none", rule.DstPorts)
	}
	if len(rule.CapGrant) != 1 {
		t.Fatalf("CapGrant = %+v, want one entry", rule.CapGrant)
	}
	grant := rule.CapGrant[0]
	if len(grant.Dsts) != 1 || grant.Dsts[0] != netip.MustParsePrefix("100.64.0.1/32") {
		t.Errorf("CapGrant.Dsts = %v, want the destination prefix", grant.Dsts)
	}
	values, ok := grant.CapMap[tailcfg.PeerCapability("tailscale.com/cap/kubernetes")]
	if !ok || len(values) != 1 {
		t.Fatalf("CapMap = %+v, want the kubernetes capability", grant.CapMap)
	}
	var decoded map[string]string
	if err := json.Unmarshal([]byte(values[0]), &decoded); err != nil {
		t.Fatalf("cap value is not valid JSON: %v", err)
	}
	if decoded["impersonate"] != "group:dev" {
		t.Errorf("cap value = %v, want the document's value preserved", decoded)
	}
}

func TestGrantCompanionCaps(t *testing.T) {
	engine := mustEngine(t, `{
		"grants": [{
			"src": ["100.64.0.2/32"],
			"dst": ["100.64.0.1/32"],
			"app": {"tailscale.com/cap/drive": [{"name": "docs"}]},
		}],
	}`)

	one := testNode(1, "one", "100.64.0.1")
	two := testNode(2, "two", "100.64.0.2")
	nodes := []state.Node{one, two}

	filter := engine.FilterFor(one, nodes)
	if len(filter) != 2 {
		t.Fatalf("filter = %+v, want the cap grant and its companion", filter)
	}

	companion := filter[1]
	if len(companion.SrcIPs) != 1 || companion.SrcIPs[0] != "100.64.0.1/32" {
		t.Errorf("companion SrcIPs = %v, want the original destination", companion.SrcIPs)
	}
	if len(companion.CapGrant) != 1 ||
		companion.CapGrant[0].Dsts[0] != netip.MustParsePrefix("100.64.0.2/32") {
		t.Errorf("companion CapGrant = %+v, want the reversed destination", companion.CapGrant)
	}
	if _, ok := companion.CapGrant[0].CapMap[tailcfg.PeerCapability("tailscale.com/cap/drive-sharer")]; !ok {
		t.Errorf("companion CapMap = %+v, want the drive-sharer capability",
			companion.CapGrant[0].CapMap)
	}
}

func TestGrantSelfDestinationIsPerNode(t *testing.T) {
	engine := mustEngine(t, `{
		"grants": [{"src": ["100.64.0.2/32"], "dst": ["autogroup:self"], "ip": ["tcp:22"]}],
	}`)

	me := testNode(1, "me", "100.64.0.1")
	other := testNode(2, "other", "100.64.0.2")
	other.UserID = 2
	nodes := []state.Node{me, other}

	filter := engine.FilterFor(me, nodes)
	if len(filter) != 1 {
		t.Fatalf("filter = %+v, want one rule", filter)
	}
	if len(filter[0].DstPorts) != 2 || filter[0].DstPorts[0].IP != "100.64.0.1/32" ||
		filter[0].DstPorts[1].IP != "fd7a:115c:a1e0::1/128" ||
		filter[0].DstPorts[0].Ports.First != 22 {
		t.Errorf("DstPorts = %+v, want this node on 22", filter[0].DstPorts)
	}
	if len(filter[0].SrcIPs) != 1 || filter[0].SrcIPs[0] != "100.64.0.2/32" {
		t.Errorf("SrcIPs = %v, want the other node", filter[0].SrcIPs)
	}
}

func TestGrantWildcardSupportsMixedFamilies(t *testing.T) {
	engine := mustEngine(t, `{
		"grants": [{"src": ["*"], "dst": ["*"], "app": {"example.com/cap/x": []}}],
	}`)
	one := testNode(1, "one", "100.64.0.1")
	nodes := []state.Node{one}

	filter := engine.FilterFor(one, nodes)
	if len(filter) != 1 || len(filter[0].CapGrant) != 1 {
		t.Fatalf("filter = %+v, want the wildcard cap grant", filter)
	}
	dsts := filter[0].CapGrant[0].Dsts
	if len(dsts) != 2 || dsts[0] != netip.MustParsePrefix("100.64.0.0/10") ||
		dsts[1] != netip.MustParsePrefix("fd7a:115c:a1e0::/48") {
		t.Errorf("wildcard CapGrant.Dsts = %v, want the tailnet ranges", dsts)
	}
}

func TestGrantCountsAndValidation(t *testing.T) {
	engine := mustEngine(t, `{
		"grants": [{"src": ["*"], "dst": ["*"], "ip": ["*:*"]}],
	}`)
	if engine.RuleCount() != 1 || !engine.HasRules() {
		t.Errorf("RuleCount = %d, HasRules = %v; want the grant counted",
			engine.RuleCount(), engine.HasRules())
	}

	cases := map[string]string{
		"no ip or app":  `{"grants": [{"src": ["*"], "dst": ["*"]}]}`,
		"missing src":   `{"grants": [{"dst": ["*"], "ip": ["tcp:22"]}]}`,
		"missing dst":   `{"grants": [{"src": ["*"], "ip": ["tcp:22"]}]}`,
		"via":           `{"grants": [{"src": ["*"], "dst": ["*"], "ip": ["tcp:22"], "via": ["tag:router"]}]}`,
		"bad ip proto":  `{"grants": [{"src": ["*"], "dst": ["*"], "ip": ["bogus:22"]}]}`,
		"bad ip port":   `{"grants": [{"src": ["*"], "dst": ["*"], "ip": ["tcp:notaport"]}]}`,
		"bad app name":  `{"grants": [{"src": ["*"], "dst": ["*"], "app": {"bad cap": []}}]}`,
		"unknown alias": `{"grants": [{"src": ["group:nope"], "dst": ["*"], "ip": ["tcp:22"]}]}`,
	}
	for name, doc := range cases {
		t.Run(name, func(t *testing.T) {
			parsed, err := ParseString(doc)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if _, err := NewEngine(parsed, Options{Domain: "xunara.test"}); err == nil {
				t.Fatalf("NewEngine(%s) succeeded, want error", name)
			}
		})
	}
}

func TestGrantPortOnlyEntryUsesDefaultProtos(t *testing.T) {
	engine := mustEngine(t, `{
		"grants": [{"src": ["*"], "dst": ["100.64.0.1/32"], "ip": ["443"]}],
	}`)
	one := testNode(1, "one", "100.64.0.1")
	filter := engine.FilterFor(one, []state.Node{one})
	if len(filter) != 1 {
		t.Fatalf("filter = %+v, want one rule", filter)
	}
	if len(filter[0].IPProto) != 0 {
		t.Errorf("IPProto = %v, want none (all default protocols)", filter[0].IPProto)
	}
	if filter[0].DstPorts[0].Ports.First != 443 {
		t.Errorf("DstPorts = %+v, want port 443", filter[0].DstPorts)
	}
}

// slices_EqualInts compares small int slices.
func slices_EqualInts(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
