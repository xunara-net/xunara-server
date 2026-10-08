package policy

import (
	"strings"
	"testing"

	"tailscale.com/tailcfg"

	"github.com/xunara-net/xunara-server/state"
)

// capsOf returns one node's capability map from a fresh compile.
func capsOf(engine *Engine, nodes []state.Node, id state.NodeID) tailcfg.NodeCapMap {
	return engine.NodeCapMaps(nodes)[id]
}

func TestNodeAttrsGrantsToTag(t *testing.T) {
	engine := mustEngine(t, `{
		"tagOwners": {"tag:server": ["local"]},
		"nodeAttrs": [{"target": ["tag:server"], "attr": ["https"]}],
		"acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}],
	}`)

	server := testNode(1, "server", "100.64.0.1")
	server.Tags = []string{"tag:server"}
	client := testNode(2, "client", "100.64.0.2")
	nodes := []state.Node{server, client}

	got := capsOf(engine, nodes, server.ID)
	if len(got) != 1 {
		t.Fatalf("server caps = %v, want {https: nil}", got)
	}
	if v, ok := got[tailcfg.CapabilityHTTPS]; !ok || v != nil {
		t.Errorf("server cap https = %v (present %v), want nil", v, ok)
	}
	if got := capsOf(engine, nodes, client.ID); got != nil {
		t.Errorf("client caps = %v, want none", got)
	}
}

func TestNodeAttrsGrantsToUserAndGroup(t *testing.T) {
	engine := mustEngineOpts(t, `{
		"groups": {"group:dev": ["alice"]},
		"nodeAttrs": [
			{"target": ["alice"], "attr": ["https"]},
			{"target": ["group:dev"], "attr": ["https://tailscale.com/cap/file-sharing"]},
		],
	}`, logins(map[tailcfg.UserID]string{1: "alice", 2: "bob"}))

	alice := testNode(1, "alice-laptop", "100.64.0.1")
	bob := testNode(2, "bob-laptop", "100.64.0.2")
	bob.UserID = 2
	nodes := []state.Node{alice, bob}

	got := capsOf(engine, nodes, alice.ID)
	if len(got) != 2 {
		t.Fatalf("alice caps = %v, want https and file-sharing", got)
	}
	if _, ok := got[tailcfg.CapabilityHTTPS]; !ok {
		t.Errorf("alice caps = %v, want https", got)
	}
	if _, ok := got[tailcfg.CapabilityFileSharing]; !ok {
		t.Errorf("alice caps = %v, want %s", got, tailcfg.CapabilityFileSharing)
	}
	if got := capsOf(engine, nodes, bob.ID); got != nil {
		t.Errorf("bob caps = %v, want none", got)
	}
}

func TestNodeAttrsAutogroupSelectors(t *testing.T) {
	engine := mustEngine(t, `{
		"tagOwners": {"tag:server": ["local"]},
		"nodeAttrs": [
			{"target": ["autogroup:tagged"], "attr": ["https"]},
			{"target": ["autogroup:member"], "attr": ["https://tailscale.com/cap/file-sharing"]},
			{"target": ["*"], "attr": ["https://tailscale.com/cap/example"]},
		],
	}`)

	server := testNode(1, "server", "100.64.0.1")
	server.Tags = []string{"tag:server"}
	client := testNode(2, "client", "100.64.0.2")
	nodes := []state.Node{server, client}

	// A tagged device is not a member: it receives the autogroup:tagged and
	// wildcard grants, but not the autogroup:member one.
	got := capsOf(engine, nodes, server.ID)
	if len(got) != 2 {
		t.Errorf("server caps = %v, want https (tagged) plus the wildcard grant", got)
	}
	if _, ok := got[tailcfg.CapabilityHTTPS]; !ok {
		t.Errorf("server caps = %v, want https from autogroup:tagged", got)
	}
	if _, ok := got[tailcfg.CapabilityFileSharing]; ok {
		t.Errorf("server caps = %v, want no autogroup:member grant on a tagged node", got)
	}

	// The untagged device is a member, but not tagged.
	got = capsOf(engine, nodes, client.ID)
	if len(got) != 2 {
		t.Errorf("client caps = %v, want member+wildcard grants", got)
	}
	if _, ok := got[tailcfg.CapabilityFileSharing]; !ok {
		t.Errorf("client caps = %v, want the member grant", got)
	}
	if _, ok := got[tailcfg.CapabilityHTTPS]; ok {
		t.Errorf("client caps = %v, want no https (untagged)", got)
	}
}

func TestNodeAttrsPrefixTarget(t *testing.T) {
	engine := mustEngine(t, `{
		"nodeAttrs": [{"target": ["100.64.0.2/32"], "attr": ["https"]}],
	}`)

	one := testNode(1, "one", "100.64.0.1")
	two := testNode(2, "two", "100.64.0.2")
	nodes := []state.Node{one, two}

	if got := capsOf(engine, nodes, one.ID); got != nil {
		t.Errorf("one caps = %v, want none", got)
	}
	if got := capsOf(engine, nodes, two.ID); len(got) != 1 {
		t.Errorf("two caps = %v, want https", got)
	}
}

func TestNodeAttrsRowsMerge(t *testing.T) {
	engine := mustEngine(t, `{
		"nodeAttrs": [
			{"target": ["*"], "attr": ["https"]},
			{"target": ["*"], "attr": ["https", "https://tailscale.com/cap/file-sharing"]},
		],
	}`)

	one := testNode(1, "one", "100.64.0.1")
	got := capsOf(engine, []state.Node{one}, one.ID)
	if len(got) != 2 {
		t.Fatalf("caps = %v, want the union of both rows", got)
	}
	if _, ok := got[tailcfg.CapabilityHTTPS]; !ok {
		t.Errorf("caps = %v, want https", got)
	}
	if _, ok := got[tailcfg.CapabilityFileSharing]; !ok {
		t.Errorf("caps = %v, want %s", got, tailcfg.CapabilityFileSharing)
	}
}

func TestNodeAttrsNoSection(t *testing.T) {
	engine := mustEngine(t, `{"acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}]}`)
	one := testNode(1, "one", "100.64.0.1")
	if got := engine.NodeCapMaps([]state.Node{one}); got != nil {
		t.Errorf("NodeCapMaps = %v, want nil without nodeAttrs", got)
	}
}

func TestNodeAttrsRejectsInvalidRows(t *testing.T) {
	cases := map[string]string{
		"empty target":      `{"nodeAttrs": [{"target": [], "attr": ["https"]}]}`,
		"self target":       `{"nodeAttrs": [{"target": ["autogroup:self"], "attr": ["https"]}]}`,
		"internet target":   `{"nodeAttrs": [{"target": ["autogroup:internet"], "attr": ["https"]}]}`,
		"unknown autogroup": `{"nodeAttrs": [{"target": ["autogroup:nope"], "attr": ["https"]}]}`,
		"funnel attr":       `{"nodeAttrs": [{"target": ["*"], "attr": ["funnel"]}]}`,
		"empty attr":        `{"nodeAttrs": [{"target": ["*"], "attr": [""]}]}`,
		"attr with space":   `{"nodeAttrs": [{"target": ["*"], "attr": ["http s"]}]}`,
		"oversize attr":     `{"nodeAttrs": [{"target": ["*"], "attr": ["` + strings.Repeat("x", maxAttrLength+1) + `"]}]}`,
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

func TestAutogroupTaggedACLAndSSH(t *testing.T) {
	engine := mustEngine(t, `{
		"tagOwners": {"tag:server": ["local"]},
		"acls": [{"action": "accept", "src": ["autogroup:tagged"], "dst": ["*:*"]}],
		"ssh": [{"action": "accept", "src": ["autogroup:member"], "dst": ["autogroup:tagged"], "users": ["root"]}],
	}`)

	server := testNode(1, "server", "100.64.0.1")
	server.Tags = []string{"tag:server"}
	client := testNode(2, "client", "100.64.0.2")
	nodes := []state.Node{server, client}

	filter := engine.FilterFor(client, nodes)
	if len(filter) != 1 {
		t.Fatalf("filter = %+v, want one rule", filter)
	}
	if len(filter[0].SrcIPs) == 0 || filter[0].SrcIPs[0] != server.IPv4.String()+"/32" {
		t.Errorf("SrcIPs = %v, want the tagged server's address", filter[0].SrcIPs)
	}

	if pol := engine.CompileSSHPolicy(server, nodes); pol == nil || len(pol.Rules) != 1 {
		t.Errorf("tagged server should be an SSH destination, got %+v", pol)
	}
	if pol := engine.CompileSSHPolicy(client, nodes); pol != nil {
		t.Errorf("untagged client must not be an SSH destination, got %+v", pol)
	}
}
