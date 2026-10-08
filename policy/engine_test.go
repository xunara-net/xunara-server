package policy

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"

	"tailscale.com/tailcfg"

	"github.com/xunara-net/xunara-server/state"
)

func testNode(id state.NodeID, hostname string, addr string) state.Node {
	return state.Node{
		ID:       id,
		StableID: fmt.Sprintf("n%d", id),
		Hostname: hostname,
		UserID:   state.DefaultUserID,
		IPv4:     netip.MustParseAddr(addr),
		IPv6:     netip.MustParseAddr(fmt.Sprintf("fd7a:115c:a1e0::%d", id)),
	}
}

func mustEngine(t *testing.T, doc string) *Engine {
	t.Helper()
	return mustEngineOpts(t, doc, Options{Domain: "xunara.test"})
}

func mustEngineOpts(t *testing.T, doc string, opts Options) *Engine {
	t.Helper()

	parsed, err := ParseString(doc)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	engine, err := NewEngine(parsed, opts)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	return engine
}

// logins returns an Options.LoginName that maps each user to a name, so tests
// can describe multi-user tailnets the single-user default cannot.
func logins(byID map[tailcfg.UserID]string) Options {
	return Options{
		Domain:    "xunara.test",
		LoginName: func(id tailcfg.UserID) string { return byID[id] },
	}
}

func TestParseHuJSON(t *testing.T) {
	doc, err := ParseString(`{
		// comments and trailing commas are allowed
		"acls": [
			{"action": "accept", "src": ["*"], "dst": ["*:*"]},
		],
		"ssh": [{"action": "accept", "src": ["*"], "dst": ["*"], "users": ["root"]}],
		"grants": [{"src": ["*"], "dst": ["*"], "app": {"example.com/cap/x": []}}],
		"autoApprovers": {"routes": {"10.0.0.0/8": ["tag:router"]}},
	}`)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(doc.ACLs) != 1 {
		t.Fatalf("acls = %d, want 1", len(doc.ACLs))
	}
	if len(doc.SSH) != 1 || doc.SSH[0].Action != "accept" {
		t.Errorf("SSH = %+v, want one accept rule", doc.SSH)
	}
	if len(doc.Grants) != 1 || doc.Grants[0].Src[0] != "*" {
		t.Errorf("Grants = %+v, want the parsed grant row", doc.Grants)
	}
	if len(doc.Unsupported) != 1 || doc.Unsupported[0] != "autoApprovers" {
		t.Errorf("Unsupported = %v, want [autoApprovers]", doc.Unsupported)
	}
}

func TestAllowAllPolicy(t *testing.T) {
	engine := mustEngine(t, `{"acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}]}`)

	nodes := []state.Node{testNode(1, "one", "100.64.0.1"), testNode(2, "two", "100.64.0.2")}
	filter := engine.FilterFor(nodes[0], nodes)

	if len(filter) != 1 {
		t.Fatalf("filter = %+v, want one rule", filter)
	}
	if filter[0].SrcIPs[0] != "*" {
		t.Errorf("SrcIPs = %v, want [*]", filter[0].SrcIPs)
	}
	if filter[0].DstPorts[0].IP != "*" || filter[0].DstPorts[0].Ports != tailcfg.PortRangeAny {
		t.Errorf("DstPorts = %+v, want *:*", filter[0].DstPorts)
	}
	if len(engine.Warnings()) != 0 {
		t.Errorf("warnings = %v, want none", engine.Warnings())
	}
}

func TestEmptyPolicyDeniesEverything(t *testing.T) {
	engine := mustEngine(t, `{}`)
	if engine.HasRules() {
		t.Fatal("an empty policy must not grant anything")
	}
	if got := engine.FilterFor(state.Node{}, nil); len(got) != 0 {
		t.Errorf("filter = %+v, want no rules", got)
	}
}

func TestGroupSelectors(t *testing.T) {
	engine := mustEngineOpts(t, `{
		"groups": {
			"group:dev": ["alice"],
			"group:all": ["group:dev"],
		},
		"acls": [{"action": "accept", "src": ["group:all"], "dst": ["100.64.0.2:443"]}],
	}`, logins(map[tailcfg.UserID]string{1: "alice", 2: "bob"}))

	one := testNode(1, "one", "100.64.0.1")
	two := testNode(2, "two", "100.64.0.2")
	two.UserID = 2
	nodes := []state.Node{one, two}
	filter := engine.FilterFor(one, nodes)

	if len(filter) != 1 {
		t.Fatalf("filter = %+v, want one rule", filter)
	}
	want := []string{"100.64.0.1/32", "fd7a:115c:a1e0::1/128"}
	if strings.Join(filter[0].SrcIPs, ",") != strings.Join(want, ",") {
		t.Errorf("SrcIPs = %v, want %v", filter[0].SrcIPs, want)
	}
	if filter[0].DstPorts[0].IP != "100.64.0.2/32" {
		t.Errorf("DstPorts = %+v, want the destination prefix", filter[0].DstPorts)
	}
	if p := filter[0].DstPorts[0].Ports; p.First != 443 || p.Last != 443 {
		t.Errorf("ports = %+v, want 443", p)
	}
}

func TestEmailUserSelectorMatchesLoginName(t *testing.T) {
	engine := mustEngine(t, `{"acls": [{"action": "accept", "src": ["local@xunara.test"], "dst": ["*:*"]}]}`)

	nodes := []state.Node{testNode(1, "one", "100.64.0.1")}
	filter := engine.FilterFor(nodes[0], nodes)
	if len(filter) != 1 || filter[0].SrcIPs[0] != "100.64.0.1/32" {
		t.Fatalf("filter = %+v, want the local user's address", filter)
	}
}

func TestAutogroupMemberExcludesTagged(t *testing.T) {
	engine := mustEngine(t, `{
		"tagOwners": {"tag:server": ["local"]},
		"acls": [
			{"action": "accept", "src": ["autogroup:member"], "dst": ["*:*"]},
			{"action": "accept", "src": ["autogroup:tagged"], "dst": ["100.64.0.9:443"]},
		],
	}`)

	tagged := testNode(1, "tagged", "100.64.0.1")
	tagged.Tags = []string{"tag:server"}
	plain := testNode(2, "plain", "100.64.0.2")
	nodes := []state.Node{tagged, plain}

	filter := engine.FilterFor(plain, nodes)
	if len(filter) != 2 {
		t.Fatalf("filter = %+v, want both rules", filter)
	}
	memberSrc := strings.Join(filter[0].SrcIPs, ",")
	if memberSrc != "100.64.0.2/32,fd7a:115c:a1e0::2/128" {
		t.Errorf("member SrcIPs = %v, want the untagged device only", filter[0].SrcIPs)
	}
	taggedSrc := strings.Join(filter[1].SrcIPs, ",")
	if taggedSrc != "100.64.0.1/32,fd7a:115c:a1e0::1/128" {
		t.Errorf("tagged SrcIPs = %v, want the tagged device only", filter[1].SrcIPs)
	}
}

func TestAutogroupSelfIsPerNode(t *testing.T) {
	engine := mustEngine(t, `{"acls": [{"action": "accept", "src": ["autogroup:self"], "dst": ["*:*"]}]}`)

	me := testNode(1, "me", "100.64.0.1")
	other := testNode(2, "other", "100.64.0.2")
	other.UserID = 99
	nodes := []state.Node{me, other}

	filter := engine.FilterFor(me, nodes)
	if len(filter) != 1 {
		t.Fatalf("filter = %+v, want one rule", filter)
	}
	if strings.Join(filter[0].SrcIPs, ",") != "100.64.0.1/32,fd7a:115c:a1e0::1/128" {
		t.Errorf("SrcIPs = %v, want only the same user's node", filter[0].SrcIPs)
	}
}

func TestAutogroupSelfExcludesTagged(t *testing.T) {
	engine := mustEngine(t, `{
		"tagOwners": {"tag:server": ["local"]},
		"acls": [{"action": "accept", "src": ["autogroup:self"], "dst": ["*:*"]}],
	}`)

	tagged := testNode(1, "tagged", "100.64.0.1")
	tagged.Tags = []string{"tag:server"}
	plain := testNode(2, "plain", "100.64.0.2")
	nodes := []state.Node{tagged, plain}

	// The untagged node's autogroup:self resolves to its own untagged devices.
	filter := engine.FilterFor(plain, nodes)
	if len(filter) != 1 {
		t.Fatalf("filter = %+v, want one rule", filter)
	}
	if got := strings.Join(filter[0].SrcIPs, ","); got != "100.64.0.2/32,fd7a:115c:a1e0::2/128" {
		t.Errorf("SrcIPs = %v, want the untagged device only", filter[0].SrcIPs)
	}

	// A tagged node has no user identity, so autogroup:self matches nothing
	// for it (either as a source or as a destination).
	if filter := engine.FilterFor(tagged, nodes); len(filter) != 0 {
		t.Errorf("filter = %+v, want no rules for a tagged source", filter)
	}
}

func TestUserSelectorExcludesTagged(t *testing.T) {
	engine := mustEngine(t, `{
		"tagOwners": {"tag:server": ["local"]},
		"acls": [{"action": "accept", "src": ["local@xunara.test"], "dst": ["*:*"]}],
	}`)

	tagged := testNode(1, "tagged", "100.64.0.1")
	tagged.Tags = []string{"tag:server"}
	plain := testNode(2, "plain", "100.64.0.2")
	nodes := []state.Node{tagged, plain}

	filter := engine.FilterFor(plain, nodes)
	if len(filter) != 1 {
		t.Fatalf("filter = %+v, want one rule", filter)
	}
	if got := strings.Join(filter[0].SrcIPs, ","); got != "100.64.0.2/32,fd7a:115c:a1e0::2/128" {
		t.Errorf("user selector SrcIPs = %v, want the untagged device only", filter[0].SrcIPs)
	}
}

func TestHostsAliasesAndPrefixes(t *testing.T) {
	engine := mustEngine(t, `{
		"hosts": {"db": "100.64.0.9", "lan": "192.168.0.0/16"},
		"acls": [{"action": "accept", "src": ["lan", "10.0.0.0/8"], "dst": ["db:5432,5433-5434"]}],
	}`)

	filter := engine.FilterFor(state.Node{}, nil)
	if len(filter) != 1 {
		t.Fatalf("filter = %+v, want one rule", filter)
	}
	if strings.Join(filter[0].SrcIPs, ",") != "10.0.0.0/8,192.168.0.0/16" {
		t.Errorf("SrcIPs = %v", filter[0].SrcIPs)
	}
	if len(filter[0].DstPorts) != 2 {
		t.Fatalf("DstPorts = %+v, want two port ranges", filter[0].DstPorts)
	}
	if got := filter[0].DstPorts[0].Ports; got.First != 5432 || got.Last != 5432 {
		t.Errorf("first range = %+v", got)
	}
	if got := filter[0].DstPorts[1].Ports; got.First != 5433 || got.Last != 5434 {
		t.Errorf("second range = %+v", got)
	}
}

func TestProtoAndIPv6Brackets(t *testing.T) {
	engine := mustEngine(t, `{
		"acls": [{"action": "accept", "proto": "tcp", "src": ["*"], "dst": ["[fd7a:115c:a1e0::1]:443"]}]
	}`)

	filter := engine.FilterFor(state.Node{}, nil)
	if len(filter) != 1 {
		t.Fatalf("filter = %+v, want one rule", filter)
	}
	if got := filter[0].IPProto; len(got) != 1 || got[0] != 6 {
		t.Errorf("IPProto = %v, want [6]", got)
	}
	if got := filter[0].DstPorts[0].IP; got != "fd7a:115c:a1e0::1/128" {
		t.Errorf("DstPorts IP = %q", got)
	}
}

func TestTagSelectorsWarnWithoutTags(t *testing.T) {
	engine := mustEngine(t, `{
		"tagOwners": {"tag:web": ["local"]},
		"acls": [{"action": "accept", "src": ["tag:web"], "dst": ["*:*"]}],
	}`)

	nodes := []state.Node{testNode(1, "one", "100.64.0.1")}
	filter := engine.FilterFor(nodes[0], nodes)
	if len(filter) != 0 {
		t.Errorf("filter = %+v, want no rules while no node carries the tag", filter)
	}
	if len(engine.Warnings()) == 0 {
		t.Error("expected a warning about a tag selector matching nothing")
	}
}

func TestPolicyValidationErrors(t *testing.T) {
	cases := map[string]string{
		"unknown group":      `{"acls": [{"action": "accept", "src": ["group:nope"], "dst": ["*:*"]}]}`,
		"unknown tag":        `{"acls": [{"action": "accept", "src": ["tag:nope"], "dst": ["*:*"]}]}`,
		"unsupported action": `{"acls": [{"action": "deny", "src": ["*"], "dst": ["*:*"]}]}`,
		"missing dst":        `{"acls": [{"action": "accept", "src": ["*"]}]}`,
		"missing port":       `{"acls": [{"action": "accept", "src": ["*"], "dst": ["100.64.0.1"]}]}`,
		"bad port":           `{"acls": [{"action": "accept", "src": ["*"], "dst": ["100.64.0.1:0"]}]}`,
		"bad prefix":         `{"hosts": {"x": "not-an-ip"}, "acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}]}`,
		"bad proto":          `{"acls": [{"action": "accept", "proto": "icmp9", "src": ["*"], "dst": ["*:*"]}]}`,
		"group cycle": `{
			"groups": {"group:a": ["group:b"], "group:b": ["group:a"]},
			"acls": [{"action": "accept", "src": ["group:a"], "dst": ["*:*"]}]
		}`,
		"autogroup in src": `{"acls": [{"action": "accept", "src": ["autogroup:internet"], "dst": ["*:*"]}]}`,
	}

	for name, doc := range cases {
		t.Run(name, func(t *testing.T) {
			parsed, err := ParseString(doc)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if _, err := NewEngine(parsed, Options{}); err == nil {
				t.Error("expected a validation error")
			}
		})
	}
}

func TestRunTests(t *testing.T) {
	opts := logins(map[tailcfg.UserID]string{1: "alice", 2: "bob"})
	engine := mustEngineOpts(t, `{
		"acls": [{"action": "accept", "src": ["alice"], "dst": ["100.64.0.2:443"]}],
		"tests": [
			{"src": "alice", "accept": ["100.64.0.2:443"], "deny": ["100.64.0.2:80"]},
		],
	}`, opts)

	one := testNode(1, "one", "100.64.0.1")
	two := testNode(2, "two", "100.64.0.2")
	two.UserID = 2
	nodes := []state.Node{one, two}

	results, err := engine.RunTests(nodes)
	if err != nil {
		t.Fatalf("RunTests: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("results = %d, want 1", len(results))
	}
	if !results[0].Pass() {
		t.Errorf("test failed: %v", results[0].Failures)
	}

	failing := mustEngineOpts(t, `{
		"acls": [{"action": "accept", "src": ["alice"], "dst": ["100.64.0.2:443"]}],
		"tests": [{"src": "alice", "accept": ["100.64.0.2:80"]}],
	}`, opts)
	results, err = failing.RunTests(nodes)
	if err != nil {
		t.Fatalf("RunTests: %v", err)
	}
	if results[0].Pass() {
		t.Error("expected the test to fail")
	}
}

// TestTagOwnership covers the tagOwners checks used when a client advertises
// tags: TagExists is the "is this tag defined at all" gate, UserOwnsTag the
// "may this user claim it" gate.
func TestTagOwnership(t *testing.T) {
	engine := mustEngine(t, `{
		"groups": {
			"group:ops": ["alice@example.com", "group:oncall"],
			"group:oncall": ["bob"],
		},
		"tagOwners": {
			"tag:server": ["alice@example.com"],
			"tag:prod": ["group:ops"],
			"tag:edge": ["tag:prod"],
		},
		"acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}],
	}`)

	if !engine.TagExists("tag:server") || engine.TagExists("tag:missing") {
		t.Errorf("TagExists = %v/%v, want true/false", engine.TagExists("tag:server"), engine.TagExists("tag:missing"))
	}

	owns := []struct {
		login string
		tag   string
		want  bool
	}{
		{"alice", "tag:server", true}, // listed directly, bare login vs email
		{"alice@example.com", "tag:server", true},
		{"bob", "tag:server", false}, // not an owner
		{"alice", "tag:prod", true},  // via group:ops
		{"bob", "tag:prod", true},    // via nested group:oncall
		{"carol", "tag:prod", false}, // in no group
		{"bob", "tag:edge", true},    // tag:prod owns tag:edge
		{"carol", "tag:edge", false},
		{"alice", "tag:missing", false}, // undefined tag
		{"", "tag:server", false},       // unknown user
	}
	for _, tt := range owns {
		if got := engine.UserOwnsTag(tt.login, tt.tag); got != tt.want {
			t.Errorf("UserOwnsTag(%q, %q) = %v, want %v", tt.login, tt.tag, got, tt.want)
		}
	}
}

// TestTagOwnershipHandlesCycles proves a tag-to-tag ownership loop cannot hang.
func TestTagOwnershipHandlesCycles(t *testing.T) {
	engine := mustEngine(t, `{
		"tagOwners": {
			"tag:a": ["tag:b"],
			"tag:b": ["tag:a"],
		},
		"acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}],
	}`)

	if engine.UserOwnsTag("alice", "tag:a") {
		t.Error("a tag cycle must not authorize anyone")
	}
}
