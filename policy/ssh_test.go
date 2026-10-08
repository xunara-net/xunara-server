package policy

import (
	"strings"
	"testing"
	"time"

	"tailscale.com/tailcfg"

	"github.com/xunara-net/xunara-server/state"
)

// sshPrincipalsOf flattens the principals of a compiled policy.
func sshPrincipalsOf(pol *tailcfg.SSHPolicy) []string {
	if pol == nil {
		return nil
	}
	var out []string
	for _, rule := range pol.Rules {
		for _, p := range rule.Principals {
			out = append(out, p.NodeIP)
		}
	}
	return out
}

func TestCompileSSHPolicyAccept(t *testing.T) {
	engine := mustEngine(t, `{
		"ssh": [{
			"action": "accept",
			"src": ["autogroup:member"],
			"dst": ["autogroup:self"],
			"users": ["autogroup:nonroot", "root"],
		}],
		"acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}],
	}`)

	one := testNode(1, "one", "100.64.0.1")
	two := testNode(2, "two", "100.64.0.2")
	nodes := []state.Node{one, two}

	pol := engine.CompileSSHPolicy(one, nodes)
	if pol == nil || len(pol.Rules) != 1 {
		t.Fatalf("policy = %+v, want one rule", pol)
	}
	rule := pol.Rules[0]

	got := sshPrincipalsOf(pol)
	if len(got) != 4 { // both nodes, both addresses
		t.Errorf("principals = %v, want both nodes' addresses", got)
	}
	if rule.SSHUsers["*"] != "=" || rule.SSHUsers["root"] != "root" {
		t.Errorf("SSHUsers = %v, want *→= and root→root", rule.SSHUsers)
	}
	if rule.Action == nil || !rule.Action.Accept {
		t.Errorf("action = %+v, want accept", rule.Action)
	}
}

func TestCompileSSHPolicyDoesNotMatchOtherUsers(t *testing.T) {
	engine := mustEngineOpts(t, `{
		"ssh": [{"action": "accept", "src": ["autogroup:member"], "dst": ["autogroup:self"], "users": ["root"]}],
		"acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}],
	}`, logins(map[tailcfg.UserID]string{1: "alice", 2: "bob"}))

	one := testNode(1, "one", "100.64.0.1")
	two := testNode(2, "two", "100.64.0.2")
	two.UserID = 2
	nodes := []state.Node{one, two}

	got := sshPrincipalsOf(engine.CompileSSHPolicy(one, nodes))
	if len(got) != 2 || strings.Contains(strings.Join(got, ","), "100.64.0.2") {
		t.Errorf("principals = %v, want only alice's node", got)
	}
}

func TestCompileSSHPolicyDestinationSelectors(t *testing.T) {
	engine := mustEngine(t, `{
		"tagOwners": {"tag:server": ["local"]},
		"ssh": [{"action": "accept", "src": ["autogroup:member"], "dst": ["tag:server"], "users": ["root"]}],
		"acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}],
	}`)

	server := testNode(1, "server", "100.64.0.1")
	server.Tags = []string{"tag:server"}
	client := testNode(2, "client", "100.64.0.2")
	nodes := []state.Node{server, client}

	if pol := engine.CompileSSHPolicy(server, nodes); pol == nil || len(pol.Rules) != 1 {
		t.Errorf("the tagged server should receive an SSH policy, got %+v", pol)
	}
	if pol := engine.CompileSSHPolicy(client, nodes); pol != nil {
		t.Errorf("a non-destination node must not receive an SSH policy, got %+v", pol)
	}

	dests := engine.SSHDestinations(nodes)
	if !dests[server.ID] || dests[client.ID] {
		t.Errorf("destinations = %v, want only the tagged server", dests)
	}
}

func TestCompileSSHPolicyCheckModeHolds(t *testing.T) {
	engine := mustEngineOpts(t, `{
		"ssh": [{
			"action": "check",
			"src": ["autogroup:member"],
			"dst": ["autogroup:self"],
			"users": ["root"],
			"checkPeriod": "1h",
		}],
		"acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}],
	}`, Options{Domain: "xunara.test", ServerURL: "https://control.example/"})

	one := testNode(1, "one", "100.64.0.1")
	nodes := []state.Node{one}

	pol := engine.CompileSSHPolicy(one, nodes)
	if pol == nil || len(pol.Rules) != 1 {
		t.Fatalf("policy = %+v, want one rule", pol)
	}
	action := pol.Rules[0].Action
	if action == nil || action.Accept || action.Reject {
		t.Fatalf("action = %+v, want a hold", action)
	}
	want := "https://control.example/machine/ssh/action/$SRC_NODE_ID/to/$DST_NODE_ID?local_user=$LOCAL_USER"
	if action.HoldAndDelegate != want {
		t.Errorf("HoldAndDelegate = %q, want %q", action.HoldAndDelegate, want)
	}
	if action.AllowAgentForwarding || action.AllowLocalPortForwarding || action.AllowRemotePortForwarding {
		t.Errorf("forwarding = %+v, want all off while held", action)
	}

	period, ok := engine.SSHCheckPeriod(one, one, nodes)
	if !ok || period != time.Hour {
		t.Errorf("SSHCheckPeriod = %v (ok=%v), want 1h", period, ok)
	}
	if engine.SSHDestinations(nodes)[one.ID] != true {
		t.Error("a check rule must still mark its destination nodes")
	}
}

func TestSSHCheckPeriodValues(t *testing.T) {
	cases := map[string]struct {
		rule string
		want time.Duration
	}{
		"default":  {`{"action": "check", "src": ["*"], "dst": ["*"], "users": ["root"]}`, sshCheckPeriodDefault},
		"always":   {`{"action": "check", "src": ["*"], "dst": ["*"], "users": ["root"], "checkPeriod": "always"}`, 0},
		"explicit": {`{"action": "check", "src": ["*"], "dst": ["*"], "users": ["root"], "checkPeriod": "30m"}`, 30 * time.Minute},
		"max":      {`{"action": "check", "src": ["*"], "dst": ["*"], "users": ["root"], "checkPeriod": "168h"}`, sshCheckPeriodMax},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			engine := mustEngine(t, `{"ssh": [`+tc.rule+`], "acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}]}`)
			one := testNode(1, "one", "100.64.0.1")
			period, ok := engine.SSHCheckPeriod(one, one, []state.Node{one})
			if !ok || period != tc.want {
				t.Errorf("SSHCheckPeriod = %v (ok=%v), want %v", period, ok, tc.want)
			}
		})
	}
}

func TestSSHCheckPeriodRejectsInvalid(t *testing.T) {
	cases := map[string]string{
		"negative":       `{"action": "check", "src": ["*"], "dst": ["*"], "users": ["root"], "checkPeriod": "-1h"}`,
		"above max":      `{"action": "check", "src": ["*"], "dst": ["*"], "users": ["root"], "checkPeriod": "169h"}`,
		"not a duration": `{"action": "check", "src": ["*"], "dst": ["*"], "users": ["root"], "checkPeriod": "soon"}`,
		"wrong type":     `{"action": "check", "src": ["*"], "dst": ["*"], "users": ["root"], "checkPeriod": 5}`,
		"accept rule":    `{"action": "accept", "src": ["*"], "dst": ["*"], "users": ["root"], "checkPeriod": "1h"}`,
	}
	for name, rule := range cases {
		t.Run(name, func(t *testing.T) {
			parsed, err := ParseString(`{"ssh": [` + rule + `], "acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}]}`)
			if err != nil {
				// A malformed or non-string checkPeriod is rejected while
				// parsing; a semantic error (negative, above max, on an
				// accept rule) surfaces from NewEngine below.
				return
			}
			if _, err := NewEngine(parsed, Options{Domain: "xunara.test"}); err == nil {
				t.Fatalf("NewEngine(%s) succeeded, want error", name)
			}
		})
	}
}

func TestSSHCheckPeriodNoMatch(t *testing.T) {
	engine := mustEngine(t, `{
		"ssh": [{"action": "check", "src": ["100.64.0.2/32"], "dst": ["tag:server"], "users": ["root"]}],
		"tagOwners": {"tag:server": ["local"]},
		"acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}],
	}`)

	server := testNode(1, "server", "100.64.0.1")
	server.Tags = []string{"tag:server"}
	other := testNode(2, "other", "100.64.0.2")
	nodes := []state.Node{server, other}

	if _, ok := engine.SSHCheckPeriod(other, server, nodes); !ok {
		t.Error("the matching (source, destination) pair should resolve a period")
	}
	if _, ok := engine.SSHCheckPeriod(server, other, nodes); ok {
		t.Error("an unmatched destination must not resolve a period")
	}
}

func TestSSHAutogroupSelfExcludesTagged(t *testing.T) {
	engine := mustEngine(t, `{
		"tagOwners": {"tag:server": ["local"]},
		"ssh": [{"action": "accept", "src": ["autogroup:member"], "dst": ["autogroup:self"], "users": ["root"]}],
	}`)

	tagged := testNode(1, "tagged", "100.64.0.1")
	tagged.Tags = []string{"tag:server"}
	plain := testNode(2, "plain", "100.64.0.2")
	nodes := []state.Node{tagged, plain}

	// A tagged node has no user: it can neither be reached through
	// autogroup:self nor act as a principal for it.
	if pol := engine.CompileSSHPolicy(tagged, nodes); pol != nil {
		t.Errorf("policy = %+v, want nil for a tagged autogroup:self destination", pol)
	}
	pol := engine.CompileSSHPolicy(plain, nodes)
	principals := sshPrincipalsOf(pol)
	if len(principals) != 2 {
		t.Fatalf("principals = %v, want the untagged device's two addresses", principals)
	}
	for _, p := range principals {
		if strings.HasPrefix(p, "100.64.0.1") || p == "fd7a:115c:a1e0::1/128" {
			t.Errorf("principal %q belongs to the tagged device", p)
		}
	}

	dests := engine.SSHDestinations(nodes)
	if dests[tagged.ID] {
		t.Error("a tagged node must not be marked as an autogroup:self destination")
	}
	if !dests[plain.ID] {
		t.Error("the untagged node must be marked as an autogroup:self destination")
	}
}

func TestSSHCheckPeriodAutogroupSelfExcludesTagged(t *testing.T) {
	engine := mustEngine(t, `{
		"tagOwners": {"tag:server": ["local"]},
		"ssh": [{"action": "check", "checkPeriod": "always", "src": ["autogroup:self"], "dst": ["autogroup:self"], "users": ["root"]}],
	}`)

	tagged := testNode(1, "tagged", "100.64.0.1")
	tagged.Tags = []string{"tag:server"}
	plain := testNode(2, "plain", "100.64.0.2")
	other := testNode(3, "other", "100.64.0.3")
	nodes := []state.Node{tagged, plain, other}

	if _, ok := engine.SSHCheckPeriod(tagged, plain, nodes); ok {
		t.Error("a tagged source matched autogroup:self")
	}
	if _, ok := engine.SSHCheckPeriod(plain, tagged, nodes); ok {
		t.Error("a tagged destination matched autogroup:self")
	}
	if _, ok := engine.SSHCheckPeriod(plain, other, nodes); !ok {
		t.Error("two untagged devices of the same user must match autogroup:self")
	}
}

func TestSSHRuleValidation(t *testing.T) {
	bad := []struct {
		name string
		doc  string
	}{
		{"missing action", `{"ssh": [{"src": ["*"], "dst": ["*"], "users": ["root"]}]}`},
		{"unknown action", `{"ssh": [{"action": "deny", "src": ["*"], "dst": ["*"], "users": ["root"]}]}`},
		{"missing src", `{"ssh": [{"action": "accept", "dst": ["*"], "users": ["root"]}]}`},
		{"missing dst", `{"ssh": [{"action": "accept", "src": ["*"], "users": ["root"]}]}`},
		{"missing users", `{"ssh": [{"action": "accept", "src": ["*"], "dst": ["*"]}]}`},
		{"wildcard user", `{"ssh": [{"action": "accept", "src": ["*"], "dst": ["*"], "users": ["*"]}]}`},
		{"port in dst", `{"ssh": [{"action": "accept", "src": ["*"], "dst": ["*:22"], "users": ["root"]}]}`},
		{"unknown tag in dst", `{"ssh": [{"action": "accept", "src": ["*"], "dst": ["tag:nope"], "users": ["root"]}]}`},
		{"bad acceptEnv", `{"ssh": [{"action": "accept", "src": ["*"], "dst": ["*"], "users": ["root"], "acceptEnv": ["FOO BAR"]}]}`},
	}

	for _, tt := range bad {
		t.Run(tt.name, func(t *testing.T) {
			doc, err := ParseString(tt.doc)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if _, err := NewEngine(doc, Options{}); err == nil {
				t.Error("NewEngine accepted an invalid ssh rule")
			}
		})
	}
}
