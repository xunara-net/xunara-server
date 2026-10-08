package policy

import (
	"testing"

	"tailscale.com/tailcfg"

	"github.com/xunara-net/xunara-server/state"
)

const ingressDoc = `{
	"groups": {"group:eng": ["alice@example.com"]},
	"tagOwners": {"tag:prod": ["alice@example.com"]},
	"acls": [
		{"action": "accept", "src": ["group:eng"], "dst": ["tag:prod:8080"]},
		{"action": "accept", "src": ["*"], "dst": ["*:443"]},
		{"action": "accept", "src": ["autogroup:self"], "dst": ["autogroup:self:22"]},
		{"action": "accept", "src": ["*"], "dst": ["autogroup:internet:*"]},
		{"action": "accept", "src": ["*"], "dst": ["100.64.0.9/32:1000-2000"], "proto": "udp"}
	],
}`

// ingressTailnet is the node set the document is evaluated against: Alice's
// laptop, Bob's phone, a tagged production node owned by Bob, and a database
// node at the hosted address.
func ingressTailnet(t *testing.T) (alice, bob, tablet, prod, database state.Node, nodes []state.Node) {
	t.Helper()
	alice = testNode(1, "alice-laptop", "100.64.0.1")
	bob = testNode(2, "bob-phone", "100.64.0.2")
	bob.UserID = 2
	tablet = testNode(5, "bob-tablet", "100.64.0.5")
	tablet.UserID = 2
	prod = testNode(3, "prod-web", "100.64.0.3")
	prod.UserID = 2
	prod.Tags = []string{"tag:prod"}
	database = testNode(4, "db", "100.64.0.9")
	nodes = []state.Node{alice, bob, tablet, prod, database}
	return alice, bob, tablet, prod, database, nodes
}

func TestAllowsIngress(t *testing.T) {
	alice, bob, tablet, prod, database, nodes := ingressTailnet(t)
	opts := logins(map[tailcfg.UserID]string{1: "alice@example.com", 2: "bob@example.com"})

	for _, tt := range []struct {
		name  string
		doc   string
		dst   state.Node
		src   state.Node
		proto string
		port  uint16
		want  bool
	}{
		{name: "tag rule allows the group at the service port", doc: ingressDoc,
			dst: prod, src: alice, proto: "tcp", port: 8080, want: true},
		{name: "tag rule does not allow another port", doc: ingressDoc,
			dst: prod, src: alice, proto: "tcp", port: 8081, want: false},
		{name: "tag rule does not allow another user", doc: ingressDoc,
			dst: prod, src: bob, proto: "tcp", port: 8080, want: false},
		{name: "wildcard rule covers every node", doc: ingressDoc,
			dst: database, src: bob, proto: "tcp", port: 443, want: true},
		{name: "autogroup:self allows the same user", doc: ingressDoc,
			dst: tablet, src: bob, proto: "tcp", port: 22, want: true},
		{name: "autogroup:self denies another user", doc: ingressDoc,
			dst: tablet, src: alice, proto: "tcp", port: 22, want: false},
		{name: "internet rules never grant tailnet access", doc: ingressDoc,
			dst: prod, src: alice, proto: "tcp", port: 9999, want: false},
		{name: "prefix rule with protocol and port range", doc: ingressDoc,
			dst: database, src: alice, proto: "udp", port: 1500, want: true},
		{name: "prefix rule rejects another protocol", doc: ingressDoc,
			dst: database, src: alice, proto: "tcp", port: 1500, want: false},
		{name: "empty policy denies", doc: `{"acls": []}`,
			dst: prod, src: alice, proto: "tcp", port: 8080, want: false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			engine := mustEngineOpts(t, tt.doc, opts)
			rules := engine.FilterFor(tt.dst, nodes)
			if got := AllowsIngress(rules, tt.dst, tt.src, tt.proto, tt.port); got != tt.want {
				t.Errorf("AllowsIngress(%s -> %s:%d/%s) = %v, want %v",
					tt.src.Hostname, tt.dst.Hostname, tt.port, tt.proto, got, tt.want)
			}
		})
	}
}

// TestAllowsIngressUnknownInputsFailClosed pins the denial paths: unknown
// protocols, nodes without addresses and an empty rule set never widen
// visibility.
func TestAllowsIngressUnknownInputsFailClosed(t *testing.T) {
	alice, _, _, prod, _, nodes := ingressTailnet(t)
	opts := logins(map[tailcfg.UserID]string{1: "alice@example.com", 2: "bob@example.com"})
	rules := mustEngineOpts(t, ingressDoc, opts).FilterFor(prod, nodes)

	if AllowsIngress(rules, prod, alice, "sctp", 8080) {
		t.Error("an unknown service protocol was allowed")
	}
	if AllowsIngress(rules, prod, state.Node{}, "tcp", 8080) {
		t.Error("a source without addresses was allowed")
	}
	if AllowsIngress(nil, prod, alice, "tcp", 8080) {
		t.Error("an empty rule set was allowed")
	}
}
