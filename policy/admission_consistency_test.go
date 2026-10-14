package policy

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/xunara-net/xunara-server/state"
)

func TestEveryPolicySourceRejectsUnsupportedRestrictions(test *testing.T) {
	for _, content := range []string{
		`{"grants":[{"src":["*"],"dst":["*"],"ip":["tcp:443"],"srcPosture":["posture:managed"]}]}`,
		`{"acls":[{"action":"accept","src":["*"],"dst":["*:443"],"srcPosture":["posture:managed"]}]}`,
		`{"acls":[],"autoApprovers":{"routes":{"10.0.0.0/8":["*"]}}}`,
		`{"acls":[],"acls":[{"action":"accept","src":["*"],"dst":["*:*"]}]}`,
	} {
		if _, err := ParseString(content); err == nil {
			test.Fatal("legacy parser ignored a security restriction")
		}
		if _, _, err := ParseManaged([]byte(content)); err == nil {
			test.Fatal("managed parser ignored a security restriction")
		}
		filename := filepath.Join(test.TempDir(), "policy.hujson")
		if err := os.WriteFile(filename, []byte(content), 0600); err != nil {
			test.Fatal(err)
		}
		if _, err := Load(filename); err == nil {
			test.Fatal("file parser ignored a security restriction")
		}
	}
}

func TestWildcardApplicationGrantsIncludeOnlyActualCustomAddresses(test *testing.T) {
	engine := mustEngine(test, `{"grants":[{"src":["*"],"dst":["*"],"app":{"example.com/cap/read":[]}}]}`)
	nodes := []state.Node{
		{ID: 1, UserID: 1, IPv4: netip.MustParseAddr("10.10.9.4")},
		{ID: 2, UserID: 1, IPv4: netip.MustParseAddr("192.168.17.9"), IPv6: netip.MustParseAddr("fd00:1234::1")},
	}
	prefixes := engine.FilterFor(nodes[0], nodes)[0].CapGrant[0].Dsts
	contains := func(address netip.Addr) bool {
		for _, prefix := range prefixes {
			if prefix.Contains(address) {
				return true
			}
		}
		return false
	}
	for _, address := range []netip.Addr{nodes[0].IPv4, nodes[1].IPv4, nodes[1].IPv6} {
		if !contains(address) {
			test.Fatal("application grant omitted an actual device address")
		}
	}
	for _, address := range []string{"10.10.9.5", "192.168.17.10", "fd00:1234::2"} {
		if contains(netip.MustParseAddr(address)) {
			test.Fatal("application grant widened to an unrelated address")
		}
	}
}
