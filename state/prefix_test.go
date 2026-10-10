package state

import (
	"context"
	"net/netip"
	"path/filepath"
	"testing"

	"tailscale.com/types/key"
)

// newTestStores returns both store implementations, so the address rules are
// verified twice: once against memory and once against SQLite.
func newTestStores(t *testing.T) map[string]Store {
	t.Helper()
	ctx := context.Background()
	sqliteStore, err := OpenSQLite(ctx, filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("OpenSQLite: %v", err)
	}
	t.Cleanup(func() { sqliteStore.Close() })
	return map[string]Store{"memory": NewMemoryStore(), "sqlite": sqliteStore}
}

// addNode creates a node with a fresh key.
func addNode(t *testing.T, s Store) Node {
	t.Helper()
	n := Node{
		NodeKey:    key.NewNode().Public(),
		MachineKey: key.NewMachine().Public(),
		Hostname:   "test",
	}
	if err := s.CreateNode(&n); err != nil {
		t.Fatalf("CreateNode: %v", err)
	}
	return n
}

func TestAddressPrefixesDefaultToTheTailnetRanges(t *testing.T) {
	for name, s := range newTestStores(t) {
		v4, v6 := s.AddressPrefixes()
		if v4 != defaultIPv4Prefix || v6 != defaultIPv6Prefix {
			t.Fatalf("%s store defaults = (%s, %s), want (%s, %s)", name, v4, v6, defaultIPv4Prefix, defaultIPv6Prefix)
		}
		n := addNode(t, s)
		if !defaultIPv4Prefix.Contains(n.IPv4) || !defaultIPv6Prefix.Contains(n.IPv6) {
			t.Fatalf("%s store allocated (%s, %s) outside the default ranges", name, n.IPv4, n.IPv6)
		}
	}
}

func TestAddressPrefixesAllocateFromTheTenantRange(t *testing.T) {
	block := netip.MustParsePrefix("100.100.7.0/24")
	for name, s := range newTestStores(t) {
		if err := s.SetAddressPrefixes(block, netip.Prefix{}); err != nil {
			t.Fatalf("%s SetAddressPrefixes: %v", name, err)
		}
		v4, v6 := s.AddressPrefixes()
		if v4 != block || v6 != defaultIPv6Prefix {
			t.Fatalf("%s prefixes = (%s, %s), want (%s, %s)", name, v4, v6, block, defaultIPv6Prefix)
		}

		seen := make(map[netip.Addr]bool)
		for i := 0; i < 3; i++ {
			n := addNode(t, s)
			if !block.Contains(n.IPv4) {
				t.Fatalf("%s allocated %s outside %s", name, n.IPv4, block)
			}
			if seen[n.IPv4] {
				t.Fatalf("%s allocated %s twice", name, n.IPv4)
			}
			seen[n.IPv4] = true
		}
	}
}

func TestAddressPrefixChangeKeepsExistingNodesAndSkipsTheirAddresses(t *testing.T) {
	wide := netip.MustParsePrefix("100.64.0.0/24")
	for name, s := range newTestStores(t) {
		existing := addNode(t, s)
		if !wide.Contains(existing.IPv4) {
			t.Fatalf("%s: unexpected default address %s", name, existing.IPv4)
		}

		// A new range that covers the address already handed out: the node
		// keeps it, and the next allocation must not reuse it.
		if err := s.SetAddressPrefixes(wide, netip.Prefix{}); err != nil {
			t.Fatalf("%s SetAddressPrefixes: %v", name, err)
		}
		next := addNode(t, s)
		if next.IPv4 == existing.IPv4 {
			t.Fatalf("%s handed out %s twice after the range change", name, next.IPv4)
		}
		if !wide.Contains(next.IPv4) {
			t.Fatalf("%s allocated %s outside the new range", name, next.IPv4)
		}

		stored, ok := s.GetNodeByID(existing.ID)
		if !ok || stored.IPv4 != existing.IPv4 {
			t.Fatalf("%s: existing node address changed to %s", name, stored.IPv4)
		}
	}
}

func TestAddressPrefixRejectsWrongFamilies(t *testing.T) {
	for name, s := range newTestStores(t) {
		if err := s.SetAddressPrefixes(netip.MustParsePrefix("fd00::/64"), netip.Prefix{}); err == nil {
			t.Errorf("%s accepted an IPv6 range as IPv4", name)
		}
		if err := s.SetAddressPrefixes(netip.Prefix{}, netip.MustParsePrefix("100.100.0.0/24")); err == nil {
			t.Errorf("%s accepted an IPv4 range as IPv6", name)
		}
		if err := s.SetAddressPrefixes(netip.Prefix{}, netip.Prefix{}); err == nil {
			t.Errorf("%s accepted an empty prefix pair", name)
		}
		if err := s.SetAddressPrefixes(netip.MustParsePrefix("0.0.0.0/0"), netip.Prefix{}); err == nil {
			t.Errorf("%s accepted a range covering every address", name)
		}
	}
}

func TestAddressPrefixExhaustionIsReported(t *testing.T) {
	// A /30 holds three addresses by the tailnet's rules (addresses are
	// allocated per node, so there is no network or broadcast address): the
	// fourth node must be refused instead of silently landing outside the
	// tenant's range.
	tiny := netip.MustParsePrefix("192.168.77.0/30")
	for name, s := range newTestStores(t) {
		if err := s.SetAddressPrefixes(tiny, netip.Prefix{}); err != nil {
			t.Fatalf("%s SetAddressPrefixes: %v", name, err)
		}
		for i := 0; i < 3; i++ {
			addNode(t, s)
		}
		n := Node{NodeKey: key.NewNode().Public(), MachineKey: key.NewMachine().Public()}
		if err := s.CreateNode(&n); err == nil {
			t.Errorf("%s allocated a fourth address out of a /30 range", name)
		}
	}
}

func TestAddressAllocationSkipsOfficialClientReservedRanges(t *testing.T) {
	for _, example := range []struct {
		prefix string
		first  string
	}{
		{"100.100.0.0/23", "100.100.1.0"},
		{"100.100.100.0/23", "100.100.101.0"},
		{"100.115.92.0/22", "100.115.94.0"},
	} {
		t.Run(example.prefix, func(t *testing.T) {
			for name, store := range newTestStores(t) {
				if err := store.SetAddressPrefixes(netip.MustParsePrefix(example.prefix), netip.Prefix{}); err != nil {
					t.Fatal(err)
				}
				if address := addNode(t, store).IPv4; address != netip.MustParseAddr(example.first) {
					t.Fatalf("%s first unreserved address = %s, want %s", name, address, example.first)
				}
			}
		})
	}
}
