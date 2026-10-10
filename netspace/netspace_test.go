package netspace

import (
	"errors"
	"net/netip"
	"testing"
)

func mustPrefix(t *testing.T, s string) netip.Prefix {
	t.Helper()
	p, err := netip.ParsePrefix(s)
	if err != nil {
		t.Fatalf("parsing %q: %v", s, err)
	}
	return p
}

func TestValidateTenantPrefixAcceptsPrivateRanges(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want string
	}{
		{"192.168.50.0/24", "192.168.50.0/24"},
		{"192.168.50.5/24", "192.168.50.0/24"}, // host bits are normalized away
		{"10.10.0.0/24", "10.10.0.0/24"},
		{"172.16.50.0/24", "172.16.50.0/24"},
		{"100.100.1.0/24", "100.100.1.0/24"}, // a free-plan block from the pool
		{"100.64.0.0/16", "100.64.0.0/16"},
		{"10.0.0.0/16", "10.0.0.0/16"},
		{"10.42.50.5/8", "10.0.0.0/8"},
		{"172.31.50.5/12", "172.16.0.0/12"},
		{"192.168.50.5/29", "192.168.50.0/29"},
		{"192.168.50.5/30", "192.168.50.4/30"},
		{"192.168.50.5/31", "192.168.50.4/31"},
		{"192.168.50.5/32", "192.168.50.5/32"},
		{"2.0.0.0/7", "2.0.0.0/7"},
		{"192.168.1.16/28", "192.168.1.16/28"},
	} {
		got, err := ValidateTenantPrefix(mustPrefix(t, tc.in), nil)
		if err != nil {
			t.Fatalf("ValidateTenantPrefix(%s): %v", tc.in, err)
		}
		if got.String() != tc.want {
			t.Fatalf("ValidateTenantPrefix(%s) = %s, want %s", tc.in, got, tc.want)
		}
	}
}

func TestValidateTenantPrefixRejectsReservedAndMalformed(t *testing.T) {
	extra := []netip.Prefix{mustPrefix(t, "100.127.0.0/16")}
	for _, tc := range []struct {
		in    string
		extra []netip.Prefix
	}{
		{"127.0.0.0/24", nil},
		{"169.254.0.0/24", nil},
		{"224.0.0.0/24", nil},
		{"255.255.255.255/32", nil},
		{"0.0.0.0/8", nil},
		{"198.18.0.0/24", nil},
		{"192.0.2.0/24", nil},
		{"fd00::/64", nil}, // IPv6 is not customizable
		{"100.127.0.0/24", extra},
	} {
		if _, err := ValidateTenantPrefix(mustPrefix(t, tc.in), tc.extra); err == nil {
			t.Fatalf("ValidateTenantPrefix(%s) accepted a range it must reject", tc.in)
		}
	}
	if _, err := ValidateTenantPrefix(netip.Prefix{}, nil); err == nil {
		t.Fatal("ValidateTenantPrefix accepted an invalid prefix")
	}
}

func TestPoolBlocksAndAllocation(t *testing.T) {
	pool, err := NewPool(mustPrefix(t, "100.100.0.0/16"), 24)
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}
	if pool.Blocks() != 256 {
		t.Fatalf("Blocks() = %d, want 256", pool.Blocks())
	}
	first, ok := pool.Block(0)
	if !ok || first.String() != "100.100.0.0/24" {
		t.Fatalf("Block(0) = %s (%v)", first, ok)
	}
	second, ok := pool.Block(1)
	if !ok || second.String() != "100.100.1.0/24" {
		t.Fatalf("Block(1) = %s (%v)", second, ok)
	}
	if _, ok := pool.Block(256); ok {
		t.Fatal("Block(256) exists in a 256-block pool")
	}

	used := []netip.Prefix{mustPrefix(t, "100.100.0.0/24")}
	got, err := pool.Allocate(nil, used)
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}
	if got.String() != "100.100.1.0/24" {
		t.Fatalf("Allocate(used first block) = %s, want 100.100.1.0/24", got)
	}
}

func TestPoolAllocationSkipsReservedAndOverlappingBlocks(t *testing.T) {
	pool, err := NewPool(mustPrefix(t, "100.100.0.0/22"), 24)
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}
	reserved := []netip.Prefix{mustPrefix(t, "100.100.0.0/23")}
	used := []netip.Prefix{mustPrefix(t, "100.100.2.0/24")}
	got, err := pool.Allocate(reserved, used)
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}
	if got.String() != "100.100.3.0/24" {
		t.Fatalf("Allocate = %s, want 100.100.3.0/24", got)
	}
}

func TestPoolExhaustion(t *testing.T) {
	pool, err := NewPool(mustPrefix(t, "100.100.9.0/24"), 24)
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}
	used := []netip.Prefix{mustPrefix(t, "100.100.9.0/24")}
	if _, err := pool.Allocate(nil, used); !errors.Is(err, ErrNoBlock) {
		t.Fatalf("Allocate on an exhausted pool = %v, want ErrNoBlock", err)
	}
}

func TestPoolRejectsBadDefinitions(t *testing.T) {
	for _, tc := range []struct {
		pool string
		bits int
	}{
		{"127.0.0.0/16", 24},   // reserved pool
		{"100.100.0.0/16", 12}, // block larger than the pool
		{"100.100.0.0/16", 33}, // invalid IPv4 block length
		{"100.100.0.0/16", -1},
		{"10.0.0.0/8", 32}, // too many candidate blocks
		{"2.0.0.0/7", 24},
		{"fd00::/48", 64}, // IPv6
		{"0.0.0.0/0", 24}, // larger than /8
	} {
		if _, err := NewPool(mustPrefix(t, tc.pool), tc.bits); err == nil {
			t.Fatalf("NewPool(%s, /%d) accepted an invalid pool", tc.pool, tc.bits)
		}
	}
	if _, err := NewPool(mustPrefix(t, "100.100.0.0/16"), 24); err != nil {
		t.Fatalf("NewPool rejected a valid pool: %v", err)
	}
}

func TestPoolSupportsFlexibleIPv4Blocks(t *testing.T) {
	for _, example := range []struct {
		prefix string
		bits   int
		blocks int
		last   string
	}{
		{"10.0.0.0/8", 24, 65536, "10.255.255.0/24"},
		{"192.168.50.0/24", 31, 128, "192.168.50.254/31"},
		{"192.168.50.0/24", 32, 256, "192.168.50.255/32"},
		{"192.168.50.20/32", 32, 1, "192.168.50.20/32"},
		{"2.0.0.0/7", 7, 1, "2.0.0.0/7"},
	} {
		t.Run(example.prefix+"-"+example.last, func(t *testing.T) {
			pool, err := NewPool(mustPrefix(t, example.prefix), example.bits)
			if err != nil || pool.Blocks() != example.blocks {
				t.Fatalf("pool: %+v %v", pool, err)
			}
			last, found := pool.Block(example.blocks - 1)
			if !found || last.String() != example.last {
				t.Fatalf("last block = %s, found=%v", last, found)
			}
			if _, found := pool.Block(example.blocks); found {
				t.Fatal("out-of-range block exists")
			}
			if _, err := pool.Allocate(nil, []netip.Prefix{pool.Prefix()}); !errors.Is(err, ErrNoBlock) {
				t.Fatalf("exhausted pool: %v", err)
			}
		})
	}
}

func TestZeroPoolDoesNotAllocate(t *testing.T) {
	var pool Pool
	if !pool.Zero() || pool.Blocks() != 0 {
		t.Fatal("the zero pool is not empty")
	}
	if _, err := pool.Allocate(nil, nil); err == nil {
		t.Fatal("the zero pool allocated a block")
	}
}

func TestContainsAndFirstOverlap(t *testing.T) {
	pool, err := NewPool(mustPrefix(t, "100.100.0.0/16"), 24)
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}
	inside := mustPrefix(t, "100.100.7.0/24")
	if !pool.Contains(inside) {
		t.Fatalf("pool does not contain %s", inside)
	}
	if pool.Contains(mustPrefix(t, "100.101.0.0/24")) {
		t.Fatal("pool contains a range outside it")
	}

	others := []netip.Prefix{mustPrefix(t, "192.168.50.0/24"), mustPrefix(t, "100.100.7.0/24")}
	overlap, ok := FirstOverlap(inside, others)
	if !ok || overlap.String() != "100.100.7.0/24" {
		t.Fatalf("FirstOverlap = %s (%v)", overlap, ok)
	}
	if _, ok := FirstOverlap(mustPrefix(t, "10.9.0.0/24"), others); ok {
		t.Fatal("FirstOverlap found an overlap that does not exist")
	}
}

func TestReservedReturnsACopy(t *testing.T) {
	list := Reserved()
	if len(list) == 0 {
		t.Fatal("Reserved() is empty")
	}
	list[0] = netip.Prefix{}
	if Reserved()[0] == (netip.Prefix{}) {
		t.Fatal("Reserved() shares its backing array with the caller")
	}
}
