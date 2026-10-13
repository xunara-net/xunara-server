package netspace

import (
	"net/netip"
	"testing"
)

func TestAdditionalPrefixesNormalizeAndRejectOverlapOrClientDNS(t *testing.T) {
	primary := netip.MustParsePrefix("100.101.50.0/24")
	result, err := NormalizeAdditionalPrefixes(primary, []netip.Prefix{netip.MustParsePrefix("192.168.60.15/24"), netip.MustParsePrefix("10.42.0.0/16")}, nil)
	if err != nil || result[0].String() != "10.42.0.0/16" || result[1].String() != "192.168.60.0/24" {
		t.Fatal("additional prefixes were not canonicalized")
	}
	for _, ranges := range [][]string{{"100.101.50.128/25"}, {"192.168.60.0/24", "192.168.60.128/25"}, {"100.100.100.0/24"}, {"127.0.0.0/8"}, {"::/64"}} {
		var prefixes []netip.Prefix
		for _, value := range ranges {
			prefixes = append(prefixes, netip.MustParsePrefix(value))
		}
		if _, err := NormalizeAdditionalPrefixes(primary, prefixes, nil); err == nil {
			t.Fatalf("unsafe additional ranges accepted: %v", ranges)
		}
	}
}
