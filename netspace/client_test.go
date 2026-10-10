package netspace

import (
	"net/netip"
	"testing"
)

func TestTailnetAllocationRanges(t *testing.T) {
	for _, value := range []string{"100.101.50.12/24", "100.70.0.0/16", "100.126.1.0/28", "192.168.50.5/24", "10.42.0.0/8", "172.16.0.0/12", "100.63.0.0/16", "100.70.0.0/29", "192.168.50.4/30", "192.168.50.4/31", "192.168.50.5/32", "8.8.4.0/24"} {
		prefix, err := ValidateTailnetPrefix(netip.MustParsePrefix(value), nil)
		if err != nil || prefix != netip.MustParsePrefix(value).Masked() {
			t.Fatalf("valid range %s: %s %v", value, prefix, err)
		}
	}
	for _, value := range []string{"127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4", "240.0.0.0/4", "0.0.0.0/0", "100.100.0.0/24", "100.100.100.0/24", "100.115.92.0/24", "100.127.0.0/24", "100.64.0.0/10", "fd7a:115c:a1e0::/64"} {
		if _, err := ValidateTailnetPrefix(netip.MustParsePrefix(value), nil); err == nil {
			t.Fatalf("invalid device range accepted: %s", value)
		}
	}
	if _, err := ValidateTailnetPrefix(netip.MustParsePrefix("100.101.50.0/24"), []netip.Prefix{netip.MustParsePrefix("100.101.50.128/25")}); err == nil {
		t.Fatal("deployment reserved range accepted")
	}
}

func TestDeviceAddressFlexibleRangesAndSmallPools(t *testing.T) {
	for _, example := range []struct {
		prefix  string
		allowed []string
		denied  []string
	}{
		{"10.0.0.0/8", []string{"10.0.0.1", "10.255.255.254"}, []string{"10.0.0.0", "10.255.255.255", "11.0.0.1"}},
		{"192.168.50.0/30", []string{"192.168.50.1", "192.168.50.2"}, []string{"192.168.50.0", "192.168.50.3"}},
		{"192.168.50.4/31", []string{"192.168.50.4", "192.168.50.5"}, []string{"192.168.50.3", "192.168.50.6"}},
		{"192.168.50.20/32", []string{"192.168.50.20"}, []string{"192.168.50.19", "192.168.50.21"}},
		{"8.8.4.0/24", []string{"8.8.4.1"}, []string{"8.8.4.0", "8.8.4.255"}},
		{"0.0.0.0/1", nil, []string{"127.0.0.1", "0.0.0.1", "100.100.100.100", "100.127.1.1"}},
		{"128.0.0.0/1", nil, []string{"169.254.1.1", "192.0.2.1", "224.0.0.1", "255.255.255.255"}},
	} {
		t.Run(example.prefix, func(t *testing.T) {
			prefix := netip.MustParsePrefix(example.prefix)
			for _, address := range example.allowed {
				if err := ValidateNodeIPv4(netip.MustParseAddr(address), prefix); err != nil {
					t.Fatalf("allowed address %s: %v", address, err)
				}
			}
			for _, address := range example.denied {
				if err := ValidateNodeIPv4(netip.MustParseAddr(address), prefix); err == nil {
					t.Fatalf("unsafe address accepted: %s", address)
				}
			}
		})
	}
}

func TestDeviceAddressValidation(t *testing.T) {
	prefix := netip.MustParsePrefix("100.101.50.0/24")
	if err := ValidateNodeIPv4(netip.MustParseAddr("100.101.50.20"), prefix); err != nil {
		t.Fatal(err)
	}
	for _, address := range []string{"100.101.50.0", "100.101.50.255", "100.101.51.20", "::ffff:100.101.50.20", "127.0.0.1", "100.100.100.100", "100.127.1.1"} {
		if err := ValidateNodeIPv4(netip.MustParseAddr(address), prefix); err == nil {
			t.Fatalf("invalid device address accepted: %s", address)
		}
	}
}
