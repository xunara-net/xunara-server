package netspace

import (
	"net/netip"
	"testing"
)

func TestOfficialClientAllocationRanges(t *testing.T) {
	for _, value := range []string{"100.101.50.12/24", "100.70.0.0/16", "100.126.1.0/28"} {
		prefix, err := ValidateTailnetPrefix(netip.MustParsePrefix(value), nil)
		if err != nil || prefix != netip.MustParsePrefix(value).Masked() {
			t.Fatalf("valid range %s: %s %v", value, prefix, err)
		}
	}
	for _, value := range []string{"192.168.50.0/24", "10.10.0.0/24", "100.63.0.0/16", "100.100.0.0/24", "100.100.100.0/24", "100.115.92.0/24", "100.127.0.0/24", "100.64.0.0/10", "100.70.0.0/29", "fd7a:115c:a1e0::/64"} {
		if _, err := ValidateTailnetPrefix(netip.MustParsePrefix(value), nil); err == nil {
			t.Fatalf("invalid device range accepted: %s", value)
		}
	}
	if _, err := ValidateTailnetPrefix(netip.MustParsePrefix("100.101.50.0/24"), []netip.Prefix{netip.MustParsePrefix("100.101.50.128/25")}); err == nil {
		t.Fatal("deployment reserved range accepted")
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
