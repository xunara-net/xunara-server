package netspace

import (
	"errors"
	"net/netip"
)

var clientIPv4Range = netip.MustParsePrefix("100.64.0.0/10")

var clientReservedIPv4 = []netip.Prefix{
	netip.MustParsePrefix("100.100.0.0/24"),
	netip.MustParsePrefix("100.100.100.0/24"),
	netip.MustParsePrefix("100.115.92.0/23"),
	netip.MustParsePrefix("100.127.0.0/16"),
}

// ClientReserved 返回官方客户端内部地址与 Xunara 分享地址，不能用作设备池。
func ClientReserved() []netip.Prefix {
	return append([]netip.Prefix(nil), clientReservedIPv4...)
}

// IsClientReservedIPv4 让自动分配与手动修改共用保留地址检查，不影响已有设备。
func IsClientReservedIPv4(address netip.Addr) bool {
	for _, reserved := range clientReservedIPv4 {
		if reserved.Contains(address) {
			return true
		}
	}
	return false
}

// ValidateTailnetPrefix 区分设备地址与子网路由；RFC1918 不是官方节点 IP 池。
func ValidateTailnetPrefix(prefix netip.Prefix, reserved []netip.Prefix) (netip.Prefix, error) {
	canonical, err := ValidateTenantPrefix(prefix, append(ClientReserved(), reserved...))
	if err != nil {
		return netip.Prefix{}, err
	}
	if canonical.Bits() < clientIPv4Range.Bits() || !clientIPv4Range.Contains(canonical.Addr()) {
		return netip.Prefix{}, errors.New("official clients require a subnet of 100.64.0.0/10; use subnet routes for RFC1918 networks")
	}
	return canonical, nil
}

func ValidateNodeIPv4(address netip.Addr, prefix netip.Prefix) error {
	if !address.Is4() || !prefix.IsValid() || !prefix.Contains(address) {
		return errors.New("IPv4 address must belong to the current allocation range")
	}
	if !clientIPv4Range.Contains(address) {
		return errors.New("IPv4 address is not compatible with official clients")
	}
	if IsClientReservedIPv4(address) {
		return errors.New("IPv4 address is reserved by the control plane or official clients")
	}
	base := prefix.Masked().Addr().As4()
	bytes := address.As4()
	baseValue := uint32(base[0])<<24 | uint32(base[1])<<16 | uint32(base[2])<<8 | uint32(base[3])
	value := uint32(bytes[0])<<24 | uint32(bytes[1])<<16 | uint32(bytes[2])<<8 | uint32(bytes[3])
	broadcast := baseValue | uint32((uint64(1)<<(32-prefix.Bits()))-1)
	if value == baseValue || value == broadcast {
		return errors.New("network and broadcast addresses cannot be assigned to devices")
	}
	return nil
}
