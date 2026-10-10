package netspace

import (
	"errors"
	"net/netip"
)

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

// ValidateTailnetPrefix 只校验地址安全；非 CGNAT 的客户端兼容风险由管理入口提示。
func ValidateTailnetPrefix(prefix netip.Prefix, reserved []netip.Prefix) (netip.Prefix, error) {
	return ValidateTenantPrefix(prefix, append(ClientReserved(), reserved...))
}

// IsIPv4BoundaryAddress 让自动与手动分配使用相同边界；/31、/32 是主机池。
func IsIPv4BoundaryAddress(address netip.Addr, prefix netip.Prefix) bool {
	if !address.Is4() || !prefix.IsValid() || !prefix.Addr().Is4() || !prefix.Contains(address) || prefix.Bits() >= 31 {
		return false
	}
	return address == prefix.Masked().Addr() || !prefix.Contains(address.Next())
}

func ValidateNodeIPv4(address netip.Addr, prefix netip.Prefix) error {
	if !address.Is4() || !prefix.IsValid() || !prefix.Addr().Is4() || !prefix.Contains(address) {
		return errors.New("IPv4 address must belong to the current allocation range")
	}
	for _, reserved := range Reserved() {
		if reserved.Contains(address) {
			return errors.New("IPv4 address is reserved")
		}
	}
	if IsClientReservedIPv4(address) {
		return errors.New("IPv4 address is reserved by the control plane or official clients")
	}
	if IsIPv4BoundaryAddress(address, prefix) {
		return errors.New("network and broadcast addresses cannot be assigned to devices")
	}
	return nil
}
