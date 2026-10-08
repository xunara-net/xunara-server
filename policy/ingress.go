package policy

import (
	"net/netip"
	"slices"

	"tailscale.com/tailcfg"

	"github.com/xunara-net/xunara-server/state"
)

// AllowsIngress reports whether a node's compiled ingress filter - the
// Tailscale packet-filter rules the destination receives in its netmap - lets
// src connect to dst on proto/port. Xunara Atlas uses it for ACL-derived
// service visibility (spec section 48): visibility follows connectivity, so the
// question is answered with exactly the rules the destination's client
// enforces, not with a second, drifting interpretation of the document.
//
// proto is a service protocol ("tcp" or "udp"). A rule without a protocol list
// matches TCP, UDP and ICMP (the upstream tailcfg semantics), so both service
// protocols pass it.
//
// Destination entries that denote "the internet" (autogroup:internet compiles
// to 0.0.0.0/0 and ::/0) never grant access to a tailnet address: they
// authorise exit-node traffic, not intra-tailnet connections. Anything that
// cannot be parsed is skipped, so an unknown form denies rather than widens.
func AllowsIngress(rules []tailcfg.FilterRule, dst, src state.Node, proto string, port uint16) bool {
	num, ok := ianaProtocols[proto]
	if !ok {
		return false
	}
	srcAddrs := nodeAddrs(src)
	dstAddrs := nodeAddrs(dst)
	if len(srcAddrs) == 0 || len(dstAddrs) == 0 {
		return false
	}

	for _, rule := range rules {
		if !protocolMatches(rule.IPProto, num) {
			continue
		}
		if !sourceMatches(rule.SrcIPs, srcAddrs) {
			continue
		}
		for _, dstPort := range rule.DstPorts {
			if !dstPort.Ports.Contains(port) {
				continue
			}
			if destinationMatches(dstPort.IP, dstAddrs) {
				return true
			}
		}
	}
	return false
}

// nodeAddrs returns the node's own addresses, the ones a filter must contain
// for a connection to reach it.
func nodeAddrs(n state.Node) []netip.Addr {
	var out []netip.Addr
	if n.IPv4.IsValid() {
		out = append(out, n.IPv4)
	}
	if n.IPv6.IsValid() {
		out = append(out, n.IPv6)
	}
	return out
}

// protocolMatches applies the tailcfg rule: an empty protocol list means TCP,
// UDP and ICMP; otherwise the wanted number must be listed.
func protocolMatches(protos []int, want int) bool {
	if len(protos) == 0 {
		return want == ianaProtocols["tcp"] || want == ianaProtocols["udp"]
	}
	return slices.Contains(protos, want)
}

// sourceMatches reports whether any of the node's addresses is covered by one
// of the rule's source entries ("*", a bare IP or a CIDR).
func sourceMatches(entries []string, addrs []netip.Addr) bool {
	for _, entry := range entries {
		if entry == "*" {
			return true
		}
		prefix, ok := parsePrefixEntry(entry)
		if !ok {
			continue
		}
		for _, addr := range addrs {
			if prefix.Contains(addr) {
				return true
			}
		}
	}
	return false
}

// destinationMatches reports whether a rule's destination entry covers the
// node. The /0 prefixes are "the internet" and never match a tailnet node.
func destinationMatches(entry string, addrs []netip.Addr) bool {
	if entry == "*" {
		return true
	}
	prefix, ok := parsePrefixEntry(entry)
	if !ok || prefix.Bits() == 0 {
		return false
	}
	for _, addr := range addrs {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

// parsePrefixEntry parses the entry forms the compiler emits: a bare IP or a
// CIDR (FilterRule.SrcIPs and NetPortRange.IP).
func parsePrefixEntry(entry string) (netip.Prefix, bool) {
	if addr, err := netip.ParseAddr(entry); err == nil {
		return netip.PrefixFrom(addr, addr.BitLen()), true
	}
	if prefix, err := netip.ParsePrefix(entry); err == nil {
		return prefix.Masked(), true
	}
	return netip.Prefix{}, false
}
