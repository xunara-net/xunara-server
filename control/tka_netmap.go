package control

import (
	"net/netip"
	"slices"

	"tailscale.com/tailcfg"

	"github.com/xunara-net/xunara-server/state"
)

// This file adapts tailnet-lock (TKA) state into the netmap: the TKAInfo
// header clients sync against, the per-node key signatures they verify, and
// the packet-filter narrowing required when some peers are unsigned.

// tkaInfo returns the tailnet-lock state to advertise in a netmap.
//
// Nil means "this tailnet never had tailnet lock", which clients distinguish
// from an explicit disablement (Disabled: true); the wire type needs that
// distinction because nil in a delta response means "unchanged".
func (s *Server) tkaInfo() *tailcfg.TKAInfo {
	view := s.tka.view()
	switch {
	case !view.EverEnabled:
		return nil
	case view.Enabled:
		return &tailcfg.TKAInfo{Head: view.Head}
	case view.Disabled:
		return &tailcfg.TKAInfo{Disabled: true}
	default:
		// An init that never reached init/finish: there is nothing for
		// clients to do yet, and nil means "no change".
		return nil
	}
}

// unsignedPeers returns the IDs of nodes whose node keys tailnet lock does not
// currently authorize, or nil when the tailnet is not locked.
//
// A node is unsigned when it has no stored node-key signature. Clients verify
// signatures themselves, so a signature that no longer verifies (for example
// after `lock revoke-keys`) is dropped by the peers that receive it.
func (s *Server) unsignedPeers(nodes []state.Node) map[state.NodeID]bool {
	if !s.tka.view().Enabled {
		return nil
	}
	var out map[state.NodeID]bool
	for _, n := range nodes {
		if len(n.KeySignature) == 0 {
			if out == nil {
				out = make(map[state.NodeID]bool)
			}
			out[n.ID] = true
		}
	}
	return out
}

// restrictFilterToSignedPeers rewrites a packet filter so that no unsigned
// peer can be a source.
//
// Clients reject a packet filter that permits an UnsignedPeerAPIOnly peer
// (reference/tailscale/ipn/ipnlocal/local.go:packetFilterPermitsUnlockedNodes)
// and then block everything, so a locked tailnet with an unsigned node must
// never be sent a wildcard rule. Wildcard and internet sources are replaced
// with the signed nodes' own addresses and the routes they serve; rules whose
// explicit sources overlap an unsigned peer are dropped, because a partial
// subtraction could silently permit it.
func restrictFilterToSignedPeers(rules []tailcfg.FilterRule, unsigned map[state.NodeID]bool, nodes []state.Node) []tailcfg.FilterRule {
	if len(unsigned) == 0 {
		return rules
	}

	var banned []netip.Prefix
	for _, n := range nodes {
		if unsigned[n.ID] {
			banned = append(banned, nodePrefixes(n)...)
		}
	}

	var signed []string
	for _, n := range nodes {
		if unsigned[n.ID] {
			continue
		}
		// A signed subnet router forwards traffic from the routes it serves,
		// so those prefixes stay permitted as sources too. Exit routes are
		// skipped: they are /0 and would re-permit every unsigned peer, which
		// is exactly what this function prevents.
		for _, r := range n.EffectiveRoutes() {
			if !state.IsExitRoute(r) {
				signed = append(signed, r.String())
			}
		}
	}
	for _, n := range nodes {
		if unsigned[n.ID] {
			continue
		}
		for _, p := range nodePrefixes(n) {
			signed = append(signed, p.String())
		}
	}
	signed = slices.Compact(slices.Sorted(slices.Values(signed)))

	out := make([]tailcfg.FilterRule, 0, len(rules))
	for _, rule := range rules {
		srcs := make([]string, 0, len(rule.SrcIPs))
		for _, src := range rule.SrcIPs {
			switch src {
			case "*", "0.0.0.0/0", "::/0":
				srcs = append(srcs, signed...)
			default:
				if prefixOverlapsAny(src, banned) {
					continue
				}
				srcs = append(srcs, src)
			}
		}
		srcs = slices.Compact(slices.Sorted(slices.Values(srcs)))
		if len(srcs) == 0 {
			continue
		}
		rule.SrcIPs = srcs
		out = append(out, rule)
	}
	return out
}

// nodePrefixes returns a node's own tailnet addresses as /32 or /128 prefixes.
func nodePrefixes(n state.Node) []netip.Prefix {
	var out []netip.Prefix
	if n.IPv4.IsValid() {
		out = append(out, netip.PrefixFrom(n.IPv4, n.IPv4.BitLen()))
	}
	if n.IPv6.IsValid() {
		out = append(out, netip.PrefixFrom(n.IPv6, n.IPv6.BitLen()))
	}
	return out
}

// prefixOverlapsAny reports whether src (an IP or CIDR string) overlaps any of
// the given prefixes. Unparseable sources are reported as overlapping so a
// rule this build cannot reason about fails closed.
func prefixOverlapsAny(src string, prefixes []netip.Prefix) bool {
	p, err := netip.ParsePrefix(src)
	if err != nil {
		addr, err := netip.ParseAddr(src)
		if err != nil {
			return true
		}
		p = netip.PrefixFrom(addr, addr.BitLen())
	}
	for _, b := range prefixes {
		if p.Overlaps(b) {
			return true
		}
	}
	return false
}
