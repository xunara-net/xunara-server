package policy

import (
	"fmt"
	"net/netip"
	"strings"

	"tailscale.com/tailcfg"

	"github.com/xunara-net/xunara-server/state"
)

// This file compiles the document's "grants" section (ACL v2) into the same
// packet filter the ACLs produce, plus tailcfg.CapGrant entries that carry
// per-peer application capabilities ("app").
//
// Semantics follow reference/headscale/hscontrol/policy/v2/compiled.go
// (compileGrants, compileOtherDests) and the upstream FilterRule/CapGrant
// types. "via" grants are not implemented and are rejected at load time.

// tailnetPrefixes are the address ranges a wildcard destination resolves to
// for CapGrant.Dsts, which cannot hold the wire "*" form. They mirror the
// allocator in package state.
var tailnetPrefixes = []netip.Prefix{
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("fd7a:115c:a1e0::/48"),
}

// companionCap pairs a granted capability with the reversed rule Tailscale
// generates alongside it: when a grant hands a node the left capability, the
// peers it grants toward receive the right one (references
// peercap.Taildrive/TaildriveSharer and Relay/RelayTarget).
type companionCap struct {
	original  tailcfg.PeerCapability
	companion tailcfg.PeerCapability
}

var companionCaps = []companionCap{
	{"tailscale.com/cap/drive", "tailscale.com/cap/drive-sharer"},
	{"tailscale.com/cap/relay", "tailscale.com/cap/relay-target"},
}

// compiledGrant is a validated "grants" row.
type compiledGrant struct {
	// index is the row's position in the document, for warnings.
	index int

	src []selector
	dst []selector

	// selfOnly reports that dst named autogroup:self: the rule then applies
	// between devices of the node's user.
	selfOnly bool

	// ips are the parsed "ip" entries. An empty list means the grant grants
	// only capabilities, no traffic.
	ips []grantIP

	app tailcfg.PeerCapMap
}

// grantIP is one parsed "protocol:ports" entry.
type grantIP struct {
	proto []int
	ports []tailcfg.PortRange
}

// compileGrants validates and classifies the document's grant rows.
func (e *Engine) compileGrants() error {
	for i, row := range e.doc.Grants {
		grant, err := e.compileGrant(i, row)
		if err != nil {
			return fmt.Errorf("policy: grants[%d]: %w", i, err)
		}
		e.grants = append(e.grants, grant)
	}
	return nil
}

func (e *Engine) compileGrant(index int, row GrantRow) (compiledGrant, error) {
	grant := compiledGrant{index: index}

	if len(row.Via) > 0 {
		return grant, fmt.Errorf("via grants are not supported by this build")
	}
	if len(row.Src) == 0 {
		return grant, fmt.Errorf("src is required")
	}
	if len(row.Dst) == 0 {
		return grant, fmt.Errorf("dst is required")
	}
	if len(row.IP) == 0 && len(row.App) == 0 {
		return grant, fmt.Errorf("at least one of ip or app is required")
	}

	for _, s := range row.Src {
		sel, err := e.classifySource(s)
		if err != nil {
			return grant, fmt.Errorf("src: %w", err)
		}
		grant.src = append(grant.src, sel)
	}
	for _, d := range row.Dst {
		sel, err := e.classifyHost(d, false)
		if err != nil {
			return grant, fmt.Errorf("dst: %w", err)
		}
		if sel.kind == selSelf {
			grant.selfOnly = true
			continue
		}
		grant.dst = append(grant.dst, sel)
	}

	for _, entry := range row.IP {
		proto, ports, err := parseGrantIP(entry)
		if err != nil {
			return grant, fmt.Errorf("ip: %w", err)
		}
		grant.ips = append(grant.ips, grantIP{proto: proto, ports: ports})
	}

	if len(row.App) > 0 {
		grant.app = make(tailcfg.PeerCapMap, len(row.App))
		for name, values := range row.App {
			if name == "" || len(name) > maxAttrLength || strings.ContainsAny(name, " \t\r\n\"") {
				return grant, fmt.Errorf("app: %q is not a capability name", name)
			}
			caps := make([]tailcfg.RawMessage, len(values))
			for i, value := range values {
				caps[i] = tailcfg.RawMessage(value)
			}
			grant.app[tailcfg.PeerCapability(name)] = caps
		}
	}

	return grant, nil
}

// parseGrantIP parses one "ip" entry: "*", "tcp:443", "udp:6000-6100", or a
// bare port list with no protocol restriction.
func parseGrantIP(entry string) ([]int, []tailcfg.PortRange, error) {
	entry = strings.TrimSpace(entry)
	if entry == "" {
		return nil, nil, fmt.Errorf("empty entry")
	}
	if entry == "*" {
		return nil, []tailcfg.PortRange{tailcfg.PortRangeAny}, nil
	}

	protoSpec, portSpec, hasProto := strings.Cut(entry, ":")
	if !hasProto {
		ports, err := parsePorts(entry)
		if err != nil {
			return nil, nil, fmt.Errorf("%q: %w", entry, err)
		}
		return nil, ports, nil
	}

	proto, err := parseProto(protoSpec)
	if err != nil {
		return nil, nil, fmt.Errorf("%q: %w", entry, err)
	}
	ports, err := parsePorts(portSpec)
	if err != nil {
		return nil, nil, fmt.Errorf("%q: %w", entry, err)
	}
	return proto, ports, nil
}

// grantFilterRules compiles the grant rows for one destination snapshot.
func (e *Engine) grantFilterRules(r *resolution) []tailcfg.FilterRule {
	var out []tailcfg.FilterRule

	for _, grant := range e.grants {
		srcIPs := r.sourceIPs(grant.src)
		if len(srcIPs) == 0 {
			continue
		}

		for _, spec := range grant.ips {
			dstPorts := r.destinations(r.grantDstSelectors(grant, spec.ports))
			if len(dstPorts) == 0 {
				continue
			}
			out = append(out, tailcfg.FilterRule{
				SrcIPs:   srcIPs,
				DstPorts: dstPorts,
				IPProto:  spec.proto,
			})
		}

		if len(grant.app) == 0 {
			continue
		}
		dstPrefixes := r.grantDstPrefixes(grant)
		if len(dstPrefixes) == 0 {
			continue
		}
		out = append(out, tailcfg.FilterRule{
			SrcIPs: srcIPs,
			CapGrant: []tailcfg.CapGrant{{
				Dsts:   dstPrefixes,
				CapMap: grant.app,
			}},
		})
		out = append(out, companionCapGrantRules(r.grantDstIPs(grant), r.sourcePrefixes(grant.src), grant.app)...)
	}

	return out
}

// companionCapGrantRules returns the reversed rules Tailscale emits for
// well-known capabilities: SrcIPs are the original destinations (as wire
// strings) and CapGrant.Dsts the original sources, so a node can ask whether a
// peer may share a drive (or allocate a relay) toward it.
func companionCapGrantRules(dstIPStrings []string, srcPrefixes []netip.Prefix, app tailcfg.PeerCapMap) []tailcfg.FilterRule {
	var out []tailcfg.FilterRule
	for _, c := range companionCaps {
		if _, ok := app[c.original]; !ok {
			continue
		}
		out = append(out, tailcfg.FilterRule{
			SrcIPs: dstIPStrings,
			CapGrant: []tailcfg.CapGrant{{
				Dsts:   srcPrefixes,
				CapMap: tailcfg.PeerCapMap{c.companion: nil},
			}},
		})
	}
	return out
}

// grantDstSelectors pairs the grant's destination selectors with one ip
// entry's ports, so the ACL compiler's destination resolution can be reused.
func (r *resolution) grantDstSelectors(grant compiledGrant, ports []tailcfg.PortRange) []dstSelector {
	out := make([]dstSelector, 0, len(grant.dst)+1)
	for _, sel := range grant.dst {
		out = append(out, dstSelector{host: sel, ports: ports})
	}
	if grant.selfOnly {
		out = append(out, dstSelector{host: selector{kind: selSelf, raw: "autogroup:self"}, ports: ports})
	}
	return out
}

// grantDstPrefixes resolves the grant's destinations as prefixes, the form
// CapGrant.Dsts needs.
func (r *resolution) grantDstPrefixes(grant compiledGrant) []netip.Prefix {
	var out []netip.Prefix
	add := func(sel selector) {
		for _, prefix := range r.hostPrefixes(sel) {
			if !containsPrefix(out, prefix) {
				out = append(out, prefix)
			}
		}
	}
	for _, sel := range grant.dst {
		add(sel)
	}
	if grant.selfOnly {
		add(selector{kind: selSelf, raw: "autogroup:self"})
	}
	return out
}

// grantDstIPs resolves the grant's destinations as wire IP strings, used as
// the sources of companion cap rules.
func (r *resolution) grantDstIPs(grant compiledGrant) []string {
	var out []string
	add := func(sel selector) {
		for _, ip := range r.hostIPs(sel) {
			if !slicesContains(out, ip) {
				out = append(out, ip)
			}
		}
	}
	for _, sel := range grant.dst {
		add(sel)
	}
	if grant.selfOnly {
		add(selector{kind: selSelf, raw: "autogroup:self"})
	}
	return out
}

// sourcePrefixes resolves source selectors as prefixes.
func (r *resolution) sourcePrefixes(sels []selector) []netip.Prefix {
	var out []netip.Prefix
	for _, sel := range sels {
		for _, prefix := range r.hostPrefixes(sel) {
			if !containsPrefix(out, prefix) {
				out = append(out, prefix)
			}
		}
	}
	return out
}

// hostPrefixes resolves a host selector to prefixes. Wildcard becomes the
// tailnet ranges because CapGrant.Dsts cannot hold the wire "*" form.
func (r *resolution) hostPrefixes(sel selector) []netip.Prefix {
	if sel.kind == selWildcard {
		prefixes := append([]netip.Prefix(nil), tailnetPrefixes...)
		// 标准范围维持兼容；非标准地址只覆盖实际节点，不扩大到整个局域网。
		for _, node := range append(append([]state.Node(nil), r.nodes...), r.self) {
			for _, address := range []netip.Addr{node.IPv4, node.IPv6} {
				if !address.IsValid() || address.IsUnspecified() {
					continue
				}
				covered := false
				for _, prefix := range prefixes {
					if prefix.Contains(address) {
						covered = true
						break
					}
				}
				if !covered {
					prefixes = append(prefixes, netip.PrefixFrom(address, address.BitLen()))
				}
			}
		}
		return prefixes
	}

	var out []netip.Prefix
	for _, ip := range r.hostIPs(sel) {
		prefix, err := netip.ParsePrefix(ip)
		if err != nil {
			continue
		}
		out = append(out, prefix)
	}
	return out
}

func containsPrefix(prefixes []netip.Prefix, want netip.Prefix) bool {
	for _, p := range prefixes {
		if p == want {
			return true
		}
	}
	return false
}

func slicesContains(haystack []string, want string) bool {
	for _, s := range haystack {
		if s == want {
			return true
		}
	}
	return false
}
