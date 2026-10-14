package control

import (
	"net/netip"
	"strings"

	"github.com/xunara-net/xunara-server/state"
	"go4.org/netipx"
	"tailscale.com/tailcfg"
)

// quarantine 不允许共享机器主动连入接收方；官方客户端有状态过滤器仍允许回复。
// 互相分享时同一节点有 sharee 授权，因此保留该节点的发起权限。
func restrictShareFilter(rules []tailcfg.FilterRule, nodes []state.Node) []tailcfg.FilterRule {
	blocked := make(map[netip.Addr]bool)
	allowed := make(map[netip.Addr]bool)
	for _, node := range nodes {
		if !strings.HasPrefix(node.StableID, "share:") {
			continue
		}
		for _, prefix := range nodePrefixes(node) {
			if node.Hostinfo != nil && node.Hostinfo.ShareeNode {
				allowed[prefix.Addr()] = true
			} else {
				blocked[prefix.Addr()] = true
			}
		}
	}
	for address := range allowed {
		delete(blocked, address)
	}
	if len(blocked) == 0 {
		return rules
	}
	out := make([]tailcfg.FilterRule, 0, len(rules))
	for _, rule := range rules {
		var sources netipx.IPSetBuilder
		for _, raw := range rule.SrcIPs {
			if raw == "*" {
				sources.AddPrefix(netip.MustParsePrefix("0.0.0.0/0"))
				sources.AddPrefix(netip.MustParsePrefix("::/0"))
				continue
			}
			if prefix, err := netip.ParsePrefix(raw); err == nil {
				sources.AddPrefix(prefix)
			} else if address, err := netip.ParseAddr(raw); err == nil {
				sources.Add(address)
			}
		}
		for address := range blocked {
			sources.Remove(address)
		}
		set, err := sources.IPSet()
		if err != nil {
			continue
		}
		rule.SrcIPs = make([]string, 0)
		rule.SrcBits = nil
		for _, prefix := range set.Prefixes() {
			rule.SrcIPs = append(rule.SrcIPs, prefix.String())
		}
		if len(rule.SrcIPs) != 0 {
			out = append(out, rule)
		}
	}
	return out
}
