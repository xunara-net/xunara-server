package control

import (
	"fmt"
	"hash/fnv"
	"slices"
	"sync"

	"tailscale.com/tailcfg"

	"github.com/xunara-net/xunara-server/policy"
	"github.com/xunara-net/xunara-server/state"
)

// Xunara Atlas: ACL-derived service visibility (PROJECT_SPEC section 48).
//
// A service may derive its discovery from the ACL instead of a selector list:
// a node discovers it exactly when the packet filter lets that node connect to
// the publishing machine on the service's protocol and port. The evaluation
// uses the destination's ingress filter - the same rules the publisher's
// client enforces - so "visible" means "the connection would be accepted",
// and discovery still grants nothing by itself.

// aclIngressCache memoizes the ingress filter of each destination node.
// Compiling a filter costs the same order of work as building one netmap, so
// it is done once per policy engine and node snapshot instead of once per
// service or per viewer. The snapshot excludes volatile fields (endpoints,
// liveness, hostinfo), so ordinary traffic does not invalidate the cache.
type aclIngressCache struct {
	mu     sync.Mutex
	engine *policy.Engine
	stamp  uint64
	rules  map[state.NodeID][]tailcfg.FilterRule
}

// filterACLDerivedServices removes the services whose declaration derives
// visibility from the ACL when this node may not connect to them. The caller
// has already applied the selector visibility (services with a selector list
// keep that result); the publisher always keeps its own services.
func (s *Server) filterACLDerivedServices(self state.Node, services []state.Service, visible map[string]bool) {
	if !slices.ContainsFunc(services, func(svc state.Service) bool { return svc.VisibilityFromACL }) {
		return
	}
	engine := s.policy.Load()
	if engine == nil {
		// Without a policy document every node may reach every node, so the
		// derived visibility is the organization default.
		return
	}
	nodes := s.store.ListNodes()
	stamp := aclNodeStamp(nodes)

	for _, svc := range services {
		if !svc.VisibilityFromACL || !visible[svc.Name] || svc.NodeID == self.ID {
			continue
		}
		publisher, ok := s.store.GetNodeByID(svc.NodeID)
		if !ok {
			visible[svc.Name] = false
			continue
		}
		rules := s.aclIngressRules(engine, stamp, nodes, publisher)
		if !policy.AllowsIngress(rules, publisher, self, svc.Protocol, svc.Port) {
			visible[svc.Name] = false
		}
	}
}

// aclIngressRules returns the ingress filter of dst, memoized for the current
// engine and node snapshot.
func (s *Server) aclIngressRules(engine *policy.Engine, stamp uint64, nodes []state.Node, dst state.Node) []tailcfg.FilterRule {
	c := &s.aclIngress
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.engine != engine || c.stamp != stamp {
		c.engine = engine
		c.stamp = stamp
		c.rules = make(map[state.NodeID][]tailcfg.FilterRule)
	}
	if rules, ok := c.rules[dst.ID]; ok {
		return rules
	}
	rules := s.packetFilterForNodes(dst, nodes)
	c.rules[dst.ID] = rules
	return rules
}

// aclNodeStamp fingerprints the policy-relevant facts of a node snapshot:
// identities, addresses and tags, in a deterministic order.
func aclNodeStamp(nodes []state.Node) uint64 {
	ordered := slices.Clone(nodes)
	slices.SortFunc(ordered, func(a, b state.Node) int { return int(a.ID) - int(b.ID) })

	h := fnv.New64a()
	for _, n := range ordered {
		fmt.Fprintf(h, "%d/%d/%v/%v/%v|", n.ID, n.UserID, n.Tags, n.IPv4, n.IPv6)
	}
	return h.Sum64()
}
