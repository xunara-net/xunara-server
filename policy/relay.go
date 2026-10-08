package policy

import (
	"slices"

	"tailscale.com/tailcfg"

	"github.com/xunara-net/xunara-server/state"
)

// This file exposes the document's peer-relay authorizations as a resolved,
// read-only view for the management plane (PROJECT_SPEC section 42). The
// wire side already exists: a "grants" row whose app map carries
// tailscale.com/cap/relay compiles into tailcfg.FilterRule.CapGrant entries
// (grants.go), and clients allocate relay endpoints from them. Nothing here
// changes the netmap.

// RelayGrant is one "grants" row carrying tailscale.com/cap/relay, resolved
// against a node snapshot: Sources may allocate relay endpoints from Targets.
//
// A destination of autogroup:self is expanded per source node, because "my
// own devices may relay for each other" is a different target set for every
// user.
type RelayGrant struct {
	Sources []state.NodeID
	Targets []state.NodeID
}

// RelayGrants returns the relay grants in document order, each resolved to
// node IDs. A row that resolves to no source or no target node is dropped:
// an empty relation authorizes nothing.
func (e *Engine) RelayGrants(nodes []state.Node) []RelayGrant {
	var out []RelayGrant

	byID := make(map[state.NodeID]state.Node, len(nodes))
	for _, n := range nodes {
		byID[n.ID] = n
	}

	for _, grant := range e.grants {
		if _, ok := grant.app[tailcfg.PeerCapabilityRelay]; !ok {
			continue
		}

		r := &resolution{engine: e, nodes: nodes}
		sources := sortedIDSet(r.nodesForSelectors(grant.src))
		if len(sources) == 0 {
			continue
		}
		if !grant.selfOnly {
			targets := sortedIDSet(r.nodesForSelectors(grant.dst))
			if len(targets) == 0 {
				continue
			}
			out = append(out, RelayGrant{Sources: sources, Targets: targets})
			continue
		}
		for _, id := range sources {
			self := &resolution{engine: e, self: byID[id], nodes: nodes}
			targets := sortedNodeIDs(self.selfNodes())
			if len(targets) == 0 {
				continue
			}
			out = append(out, RelayGrant{Sources: []state.NodeID{id}, Targets: targets})
		}
	}
	return out
}

// sortedNodeIDs turns a node list into IDs sorted ascending, so every caller
// renders the same order.
func sortedNodeIDs(nodes []state.Node) []state.NodeID {
	out := make([]state.NodeID, 0, len(nodes))
	for _, n := range nodes {
		out = append(out, n.ID)
	}
	slices.Sort(out)
	return out
}

// sortedIDSet turns a node-ID set into a sorted list.
func sortedIDSet(ids map[state.NodeID]bool) []state.NodeID {
	out := make([]state.NodeID, 0, len(ids))
	for id := range ids {
		out = append(out, id)
	}
	slices.Sort(out)
	return out
}
