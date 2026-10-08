package control

import (
	"net/http"
	"slices"

	"tailscale.com/tailcfg"

	"github.com/xunara-net/xunara-server/identity"
	"github.com/xunara-net/xunara-server/policy"
	"github.com/xunara-net/xunara-server/state"
)

// Xunara Relay management plane (PROJECT_SPEC section 42): the read-only view
// of peer relays, upstream's mesh extension. Two independent facts make a
// relay work, and this plane reports both without changing either:
//
//   - a node offers to serve as an underlay UDP relay server
//     (Hostinfo.PeerRelay, set by `tailscale set --relay-server-port=…`);
//   - an ACL grant carrying tailscale.com/cap/relay authorizes a source node
//     to allocate relay endpoints from the target nodes it names.
//
// The client decides whether to use a relay at all; the control plane never
// selects one.

// relayNodeView is one node's relay posture.
type relayNodeView struct {
	NodeID   uint64 `json:"nodeId"`
	StableID string `json:"stableId"`
	Hostname string `json:"hostname"`
	Owner    string `json:"owner"`
	Online   bool   `json:"online"`

	// Announced reports that the node told control it is willing to run a
	// relay server (Hostinfo.PeerRelay).
	Announced bool `json:"announced"`
	// Disabled reports that the policy hands the node the
	// disable-relay-server node attribute: it will refuse to serve even if it
	// is willing.
	Disabled bool `json:"disabled"`
	// ClientDisabled reports that the policy hands the node the
	// disable-relay-client node attribute: it will not allocate relay
	// endpoints, so a grant naming it as a source cannot take effect.
	ClientDisabled bool `json:"clientDisabled"`
	// Targeted reports that at least one relay grant names the node as a
	// relay. It is a snapshot-level fact: the same value appears wherever the
	// node is referenced.
	Targeted bool `json:"targeted"`
}

// relayGrantView is one relay grant with both sides resolved to nodes.
type relayGrantView struct {
	Sources []relayNodeView `json:"sources"`
	Targets []relayNodeView `json:"targets"`
}

// relaysView is the JSON shape of GET /api/v2/relays.
type relaysView struct {
	Relays []relayNodeView  `json:"relays"`
	Grants []relayGrantView `json:"grants"`
}

// relaysView builds the snapshot: every node that offers to relay or is named
// as a relay by a grant, plus the resolved relay grants themselves.
func (s *Server) relaysView() relaysView {
	nodes := s.store.ListNodes()

	var grants []policy.RelayGrant
	if engine := s.policy.Load(); engine != nil {
		grants = engine.RelayGrants(nodes)
	}

	targeted := make(map[state.NodeID]bool)
	for _, grant := range grants {
		for _, id := range grant.Targets {
			targeted[id] = true
		}
	}

	byID := make(map[state.NodeID]state.Node, len(nodes))
	for _, node := range nodes {
		byID[node.ID] = node
	}

	view := relaysView{Relays: []relayNodeView{}, Grants: []relayGrantView{}}
	nodeView := func(node state.Node) relayNodeView {
		caps := s.nodeCapMap(node)
		_, disabled := caps[tailcfg.NodeAttrDisableRelayServer]
		_, clientDisabled := caps[tailcfg.NodeAttrDisableRelayClient]
		return relayNodeView{
			NodeID:         uint64(node.ID),
			StableID:       node.StableID,
			Hostname:       nodeDisplayHostname(node),
			Owner:          s.userLoginName(node.UserID),
			Online:         s.isOnline(node.ID),
			Announced:      node.Hostinfo != nil && node.Hostinfo.PeerRelay,
			Disabled:       disabled,
			ClientDisabled: clientDisabled,
			Targeted:       targeted[node.ID],
		}
	}

	for _, node := range nodes {
		announced := node.Hostinfo != nil && node.Hostinfo.PeerRelay
		if !announced && !targeted[node.ID] {
			continue
		}
		view.Relays = append(view.Relays, nodeView(node))
	}
	slices.SortFunc(view.Relays, func(a, b relayNodeView) int { return int(a.NodeID) - int(b.NodeID) })

	for _, grant := range grants {
		resolved := relayGrantView{Sources: []relayNodeView{}, Targets: []relayNodeView{}}
		for _, id := range grant.Sources {
			if node, ok := byID[id]; ok {
				resolved.Sources = append(resolved.Sources, nodeView(node))
			}
		}
		for _, id := range grant.Targets {
			if node, ok := byID[id]; ok {
				resolved.Targets = append(resolved.Targets, nodeView(node))
			}
		}
		view.Grants = append(view.Grants, resolved)
	}
	return view
}

// handleAPIV2Relays implements GET /api/v2/relays (spec section 42.2).
func (s *Server) handleAPIV2Relays(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireScope(w, r, identity.ScopeRead); !ok {
		return
	}
	writeJSON(w, http.StatusOK, s.relaysView())
}
