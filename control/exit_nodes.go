package control

import (
	"net/http"
	"slices"
	"time"

	"tailscale.com/tailcfg"

	"github.com/xunara-net/xunara-server/identity"
	"github.com/xunara-net/xunara-server/state"
)

// Xunara Horizon (PROJECT_SPEC section 40): the read-only exit-node
// management plane. It joins the two halves of the feature — nodes approved
// to serve the default route, and the clients that told control which exit
// node they selected (Hostinfo.ExitNodeID) — without ever changing either:
// approval stays on the machines page and selection stays client-local.

// exitNodeClientView is one client of an exit node.
type exitNodeClientView struct {
	NodeID   uint64 `json:"nodeId"`
	StableID string `json:"stableId"`
	Hostname string `json:"hostname"`
	Owner    string `json:"owner"`
	Online   bool   `json:"online"`
}

// exitNodeView is one approved exit node.
type exitNodeView struct {
	NodeID   uint64 `json:"nodeId"`
	StableID string `json:"stableId"`
	Hostname string `json:"hostname"`
	Owner    string `json:"owner"`
	Online   bool   `json:"online"`
	// Announced reports whether the node is still advertising the default
	// route; approval without announcement is a misconfiguration to surface.
	Announced bool                 `json:"announced"`
	IPv4      string               `json:"ipv4,omitempty"`
	IPv6      string               `json:"ipv6,omitempty"`
	DERPHome  tailcfg.DERPRegionID `json:"derpHome,omitempty"`
	LastSeen  *time.Time           `json:"lastSeen,omitzero"`

	ClientCount int                  `json:"clientCount"`
	Clients     []exitNodeClientView `json:"clients"`
}

// exitNodeSelectionView is one node's exit-node selection.
type exitNodeSelectionView struct {
	NodeID   uint64 `json:"nodeId"`
	StableID string `json:"stableId"`
	Hostname string `json:"hostname"`
	Owner    string `json:"owner"`
	Online   bool   `json:"online"`
	// ExitNodeStableID is the stable ID the client reported.
	ExitNodeStableID string `json:"exitNodeStableId"`
	// ExitNodeHostname names the selected node when it still exists,
	// whether or not it is an approved exit node.
	ExitNodeHostname string `json:"exitNodeHostname,omitempty"`
	// Resolved reports whether the selection is an approved exit node right
	// now. Unresolved selections are kept visible, never silently dropped.
	Resolved bool `json:"resolved"`
}

// exitNodesView is the JSON shape of GET /api/v2/exit-nodes.
type exitNodesView struct {
	ExitNodes []exitNodeView          `json:"exitNodes"`
	Clients   []exitNodeSelectionView `json:"clients"`
}

// exitNodesView builds the snapshot. Exit nodes are ordered by node ID and
// clients by node ID, like every other management list.
func (s *Server) exitNodesView() exitNodesView {
	nodes := s.store.ListNodes()

	byStableID := make(map[string]state.Node, len(nodes))
	for _, node := range nodes {
		if node.StableID != "" {
			byStableID[node.StableID] = node
		}
	}

	view := exitNodesView{ExitNodes: []exitNodeView{}, Clients: []exitNodeSelectionView{}}
	index := make(map[string]int) // stable ID -> index in ExitNodes
	for _, node := range nodes {
		if !nodeHasApprovedExitRoute(node) {
			continue
		}
		index[node.StableID] = len(view.ExitNodes)
		view.ExitNodes = append(view.ExitNodes, exitNodeView{
			NodeID:    uint64(node.ID),
			StableID:  node.StableID,
			Hostname:  nodeDisplayHostname(node),
			Owner:     s.userLoginName(node.UserID),
			Online:    s.isOnline(node.ID),
			Announced: node.IsExitNode(),
			IPv4:      addrString(node.IPv4),
			IPv6:      addrString(node.IPv6),
			DERPHome:  node.HomeDERP,
			LastSeen:  node.LastSeen,
			Clients:   []exitNodeClientView{},
		})
	}

	for _, node := range nodes {
		if node.Hostinfo == nil || node.Hostinfo.ExitNodeID == "" {
			continue
		}
		selection := exitNodeSelectionView{
			NodeID:           uint64(node.ID),
			StableID:         node.StableID,
			Hostname:         nodeDisplayHostname(node),
			Owner:            s.userLoginName(node.UserID),
			Online:           s.isOnline(node.ID),
			ExitNodeStableID: string(node.Hostinfo.ExitNodeID),
		}
		if selected, ok := byStableID[selection.ExitNodeStableID]; ok {
			selection.ExitNodeHostname = nodeDisplayHostname(selected)
		}
		if i, ok := index[selection.ExitNodeStableID]; ok {
			selection.Resolved = true
			view.ExitNodes[i].Clients = append(view.ExitNodes[i].Clients, exitNodeClientView{
				NodeID:   selection.NodeID,
				StableID: selection.StableID,
				Hostname: selection.Hostname,
				Owner:    selection.Owner,
				Online:   selection.Online,
			})
		}
		view.Clients = append(view.Clients, selection)
	}

	slices.SortFunc(view.ExitNodes, func(a, b exitNodeView) int {
		return int(a.NodeID) - int(b.NodeID)
	})
	slices.SortFunc(view.Clients, func(a, b exitNodeSelectionView) int {
		return int(a.NodeID) - int(b.NodeID)
	})
	for i := range view.ExitNodes {
		view.ExitNodes[i].ClientCount = len(view.ExitNodes[i].Clients)
	}
	return view
}

// nodeHasApprovedExitRoute reports whether the node carries an approved
// default route. Announcement is reported separately (exitNodeView.Announced).
func nodeHasApprovedExitRoute(node state.Node) bool {
	for _, route := range node.ApprovedRoutes {
		if state.IsExitRoute(route) {
			return true
		}
	}
	return false
}

// handleAPIV2ExitNodes implements GET /api/v2/exit-nodes (spec section 40.2).
func (s *Server) handleAPIV2ExitNodes(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireScope(w, r, identity.ScopeRead); !ok {
		return
	}
	writeJSON(w, http.StatusOK, s.exitNodesView())
}
