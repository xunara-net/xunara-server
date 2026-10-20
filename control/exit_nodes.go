package control

import (
	"net/http"
	"slices"
	"time"

	"tailscale.com/tailcfg"

	"github.com/xunara-net/xunara-server/identity"
	"github.com/xunara-net/xunara-server/state"
)

// 出口总览只合并审批与客户端自报选择，不替用户修改客户端本地偏好。
// 路由审批由独立的事务写入流程完成，自报选择不证明实时流量。

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
	// Announced reports whether both default routes are still effective;
	// partial approval or a withdrawn announcement must not look selectable.
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
	// Resolved reports whether both default routes are advertised and approved.
	// Unresolved selections are kept visible, never silently dropped.
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
	return s.exitNodesViewFor(s.store.ListNodes())
}

func (s *Server) exitNodesViewFor(nodes []state.Node) exitNodesView {

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
			selection.Resolved = byStableID[selection.ExitNodeStableID].IsExitNode()
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
	w.Header().Set("Cache-Control", "no-store")
	if _, ok := s.requireScope(w, r, identity.ScopeRead); !ok {
		return
	}
	nodes, err := s.networkNodes(r.Context())
	if err != nil {
		s.writeNetworkError(w, err)
		return
	}
	view := s.exitNodesViewFor(nodes)
	if len(view.ExitNodes) > routeOverviewLimit || len(view.Clients) > routeOverviewLimit*2 {
		s.writeRouteManagementError(w, errRouteViewLarge)
		return
	}
	writeJSON(w, http.StatusOK, view)
}
