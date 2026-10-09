package control

import (
	"net/http"
	"slices"
	"sort"

	"tailscale.com/tailcfg"

	"github.com/xunara-net/xunara-server/identity"
)

// This file is the read-only DERP management surface (PROJECT_SPEC section 32):
// which regions this organization serves its clients, and where its nodes are
// homed. The policy itself is startup/organization-table configuration; there
// is no write path here.

// derpRegionView is one DERP region the served map actually advertises.
type derpRegionView struct {
	ID        int32    `json:"id"`
	Code      string   `json:"code"`
	Name      string   `json:"name"`
	Hosts     []string `json:"hosts"`
	NodeCount int      `json:"nodeCount"`
}

// derpStatusView is the JSON shape of GET /api/v2/derp.
type derpStatusView struct {
	PolicyMode    string  `json:"policyMode"`
	PolicyRegions []int32 `json:"policyRegions"`
	// MapConfigured distinguishes "the deployment configured no map" (nil:
	// clients keep their built-in default regions) from a map that serves no
	// regions (policy none tells clients there is no DERP at all). Both
	// report RegionsServed == 0; they are not the same instruction.
	MapConfigured         bool             `json:"mapConfigured"`
	RegionsServed         int              `json:"regionsServed"`
	Regions               []derpRegionView `json:"regions"`
	NodesWithoutHome      int              `json:"nodesWithoutHome"`
	NodesWithUnservedHome int              `json:"nodesWithUnservedHome"`
}

// derpNodeView is one node's placement, rendered on the console. It stays out
// of the JSON shape: counts are enough for automation, and a large tailnet
// must not turn one API response into a node dump.
type derpNodeView struct {
	StableID string
	Hostname string
	Online   bool
	// Home is the region the node is homed to; zero means none chosen yet.
	Home tailcfg.DERPRegionID
	// Unserved marks a home region the served map no longer contains; the
	// next map request clears it and re-homes the node.
	Unserved bool
}

// derpStatus renders the DERP state of this organization. It returns the API
// view and the per-node placement the console builds its table from.
func (s *Server) derpStatus() (derpStatusView, []derpNodeView) {
	counts := make(map[tailcfg.DERPRegionID]int)
	nodes := s.store.ListNodes()
	nodeViews := make([]derpNodeView, 0, len(nodes))
	// The zero value of the policy mode means "inherit"; render it by name so
	// an automation client never has to know that the empty string is a mode.
	mode := string(s.cfg.DERPPolicy.Mode)
	if mode == "" {
		mode = "inherit"
	}
	view := derpStatusView{
		PolicyMode:    mode,
		PolicyRegions: []int32{},
		MapConfigured: s.cfg.DERPMap != nil,
		Regions:       []derpRegionView{},
	}
	for _, id := range s.cfg.DERPPolicy.Regions {
		view.PolicyRegions = append(view.PolicyRegions, int32(id))
	}
	for _, node := range nodes {
		placement := derpNodeView{
			StableID: node.StableID,
			Hostname: node.Hostname,
			Online:   s.isOnline(node.ID),
			Home:     node.HomeDERP,
		}
		switch {
		case node.HomeDERP == 0:
			view.NodesWithoutHome++
		case !s.derpRegionKnown(node.HomeDERP):
			placement.Unserved = true
			view.NodesWithUnservedHome++
		default:
			counts[node.HomeDERP]++
		}
		nodeViews = append(nodeViews, placement)
	}

	served := s.DERPMap()
	if served == nil {
		return view, nodeViews
	}
	view.MapConfigured = true
	ids := make([]tailcfg.DERPRegionID, 0, len(served.Regions))
	for id := range served.Regions {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	for _, id := range ids {
		region := served.Regions[id]
		if region == nil {
			// A nil entry is not a served region; clients skip it too.
			continue
		}
		hosts := make([]string, 0, len(region.Nodes))
		for _, relay := range region.Nodes {
			if relay != nil && relay.HostName != "" && !slices.Contains(hosts, relay.HostName) {
				hosts = append(hosts, relay.HostName)
			}
		}
		sort.Strings(hosts)
		view.Regions = append(view.Regions, derpRegionView{
			ID:        int32(id),
			Code:      region.RegionCode,
			Name:      region.RegionName,
			Hosts:     hosts,
			NodeCount: counts[id],
		})
	}
	view.RegionsServed = len(view.Regions)
	return view, nodeViews
}

// handleAPIV2DERP implements GET /api/v2/derp: the read-only DERP status of
// this organization (spec section 32.1).
func (s *Server) handleAPIV2DERP(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireScope(w, r, identity.ScopeRead); !ok {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	view, _ := s.derpStatus()
	writeJSON(w, http.StatusOK, view)
}
