package control

import (
	"net/http"
	"reflect"

	"tailscale.com/tailcfg"
)

const relayAdmissionPath = "/api/relay/v1/admit"

func (r *Router) handleSharedDERPAdmit(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	body, ok := decodeDERPAdmitRequest(w, req)
	if !ok {
		return
	}

	allow := false
	if !body.NodePublic.IsZero() {
		for _, org := range r.orgSnapshot() {
			server := org.site.Server
			if sharesDERPRelay(server.DERPMap(), r.cfg.SharedDERPMap) && server.allowsDERPClient(body.NodePublic) {
				allow = true
				break
			}
		}
	}
	writeJSON(w, http.StatusOK, tailcfg.DERPAdmitClientResponse{Allow: allow})
}

func sharesDERPRelay(served, shared *tailcfg.DERPMap) bool {
	if served == nil || shared == nil {
		return false
	}
	for regionID, sharedRegion := range shared.Regions {
		servedRegion := served.Regions[regionID]
		if sharedRegion == nil || servedRegion == nil {
			continue
		}
		for _, sharedNode := range sharedRegion.Nodes {
			if sharedNode == nil {
				continue
			}
			for _, servedNode := range servedRegion.Nodes {
				if servedNode != nil && reflect.DeepEqual(sharedNode, servedNode) {
					return true
				}
			}
		}
	}
	return false
}
