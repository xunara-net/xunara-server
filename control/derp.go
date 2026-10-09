package control

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

// maxDERPAdmitRequestBytes bounds the admission request body. The body is a
// single node key plus an address; anything larger is abuse.
const maxDERPAdmitRequestBytes = 4 << 10

// handleDERPAdmit implements the DERP admission controller endpoint
// (POST /derp/admit) that Xunara Veil calls before admitting a DERP client,
// following the protocol of the upstream `derper --verify-client-url`.
//
// A client is admitted only when its node key belongs to a registered,
// unexpired node of this tailnet and the organization's DERP policy admits it
// (control/derp_policy.go). The endpoint deliberately fails closed:
// malformed requests and internal errors produce responses that
// [tailscale.com/derp/derpserver] treats as a rejection, never as an allow.
func (s *Server) handleDERPAdmit(w http.ResponseWriter, r *http.Request) {
	req, ok := decodeDERPAdmitRequest(w, r)
	if !ok {
		return
	}
	allow := s.allowsDERPClient(req.NodePublic)

	s.log.Debug("derp admission",
		"node", req.NodePublic.ShortString(),
		"source", req.Source.String(),
		"allow", allow,
	)

	writeJSON(w, http.StatusOK, tailcfg.DERPAdmitClientResponse{Allow: allow})
}

func decodeDERPAdmitRequest(w http.ResponseWriter, r *http.Request) (tailcfg.DERPAdmitClientRequest, bool) {
	r.Body = http.MaxBytesReader(w, r.Body, maxDERPAdmitRequestBytes)

	var req tailcfg.DERPAdmitClientRequest
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&req); err != nil {
		if errors.Is(err, io.EOF) {
			http.Error(w, "empty admission request", http.StatusBadRequest)
			return req, false
		}
		http.Error(w, "invalid admission request", http.StatusBadRequest)
		return req, false
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		http.Error(w, "invalid admission request", http.StatusBadRequest)
		return req, false
	}
	return req, true
}

func (s *Server) allowsDERPClient(nodeKey key.NodePublic) bool {
	if nodeKey.IsZero() {
		return false
	}
	node, ok := s.store.GetNodeByNodeKey(nodeKey)
	return ok && !node.Expired(time.Now()) && s.derpPolicy.admits(node.HomeDERP, s.derpRegionKnown)
}
