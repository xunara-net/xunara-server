package control

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"tailscale.com/tailcfg"

	"github.com/xunara-net/xunara-server/state"
)

// This file implements POST /machine/feature/query, the endpoint official
// clients hit when the user enables a feature such as `tailscale serve`. The
// request asks the control plane for instructions; the endpoint never enables
// anything itself. Enablement is expressed through the node's capability map
// (policy nodeAttrs / grants), which the client re-reads from its netmap.
//
// Reference: reference/tailscale/tailcfg/tailcfg.go (QueryFeatureRequest /
// QueryFeatureResponse), reference/tailscale/cmd/tailscale/cli/serve_legacy.go
// (enableFeatureInteractive, the consumer of the response).

// featureRequirements maps a feature identifier to the node capabilities the
// client must already have for the feature to work. The identifiers are sent
// by the client ("serve", "funnel"); "https" is accepted as an alias because
// the capability itself is named https.
var featureRequirements = map[string][]tailcfg.NodeCapability{
	"serve":  {tailcfg.CapabilityHTTPS},
	"https":  {tailcfg.CapabilityHTTPS},
	"funnel": {tailcfg.CapabilityHTTPS, tailcfg.NodeAttrFunnel},
}

// maxFeatureNameLen bounds the feature identifier echoed back in the response
// text; the value arrives from the client and is rendered into a terminal.
const maxFeatureNameLen = 64

const (
	// featureHelpServe explains how to switch on HTTPS serving. Grants come
	// from the tailnet policy file, so the actionable step is an admin edit,
	// not a visit to a web page: URL stays empty.
	featureHelpServe = `HTTPS serving is not enabled for this device.

Ask a tailnet admin to grant the "https" capability to this device, e.g. in the tailnet policy file:

  "nodeAttrs": [
    {"target": ["tag:server"], "attr": ["https"]}
  ]

Then rerun this command.`

	// featureHelpFunnel: this build runs no public ingress, and the policy
	// loader rejects the "funnel" attribute outright, so no netmap will ever
	// satisfy the requirement.
	featureHelpFunnel = `Funnel is not supported by this control server.

HTTPS serving ("tailscale serve") may still be available; it needs the "https" capability granted through the tailnet policy nodeAttrs section.`
)

// handleFeatureQuery implements POST /machine/feature/query inside a Noise
// session. The session's machine key must match the node key in the request,
// so a throwaway Noise session cannot probe another node's capabilities.
func (ns *noiseServer) handleFeatureQuery(w http.ResponseWriter, req *http.Request) {
	var query tailcfg.QueryFeatureRequest
	if err := json.NewDecoder(req.Body).Decode(&query); err != nil {
		httpError(w, err)
		return
	}

	node, err := ns.getAndValidateNode(tailcfg.MapRequest{NodeKey: query.NodeKey})
	if err != nil {
		httpError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, ns.server.featureQueryResponse(node, query.Feature))
}

// featureQueryResponse builds the answer for one feature query: complete when
// the node already carries every required capability, otherwise an
// explanation. ShouldWait is always false — Xunara has no server-side
// enablement flow the client could block on, so the CLI prints the text and
// exits instead of hanging.
func (s *Server) featureQueryResponse(node state.Node, feature string) tailcfg.QueryFeatureResponse {
	name := strings.ToLower(strings.TrimSpace(feature))

	required, known := featureRequirements[name]
	if known && s.nodeHasCaps(node, required) {
		return tailcfg.QueryFeatureResponse{Complete: true}
	}

	switch name {
	case "serve", "https":
		return tailcfg.QueryFeatureResponse{Text: featureHelpServe}
	case "funnel":
		return tailcfg.QueryFeatureResponse{Text: featureHelpFunnel}
	default:
		return tailcfg.QueryFeatureResponse{
			Text: fmt.Sprintf("This control server does not recognise the feature %q.", truncateFeatureName(name)),
		}
	}
}

// nodeHasCaps reports whether every capability is present in the node's
// capability map.
func (s *Server) nodeHasCaps(node state.Node, required []tailcfg.NodeCapability) bool {
	caps := s.nodeCapMap(node)
	for _, capability := range required {
		if _, ok := caps[capability]; !ok {
			return false
		}
	}
	return true
}

// truncateFeatureName bounds a client-supplied feature identifier before it is
// echoed back; anything non-printable is dropped so the text stays terminal
// safe.
func truncateFeatureName(name string) string {
	if len(name) > maxFeatureNameLen {
		name = name[:maxFeatureNameLen]
	}
	return strings.Map(func(r rune) rune {
		if r < ' ' || r == 0x7f {
			return -1
		}
		return r
	}, name)
}
