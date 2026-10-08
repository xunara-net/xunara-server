package control

import (
	"net/http"
	"slices"

	"tailscale.com/tailcfg"

	"github.com/xunara-net/xunara-server/identity"
)

// Xunara Serve/Funnel management plane (PROJECT_SPEC section 43): the
// read-only view of tailnet HTTPS serving. Serve runs on the node and needs
// two things from the control plane: the "https" node attribute (the policy
// authorizes the device to serve) and a way to obtain a certificate (the DNS
// provider the control plane proxies ACME DNS-01 challenges with). Funnel
// additionally needs public ingress, which this build does not run: the
// policy loader rejects the "funnel" attribute, so no netmap can ever grant
// it. This page reports all of that without changing any of it.

// serveNodeView is one node's Serve/Funnel posture.
type serveNodeView struct {
	NodeID   uint64 `json:"nodeId"`
	StableID string `json:"stableId"`
	Hostname string `json:"hostname"`
	Owner    string `json:"owner"`
	Online   bool   `json:"online"`

	// Serve reports that the policy grants the node the "https" capability,
	// which is what unlocks `tailscale serve` on the device.
	Serve bool `json:"serve"`
	// Funnel reports that the node told control it has Funnel endpoints
	// enabled (Hostinfo.IngressEnabled). This build cannot support Funnel, so
	// a true value is a misconfiguration shown as-is, never a grant.
	Funnel bool `json:"funnel"`
	// WantsIngress reports that the node asked to be wired up for ingress
	// even though no Funnel endpoint is enabled (Hostinfo.WireIngress).
	WantsIngress bool `json:"wantsIngress"`
	// CertDomains are the names the node may obtain certificates for; empty
	// when no DNS provider is configured, which is what makes clients report
	// certificates as unsupported.
	CertDomains []string `json:"certDomains"`
}

// serveView is the JSON shape of GET /api/v2/serve.
type serveView struct {
	// Certificates reports whether a DNS provider is configured: without one
	// no client can complete an ACME challenge, so Serve has no certificate
	// to use.
	Certificates bool `json:"certificates"`
	// CertDomains are the operator-configured extra certificate domains
	// (the tailnet's own domain is implied).
	CertDomains []string `json:"certDomains"`
	// FunnelSupported is false in this build: Funnel needs public ingress
	// infrastructure the control plane does not run (spec section 43.3).
	FunnelSupported bool `json:"funnelSupported"`

	Nodes []serveNodeView `json:"nodes"`
}

// serveView builds the snapshot: every node whose HTTPS serving is authorized
// or that reports Funnel/ingress activity, ordered by node ID.
func (s *Server) serveView() serveView {
	nodes := s.store.ListNodes()

	view := serveView{
		Certificates:    s.cfg.DNSProvider != nil,
		CertDomains:     slices.Clone(s.certDomains),
		FunnelSupported: false,
		Nodes:           []serveNodeView{},
	}

	for _, node := range nodes {
		_, serve := s.nodeCapMap(node)[tailcfg.CapabilityHTTPS]
		funnel := node.Hostinfo != nil && node.Hostinfo.IngressEnabled
		wantsIngress := node.Hostinfo != nil && node.Hostinfo.WireIngress
		if !serve && !funnel && !wantsIngress {
			continue
		}
		domains := s.certDomainsFor(node)
		if domains == nil {
			domains = []string{}
		}
		view.Nodes = append(view.Nodes, serveNodeView{
			NodeID:       uint64(node.ID),
			StableID:     node.StableID,
			Hostname:     nodeDisplayHostname(node),
			Owner:        s.userLoginName(node.UserID),
			Online:       s.isOnline(node.ID),
			Serve:        serve,
			Funnel:       funnel,
			WantsIngress: wantsIngress,
			CertDomains:  domains,
		})
	}
	slices.SortFunc(view.Nodes, func(a, b serveNodeView) int { return int(a.NodeID) - int(b.NodeID) })
	return view
}

// handleAPIV2Serve implements GET /api/v2/serve (spec section 43.2).
func (s *Server) handleAPIV2Serve(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireScope(w, r, identity.ScopeRead); !ok {
		return
	}
	writeJSON(w, http.StatusOK, s.serveView())
}
