package control

import (
	"net/http"

	"github.com/xunara-net/xunara-server/identity"
)

// This file implements organization self-introspection (PROJECT_SPEC section
// 30): an authenticated caller can confirm which tenant it is talking to. The
// answer comes from the router's Host routing decision, never from the
// request, so a caller cannot ask about another organization.

// OrgIdentity is the platform identity of one organization.
type OrgIdentity struct {
	// ID is the stable organization identifier ("acme"); empty for a
	// single-tenant deployment without an organization table.
	ID string
	// Name is the human-readable organization name.
	Name string
	// Domains are the routing domains (Host patterns) this organization
	// answers. They are the routes, not the MagicDNS suffix.
	Domains []string
	// Managed is true when the platform registry owns the organization's
	// lifecycle.
	Managed bool
}

// setOrganization records the organization this server serves. The router
// calls it when a site is registered or renamed.
func (s *Server) setOrganization(org OrgIdentity) {
	org.Domains = append([]string(nil), org.Domains...)
	s.org.Store(&org)
}

// Organization returns the identity of the organization this server serves;
// the zero value for a deployment without an organization table.
func (s *Server) Organization() OrgIdentity {
	org := s.org.Load()
	if org == nil {
		return OrgIdentity{}
	}
	return OrgIdentity{
		ID:      org.ID,
		Name:    org.Name,
		Domains: append([]string(nil), org.Domains...),
		Managed: org.Managed,
	}
}

// organizationView is the wire shape of GET /api/v2/organization.
type organizationView struct {
	ID      string   `json:"id,omitempty"`
	Name    string   `json:"name,omitempty"`
	Domains []string `json:"domains"`
	// Managed reports whether the platform registry owns the lifecycle of
	// this organization.
	Managed        bool   `json:"managed"`
	MagicDNSDomain string `json:"magicDnsDomain"`
	ServerURL      string `json:"serverUrl"`
}

// handleAPIV2Organization implements GET /api/v2/organization: the identity
// of the organization this request was routed to.
func (s *Server) handleAPIV2Organization(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireScope(w, r, identity.ScopeRead); !ok {
		return
	}

	org := s.Organization()
	domains := org.Domains
	if domains == nil {
		// The shape is stable: no domains is an empty array, never null.
		domains = []string{}
	}
	writeJSON(w, http.StatusOK, organizationView{
		ID:             org.ID,
		Name:           org.Name,
		Domains:        domains,
		Managed:        org.Managed,
		MagicDNSDomain: s.cfg.Domain,
		ServerURL:      s.cfg.ServerURL,
	})
}
