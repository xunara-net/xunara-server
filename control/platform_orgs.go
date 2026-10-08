package control

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/xunara-net/xunara-server/plan"
)

// Organization CRUD for the platform API (M7d).
//
// Configured organizations (from -org-config) stay read-only: the deployment
// file owns them. Managed organizations are created here, live in the platform
// registry and can be retargeted or deleted while the process serves. Both need
// the process-level platform token; an organization's own credentials never
// reach these handlers.

// maxPlatformOrgRequestBytes bounds an organization request body.
const maxPlatformOrgRequestBytes = 8 << 10

// platformOrgCreateRequest is the body of POST /api/platform/v1/organizations.
type platformOrgCreateRequest struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	Domains   []string `json:"domains"`
	ServerURL string   `json:"server_url"`
	Domain    string   `json:"domain,omitempty"`
}

// platformOrgUpdateRequest is the body of PATCH
// /api/platform/v1/organizations/{orgID}: absent fields stay unchanged.
type platformOrgUpdateRequest struct {
	Name    *string   `json:"name,omitempty"`
	Domains *[]string `json:"domains,omitempty"`
}

// decodePlatformOrgBody reads a request body strictly: an unknown field is a
// client mistake, not something to ignore.
func decodePlatformOrgBody(w http.ResponseWriter, r *http.Request, into any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxPlatformOrgRequestBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(into); err != nil {
		http.Error(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return false
	}
	return true
}

// handlePlatformCreateOrganization implements POST
// /api/platform/v1/organizations.
func (r *Router) handlePlatformCreateOrganization(w http.ResponseWriter, req *http.Request) {
	var body platformOrgCreateRequest
	if !decodePlatformOrgBody(w, req, &body) {
		return
	}

	site, err := r.CreateManagedOrg(req.Context(), ManagedOrg{
		ID:        strings.TrimSpace(body.ID),
		Name:      strings.TrimSpace(body.Name),
		Domains:   body.Domains,
		ServerURL: strings.TrimSpace(body.ServerURL),
		Domain:    strings.TrimSpace(body.Domain),
	})
	if err != nil {
		r.writeOrgAPIError(w, err)
		return
	}

	org := r.orgByID(site.ID)
	if org == nil {
		// The organization was registered a moment ago; this only happens if
		// the router was closed concurrently.
		http.Error(w, "organization is no longer served", http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, http.StatusCreated, r.platformOrgView(org))
}

// handlePlatformUpdateOrganization implements PATCH
// /api/platform/v1/organizations/{orgID}.
func (r *Router) handlePlatformUpdateOrganization(w http.ResponseWriter, req *http.Request) {
	var body platformOrgUpdateRequest
	if !decodePlatformOrgBody(w, req, &body) {
		return
	}
	if body.Name == nil && body.Domains == nil {
		http.Error(w, "nothing to update", http.StatusBadRequest)
		return
	}

	name := body.Name
	if name != nil {
		trimmed := strings.TrimSpace(*name)
		name = &trimmed
	}
	var domains []string
	if body.Domains != nil {
		domains = *body.Domains
	}

	site, err := r.UpdateManagedOrg(req.Context(), chi.URLParam(req, "orgID"), name, domains)
	if err != nil {
		r.writeOrgAPIError(w, err)
		return
	}
	org := r.orgByID(site.ID)
	if org == nil {
		http.Error(w, "organization is no longer served", http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, http.StatusOK, r.platformOrgView(org))
}

// handlePlatformDeleteOrganization implements DELETE
// /api/platform/v1/organizations/{orgID}. The response names the archive
// directory so an operator can find (or remove) the retained state.
func (r *Router) handlePlatformDeleteOrganization(w http.ResponseWriter, req *http.Request) {
	archived, err := r.DeleteManagedOrg(req.Context(), chi.URLParam(req, "orgID"))
	if err != nil {
		r.writeOrgAPIError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"id":         chi.URLParam(req, "orgID"),
		"deleted":    true,
		"archivedAt": archived,
	})
}

// writeOrgAPIError maps organization errors to HTTP responses. Validation and
// conflict messages come from [orgAPIError] and are safe to return; everything
// else is logged and reported as an internal error.
func (r *Router) writeOrgAPIError(w http.ResponseWriter, err error) {
	var apiErr *orgAPIError
	switch {
	case errors.As(err, &apiErr):
		http.Error(w, apiErr.msg, apiErr.status)
	case errors.Is(err, ErrOrgExists):
		http.Error(w, err.Error(), http.StatusConflict)
	case errors.Is(err, ErrOrgNotFound):
		http.Error(w, err.Error(), http.StatusNotFound)
	case errors.Is(err, errOrgConfigured):
		http.Error(w, err.Error(), http.StatusConflict)
	case errors.Is(err, errManagedOrgsDisabled):
		http.Error(w, err.Error(), http.StatusForbidden)
	case errors.Is(err, ErrTenantNotFound):
		http.Error(w, err.Error(), http.StatusNotFound)
	case errors.Is(err, plan.ErrPlanNotFound):
		http.Error(w, err.Error(), http.StatusNotFound)
	case errors.Is(err, ErrPlanUnknown):
		http.Error(w, err.Error(), http.StatusBadRequest)
	case errors.Is(err, plan.ErrDefaultPlan), errors.Is(err, ErrPlanBuiltIn):
		http.Error(w, err.Error(), http.StatusConflict)
	case errors.Is(err, ErrNetworkNotAllowed):
		http.Error(w, err.Error(), http.StatusForbidden)
	case errors.Is(err, ErrNetworkConflict):
		http.Error(w, err.Error(), http.StatusConflict)
	case errors.Is(err, ErrNoNetworkBlock):
		http.Error(w, err.Error(), http.StatusConflict)
	default:
		r.log.Error("platform organization request failed", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
	}
}
