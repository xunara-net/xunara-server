package control

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/xunara-net/xunara-server/identity"
)

// Xunara Share HTTP API (PROJECT_SPEC section 38.3).
//
// Authorization is per side of the share: the source organization manages the
// machine and its outgoing shares, while the target identity owns acceptance.
// A share the caller is not part of reports 404, so the endpoint never
// confirms that some other tenant's share exists.

// apiShareCreateRequest is the body of POST /api/v2/shares.
type apiShareCreateRequest struct {
	// Node is the machine to share: a local node ID or stable ID.
	Node string `json:"node"`
	// TargetOrganization hosts the identity that may accept.
	TargetOrganization string `json:"targetOrganization"`
	// Provider and Subject are the target identity key (AGENTS.md section 6).
	Provider string `json:"provider"`
	Subject  string `json:"subject"`
}

// shareAPIError maps service errors to HTTP responses.
func shareAPIError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errShareDisabled),
		errors.Is(err, errShareNodeUnknown),
		errors.Is(err, errShareOrgUnknown),
		errors.Is(err, errShareNotMine):
		writeAPIError(w, http.StatusNotFound, err.Error())
	case errors.Is(err, errShareIdentityInvalid), errors.Is(err, errShareSelf):
		writeAPIError(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, errShareTKA), errors.Is(err, errShareDecision), errors.Is(err, ErrShareExists):
		writeAPIError(w, http.StatusConflict, err.Error())
	default:
		writeAPIError(w, http.StatusInternalServerError, "internal error")
	}
}

// handleAPIV2Shares implements GET /api/v2/shares.
func (s *Server) handleAPIV2Shares(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireScope(w, r, identity.ScopeRead)
	if !ok {
		return
	}
	if !s.sharingEnabled() {
		writeAPIError(w, http.StatusNotFound, errShareDisabled.Error())
		return
	}

	direction := r.URL.Query().Get("direction")
	if direction == "" {
		direction = "outgoing"
	}
	if direction != "outgoing" && direction != "incoming" {
		writeAPIError(w, http.StatusBadRequest, "invalid direction")
		return
	}
	shares, err := s.listShares(direction, principal)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid direction")
		return
	}

	items := make([]shareView, 0, len(shares))
	for _, share := range shares {
		items = append(items, s.shareView(share, direction))
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

// handleAPIV2CreateShare implements POST /api/v2/shares.
func (s *Server) handleAPIV2CreateShare(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireScope(w, r, identity.ScopeWrite)
	if !ok {
		return
	}
	if !s.sharingEnabled() {
		writeAPIError(w, http.StatusNotFound, errShareDisabled.Error())
		return
	}

	var req apiShareCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	share, err := s.createShare(r.Context(), principal, req.Node, req.TargetOrganization, req.Provider, req.Subject)
	if err != nil {
		shareAPIError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, s.shareView(share, "outgoing"))
}

// handleAPIV2Share implements GET /api/v2/shares/{id}.
func (s *Server) handleAPIV2Share(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireScope(w, r, identity.ScopeRead)
	if !ok {
		return
	}
	share, err := s.shareForCaller(chi.URLParam(r, "id"), principal)
	if err != nil {
		shareAPIError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, s.shareView(share, s.shareDirection(share)))
}

// handleAPIV2AcceptShare implements POST /api/v2/shares/{id}/accept.
func (s *Server) handleAPIV2AcceptShare(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireScope(w, r, identity.ScopeRead)
	if !ok {
		return
	}
	share, err := s.acceptShare(r.Context(), principal, chi.URLParam(r, "id"))
	if err != nil {
		shareAPIError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, s.shareView(share, "incoming"))
}

// handleAPIV2RejectShare implements POST /api/v2/shares/{id}/reject.
func (s *Server) handleAPIV2RejectShare(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireScope(w, r, identity.ScopeRead)
	if !ok {
		return
	}
	share, err := s.rejectShare(r.Context(), principal, chi.URLParam(r, "id"))
	if err != nil {
		shareAPIError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, s.shareView(share, "incoming"))
}

// handleAPIV2RevokeShare implements DELETE /api/v2/shares/{id}.
func (s *Server) handleAPIV2RevokeShare(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireScope(w, r, identity.ScopeRead)
	if !ok {
		return
	}
	share, err := s.revokeShare(r.Context(), principal, chi.URLParam(r, "id"))
	if errors.Is(err, errShareForbidden) {
		writeAPIError(w, http.StatusForbidden, err.Error())
		return
	}
	if err != nil {
		shareAPIError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, s.shareView(share, s.shareDirection(share)))
}

// shareDirection reports how this organization participates in a share.
func (s *Server) shareDirection(share Share) string {
	if share.SourceOrg == s.Organization().ID {
		return "outgoing"
	}
	return "incoming"
}
