package control

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/xunara-net/xunara-server/identity"
	"github.com/xunara-net/xunara-server/state"
)

// This file is the read-only management surface for Xunara Flux (PROJECT_SPEC
// section 33). It exposes the metadata of file transfers - never content,
// never keys: the control plane is zero-knowledge by design (section 25.4),
// and administration does not change that. The records are the same ones the
// two agents use; there is no second copy.

// fluxPeer is the public identity of one participant.
type fluxPeer struct {
	NodeID   uint64 `json:"nodeId"`
	StableID string `json:"stableId"`
	Hostname string `json:"hostname,omitempty"`
}

// fluxAdminTransfer is one transfer as the management plane sees it. Compared
// with the agent view there is no viewer-relative direction, and the
// recipient's per-transfer public key is left out: the sender needs it, an
// administrator does not. Content and its file path never appear here.
type fluxAdminTransfer struct {
	ID        string    `json:"id"`
	State     string    `json:"state"`
	Name      string    `json:"name"`
	Size      int64     `json:"size"`
	SHA256    string    `json:"sha256"`
	Sender    fluxPeer  `json:"sender"`
	Recipient fluxPeer  `json:"recipient"`
	Reason    string    `json:"reason,omitempty"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
	ExpiresAt time.Time `json:"expiresAt"`
}

// handleAPIV2FluxTransfers implements GET /api/v2/flux/transfers, newest first.
//
// Filters: state=<transfer state>, node=<id or stable ID>. Both are
// fail-closed: an unknown state is a 400 and an unknown node matches nothing,
// because a filter that silently widens its result is a security bug.
func (s *Server) handleAPIV2FluxTransfers(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireScope(w, r, identity.ScopeRead); !ok {
		return
	}
	if s.fluxDisabled(w) {
		return
	}
	w.Header().Set("Cache-Control", "no-store")

	limit, ok := apiV2Limit(w, r, 100)
	if !ok {
		return
	}
	afterCreated, afterID, ok := apiV2TimeCursor(w, r, "flux")
	if !ok {
		return
	}

	query := r.URL.Query()
	var stateFilter state.FluxTransferState
	if raw := query.Get("state"); raw != "" {
		stateFilter = state.FluxTransferState(raw)
		if !stateFilter.Valid() {
			writeAPIError(w, http.StatusBadRequest, "invalid state filter")
			return
		}
	}
	nodeFilter := s.apiV2NodeFilter(query.Get("node"))

	items := make([]fluxAdminTransfer, 0, limit)
	var last state.FluxTransfer
	next := ""
	for _, transfer := range s.store.ListAllFluxTransfers() {
		if !newestFirstAfterCursor(transfer.CreatedAt, transfer.ID, afterCreated, afterID) {
			continue
		}
		if stateFilter != "" && transfer.State != stateFilter {
			continue
		}
		if nodeFilter != 0 && transfer.SenderNode != nodeFilter && transfer.RecipientNode != nodeFilter {
			continue
		}
		if len(items) == limit {
			next = fluxEncodePageCursor(last)
			break
		}
		view, ok := s.fluxAdminView(transfer)
		if !ok {
			// A participant's node row is gone; the transfer cascade removes
			// it too, so this is only a race with the deletion.
			continue
		}
		items = append(items, view)
		last = transfer
	}

	writeJSON(w, http.StatusOK, map[string]any{"items": items, "nextCursor": next})
}

// handleAPIV2FluxTransfer implements GET /api/v2/flux/transfers/{id}: the
// metadata of one transfer. There is deliberately no content endpoint here.
func (s *Server) handleAPIV2FluxTransfer(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireScope(w, r, identity.ScopeRead); !ok {
		return
	}
	if s.fluxDisabled(w) {
		return
	}
	w.Header().Set("Cache-Control", "no-store")

	transfer, ok := s.store.GetFluxTransfer(chi.URLParam(r, "id"))
	if !ok {
		writeAPIError(w, http.StatusNotFound, "no such transfer")
		return
	}
	view, ok := s.fluxAdminView(transfer)
	if !ok {
		writeAPIError(w, http.StatusNotFound, "no such transfer")
		return
	}
	writeJSON(w, http.StatusOK, view)
}

// fluxEncodePageCursor packs a list position for the flux cursor kind.
func fluxEncodePageCursor(transfer state.FluxTransfer) string {
	return apiV2EncodeTimeCursor("flux", transfer.CreatedAt, transfer.ID)
}

// fluxAdminView renders one transfer without content or keys.
func (s *Server) fluxAdminView(transfer state.FluxTransfer) (fluxAdminTransfer, bool) {
	sender, ok := s.store.GetNodeByID(transfer.SenderNode)
	if !ok {
		return fluxAdminTransfer{}, false
	}
	recipient, ok := s.store.GetNodeByID(transfer.RecipientNode)
	if !ok {
		return fluxAdminTransfer{}, false
	}
	return fluxAdminTransfer{
		ID:        transfer.ID,
		State:     string(transfer.State),
		Name:      transfer.Name,
		Size:      transfer.Size,
		SHA256:    transfer.SHA256,
		Sender:    fluxPeerView(sender),
		Recipient: fluxPeerView(recipient),
		Reason:    transfer.Reason,
		CreatedAt: transfer.CreatedAt,
		UpdatedAt: transfer.UpdatedAt,
		ExpiresAt: transfer.ExpiresAt,
	}, true
}

// fluxPeerView renders one participant.
func fluxPeerView(node state.Node) fluxPeer {
	return fluxPeer{
		NodeID:   uint64(node.ID),
		StableID: node.StableID,
		Hostname: node.Hostname,
	}
}

// fluxDisabled answers 404 when the deployment turned Flux off, matching the
// agent endpoints.
func (s *Server) fluxDisabled(w http.ResponseWriter) bool {
	if s.flux != nil {
		return false
	}
	httpError(w, NewHTTPError(http.StatusNotFound, "flux is not enabled", nil))
	return true
}
