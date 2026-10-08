package control

import (
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/xunara-net/xunara-server/identity"
)

// Xunara device authorization management plane (PROJECT_SPEC section 41).
//
// A device authorization is the machine-identity admission half of the
// registration flow: the client presented a (machine key, node key) pair and
// is waiting for a human to confirm it. This surface lists those requests and
// records approve/deny decisions. It never carries key material, and a
// decision always works from the stored row (AGENTS.md sections 5, 10 and
// 11), so an API caller cannot substitute a key pair it does not own.

// pendingDeviceLimit bounds one pending-device response. Pending
// authorizations are already bounded by their TTL; the list is newest-first,
// so cutting the tail drops the requests that are closest to expiring.
const pendingDeviceLimit = apiV2MaxPageSize

// pendingDeviceView is one pending authorization, without key material.
type pendingDeviceView struct {
	ID       string `json:"id"`
	Hostname string `json:"hostname"`
	OS       string `json:"os"`
	// Ephemeral and RequestedTags are the client's claims; approval resolves
	// them against policy, so the approver sees exactly what is being asked.
	Ephemeral     bool     `json:"ephemeral,omitempty"`
	RequestedTags []string `json:"requestedTags,omitempty"`

	Created time.Time `json:"created"`
	Expires time.Time `json:"expires"`
}

// pendingDevicesView is the JSON shape of GET /api/v2/devices.
type pendingDevicesView struct {
	Devices []pendingDeviceView `json:"devices"`
	// Truncated reports that older pending rows were dropped at
	// pendingDeviceLimit, so a client knows the list is bounded instead of
	// silently incomplete.
	Truncated bool `json:"truncated"`
}

// pendingDeviceViews lists the authorizations still waiting for a decision,
// newest first (the store's order), capped at pendingDeviceLimit.
func (s *Server) pendingDeviceViews(now time.Time) pendingDevicesView {
	pending := s.identity.ListPendingDeviceAuthorizations(now)
	view := pendingDevicesView{Devices: make([]pendingDeviceView, 0, len(pending))}
	for i, da := range pending {
		if i == pendingDeviceLimit {
			view.Truncated = true
			break
		}
		meta := decodeDeviceMetadata(da.ClientMetadata)
		view.Devices = append(view.Devices, pendingDeviceView{
			ID:            da.ID,
			Hostname:      meta.Hostname,
			OS:            meta.OS,
			Ephemeral:     meta.Ephemeral,
			RequestedTags: meta.requestedTags(),
			Created:       da.CreatedAt,
			Expires:       da.ExpiresAt,
		})
	}
	return view
}

// handleAPIV2Devices implements GET /api/v2/devices (spec section 41.2).
func (s *Server) handleAPIV2Devices(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireScope(w, r, identity.ScopeRead); !ok {
		return
	}
	writeJSON(w, http.StatusOK, s.pendingDeviceViews(time.Now()))
}

// handleAPIV2ApproveDevice implements POST /api/v2/devices/{id}/approve.
func (s *Server) handleAPIV2ApproveDevice(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireScope(w, r, identity.ScopeWrite)
	if !ok {
		return
	}
	s.apiDecideDevice(w, r, principal, true)
}

// handleAPIV2DenyDevice implements POST /api/v2/devices/{id}/deny.
func (s *Server) handleAPIV2DenyDevice(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireScope(w, r, identity.ScopeWrite)
	if !ok {
		return
	}
	s.apiDecideDevice(w, r, principal, false)
}

// apiDecideDevice records an approve/deny decision and maps the service
// errors every caller shares (unknown 404, expired 410, opposite decision
// 409). Repeating the same decision is idempotent.
func (s *Server) apiDecideDevice(w http.ResponseWriter, r *http.Request, principal apiPrincipal, approve bool) {
	id := chi.URLParam(r, "id")

	var (
		da  identity.DeviceAuthorization
		err error
	)
	if approve {
		da, err = s.approveDevice(id, principal.UserID, principal.actor())
	} else {
		da, err = s.denyDevice(id, principal.UserID, principal.actor())
	}
	if err != nil {
		var he HTTPError
		if errors.As(err, &he) {
			writeAPIError(w, he.Code, he.Msg)
			return
		}
		s.log.Error("deciding device", "device", id, "err", err)
		writeAPIError(w, http.StatusInternalServerError, "could not record the decision")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": da.ID, "state": string(da.State)})
}
