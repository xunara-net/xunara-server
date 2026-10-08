package control

import (
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/xunara-net/xunara-server/state"
)

// Platform-level relay administration: the operator surface above every
// organization. Relays are tenant-scoped resources, so each handler resolves
// the tenant first and then reuses the same code path as the console API.

// platformRelayView pairs a relay with the tenant that owns it.
type platformRelayView struct {
	OrganizationID   string `json:"organizationId"`
	OrganizationName string `json:"organizationName,omitempty"`
	relayView
}

// handlePlatformRelays implements GET /api/platform/v1/relays.
func (r *Router) handlePlatformRelays(w http.ResponseWriter, _ *http.Request) {
	now := time.Now().UTC()
	views := make([]platformRelayView, 0)
	for _, org := range r.orgSnapshot() {
		for _, relay := range org.site.Server.store.ListRelays() {
			views = append(views, platformRelayView{
				OrganizationID:   org.site.ID,
				OrganizationName: org.site.Name,
				relayView:        relayViewFor(relay, now),
			})
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"relays": views, "count": len(views)})
}

// handlePlatformCreateRelayEnrollToken implements POST
// /api/platform/v1/organizations/{orgID}/relays/enroll-tokens.
func (r *Router) handlePlatformCreateRelayEnrollToken(w http.ResponseWriter, req *http.Request) {
	orgID := chi.URLParam(req, "orgID")
	server := r.serverFor(orgID)
	if server == nil {
		http.Error(w, "organization not found", http.StatusNotFound)
		return
	}
	var body apiRelayEnrollTokenCreateRequest
	if !decodeAPIBody(w, req, &body) {
		return
	}

	actor := "platform:" + orgID
	tok, secret, err := server.createRelayEnrollmentToken(body.Name, body.Visibility,
		time.Duration(body.TTLSeconds)*time.Second, actor)
	if err != nil {
		if errors.Is(err, errRelayLimitReached) {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	r.auditTenant(orgID, actor, "relay.enrollment_token_created", "relay-token:"+tok.ID,
		"created by the platform API for a "+tok.Visibility+" relay")
	r.log.Info("platform issued a relay enrollment token", "organization", orgID, "token", tok.ID)

	writeJSON(w, http.StatusCreated, map[string]any{
		"token": secret,
		"item":  relayEnrollTokenViewFor(tok, time.Now().UTC()),
	})
}

// handlePlatformUpdateRelay implements PATCH
// /api/platform/v1/organizations/{orgID}/relays/{relayID}.
func (r *Router) handlePlatformUpdateRelay(w http.ResponseWriter, req *http.Request) {
	orgID := chi.URLParam(req, "orgID")
	server := r.serverFor(orgID)
	if server == nil {
		http.Error(w, "organization not found", http.StatusNotFound)
		return
	}
	var body apiRelayConfigRequest
	if !decodeAPIBody(w, req, &body) {
		return
	}
	if body.DesiredState != "" && !state.ValidRelayState(body.DesiredState) {
		http.Error(w, "desired_state must be online, maintenance, disabled or revoked", http.StatusBadRequest)
		return
	}
	if body.BandwidthLimit != nil && *body.BandwidthLimit < -1 {
		http.Error(w, "bandwidth_limit must be -1, 0 or a positive byte rate", http.StatusBadRequest)
		return
	}

	relayID := chi.URLParam(req, "relayID")
	relay, err := server.store.UpdateRelayConfig(relayID, state.RelayConfigUpdate{
		DesiredState:   body.DesiredState,
		BandwidthLimit: body.BandwidthLimit,
		RegionName:     body.RegionName,
	})
	if err != nil {
		if errors.Is(err, state.ErrRelayNotFound) {
			http.Error(w, "relay not found", http.StatusNotFound)
			return
		}
		http.Error(w, "could not update the relay", http.StatusInternalServerError)
		return
	}
	actor := "platform:" + orgID
	r.auditTenant(orgID, actor, "relay.updated", "relay:"+relayID, "desired state "+relay.DesiredState)
	r.log.Info("platform updated a relay", "organization", orgID, "relay", relayID, "state", relay.DesiredState)
	writeJSON(w, http.StatusOK, platformRelayView{
		OrganizationID: orgID, relayView: relayViewFor(relay, time.Now().UTC()),
	})
}

// handlePlatformDeleteRelay implements DELETE
// /api/platform/v1/organizations/{orgID}/relays/{relayID}.
func (r *Router) handlePlatformDeleteRelay(w http.ResponseWriter, req *http.Request) {
	orgID := chi.URLParam(req, "orgID")
	server := r.serverFor(orgID)
	if server == nil {
		http.Error(w, "organization not found", http.StatusNotFound)
		return
	}
	relayID := chi.URLParam(req, "relayID")
	relay, exists := server.store.RelayByID(relayID)
	if !exists {
		http.Error(w, "relay not found", http.StatusNotFound)
		return
	}
	if err := server.store.DeleteRelay(relayID); err != nil {
		http.Error(w, "could not delete the relay", http.StatusInternalServerError)
		return
	}
	actor := "platform:" + orgID
	r.auditTenant(orgID, actor, "relay.deleted", "relay:"+relayID, "deleted relay "+relay.Name)
	r.log.Info("platform deleted a relay", "organization", orgID, "relay", relayID)
	w.WriteHeader(http.StatusNoContent)
}
