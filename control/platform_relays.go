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
func (r *Router) handlePlatformRelays(w http.ResponseWriter, req *http.Request) {
	now := time.Now().UTC()
	views := make([]platformRelayView, 0)
	for _, org := range r.orgSnapshot() {
		store, ok := org.site.Server.store.(*state.SQLiteStore)
		if !ok {
			org.site.Server.writeNetworkError(w, errors.New("relay management requires a durable store"))
			return
		}
		relays, err := store.ListRelaysContext(req.Context())
		if err != nil {
			org.site.Server.writeRelayManagementError(w, err)
			return
		}
		for _, relay := range relays {
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
	if !validRelayConfigRequest(w, body) {
		return
	}

	relayID := chi.URLParam(req, "relayID")
	if server.networkConfig == nil {
		server.writeNetworkError(w, errors.New("relay configuration requires a durable store"))
		return
	}
	relay, err := server.networkConfig.SavePlatformRelay(req.Context(), relayID, body.update(), body.RestoreFrom, orgID)
	if err != nil {
		server.writeRelayManagementError(w, err)
		return
	}
	r.log.Info("platform updated a relay", "organization", orgID, "relay", relayID, "state", relay.DesiredState)
	server.refreshRelayMapAfterChange(req.Context())
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
	expected, ok := relayExpectedVersion(w, req)
	if !ok {
		return
	}
	if server.networkConfig == nil {
		server.writeNetworkError(w, errors.New("relay configuration requires a durable store"))
		return
	}
	if err := server.networkConfig.DeletePlatformRelay(req.Context(), relayID, expected, orgID); err != nil {
		server.writeRelayManagementError(w, err)
		return
	}
	r.log.Info("platform deleted a relay", "organization", orgID, "relay", relayID)
	server.refreshRelayMapAfterChange(req.Context())
	w.WriteHeader(http.StatusNoContent)
}

func (r *Router) handlePlatformRelay(w http.ResponseWriter, req *http.Request) {
	orgID := chi.URLParam(req, "orgID")
	server := r.serverFor(orgID)
	if server == nil {
		writeAPIError(w, http.StatusNotFound, "organization not found")
		return
	}
	relay, err := server.lookupManagedRelay(req.Context(), chi.URLParam(req, "relayID"))
	if err != nil {
		server.writeRelayManagementError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, platformRelayView{OrganizationID: orgID, relayView: relayViewFor(relay, time.Now().UTC())})
}

func (r *Router) handlePlatformRelayHistory(w http.ResponseWriter, req *http.Request) {
	server := r.serverFor(chi.URLParam(req, "orgID"))
	if server == nil {
		writeAPIError(w, http.StatusNotFound, "organization not found")
		return
	}
	server.writeRelayHistory(w, req, chi.URLParam(req, "relayID"))
}
