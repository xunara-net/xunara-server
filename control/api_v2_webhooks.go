package control

import (
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/xunara-net/xunara-server/identity"
	"github.com/xunara-net/xunara-server/webhook"
)

// Managed webhook receivers (M8c).
//
// Deployment-configured endpoints come from flags/environment and keep their
// secrets there; managed endpoints are created through /api/v2 and the console
// and their secrets are sealed with the server's webhook key before they are
// stored. Both share one dispatcher, one cursor per endpoint ID and the same
// lease, so the delivery semantics do not depend on how an endpoint was
// configured.

// webhookIDPattern bounds an endpoint ID: it becomes a cursor key and an audit
// target, so it must be safe to log and stable across a rename-free lifetime.
var webhookIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// Sentinels marking why a managed endpoint cannot be created or removed. They
// carry no text: the API and the console phrase their own messages.
var (
	errWebhookIDInvalid  = errors.New("invalid webhook id")
	errWebhookIDManaged  = errors.New("a managed webhook with this id exists")
	errWebhookConfigured = errors.New("this webhook comes from the server configuration")
	errWebhookUnknown    = errors.New("unknown webhook")
)

// apiWebhookView is a webhook endpoint as the API presents it. The signing
// secret is never returned: it is write-only material.
type apiWebhookView struct {
	ID        string     `json:"id"`
	URL       string     `json:"url"`
	Events    []string   `json:"events,omitempty"`
	Enabled   bool       `json:"enabled"`
	Source    string     `json:"source"`
	CreatedAt *time.Time `json:"createdAt,omitempty"`
	UpdatedAt *time.Time `json:"updatedAt,omitempty"`
}

// normalizeManagedWebhook applies the rules shared by the platform API and the
// console before a new managed endpoint is sealed and stored. The returned
// endpoint carries the secret in the clear; callers must not retain it.
func (s *Server) normalizeManagedWebhook(id, rawURL, secret string, events []string) (webhook.Endpoint, error) {
	if !webhookIDPattern.MatchString(id) {
		return webhook.Endpoint{}, errWebhookIDInvalid
	}
	if _, ok := s.identity.GetWebhookEndpoint(id); ok {
		return webhook.Endpoint{}, errWebhookIDManaged
	}
	if slices.ContainsFunc(s.cfg.Webhooks, func(ep webhook.Endpoint) bool { return ep.ID == id }) {
		return webhook.Endpoint{}, errWebhookConfigured
	}

	events = slices.Clone(events)
	slices.Sort(events)
	events = slices.Compact(events)

	endpoint := webhook.Endpoint{ID: id, URL: rawURL, Secret: secret, Events: events}
	if err := webhook.ValidateEndpoint(endpoint); err != nil {
		return webhook.Endpoint{}, err
	}
	return endpoint, nil
}

// storeManagedWebhook seals the signing secret, records the endpoint and, when
// it is enabled, starts delivery.
func (s *Server) storeManagedWebhook(endpoint webhook.Endpoint, enabled bool) (identity.WebhookEndpoint, error) {
	sealed, err := sealWebhookSecret(s.webhookKey, endpoint.Secret)
	if err != nil {
		return identity.WebhookEndpoint{}, fmt.Errorf("sealing webhook secret: %w", err)
	}

	managed := identity.WebhookEndpoint{
		ID:      endpoint.ID,
		URL:     endpoint.URL,
		Secret:  sealed,
		Events:  endpoint.Events,
		Enabled: enabled,
	}
	if err := s.identity.CreateWebhookEndpoint(&managed); err != nil {
		return identity.WebhookEndpoint{}, err
	}

	if enabled && s.webhooks != nil {
		if err := s.webhooks.Upsert(endpoint); err != nil {
			// The endpoint is stored; delivery simply will not start until
			// the next configuration load. Logged, never fatal.
			s.log.Error("starting webhook delivery", "webhook", endpoint.ID, "err", err)
		}
	}
	return managed, nil
}

// deleteManagedWebhook stops delivery and removes a managed endpoint and its
// cursor. Deployment-configured endpoints can only be removed from the server
// configuration.
func (s *Server) deleteManagedWebhook(id string) error {
	if slices.ContainsFunc(s.cfg.Webhooks, func(ep webhook.Endpoint) bool { return ep.ID == id }) {
		return errWebhookConfigured
	}
	if _, ok := s.identity.GetWebhookEndpoint(id); !ok {
		return errWebhookUnknown
	}

	if s.webhooks != nil {
		s.webhooks.Remove(id)
	}
	if err := s.identity.DeleteWebhookEndpoint(id); err != nil {
		return err
	}
	return nil
}

// handleAPIV2Webhooks implements GET /api/v2/webhooks.
func (s *Server) handleAPIV2Webhooks(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireScope(w, r, identity.ScopeRead); !ok {
		return
	}

	views := make([]apiWebhookView, 0, len(s.cfg.Webhooks)+4)
	for _, managed := range s.identity.ListWebhookEndpoints() {
		created, updated := managed.CreatedAt, managed.UpdatedAt
		views = append(views, apiWebhookView{
			ID:        managed.ID,
			URL:       managed.URL,
			Events:    managed.Events,
			Enabled:   managed.Enabled,
			Source:    "managed",
			CreatedAt: &created,
			UpdatedAt: &updated,
		})
	}
	for _, ep := range s.cfg.Webhooks {
		views = append(views, apiWebhookView{
			ID:      ep.ID,
			URL:     ep.URL,
			Events:  ep.Events,
			Enabled: true,
			Source:  "config",
		})
	}

	writeJSON(w, http.StatusOK, map[string]any{"items": views})
}

// apiWebhookCreateRequest is the body of POST /api/v2/webhooks. The secret
// travels in the body, never in the URL (AGENTS.md section 8).
type apiWebhookCreateRequest struct {
	ID      string   `json:"id"`
	URL     string   `json:"url"`
	Secret  string   `json:"secret"`
	Events  []string `json:"events,omitempty"`
	Enabled *bool    `json:"enabled,omitempty"`
}

// handleAPIV2CreateWebhook implements POST /api/v2/webhooks.
func (s *Server) handleAPIV2CreateWebhook(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireScope(w, r, identity.ScopeWrite)
	if !ok {
		return
	}

	var req apiWebhookCreateRequest
	if !decodeAPIBody(w, r, &req) {
		return
	}

	endpoint, err := s.normalizeManagedWebhook(req.ID, req.URL, req.Secret, req.Events)
	switch {
	case errors.Is(err, errWebhookIDInvalid):
		writeAPIError(w, http.StatusBadRequest, "invalid webhook id")
		return
	case errors.Is(err, errWebhookIDManaged):
		writeAPIError(w, http.StatusConflict, "a managed webhook with this id exists")
		return
	case errors.Is(err, errWebhookConfigured):
		writeAPIError(w, http.StatusConflict, "a configured webhook uses this id")
		return
	case err != nil:
		// The validation message describes the endpoint, never the secret.
		writeAPIError(w, http.StatusBadRequest, err.Error())
		return
	}

	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}

	managed, err := s.storeManagedWebhook(endpoint, enabled)
	if err != nil {
		if errors.Is(err, identity.ErrWebhookEndpointExists) {
			writeAPIError(w, http.StatusConflict, "a managed webhook with this id exists")
			return
		}
		s.log.Error("creating webhook endpoint", "webhook", req.ID, "err", err)
		writeAPIError(w, http.StatusInternalServerError, "could not store the webhook")
		return
	}

	s.audit(principal.actor(), identity.AuditWebhookCreated, "webhook:"+req.ID,
		"created a managed webhook receiver")
	writeJSON(w, http.StatusCreated, apiWebhookView{
		ID: managed.ID, URL: managed.URL, Events: managed.Events,
		Enabled: managed.Enabled, Source: "managed",
		CreatedAt: &managed.CreatedAt, UpdatedAt: &managed.UpdatedAt,
	})
}

// handleAPIV2DeleteWebhook implements DELETE /api/v2/webhooks/{id}.
func (s *Server) handleAPIV2DeleteWebhook(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireScope(w, r, identity.ScopeWrite)
	if !ok {
		return
	}

	id := chi.URLParam(r, "id")
	switch err := s.deleteManagedWebhook(id); {
	case errors.Is(err, errWebhookConfigured):
		writeAPIError(w, http.StatusConflict,
			"this webhook is configured at startup; remove it from the server configuration")
		return
	case errors.Is(err, errWebhookUnknown):
		writeAPIError(w, http.StatusNotFound, "unknown webhook")
		return
	case err != nil:
		s.log.Error("deleting webhook endpoint", "webhook", id, "err", err)
		writeAPIError(w, http.StatusInternalServerError, "could not delete the webhook")
		return
	}

	s.audit(principal.actor(), identity.AuditWebhookDeleted, "webhook:"+id,
		"deleted a managed webhook receiver")
	writeJSON(w, http.StatusOK, map[string]any{"id": id, "deleted": true})
}
