package control

import (
	"errors"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/xunara-net/xunara-server/webhook"
)

// Cross-organization audit export (M7c).
//
// The platform API exposes the audit logs of every hosted organization as one
// resumable stream. Pagination is per organization, because each organization
// owns its own database and therefore its own audit IDs: a single global
// cursor cannot exist without inventing an ordering that a crash could
// contradict. Callers keep the returned cursors and hand them back on the next
// request.
//
// Only the process-level platform token reaches this handler (see
// platform.go); an organization's own credentials never do.

const (
	// platformAuditDefaultLimit and platformAuditMaxLimit bound how many raw
	// audit events one request scans per organization.
	platformAuditDefaultLimit = 500
	platformAuditMaxLimit     = 2000
)

// PlatformAuditEvent is one audit event as the platform export presents it. The
// organization is part of every event because the same actor, action and ID
// space would otherwise be ambiguous.
type PlatformAuditEvent struct {
	Org    string    `json:"org"`
	ID     uint64    `json:"id"`
	Time   time.Time `json:"time"`
	Actor  string    `json:"actor"`
	Action string    `json:"action"`
	Target string    `json:"target,omitempty"`
	Detail string    `json:"detail,omitempty"`
}

// handlePlatformAudit implements GET /api/platform/v1/audit.
//
// Query parameters:
//
//	org=acme,globex     organizations to export (default: all)
//	cursor=acme:42      last event ID already consumed, per organization
//	action=node.*,user.created
//	                    audit action globs ("*" is the only wildcard)
//	limit=500           raw events scanned per organization (max 2000)
//
// The response carries the merged events and the next cursor per organization.
// Filtered-out events still advance a cursor: exactly like a webhook filter, an
// event the caller never asked for must not be offered again.
func (r *Router) handlePlatformAudit(w http.ResponseWriter, req *http.Request) {
	query := req.URL.Query()

	orgs, err := r.selectAuditOrgs(query["org"])
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	cursors, err := parseAuditCursors(query["cursor"])
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	patterns, err := parseAuditActions(query["action"])
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	limit, err := parseAuditLimit(query.Get("limit"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	events := make([]PlatformAuditEvent, 0, len(orgs)*8)
	next := make(map[string]uint64, len(orgs))
	hasMore := false

	for _, org := range orgs {
		after := cursors[org.site.ID]
		next[org.site.ID] = after

		batch := org.site.Server.Identity().ListAuditAfter(after, limit)
		if len(batch) == limit {
			hasMore = true
		}
		for _, event := range batch {
			next[org.site.ID] = event.ID
			if !matchesAnyAction(patterns, event.Action) {
				continue
			}
			events = append(events, PlatformAuditEvent{
				Org:    org.site.ID,
				ID:     event.ID,
				Time:   event.Time,
				Actor:  event.Actor,
				Action: event.Action,
				Target: event.Target,
				Detail: event.Detail,
			})
		}
	}

	// Merge the per-organization logs into one stream ordered by time, with
	// the organization and ID breaking ties so the order is deterministic.
	slices.SortFunc(events, func(a, b PlatformAuditEvent) int {
		if c := a.Time.Compare(b.Time); c != 0 {
			return c
		}
		if c := strings.Compare(a.Org, b.Org); c != 0 {
			return c
		}
		return int(a.ID) - int(b.ID)
	})

	writeJSON(w, http.StatusOK, map[string]any{
		"events":   events,
		"cursors":  next,
		"has_more": hasMore,
	})
}

// selectAuditOrgs resolves the org filter. An empty filter selects every
// organization, in the router's configured order.
func (r *Router) selectAuditOrgs(raw []string) ([]*routerOrg, error) {
	wanted := splitAuditList(raw)
	if len(wanted) == 0 {
		r.mu.RLock()
		defer r.mu.RUnlock()
		return slices.Clone(r.orgs), nil
	}

	selected := make([]*routerOrg, 0, len(wanted))
	for _, id := range wanted {
		org := r.orgByID(id)
		if org == nil {
			return nil, errors.New("unknown organization " + strconv.Quote(id))
		}
		if !slices.ContainsFunc(selected, func(o *routerOrg) bool { return o.site.ID == id }) {
			selected = append(selected, org)
		}
	}
	return selected, nil
}

// parseAuditCursors parses "org:id" pairs, accepting the parameter once with
// comma-separated pairs or repeated. Unknown organizations and malformed pairs
// are rejected: a typo would otherwise silently re-export everything.
func parseAuditCursors(raw []string) (map[string]uint64, error) {
	cursors := make(map[string]uint64)
	for _, pair := range splitAuditList(raw) {
		org, idText, ok := strings.Cut(pair, ":")
		if !ok || org == "" || idText == "" {
			return nil, errors.New("cursor must look like org:id")
		}
		id, err := strconv.ParseUint(idText, 10, 64)
		if err != nil {
			return nil, errors.New("invalid cursor id " + strconv.Quote(idText))
		}
		cursors[org] = id
	}
	return cursors, nil
}

// parseAuditActions splits and validates the action filter. Patterns are
// validated even when nothing is exported, so a typo fails loudly.
func parseAuditActions(raw []string) ([]string, error) {
	patterns := splitAuditList(raw)
	for _, pattern := range patterns {
		if _, err := webhook.MatchGlob(pattern, ""); err != nil {
			return nil, err
		}
	}
	return patterns, nil
}

// parseAuditLimit bounds the per-organization scan.
func parseAuditLimit(raw string) (int, error) {
	if raw == "" {
		return platformAuditDefaultLimit, nil
	}
	limit, err := strconv.Atoi(raw)
	if err != nil || limit < 1 {
		return 0, errors.New("invalid limit")
	}
	return min(limit, platformAuditMaxLimit), nil
}

// matchesAnyAction reports whether an action matches one of the patterns; an
// empty filter matches everything.
func matchesAnyAction(patterns []string, action string) bool {
	if len(patterns) == 0 {
		return true
	}
	for _, pattern := range patterns {
		// Patterns were validated by parseAuditActions.
		ok, err := webhook.MatchGlob(pattern, action)
		if err == nil && ok {
			return true
		}
	}
	return false
}

// splitAuditList flattens repeated and comma-separated parameter values,
// dropping empty entries.
func splitAuditList(raw []string) []string {
	var out []string
	for _, value := range raw {
		for _, part := range strings.Split(value, ",") {
			if part = strings.TrimSpace(part); part != "" {
				out = append(out, part)
			}
		}
	}
	return out
}
