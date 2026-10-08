package control

import (
	"net/http"
	"slices"
	"time"

	"github.com/xunara-net/xunara-server/state"
)

// Security Center console (PROJECT_SPEC section 39.3): the read-only page
// rendering the same snapshot as GET /api/v2/security, plus the node-key
// expiry table that makes the findings actionable.

// consoleSecurityExpiryLimit bounds the expiry table.
const consoleSecurityExpiryLimit = 200

// consoleSecurityExpiryRow is one node with a key expiry, soonest first.
type consoleSecurityExpiryRow struct {
	Hostname string
	Owner    string
	Expiry   time.Time
	// State is "expired", "expiring" or "scheduled".
	State string
}

// consoleSecurityExpiryRows lists nodes whose key expiry is set, soonest
// first; the table is what turns "keys are expiring" into names to act on.
func (s *Server) consoleSecurityExpiryRows(now time.Time) []consoleSecurityExpiryRow {
	nodes := s.store.ListNodes()
	rows := make([]consoleSecurityExpiryRow, 0, len(nodes))
	for _, node := range nodes {
		if node.Expiry.IsZero() {
			continue
		}
		state := "scheduled"
		switch {
		case node.Expired(now):
			state = "expired"
		case node.Expiry.Before(now.Add(securityKeyExpiryWindow)):
			state = "expiring"
		}
		rows = append(rows, consoleSecurityExpiryRow{
			Hostname: nodeDisplayHostname(node),
			Owner:    s.userLoginName(node.UserID),
			Expiry:   node.Expiry,
			State:    state,
		})
	}
	slices.SortFunc(rows, func(a, b consoleSecurityExpiryRow) int {
		return a.Expiry.Compare(b.Expiry)
	})
	if len(rows) > consoleSecurityExpiryLimit {
		rows = rows[:consoleSecurityExpiryLimit]
	}
	return rows
}

// handleConsoleSecurity implements GET /console/security.
func (s *Server) handleConsoleSecurity(w http.ResponseWriter, r *http.Request) {
	_, data, ok := s.consoleSession(w, r, "security")
	if !ok {
		return
	}
	view := s.securityView()
	data["View"] = view
	data["Expiry"] = s.consoleSecurityExpiryRows(view.GeneratedAt)
	s.renderConsole(w, consoleSecurityTemplate, data)
}

// nodeDisplayHostname picks the name a node is known by on the console,
// falling back to the reported hostname and then the stable ID.
func nodeDisplayHostname(node state.Node) string {
	if node.Hostname != "" {
		return node.Hostname
	}
	if node.Hostinfo != nil && node.Hostinfo.Hostname != "" {
		return node.Hostinfo.Hostname
	}
	return node.StableID
}
