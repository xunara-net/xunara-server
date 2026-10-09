package control

import (
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/xunara-net/xunara-server/identity"
)

// Xunara Security Center (PROJECT_SPEC section 39): a read-only snapshot of
// the tailnet's security posture plus a short list of actionable findings.
//
// Everything here is derived from state the other surfaces already own; the
// snapshot has no storage, no alerting and no scoring, and never carries key
// material (AGENTS.md sections 8 and 18).

// Finding severities, most severe first.
const (
	securitySeverityHigh   = "high"
	securitySeverityMedium = "medium"
	securitySeverityLow    = "low"
	securitySeverityInfo   = "info"
)

// securityFinding is one actionable observation.
type securityFinding struct {
	ID       string `json:"id"`
	Severity string `json:"severity"`
	Title    string `json:"title"`
	Detail   string `json:"detail"`
}

// securityView is the JSON shape of GET /api/v2/security and the console page.
type securityView struct {
	GeneratedAt time.Time `json:"generatedAt"`

	TailnetLock TKAStatus `json:"tailnetLock"`
	Policy      struct {
		Configured       bool `json:"configured"`
		RuleCount        int  `json:"ruleCount"`
		WarningCount     int  `json:"warningCount"`
		UnsupportedCount int  `json:"unsupportedCount"`
		// LoadError is the local parse failure text, if any: it is an
		// operator-visible configuration error, never key material.
		LoadError string `json:"loadError,omitempty"`
	} `json:"policy"`
	Nodes struct {
		Total        int `json:"total"`
		Online       int `json:"online"`
		Expired      int `json:"expired"`
		ExpiringSoon int `json:"expiringSoon"`
		Unsigned     int `json:"unsigned"`
		Tagged       int `json:"tagged"`
		Untagged     int `json:"untagged"`
		Ephemeral    int `json:"ephemeral"`
		ExitNodes    int `json:"exitNodes"`
	} `json:"nodes"`
	Devices struct {
		Pending int `json:"pending"`
	} `json:"devices"`
	AuthKeys struct {
		Total   int `json:"total"`
		Expired int `json:"expired"`
		Unused  int `json:"unused"`
	} `json:"authKeys"`
	APIKeys struct {
		Total        int `json:"total"`
		Live         int `json:"live"`
		Revoked      int `json:"revoked"`
		Expired      int `json:"expired"`
		NeverExpires int `json:"neverExpires"`
	} `json:"apiKeys"`
	Sharing struct {
		Enabled          bool `json:"enabled"`
		OutgoingPending  int  `json:"outgoingPending"`
		OutgoingAccepted int  `json:"outgoingAccepted"`
		IncomingPending  int  `json:"incomingPending"`
		IncomingAccepted int  `json:"incomingAccepted"`
	} `json:"sharing"`
	Webhooks struct {
		Configured    int  `json:"configured"`
		ManagedActive int  `json:"managedActive"`
		ManagedPaused int  `json:"managedPaused"`
		Enabled       bool `json:"enabled"`
	} `json:"webhooks"`
	DERP struct {
		MapConfigured bool   `json:"mapConfigured"`
		Policy        string `json:"policy"`
		RegionsServed int    `json:"regionsServed"`
	} `json:"derp"`

	Findings []securityFinding `json:"findings"`
}

// securityKeyExpiryWindow is how far ahead the snapshot looks for node keys
// about to expire.
const securityKeyExpiryWindow = 30 * 24 * time.Hour

// securityView builds the current snapshot. It never fails: missing optional
// components simply report as disabled.
func (s *Server) securityView() securityView {
	now := time.Now().UTC()
	var view securityView
	view.GeneratedAt = now
	view.TailnetLock = s.TKAStatus()

	policy := s.policyView()
	view.Policy.Configured = policy.Configured
	view.Policy.RuleCount = policy.RuleCount
	view.Policy.WarningCount = len(policy.Warnings)
	view.Policy.UnsupportedCount = len(policy.Unsupported)
	view.Policy.LoadError = policy.LoadError

	for _, node := range s.store.ListNodes() {
		view.Nodes.Total++
		if s.isOnline(node.ID) {
			view.Nodes.Online++
		}
		switch {
		case node.Expired(now):
			view.Nodes.Expired++
		case !node.Expiry.IsZero() && node.Expiry.Before(now.Add(securityKeyExpiryWindow)):
			view.Nodes.ExpiringSoon++
		}
		if len(node.KeySignature) == 0 {
			view.Nodes.Unsigned++
		}
		if len(node.Tags) > 0 {
			view.Nodes.Tagged++
		} else {
			view.Nodes.Untagged++
		}
		if node.Ephemeral {
			view.Nodes.Ephemeral++
		}
		if nodeHasApprovedExitRoute(node) {
			view.Nodes.ExitNodes++
		}
	}

	view.Devices.Pending = len(s.identity.ListPendingDeviceAuthorizations(now))

	for _, key := range s.store.ListPreAuthKeys() {
		view.AuthKeys.Total++
		if !key.Expiry.IsZero() && key.Expiry.Before(now) {
			view.AuthKeys.Expired++
		}
		if !key.Used && !key.Reusable {
			view.AuthKeys.Unused++
		}
	}

	for _, key := range s.identity.ListAPIKeys() {
		view.APIKeys.Total++
		expired := !key.ExpiresAt.IsZero() && key.ExpiresAt.Before(now)
		switch {
		case !key.RevokedAt.IsZero():
			view.APIKeys.Revoked++
		case expired:
			view.APIKeys.Expired++
		default:
			view.APIKeys.Live++
			if key.ExpiresAt.IsZero() {
				view.APIKeys.NeverExpires++
			}
		}
	}

	if s.sharingEnabled() {
		view.Sharing.Enabled = true
		orgID := s.Organization().ID
		count := func(source, target string, status string) int {
			return len(s.shares.ListShares(ShareFilter{
				SourceOrg: source,
				TargetOrg: target,
				Statuses:  []string{status},
			}))
		}
		view.Sharing.OutgoingPending = count(orgID, "", SharePending)
		view.Sharing.OutgoingAccepted = count(orgID, "", ShareAccepted)
		view.Sharing.IncomingPending = count("", orgID, SharePending)
		view.Sharing.IncomingAccepted = count("", orgID, ShareAccepted)
	}

	view.Webhooks.Configured = len(s.cfg.Webhooks)
	for _, endpoint := range s.identity.ListWebhookEndpoints() {
		if endpoint.Enabled {
			view.Webhooks.ManagedActive++
		} else {
			view.Webhooks.ManagedPaused++
		}
	}
	view.Webhooks.Enabled = s.webhooksEnabled()

	view.DERP.MapConfigured = s.DERPMap() != nil
	view.DERP.Policy = string(s.cfg.DERPPolicy.Mode)
	view.DERP.RegionsServed = s.derpRegionsServed()

	view.Findings = s.securityFindings(view)
	return view
}

// securityFindings derives the findings from a finished snapshot. The list is
// ordered by severity, then by ID, so two identical tailnets render the same
// page.
func (s *Server) securityFindings(view securityView) []securityFinding {
	var findings []securityFinding
	add := func(id, severity, title, detail string) {
		findings = append(findings, securityFinding{ID: id, Severity: severity, Title: title, Detail: detail})
	}

	if !view.Policy.Configured {
		add("policy.absent", securitySeverityHigh,
			"Access control policy is not configured",
			"The tailnet runs allow-all: every node may reach every other node. Load a policy document to restrict access.")
	} else if view.Policy.LoadError != "" {
		add("policy.load_error", securitySeverityHigh,
			"The policy file no longer parses",
			"The last good document is still enforced. Fix the file: "+view.Policy.LoadError)
	}
	if view.TailnetLock.Enabled && view.TailnetLock.Nodes.Unsigned > 0 {
		add("tka.unsigned_nodes", securitySeverityHigh,
			"Tailnet lock is enforced with unsigned nodes",
			"Unsigned nodes are rejected by locked peers. Sign them with `tailscale lock sign` or remove them.")
	}
	if view.Nodes.Expired > 0 {
		add("nodes.expired_keys", securitySeverityMedium,
			"Nodes have expired keys",
			"An expired node key drops the node off the tailnet until it re-authenticates.")
	}
	if view.APIKeys.NeverExpires > 0 {
		add("apikeys.never_expires", securitySeverityLow,
			"API keys never expire",
			"Service identity keys without an expiry cannot be aged out; revoke or replace them deliberately.")
	}
	if view.Nodes.ExpiringSoon > 0 {
		add("nodes.keys_expiring", securitySeverityLow,
			"Node keys expire within 30 days",
			"Nodes whose key expires will drop off the tailnet unless their expiry is extended or they re-authenticate.")
	}
	if view.Devices.Pending > 0 {
		add("devices.pending", securitySeverityInfo,
			"Devices are waiting for approval",
			"Pending device authorizations expire on their own if they are not legitimate (section 35).")
	}

	rank := map[string]int{
		securitySeverityHigh:   0,
		securitySeverityMedium: 1,
		securitySeverityLow:    2,
		securitySeverityInfo:   3,
	}
	slices.SortStableFunc(findings, func(a, b securityFinding) int {
		if ra, rb := rank[a.Severity], rank[b.Severity]; ra != rb {
			return ra - rb
		}
		return strings.Compare(a.ID, b.ID)
	})
	return findings
}

// handleAPIV2Security implements GET /api/v2/security (spec section 39.3).
func (s *Server) handleAPIV2Security(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireScope(w, r, identity.ScopeRead); !ok {
		return
	}
	writeJSON(w, http.StatusOK, s.securityView())
}
