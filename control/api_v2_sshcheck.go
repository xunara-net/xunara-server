package control

import (
	"net/http"
	"time"

	"github.com/xunara-net/xunara-server/identity"
	"github.com/xunara-net/xunara-server/state"
)

// This file is the read-only SSH check management surface (PROJECT_SPEC
// section 35): who is trying to SSH where, which local account they asked
// for, and how the check ended. The sessions are the durable records the
// approval flow already uses - the management plane gets no second copy - and
// there is no write path: verdicts are only made on the browser approval page.

// The derived, mutually exclusive lifecycle states of one session. The raw
// verdict alone cannot express them: a consumed accept must still read as
// "consumed", and an expired session the janitor has not reaped yet must not
// read as "pending".
const (
	sshCheckStateExpired  = "expired"
	sshCheckStatePending  = "pending"
	sshCheckStateConsumed = "consumed"
	sshCheckStateAccepted = "accepted"
	sshCheckStateRejected = "rejected"
)

// sshCheckStates lists every state a state= filter accepts.
var sshCheckStates = []string{
	sshCheckStatePending,
	sshCheckStateExpired,
	sshCheckStateConsumed,
	sshCheckStateAccepted,
	sshCheckStateRejected,
}

// sshCheckStateOf derives the lifecycle state. The TTL check comes first: an
// expired session is no longer decidable even though its verdict is still
// "pending".
func sshCheckStateOf(sess identity.SSHCheckSession, now time.Time) string {
	switch {
	case sess.Pending() && sess.Expired(now):
		return sshCheckStateExpired
	case sess.Pending():
		return sshCheckStatePending
	case !sess.ConsumedAt.IsZero():
		return sshCheckStateConsumed
	case sess.Verdict == identity.SSHCheckAccepted:
		return sshCheckStateAccepted
	default:
		return sshCheckStateRejected
	}
}

// sshCheckStateValid reports whether a state= filter value is known.
func sshCheckStateValid(state string) bool {
	for _, candidate := range sshCheckStates {
		if candidate == state {
			return true
		}
	}
	return false
}

// sshCheckPeerView names one end of a session. A deleted node keeps its ID;
// the stable ID and hostname are simply absent, never invented.
type sshCheckPeerView struct {
	NodeID   int64  `json:"nodeId"`
	StableID string `json:"stableId,omitempty"`
	Hostname string `json:"hostname,omitempty"`
}

// sshCheckDeciderView names the console user who decided a session.
type sshCheckDeciderView struct {
	UserID    uint64 `json:"userId"`
	LoginName string `json:"loginName,omitempty"`
}

// sshCheckAdminSession is one session as the management plane sees it. The
// list entry is the detail: the record is small.
type sshCheckAdminSession struct {
	ID         string               `json:"id"`
	State      string               `json:"state"`
	Verdict    string               `json:"verdict"`
	Src        sshCheckPeerView     `json:"src"`
	Dst        sshCheckPeerView     `json:"dst"`
	LocalUser  string               `json:"localUser"`
	CreatedAt  time.Time            `json:"createdAt"`
	ExpiresAt  time.Time            `json:"expiresAt"`
	DecidedAt  *time.Time           `json:"decidedAt,omitempty"`
	DecidedBy  *sshCheckDeciderView `json:"decidedBy,omitempty"`
	ConsumedAt *time.Time           `json:"consumedAt,omitempty"`
}

// sshCheckScanMax bounds how many rows one page scans while filtering, so a
// filter that matches nothing cannot turn a request into a full-table walk.
// Sessions expire after 15 minutes, so this only matters when the janitor is
// broken.
const sshCheckScanMax = 10_000

// sshCheckAdminView renders one session. now decides the derived state.
func (s *Server) sshCheckAdminView(sess identity.SSHCheckSession, now time.Time) sshCheckAdminSession {
	view := sshCheckAdminSession{
		ID:        sess.ID,
		State:     sshCheckStateOf(sess, now),
		Verdict:   string(sess.Verdict),
		Src:       s.sshCheckPeerView(sess.SrcNodeID),
		Dst:       s.sshCheckPeerView(sess.DstNodeID),
		LocalUser: sess.LocalUser,
		CreatedAt: sess.CreatedAt,
		ExpiresAt: sess.ExpiresAt,
	}
	if !sess.DecidedAt.IsZero() {
		decidedAt := sess.DecidedAt
		view.DecidedAt = &decidedAt
		view.DecidedBy = &sshCheckDeciderView{
			UserID:    uint64(sess.DecidedBy),
			LoginName: s.userLoginName(sess.DecidedBy),
		}
	}
	if !sess.ConsumedAt.IsZero() {
		consumedAt := sess.ConsumedAt
		view.ConsumedAt = &consumedAt
	}
	return view
}

// sshCheckPeerView names one end; an unknown node keeps its ID only.
func (s *Server) sshCheckPeerView(id int64) sshCheckPeerView {
	view := sshCheckPeerView{NodeID: id}
	if node, ok := s.store.GetNodeByID(state.NodeID(id)); ok {
		view.StableID = node.StableID
		view.Hostname = node.Hostname
	}
	return view
}

// sshCheckPage returns one newest-first page of sessions that pass the
// filters, plus the cursor for the next page (empty when the listing ends).
func (s *Server) sshCheckPage(stateFilter string, nodeFilter state.NodeID, limit int, afterCreated time.Time, afterID string) ([]sshCheckAdminSession, string, error) {
	sessions, err := s.identity.ListSSHCheckSessions(sshCheckScanMax)
	if err != nil {
		s.log.Error("listing ssh check sessions", "err", err)
		return nil, "", err
	}

	now := time.Now().UTC()
	items := make([]sshCheckAdminSession, 0, limit)
	var last identity.SSHCheckSession
	var next string
	for _, sess := range sessions {
		if !newestFirstAfterCursor(sess.CreatedAt, sess.ID, afterCreated, afterID) {
			continue
		}
		if stateFilter != "" && sshCheckStateOf(sess, now) != stateFilter {
			continue
		}
		if nodeFilter != 0 &&
			state.NodeID(sess.SrcNodeID) != nodeFilter && state.NodeID(sess.DstNodeID) != nodeFilter {
			continue
		}
		if len(items) == limit {
			next = sshCheckEncodePageCursor(last)
			break
		}
		items = append(items, s.sshCheckAdminView(sess, now))
		last = sess
	}
	return items, next, nil
}

// sshCheckEncodePageCursor points at the last session of a page.
func sshCheckEncodePageCursor(sess identity.SSHCheckSession) string {
	return apiV2EncodeTimeCursor("sshcheck", sess.CreatedAt, sess.ID)
}

// handleAPIV2SSHCheckSessions implements GET /api/v2/ssh-check/sessions,
// newest first (spec section 35.1).
func (s *Server) handleAPIV2SSHCheckSessions(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireScope(w, r, identity.ScopeRead); !ok {
		return
	}
	w.Header().Set("Cache-Control", "no-store")

	limit, ok := apiV2Limit(w, r, 100)
	if !ok {
		return
	}
	afterCreated, afterID, ok := apiV2TimeCursor(w, r, "sshcheck")
	if !ok {
		return
	}
	stateFilter := r.URL.Query().Get("state")
	if stateFilter != "" && !sshCheckStateValid(stateFilter) {
		writeAPIError(w, http.StatusBadRequest, "invalid state filter")
		return
	}

	items, next, err := s.sshCheckPage(stateFilter, s.apiV2NodeFilter(r.URL.Query().Get("node")),
		limit, afterCreated, afterID)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "could not list ssh checks")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "nextCursor": next})
}
