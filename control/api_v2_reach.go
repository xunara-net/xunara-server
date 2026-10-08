package control

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/xunara-net/xunara-server/identity"
	"github.com/xunara-net/xunara-server/state"
)

// This file is the read-only management surface for Xunara Reach (PROJECT_SPEC
// section 31). Administrators can see who offered which command to which node,
// how it ended, and what it printed; there is no write path. The sessions are
// the same records the two agents use - the management plane gets no second
// copy - and argv/output stay out of the audit log and webhooks.

// reachOutputBytes counts a session's output without carrying it; the content
// comes from the chunks endpoint.
type reachOutputBytes struct {
	Stdout int64 `json:"stdout"`
	Stderr int64 `json:"stderr"`
}

// reachAdminSession is one session as the management plane sees it.
type reachAdminSession struct {
	reachSessionView
	OutputBytes reachOutputBytes `json:"outputBytes"`
}

// handleAPIV2ReachSessions implements GET /api/v2/reach/sessions, newest first.
//
// Filters: state=<session state>, node=<id or stable ID>. Both are
// fail-closed: an unknown state is a 400 and an unknown node matches nothing,
// because a filter that silently widens its result is a security bug.
func (s *Server) handleAPIV2ReachSessions(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireScope(w, r, identity.ScopeRead); !ok {
		return
	}
	if s.reachDisabled(w) {
		return
	}
	w.Header().Set("Cache-Control", "no-store")

	limit, ok := apiV2Limit(w, r, 100)
	if !ok {
		return
	}
	afterCreated, afterID, ok := apiV2TimeCursor(w, r, "reach")
	if !ok {
		return
	}

	query := r.URL.Query()
	var stateFilter state.ReachState
	if raw := query.Get("state"); raw != "" {
		stateFilter = state.ReachState(raw)
		if !stateFilter.Valid() {
			writeAPIError(w, http.StatusBadRequest, "invalid state filter")
			return
		}
	}
	nodeFilter := s.apiV2NodeFilter(query.Get("node"))

	items := make([]reachAdminSession, 0, limit)
	var last state.ReachSession
	next := ""
	for _, session := range s.store.ListAllReachSessions() {
		if !newestFirstAfterCursor(session.CreatedAt, session.ID, afterCreated, afterID) {
			continue
		}
		if stateFilter != "" && session.State != stateFilter {
			continue
		}
		if nodeFilter != 0 && session.Sender != nodeFilter && session.Target != nodeFilter {
			continue
		}
		if len(items) == limit {
			next = reachEncodePageCursor(last)
			break
		}
		view, ok := s.reachAdminView(session)
		if !ok {
			// A participant's node row is gone; the session cascade removes
			// it too, so this is only a race with the deletion.
			continue
		}
		items = append(items, view)
		last = session
	}

	writeJSON(w, http.StatusOK, map[string]any{"items": items, "nextCursor": next})
}

// handleAPIV2ReachSession implements GET /api/v2/reach/sessions/{id}: the full
// session, argv included (the approver saw it, the administrator may too).
func (s *Server) handleAPIV2ReachSession(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireScope(w, r, identity.ScopeRead); !ok {
		return
	}
	if s.reachDisabled(w) {
		return
	}
	w.Header().Set("Cache-Control", "no-store")

	session, ok := s.store.GetReachSession(chi.URLParam(r, "id"))
	if !ok {
		writeAPIError(w, http.StatusNotFound, "no such session")
		return
	}
	view, ok := s.reachAdminView(session)
	if !ok {
		writeAPIError(w, http.StatusNotFound, "no such session")
		return
	}
	writeJSON(w, http.StatusOK, view)
}

// handleAPIV2ReachChunks implements GET /api/v2/reach/sessions/{id}/chunks,
// the read-only output relay: the same shape as the agent endpoint, bounded to
// one page per stream.
func (s *Server) handleAPIV2ReachChunks(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireScope(w, r, identity.ScopeRead); !ok {
		return
	}
	if s.reachDisabled(w) {
		return
	}
	w.Header().Set("Cache-Control", "no-store")

	id := chi.URLParam(r, "id")
	if _, ok := s.store.GetReachSession(id); !ok {
		writeAPIError(w, http.StatusNotFound, "no such session")
		return
	}
	afterOut, err := reachCursor(r, "out")
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid out cursor")
		return
	}
	afterErr, err := reachCursor(r, "err")
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid err cursor")
		return
	}

	chunks, err := s.reachChunksPage(id, afterOut, afterErr)
	if err != nil {
		s.log.Error("reading reach output", "session", id, "err", err)
		writeAPIError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, chunks)
}

// reachAdminView renders one session with its output size counters.
func (s *Server) reachAdminView(session state.ReachSession) (reachAdminSession, bool) {
	view, ok := s.reachView(session)
	if !ok {
		return reachAdminSession{}, false
	}
	stdout, stderr, err := s.store.ReachOutputBytes(session.ID)
	if err != nil {
		// The counters are advisory; a read failure must not hide the session.
		s.log.Warn("reading reach output sizes failed", "session", session.ID, "err", err)
	}
	return reachAdminSession{
		reachSessionView: view,
		OutputBytes:      reachOutputBytes{Stdout: stdout, Stderr: stderr},
	}, true
}

// reachChunksPage reads one bounded page per stream; both the agent endpoint
// and the management surface share it.
func (s *Server) reachChunksPage(id string, afterOut, afterErr int64) (reachChunksResponse, error) {
	resp := reachChunksResponse{
		Out:     []reachChunkView{},
		Err:     []reachChunkView{},
		NextOut: afterOut,
		NextErr: afterErr,
	}
	fill := func(stream string, after int64, out *[]reachChunkView, next *int64) error {
		chunks, err := s.store.ReachChunks(id, stream, after, state.ReachMaxChunksPerRead)
		if err != nil {
			return err
		}
		for _, chunk := range chunks {
			*out = append(*out, reachChunkView{
				Stream:    chunk.Stream,
				Seq:       chunk.Seq,
				Data:      chunk.Data,
				CreatedAt: chunk.CreatedAt,
			})
			*next = chunk.Seq
		}
		return nil
	}
	if err := fill(state.ReachStreamStdout, afterOut, &resp.Out, &resp.NextOut); err != nil {
		return reachChunksResponse{}, err
	}
	if err := fill(state.ReachStreamStderr, afterErr, &resp.Err, &resp.NextErr); err != nil {
		return reachChunksResponse{}, err
	}
	return resp, nil
}

// reachEncodePageCursor packs a list position for the reach cursor kind.
func reachEncodePageCursor(session state.ReachSession) string {
	return apiV2EncodeTimeCursor("reach", session.CreatedAt, session.ID)
}
