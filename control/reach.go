package control

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/xunara-net/xunara-server/identity"
	"github.com/xunara-net/xunara-server/state"
)

// This file implements Xunara Reach, the native client's remote command
// execution protocol (PROJECT_SPEC section 29). The control plane orchestrates
// sessions - offer, approval, start, output relay, result - and never runs a
// command itself. The target agent executes argv element by element, without a
// shell; the command's stdin is empty and there is no PTY.

// Reach limits mirrored at the API edge (the store re-checks them).
const (
	defaultReachTimeout = 60 * time.Second
	// reachCreateRateLimit bounds session creation per node; the rate limiter
	// itself is durable (spec section 28 mechanism).
	reachCreateRateLimit = 6
	// reachCreateRateWindow is the limiter window.
	reachCreateRateWindow = 10 * time.Second
	// reachRetention is how long a terminal session (with its output) is kept
	// before the janitor deletes it.
	reachRetention = time.Hour
)

// agentReachCreateRequest is the body of POST /api/agent/v1/reach/sessions.
type agentReachCreateRequest struct {
	agentRequest
	// To is the target's stable ID. Hostnames are resolved by the client from
	// the netmap so the control plane never guesses between same-named nodes.
	To   string   `json:"to"`
	Argv []string `json:"argv"`
	// TimeoutSec bounds the command's runtime; 0 uses the default.
	TimeoutSec int `json:"timeoutSec,omitempty"`
}

// reachPeer is the public identity of one participant.
type reachPeer struct {
	NodeID   uint64 `json:"nodeId"`
	StableID string `json:"stableId"`
	Hostname string `json:"hostname,omitempty"`
}

// reachSessionView is one session as both agents see it.
type reachSessionView struct {
	ID         string    `json:"id"`
	State      string    `json:"state"`
	Sender     reachPeer `json:"sender"`
	Target     reachPeer `json:"target"`
	Argv       []string  `json:"argv"`
	TimeoutSec int       `json:"timeoutSec"`
	ExitCode   *int      `json:"exitCode,omitempty"`
	Error      string    `json:"error,omitempty"`
	CreatedAt  time.Time `json:"createdAt"`
	UpdatedAt  time.Time `json:"updatedAt"`
	ExpiresAt  time.Time `json:"expiresAt"`
}

// reachChunkView is one output chunk.
type reachChunkView struct {
	Stream    string    `json:"stream"`
	Seq       int64     `json:"seq"`
	Data      []byte    `json:"data"`
	CreatedAt time.Time `json:"createdAt"`
}

// reachChunksResponse is a chunk read: one list per stream plus the cursors to
// pass next time.
type reachChunksResponse struct {
	Out     []reachChunkView `json:"out"`
	Err     []reachChunkView `json:"err"`
	NextOut int64            `json:"nextOut"`
	NextErr int64            `json:"nextErr"`
}

// reachDecisionResponse is the answer to accept/deny/cancel/finish: the
// session after the transition.
type reachDecisionResponse struct {
	Session reachSessionView `json:"session"`
}

// handleReachCreate implements POST /api/agent/v1/reach/sessions.
func (s *Server) handleReachCreate(w http.ResponseWriter, req *http.Request) {
	var body agentReachCreateRequest
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		httpError(w, NewHTTPError(http.StatusBadRequest, "invalid JSON body", nil))
		return
	}
	sender, _, err := s.authenticateAgent(req, body.agentRequest.withHeaders(req))
	if err != nil {
		httpError(w, err)
		return
	}
	if s.reachDisabled(w) {
		return
	}

	target, ok := s.store.GetNodeByStableID(body.To)
	if !ok || target.ID == sender.ID {
		httpError(w, NewHTTPError(http.StatusNotFound, "no such target", nil))
		return
	}

	argv, err := normalizeReachArgv(body.Argv)
	if err != nil {
		httpError(w, NewHTTPError(http.StatusBadRequest, err.Error(), nil))
		return
	}
	timeout := defaultReachTimeout
	if body.TimeoutSec != 0 {
		if body.TimeoutSec < 0 || time.Duration(body.TimeoutSec)*time.Second > state.ReachMaxTimeout {
			httpError(w, NewHTTPError(http.StatusBadRequest, "timeoutSec is out of range", nil))
			return
		}
		timeout = time.Duration(body.TimeoutSec) * time.Second
	}

	// Session creation is rate limited per node; a rejected attempt is not
	// audited so a looping client cannot flood the log.
	allowed, retryAfter, err := s.store.AllowRate(
		"reach:"+strconv.FormatUint(uint64(sender.ID), 10), reachCreateRateLimit, reachCreateRateWindow, time.Now())
	if err != nil {
		s.log.Error("rate limiting a reach offer", "node", sender.StableID, "err", err)
		httpError(w, NewHTTPError(http.StatusInternalServerError, "internal error", nil))
		return
	}
	if !allowed {
		w.Header().Set("Retry-After", strconv.Itoa(retryAfterSeconds(retryAfter)))
		httpError(w, NewHTTPError(http.StatusTooManyRequests, "too many reach sessions", nil))
		return
	}

	session := state.ReachSession{
		Sender:  sender.ID,
		Target:  target.ID,
		State:   state.ReachOffered,
		Argv:    argv,
		Timeout: timeout,
	}
	if err := s.store.CreateReachSession(&session, state.ReachQuotas{}); err != nil {
		switch {
		case errors.Is(err, state.ErrReachSessionQuota):
			httpError(w, NewHTTPError(http.StatusTooManyRequests, "too many active sessions with this target", nil))
		default:
			s.log.Error("creating a reach session", "node", sender.StableID, "err", err)
			httpError(w, NewHTTPError(http.StatusInternalServerError, "internal error", nil))
		}
		return
	}

	s.audit(nodeActor(sender), identity.AuditReachOffered, nodeTarget(target),
		"session="+session.ID+" from="+sender.StableID)
	s.log.Info("reach offered", "session", session.ID, "from", sender.StableID, "to", target.StableID)

	view, ok := s.reachView(session)
	if !ok {
		httpError(w, NewHTTPError(http.StatusInternalServerError, "internal error", nil))
		return
	}
	writeJSON(w, http.StatusCreated, reachDecisionResponse{Session: view})
}

// handleReachList implements GET /api/agent/v1/reach/sessions: every session
// this node participates in, newest first.
func (s *Server) handleReachList(w http.ResponseWriter, req *http.Request) {
	node, err := s.authenticateReach(req)
	if err != nil {
		httpError(w, err)
		return
	}
	if s.reachDisabled(w) {
		return
	}

	sessions := s.store.ListReachSessions(node.ID)
	views := make([]reachSessionView, 0, len(sessions))
	for _, session := range sessions {
		view, ok := s.reachView(session)
		if !ok {
			continue
		}
		views = append(views, view)
	}
	writeJSON(w, http.StatusOK, map[string]any{"sessions": views})
}

// handleReachGet implements GET /api/agent/v1/reach/sessions/{id}.
func (s *Server) handleReachGet(w http.ResponseWriter, req *http.Request) {
	node, err := s.authenticateReach(req)
	if err != nil {
		httpError(w, err)
		return
	}
	if s.reachDisabled(w) {
		return
	}

	session, err := s.reachSessionFor(req, node)
	if err != nil {
		httpError(w, err)
		return
	}
	view, ok := s.reachView(session)
	if !ok {
		httpError(w, NewHTTPError(http.StatusInternalServerError, "internal error", nil))
		return
	}
	writeJSON(w, http.StatusOK, reachDecisionResponse{Session: view})
}

// handleReachAccept implements POST .../{id}/accept (target only).
func (s *Server) handleReachAccept(w http.ResponseWriter, req *http.Request) {
	s.reachTransition(w, req, state.ReachAccepted, true)
}

// handleReachDeny implements POST .../{id}/deny (target only).
func (s *Server) handleReachDeny(w http.ResponseWriter, req *http.Request) {
	s.reachTransition(w, req, state.ReachDenied, true)
}

// handleReachStart implements POST .../{id}/start (target only): the target
// agent takes over execution and the deadline becomes the execution window.
func (s *Server) handleReachStart(w http.ResponseWriter, req *http.Request) {
	node, err := s.authenticateReach(req)
	if err != nil {
		httpError(w, err)
		return
	}
	if s.reachDisabled(w) {
		return
	}
	session, err := s.reachSessionFor(req, node)
	if err != nil {
		httpError(w, err)
		return
	}
	if session.Target != node.ID {
		httpError(w, NewHTTPError(http.StatusForbidden, "only the target may start the session", nil))
		return
	}

	now := time.Now().UTC()
	ok, err := s.store.StartReachSession(session.ID, state.ReachExpiry(now, session.Timeout), now)
	if err != nil {
		s.log.Error("starting a reach session", "session", session.ID, "err", err)
		httpError(w, NewHTTPError(http.StatusInternalServerError, "internal error", nil))
		return
	}
	if !ok {
		httpError(w, NewHTTPError(http.StatusConflict, "the session is not accepted", nil))
		return
	}
	session, _ = s.store.GetReachSession(session.ID)
	s.audit(nodeActor(node), identity.AuditReachStarted, nodeTarget(node), "session="+session.ID)

	view, ok := s.reachView(session)
	if !ok {
		httpError(w, NewHTTPError(http.StatusInternalServerError, "internal error", nil))
		return
	}
	writeJSON(w, http.StatusOK, reachDecisionResponse{Session: view})
}

// handleReachChunks implements POST .../{id}/chunks (target only).
func (s *Server) handleReachChunks(w http.ResponseWriter, req *http.Request) {
	node, err := s.authenticateReach(req)
	if err != nil {
		httpError(w, err)
		return
	}
	if s.reachDisabled(w) {
		return
	}
	session, err := s.reachSessionFor(req, node)
	if err != nil {
		httpError(w, err)
		return
	}
	if session.Target != node.ID {
		httpError(w, NewHTTPError(http.StatusForbidden, "only the target may report output", nil))
		return
	}

	var body struct {
		Stream string `json:"stream"`
		Seq    int64  `json:"seq"`
		Data   []byte `json:"data"`
	}
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		httpError(w, NewHTTPError(http.StatusBadRequest, "invalid JSON body", nil))
		return
	}

	// Malformed chunks are the caller's bug, not a state conflict: a wrong
	// stream, a negative sequence or an empty/oversized payload is a 400/413
	// so the target's log points at the actual problem.
	switch {
	case !state.ReachChunkStreamValid(body.Stream):
		httpError(w, NewHTTPError(http.StatusBadRequest, "unknown output stream", nil))
		return
	case body.Seq < 0:
		httpError(w, NewHTTPError(http.StatusBadRequest, "seq must not be negative", nil))
		return
	case len(body.Data) == 0:
		httpError(w, NewHTTPError(http.StatusBadRequest, "chunk must not be empty", nil))
		return
	case len(body.Data) > state.ReachMaxChunkBytes:
		httpError(w, NewHTTPError(http.StatusRequestEntityTooLarge, "chunk is too large", nil))
		return
	}

	err = s.store.AppendReachChunk(session.ID, body.Stream, body.Seq, body.Data, state.ReachMaxOutputBytes, time.Now())
	switch {
	case err == nil:
		w.WriteHeader(http.StatusNoContent)
	case errors.Is(err, state.ErrReachChunkDuplicate):
		httpError(w, NewHTTPError(http.StatusConflict, "chunk already stored", nil))
	case errors.Is(err, state.ErrReachOutputLimit):
		httpError(w, NewHTTPError(http.StatusRequestEntityTooLarge, "session output limit exceeded", nil))
	case errors.Is(err, state.ErrReachSessionState), errors.Is(err, state.ErrReachSessionNotFound):
		s.reachStateError(w, err)
	default:
		s.log.Error("appending reach chunk", "session", session.ID, "err", err)
		httpError(w, NewHTTPError(http.StatusInternalServerError, "internal error", nil))
	}
}

// handleReachChunksRead implements GET .../{id}/chunks?out=&err=: the sender
// reads output written by the target.
func (s *Server) handleReachChunksRead(w http.ResponseWriter, req *http.Request) {
	node, err := s.authenticateReach(req)
	if err != nil {
		httpError(w, err)
		return
	}
	if s.reachDisabled(w) {
		return
	}
	session, err := s.reachSessionFor(req, node)
	if err != nil {
		httpError(w, err)
		return
	}

	afterOut, err := reachCursor(req, "out")
	if err != nil {
		httpError(w, NewHTTPError(http.StatusBadRequest, err.Error(), nil))
		return
	}
	afterErr, err := reachCursor(req, "err")
	if err != nil {
		httpError(w, NewHTTPError(http.StatusBadRequest, err.Error(), nil))
		return
	}

	resp, err := s.reachChunksPage(session.ID, afterOut, afterErr)
	if err != nil {
		s.reachStateError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleReachFinish implements POST .../{id}/finish (target only).
func (s *Server) handleReachFinish(w http.ResponseWriter, req *http.Request) {
	node, err := s.authenticateReach(req)
	if err != nil {
		httpError(w, err)
		return
	}
	if s.reachDisabled(w) {
		return
	}
	session, err := s.reachSessionFor(req, node)
	if err != nil {
		httpError(w, err)
		return
	}
	if session.Target != node.ID {
		httpError(w, NewHTTPError(http.StatusForbidden, "only the target may finish the session", nil))
		return
	}

	var body struct {
		ExitCode int    `json:"exitCode"`
		Error    string `json:"error,omitempty"`
	}
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		httpError(w, NewHTTPError(http.StatusBadRequest, "invalid JSON body", nil))
		return
	}

	ok, err := s.store.FinishReachSession(session.ID, body.ExitCode, sanitizeReachError(body.Error), time.Now())
	if err != nil {
		s.log.Error("finishing a reach session", "session", session.ID, "err", err)
		httpError(w, NewHTTPError(http.StatusInternalServerError, "internal error", nil))
		return
	}
	if !ok {
		httpError(w, NewHTTPError(http.StatusConflict, "the session is not running", nil))
		return
	}
	session, _ = s.store.GetReachSession(session.ID)

	action, detail := identity.AuditReachFinished, "session="+session.ID
	if session.State == state.ReachFailed {
		action, detail = identity.AuditReachFailed, fmt.Sprintf("session=%s exit=%d", session.ID, body.ExitCode)
	}
	s.audit(nodeActor(node), action, nodeTarget(node), detail)
	s.log.Info("reach finished", "session", session.ID, "state", session.State, "exit", body.ExitCode)

	view, ok := s.reachView(session)
	if !ok {
		httpError(w, NewHTTPError(http.StatusInternalServerError, "internal error", nil))
		return
	}
	writeJSON(w, http.StatusOK, reachDecisionResponse{Session: view})
}

// handleReachCancel implements POST .../{id}/cancel: either participant may
// withdraw a session that has not finished.
func (s *Server) handleReachCancel(w http.ResponseWriter, req *http.Request) {
	node, err := s.authenticateReach(req)
	if err != nil {
		httpError(w, err)
		return
	}
	if s.reachDisabled(w) {
		return
	}
	session, err := s.reachSessionFor(req, node)
	if err != nil {
		httpError(w, err)
		return
	}
	if !session.State.Active() {
		httpError(w, NewHTTPError(http.StatusConflict, "the session is already finished", nil))
		return
	}

	now := time.Now().UTC()
	ok, err := s.store.SetReachSessionState(session.ID, session.State, state.ReachCanceled, now)
	if err != nil {
		s.log.Error("canceling a reach session", "session", session.ID, "err", err)
		httpError(w, NewHTTPError(http.StatusInternalServerError, "internal error", nil))
		return
	}
	if !ok {
		httpError(w, NewHTTPError(http.StatusConflict, "the session state changed", nil))
		return
	}
	session, _ = s.store.GetReachSession(session.ID)
	s.audit(nodeActor(node), identity.AuditReachCanceled, nodeTarget(node), "session="+session.ID)

	view, ok := s.reachView(session)
	if !ok {
		httpError(w, NewHTTPError(http.StatusInternalServerError, "internal error", nil))
		return
	}
	writeJSON(w, http.StatusOK, reachDecisionResponse{Session: view})
}

// reachTransition handles accept/deny: only the target may answer an offer.
func (s *Server) reachTransition(w http.ResponseWriter, req *http.Request, to state.ReachState, targetOnly bool) {
	node, err := s.authenticateReach(req)
	if err != nil {
		httpError(w, err)
		return
	}
	if s.reachDisabled(w) {
		return
	}
	session, err := s.reachSessionFor(req, node)
	if err != nil {
		httpError(w, err)
		return
	}
	if targetOnly && session.Target != node.ID {
		httpError(w, NewHTTPError(http.StatusForbidden, "only the target may decide the session", nil))
		return
	}

	ok, err := s.store.SetReachSessionState(session.ID, state.ReachOffered, to, time.Now())
	if err != nil {
		s.log.Error("transitioning a reach session", "session", session.ID, "err", err)
		httpError(w, NewHTTPError(http.StatusInternalServerError, "internal error", nil))
		return
	}
	if !ok {
		httpError(w, NewHTTPError(http.StatusConflict, "the session is not waiting for a decision", nil))
		return
	}
	session, _ = s.store.GetReachSession(session.ID)

	action := identity.AuditReachAccepted
	if to == state.ReachDenied {
		action = identity.AuditReachDenied
	}
	s.audit(nodeActor(node), action, nodeTarget(node), "session="+session.ID)

	view, ok := s.reachView(session)
	if !ok {
		httpError(w, NewHTTPError(http.StatusInternalServerError, "internal error", nil))
		return
	}
	writeJSON(w, http.StatusOK, reachDecisionResponse{Session: view})
}

// authenticateReach authenticates a header-only agent request (a GET has no
// JSON body to repeat the keys in).
func (s *Server) authenticateReach(req *http.Request) (state.Node, error) {
	node, _, err := s.authenticateAgent(req, agentRequest{}.withHeaders(req))
	return node, err
}

// reachSessionFor loads the session named in the URL and requires the
// authenticated node to be a participant. Non-participants get the same 404
// as an unknown session: sessions are not enumerable.
func (s *Server) reachSessionFor(req *http.Request, node state.Node) (state.ReachSession, error) {
	id := chi.URLParam(req, "id")
	session, ok := s.store.GetReachSession(id)
	if !ok || (session.Sender != node.ID && session.Target != node.ID) {
		return state.ReachSession{}, NewHTTPError(http.StatusNotFound, "no such session", nil)
	}
	return session, nil
}

// reachStateError maps store state errors onto HTTP.
func (s *Server) reachStateError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, state.ErrReachSessionNotFound):
		httpError(w, NewHTTPError(http.StatusNotFound, "no such session", nil))
	case errors.Is(err, state.ErrReachSessionState):
		httpError(w, NewHTTPError(http.StatusConflict, "the session is not running", nil))
	default:
		s.log.Error("reading reach state", "err", err)
		httpError(w, NewHTTPError(http.StatusInternalServerError, "internal error", nil))
	}
}

// reachView renders one session, resolving both participants.
func (s *Server) reachView(session state.ReachSession) (reachSessionView, bool) {
	sender, ok := s.store.GetNodeByID(session.Sender)
	if !ok {
		return reachSessionView{}, false
	}
	target, ok := s.store.GetNodeByID(session.Target)
	if !ok {
		return reachSessionView{}, false
	}
	return reachSessionView{
		ID:         session.ID,
		State:      string(session.State),
		Sender:     reachPeerView(sender),
		Target:     reachPeerView(target),
		Argv:       append([]string(nil), session.Argv...),
		TimeoutSec: int(session.Timeout / time.Second),
		ExitCode:   session.ExitCode,
		Error:      session.Error,
		CreatedAt:  session.CreatedAt,
		UpdatedAt:  session.UpdatedAt,
		ExpiresAt:  session.ExpiresAt,
	}, true
}

// reachPeerView renders one participant.
func reachPeerView(node state.Node) reachPeer {
	return reachPeer{
		NodeID:   uint64(node.ID),
		StableID: node.StableID,
		Hostname: node.Hostname,
	}
}

// reachDisabled answers 404 when the deployment turned Reach off.
func (s *Server) reachDisabled(w http.ResponseWriter) bool {
	if s.cfg.ReachEnabled {
		return false
	}
	httpError(w, NewHTTPError(http.StatusNotFound, "reach is not enabled", nil))
	return true
}

// reachCursor parses one chunk cursor; missing means "from the beginning", so
// the first read returns everything.
func reachCursor(req *http.Request, name string) (int64, error) {
	raw := req.URL.Query().Get(name)
	if raw == "" {
		return -1, nil
	}
	value, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || value < -1 {
		return 0, fmt.Errorf("invalid %s cursor", name)
	}
	return value, nil
}

// normalizeReachArgv validates the command. An empty entry is refused because
// it is almost always a bug in the caller's argv construction.
func normalizeReachArgv(argv []string) ([]string, error) {
	if len(argv) == 0 {
		return nil, errors.New("argv must not be empty")
	}
	if len(argv) > state.ReachMaxArgvEntries {
		return nil, fmt.Errorf("argv has more than %d entries", state.ReachMaxArgvEntries)
	}
	total := 0
	for _, arg := range argv {
		if arg == "" {
			return nil, errors.New("argv entries must not be empty")
		}
		if len(arg) > state.ReachMaxArgBytes {
			return nil, fmt.Errorf("an argv entry is longer than %d bytes", state.ReachMaxArgBytes)
		}
		total += len(arg)
	}
	if total > state.ReachMaxArgvBytes {
		return nil, fmt.Errorf("argv is longer than %d bytes", state.ReachMaxArgvBytes)
	}
	return append([]string(nil), argv...), nil
}

// sanitizeReachError strips control characters and bounds the static error the
// target attaches to a failure before it is stored and shown to the sender.
func sanitizeReachError(text string) string {
	cleaned := truncateClean(text, state.ReachErrorLimit)
	return cleaned
}

// reapReach expires overdue sessions and deletes old terminal ones.
func (s *Server) reapReach(now time.Time) {
	expired, err := s.store.ExpireReachSessions(now)
	if err != nil {
		s.log.Warn("expiring reach sessions failed", "err", err)
	}
	for _, session := range expired {
		target, _ := s.store.GetNodeByID(session.Target)
		detail := "session=" + session.ID
		if target.ID != 0 {
			detail += " to=" + target.StableID
		}
		s.audit("system", identity.AuditReachExpired, nodeTarget(target), detail)
	}
	if len(expired) > 0 {
		s.log.Info("expired reach sessions", "count", len(expired))
	}

	removed, err := s.store.DeleteReachSessions(now.Add(-reachRetention))
	if err != nil {
		s.log.Warn("deleting reach sessions failed", "err", err)
	}
	if removed > 0 {
		s.log.Debug("deleted reach sessions", "count", removed)
	}
}
