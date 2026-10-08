package control

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"tailscale.com/tailcfg"

	"github.com/xunara-net/xunara-server/identity"
	"github.com/xunara-net/xunara-server/state"
)

// sshCheckPollInterval is how often a held follow-up re-reads its durable
// session for a verdict. The database is the source of truth, so any instance
// can serve the long poll without a server-local channel (AGENTS.md §9/§10).
const sshCheckPollInterval = 500 * time.Millisecond

// sshCheckActionURLPath is the template tailscaled expands with the source and
// destination node IDs and the requested local user.
const sshCheckActionURLPath = "/machine/ssh/action/$SRC_NODE_ID/to/$DST_NODE_ID?local_user=$LOCAL_USER"

// sshCheckAcceptAction is the verdict for an approved connection. Forwarding
// mirrors the upstream accept defaults.
var sshCheckAcceptAction = tailcfg.SSHAction{
	Accept:                    true,
	AllowAgentForwarding:      true,
	AllowLocalPortForwarding:  true,
	AllowRemotePortForwarding: true,
}

// handleSSHAction implements GET /machine/ssh/action/{srcNodeID}/to/{dstNodeID}
// inside a Noise session: the destination node asks the control plane whether
// an incoming SSH connection may proceed.
//
// The Noise session's machine key must belong to the destination node; without
// that check any unauthenticated client could open a throwaway Noise session
// and pollute the pair's approval memory (a stolen-key protection).
func (ns *noiseServer) handleSSHAction(w http.ResponseWriter, req *http.Request) {
	srcID, err := sshCheckNodeID(req, "srcNodeID")
	if err != nil {
		httpError(w, err)
		return
	}
	dstID, err := sshCheckNodeID(req, "dstNodeID")
	if err != nil {
		httpError(w, err)
		return
	}

	dstNode, ok := ns.server.store.GetNodeByID(state.NodeID(dstID))
	if !ok {
		httpError(w, NewHTTPError(http.StatusNotFound, "destination node not found", nil))
		return
	}
	if dstNode.MachineKey != ns.machineKey {
		httpError(w, NewHTTPError(http.StatusUnauthorized, "machine key does not match destination node", nil))
		return
	}
	srcNode, ok := ns.server.store.GetNodeByID(state.NodeID(srcID))
	if !ok {
		httpError(w, NewHTTPError(http.StatusNotFound, "source node not found", nil))
		return
	}

	period, checkFound := ns.server.sshCheckPeriod(srcNode, dstNode)

	snap := &sshCheckRequest{
		server:     ns.server,
		src:        srcNode,
		dst:        dstNode,
		period:     period,
		checkFound: checkFound,
	}

	authID := req.URL.Query().Get("auth_id")
	if authID == "" {
		// Initial request: hand out either an automatic accept (the pair was
		// approved recently enough) or a hold that asks for a human verdict.
		if snap.autoApprove(req.Context(), w) {
			return
		}
		snap.hold(w, req.URL.Query().Get("local_user"))
		return
	}

	sess, ok := ns.server.identity.GetSSHCheckSession(authID)
	if !ok {
		if checkFound {
			// The session expired, was reaped, or this control plane never
			// saw it. Re-delegate so a still-required check can complete.
			snap.hold(w, req.URL.Query().Get("local_user"))
			return
		}
		httpError(w, NewHTTPError(http.StatusBadRequest, "unknown auth_id", nil))
		return
	}
	// The cached session is bound to the exact (source, destination) pair;
	// a follow-up URL that disagrees must not be able to reuse the verdict.
	if sess.SrcNodeID != srcID || sess.DstNodeID != dstID {
		httpError(w, NewHTTPError(http.StatusUnauthorized, "auth_id is bound to another node pair", nil))
		return
	}

	verdict, err := ns.server.waitForSSHCheckVerdict(req.Context(), sess.ID)
	if err != nil {
		ns.server.log.Warn("ssh check verdict wait ended",
			"auth_id", sess.ID, "src_node", srcID, "dst_node", dstID, "err", err)
		if !checkFound {
			httpError(w, NewHTTPError(http.StatusBadRequest, "unknown auth_id", nil))
			return
		}
		snap.hold(w, req.URL.Query().Get("local_user"))
		return
	}

	if verdict.Verdict != identity.SSHCheckAccepted {
		writeSSHAction(w, tailcfg.SSHAction{
			Reject:  true,
			Message: "Access denied by the tailnet's SSH check policy.",
		})
		return
	}

	if checkFound && period > 0 {
		if err := ns.server.identity.RecordSSHCheckAuth(srcID, dstID, time.Now().UTC()); err != nil {
			ns.server.log.Warn("recording ssh check approval", "err", err)
		}
	}
	writeSSHAction(w, sshCheckAcceptAction)
}

// sshCheckRequest is one resolution of a (source, destination) pair against
// the tailnet's policy.
type sshCheckRequest struct {
	server     *Server
	src, dst   state.Node
	period     time.Duration
	checkFound bool
}

// autoApprove writes an accept action and reports true when the pair was
// approved within the rule's check period.
func (r *sshCheckRequest) autoApprove(ctx context.Context, w http.ResponseWriter) bool {
	if !r.checkFound || r.period <= 0 {
		return false
	}
	at, ok := r.server.identity.SSHCheckAuth(int64(r.src.ID), int64(r.dst.ID))
	if !ok || time.Since(at) >= r.period {
		return false
	}
	r.server.log.Debug("ssh check auto-approved",
		"src_node", r.src.ID, "dst_node", r.dst.ID, "period", r.period, "last_auth", at)
	writeSSHAction(w, sshCheckAcceptAction)
	return true
}

// hold writes the HoldAndDelegate action that parks the SSH connection until a
// human decides. Repeated initial requests for the same triple reuse the
// pending session, so client retries do not pile up approvals.
func (r *sshCheckRequest) hold(w http.ResponseWriter, localUser string) {
	now := time.Now().UTC()
	sess, ok := r.server.identity.GetPendingSSHCheckSession(int64(r.src.ID), int64(r.dst.ID), localUser, now)
	if !ok {
		var err error
		sess, err = r.server.identity.CreateSSHCheckSession(identity.NewSSHCheckOptions{
			SrcNodeID: int64(r.src.ID),
			DstNodeID: int64(r.dst.ID),
			LocalUser: localUser,
		})
		if err != nil {
			httpError(w, err)
			return
		}
	}

	hold, err := url.Parse(strings.TrimRight(r.server.cfg.ServerURL, "/") + sshCheckActionURLPath)
	if err != nil {
		httpError(w, fmt.Errorf("control: building ssh check URL: %w", err))
		return
	}
	q := hold.Query()
	q.Set("auth_id", sess.ID)
	hold.RawQuery = q.Encode()

	approveURL := strings.TrimRight(r.server.cfg.ServerURL, "/") + "/ssh/check/" + url.PathEscape(sess.ID)

	writeSSHAction(w, tailcfg.SSHAction{
		HoldAndDelegate: hold.String(),
		Message: "# Xunara SSH requires an additional check.\n" +
			"# To approve this connection, visit: " + approveURL + "\n" +
			"# Authentication checked by Xunara.",
	})

	r.server.log.Info("ssh check pending",
		"auth_id", sess.ID, "src_node", r.src.ID, "dst_node", r.dst.ID, "local_user", localUser)
}

// waitForSSHCheckVerdict blocks until the session has a verdict or the request
// context ends (client disconnected), consuming the verdict exactly once.
func (s *Server) waitForSSHCheckVerdict(ctx context.Context, id string) (identity.SSHCheckSession, error) {
	ticker := time.NewTicker(sshCheckPollInterval)
	defer ticker.Stop()

	for {
		sess, err := s.identity.ConsumeSSHCheckVerdict(id, time.Now().UTC())
		switch {
		case err == nil:
			return sess, nil
		case errors.Is(err, identity.ErrSSHCheckPending):
			// No verdict yet; keep holding.
		default:
			return identity.SSHCheckSession{}, err
		}

		select {
		case <-ctx.Done():
			return identity.SSHCheckSession{}, ctx.Err()
		case <-ticker.C:
		}
	}
}

// sshCheckPeriod resolves the check period for the pair from the current
// policy. ok is false when the policy cannot place the pair (no policy, no
// matching check rule, or a pair that no longer exists).
func (s *Server) sshCheckPeriod(src, dst state.Node) (time.Duration, bool) {
	engine := s.policy.Load()
	if engine == nil {
		return 0, false
	}
	return engine.SSHCheckPeriod(src, dst, s.store.ListNodes())
}

// sshCheckNodeID parses a positive node ID path parameter.
func sshCheckNodeID(req *http.Request, param string) (int64, error) {
	raw := chi.URLParam(req, param)
	id, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || id <= 0 {
		return 0, NewHTTPError(http.StatusBadRequest, "invalid "+param, err)
	}
	return id, nil
}

// writeSSHAction encodes a verdict for tailscaled.
func writeSSHAction(w http.ResponseWriter, action tailcfg.SSHAction) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(action); err != nil {
		return
	}
	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush()
	}
}

// handleSSHCheckPage serves the approval page a user opens from the banner the
// SSH client shows.
func (s *Server) handleSSHCheckPage(w http.ResponseWriter, req *http.Request) {
	authID := chi.URLParam(req, "authID")

	sess, ok := s.identity.GetSSHCheckSession(authID)
	if !ok {
		s.renderError(w, req, http.StatusNotFound, "Unknown SSH check",
			"This SSH check is unknown or has expired. The SSH connection will ask again.")
		return
	}
	now := time.Now()
	if sess.Expired(now) && sess.Pending() {
		s.renderError(w, req, http.StatusGone, "SSH check expired",
			"This SSH check has expired. The SSH connection will ask again.")
		return
	}
	if !sess.Pending() {
		s.renderDecidedPage(w, req, string(sess.Verdict))
		return
	}

	session, ok := s.currentSession(req)
	if !ok {
		http.Redirect(w, req, "/login?return_to="+url.QueryEscape("/ssh/check/"+authID), http.StatusFound)
		return
	}

	src, _ := s.store.GetNodeByID(state.NodeID(sess.SrcNodeID))
	dst, _ := s.store.GetNodeByID(state.NodeID(sess.DstNodeID))

	s.renderSSHCheckPage(w, req, map[string]any{
		"AuthID":      authID,
		"CanWrite":    s.userCanWrite(session.UserID),
		"Source":      nodeLabel(src, sess.SrcNodeID),
		"Destination": nodeLabel(dst, sess.DstNodeID),
		"LocalUser":   sess.LocalUser,
		"Created":     s.consoleTime(sess.CreatedAt),
		"Expires":     s.consoleTime(sess.ExpiresAt),
		"LoginName":   s.UserProfile(session.UserID).LoginName,
		"CSRF":        csrfTokenFor(sessionToken(req)),
	})
}

// handleSSHCheckApprove implements POST /ssh/check/{authID}/approve.
func (s *Server) handleSSHCheckApprove(w http.ResponseWriter, req *http.Request) {
	s.decideSSHCheck(w, req, identity.SSHCheckAccepted)
}

// handleSSHCheckDeny implements POST /ssh/check/{authID}/deny.
func (s *Server) handleSSHCheckDeny(w http.ResponseWriter, req *http.Request) {
	s.decideSSHCheck(w, req, identity.SSHCheckRejected)
}

// decideSSHCheck applies an approve/deny verdict from the browser.
func (s *Server) decideSSHCheck(w http.ResponseWriter, req *http.Request, verdict identity.SSHCheckVerdict) {
	authID := chi.URLParam(req, "authID")

	session, token, ok := s.requireSession(w, req, "/ssh/check/"+authID)
	if !ok {
		return
	}
	if !s.userCanWrite(session.UserID) {
		s.renderError(w, req, http.StatusForbidden, "SSH check rejected",
			"Your role does not allow deciding SSH checks.")
		return
	}
	if !checkCSRF(req, token) {
		s.renderError(w, req, http.StatusForbidden, "SSH check rejected",
			"The form token is invalid. Reload the page and try again.")
		return
	}

	sess, err := s.identity.DecideSSHCheckSession(authID, verdict, session.UserID, time.Now().UTC())
	if err != nil {
		switch {
		case errors.Is(err, identity.ErrSSHCheckNotFound):
			s.renderError(w, req, http.StatusNotFound, "Unknown SSH check",
				"This SSH check is unknown or has expired.")
		case errors.Is(err, identity.ErrSSHCheckExpired):
			s.renderError(w, req, http.StatusGone, "SSH check expired",
				"This SSH check has expired. The SSH connection will ask again.")
		case errors.Is(err, identity.ErrSSHCheckDecided):
			// A second tab or a replay: show the recorded outcome.
			if got, ok := s.identity.GetSSHCheckSession(authID); ok {
				s.renderDecidedPage(w, req, string(got.Verdict))
				return
			}
			s.renderError(w, req, http.StatusConflict, "SSH check already decided",
				"This SSH check was already decided.")
		default:
			s.log.Error("deciding ssh check", "err", err)
			s.renderError(w, req, http.StatusInternalServerError, "SSH check failed", "Please try again.")
		}
		return
	}

	action := identity.AuditSSHCheckApproved
	if verdict == identity.SSHCheckRejected {
		action = identity.AuditSSHCheckDenied
	}
	s.audit(fmt.Sprintf("user:%d", session.UserID), action, "sshcheck:"+authID,
		fmt.Sprintf("src_node=%d dst_node=%d local_user=%s", sess.SrcNodeID, sess.DstNodeID, sess.LocalUser))

	s.renderDecidedPage(w, req, string(verdict))
}

// nodeLabel names a node for a page, falling back to its ID when the node is
// gone.
func nodeLabel(n state.Node, id int64) string {
	if n.ID == 0 {
		return fmt.Sprintf("node %d (removed)", id)
	}
	return fmt.Sprintf("%s (%s)", n.Hostname, n.IPv4)
}
