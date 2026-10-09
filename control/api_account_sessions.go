package control

import (
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/xunara-net/xunara-server/identity"
)

type accountSessionView struct {
	ID            string     `json:"id"`
	AuthMethod    string     `json:"auth_method"`
	CreatedAt     time.Time  `json:"created_at"`
	ExpiresAt     time.Time  `json:"expires_at"`
	Status        string     `json:"status"`
	RevokedAt     *time.Time `json:"revoked_at,omitempty"`
	RevokedReason string     `json:"revoked_reason,omitempty"`
}

func (server *Server) handleAPIAccountSessions(writer http.ResponseWriter, request *http.Request) {
	principal, ok := server.requireAccountSession(writer, request, false)
	if !ok {
		return
	}
	sessions, err := server.identity.ListAccountSessions(request.Context(), principal.UserID)
	if err != nil {
		server.log.Error("listing account sessions", "user", uint64(principal.UserID), "err", err)
		writeAPIError(writer, http.StatusInternalServerError, "SESSION_LIST_FAILED: could not read account sessions")
		return
	}
	now := time.Now().UTC()
	views := make([]accountSessionView, 0, len(sessions))
	for _, session := range sessions {
		view := accountSessionView{
			ID: session.ID, AuthMethod: session.AuthMethod,
			CreatedAt: session.CreatedAt, ExpiresAt: session.ExpiresAt, Status: "active",
		}
		if !session.RevokedAt.IsZero() {
			view.Status = "revoked"
			view.RevokedAt = &session.RevokedAt
			view.RevokedReason = session.RevokedReason
		} else if !session.ExpiresAt.After(now) {
			view.Status = "expired"
		}
		views = append(views, view)
	}
	writeJSON(writer, http.StatusOK, map[string]any{
		"sessions": views, "current_session_id": principal.Session.ID,
		"csrf_token": csrfTokenFor(server.accountSessionToken(request)), "generated_at": now,
	})
}

func (server *Server) handleAPIRevokeAccountSessions(writer http.ResponseWriter, request *http.Request) {
	principal, ok := server.requireAccountSession(writer, request, true)
	if !ok {
		return
	}
	var body struct {
		Mode identity.SessionRevocationMode `json:"mode"`
	}
	if !decodeAccountBody(writer, request, &body) {
		return
	}
	if body.Mode != identity.RevokeOtherSessions && body.Mode != identity.RevokeAllSessions {
		writeAPIError(writer, http.StatusBadRequest, "INVALID_SESSION_REVOCATION: choose others or all")
		return
	}
	server.revokeAccountSessions(writer, request, principal, identity.SessionRevocation{Mode: body.Mode})
}

func (server *Server) handleAPIRevokeAccountSession(writer http.ResponseWriter, request *http.Request) {
	principal, ok := server.requireAccountSession(writer, request, true)
	if !ok {
		return
	}
	server.revokeAccountSessions(writer, request, principal, identity.SessionRevocation{
		Mode: identity.RevokeSingleSession, SessionID: chi.URLParam(request, "id"),
	})
}

func (server *Server) revokeAccountSessions(writer http.ResponseWriter, request *http.Request, principal apiPrincipal, selection identity.SessionRevocation) {
	revoked, err := server.identity.RevokeAccountSessions(request.Context(), principal.UserID, principal.Session.ID, selection)
	if err != nil {
		switch {
		case errors.Is(err, identity.ErrSessionRevoked):
			writeAPIError(writer, http.StatusUnauthorized, "SESSION_CHANGED: initiating session is no longer active")
		case errors.Is(err, identity.ErrSessionNotFound):
			writeAPIError(writer, http.StatusNotFound, "SESSION_NOT_FOUND: session not found")
		default:
			server.log.Error("revoking account sessions", "user", uint64(principal.UserID), "err", err)
			writeAPIError(writer, http.StatusInternalServerError, "SESSION_REVOKE_FAILED: could not revoke account sessions")
		}
		return
	}
	currentRevoked := selection.Mode == identity.RevokeAllSessions || selection.Mode == identity.RevokeSingleSession && selection.SessionID == principal.Session.ID
	if currentRevoked {
		server.clearSessionCookie(writer)
	}
	writeJSON(writer, http.StatusOK, map[string]any{"revoked_sessions": revoked, "current_revoked": currentRevoked})
}
