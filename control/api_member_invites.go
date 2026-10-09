package control

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/go-chi/chi/v5"
	"github.com/xunara-net/xunara-server/identity"
)

type memberInviteRequest struct {
	Role     string `json:"role"`
	Note     string `json:"note"`
	TTLHours int    `json:"ttl_hours"`
}

func (server *Server) memberInvitationsEnabled() bool {
	return server.localLogin && server.registration == RegistrationInvite && server.selfServiceInfo() == nil && !server.setupRequired()
}

func (server *Server) requireInviteOwner(writer http.ResponseWriter, request *http.Request, write bool) (apiPrincipal, bool) {
	principal, ok := server.requireAccountSession(writer, request, write)
	if !ok {
		return apiPrincipal{}, false
	}
	if !principal.Role.IsOwner() {
		writeAPIError(writer, http.StatusForbidden, "OWNER_REQUIRED: only the network owner may manage invitations")
		return apiPrincipal{}, false
	}
	return principal, true
}

func inviteView(invite identity.RegistrationInvite, now time.Time) map[string]any {
	status := "pending"
	if invite.Redeemed() {
		status = "redeemed"
	} else if invite.Expired(now) {
		status = "expired"
	}
	return map[string]any{
		"id": invite.ID, "role": string(invite.Role), "note": invite.Note,
		"created_at": invite.CreatedAt, "expires_at": invite.ExpiresAt,
		"used_at": invite.UsedAt, "used_by": uint64(invite.UsedBy), "status": status,
	}
}

func (server *Server) handleAPIMemberInvites(writer http.ResponseWriter, request *http.Request) {
	if _, ok := server.requireInviteOwner(writer, request, false); !ok {
		return
	}
	invites, err := server.identity.ListRegistrationInvitesContext(request.Context())
	if err != nil {
		server.log.Error("listing member invitations", "err", err)
		writeAPIError(writer, http.StatusServiceUnavailable, "INVITATIONS_UNAVAILABLE: try again later")
		return
	}
	now := time.Now().UTC()
	items := make([]map[string]any, 0, len(invites))
	for _, invite := range invites {
		items = append(items, inviteView(invite, now))
	}
	writeJSON(writer, http.StatusOK, map[string]any{
		"items": items, "enabled": server.memberInvitationsEnabled(),
		"registration_url": "/register", "csrf_token": csrfTokenFor(server.accountSessionToken(request)),
	})
}

// createMemberInvitation 同时供正式 JSON 与旧表单使用，不能保留两套准入和角色规则。
func (server *Server) createMemberInvitation(ctx context.Context, session identity.Session, body memberInviteRequest) (identity.RegistrationInvite, string, error) {
	if !server.memberInvitationsEnabled() {
		return identity.RegistrationInvite{}, "", NewHTTPError(http.StatusForbidden,
			"INVITATIONS_DISABLED: member invitations require invitation registration on this tenant", nil)
	}
	role, err := identity.ParseRole(body.Role)
	note := strings.TrimSpace(body.Note)
	if err != nil || role == identity.RoleOwner || body.TTLHours < 1 || body.TTLHours > 365*24 || !utf8.ValidString(note) || utf8.RuneCountInString(note) > 200 || strings.ContainsFunc(note, unicode.IsControl) {
		return identity.RegistrationInvite{}, "", NewHTTPError(http.StatusBadRequest,
			"INVALID_INVITATION: choose member/admin, 1–8760 hours, and a note of at most 200 characters", nil)
	}
	invite, token, err := server.identity.CreateMemberInvitation(ctx, identity.MemberInvitation{
		UserID: session.UserID, SessionID: session.ID, Role: role, Note: note,
		TTL: time.Duration(body.TTLHours) * time.Hour, MaxUsers: server.Plan().MaxUsers,
	})
	return invite, token, memberInvitationError(err)
}

func memberInvitationError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, identity.ErrMemberLimitReached):
		return planGateError(MsgUserLimitReached)
	case errors.Is(err, identity.ErrInviteOwnerRequired):
		return NewHTTPError(http.StatusForbidden, "OWNER_REQUIRED: only the network owner may manage invitations", err)
	case errors.Is(err, identity.ErrSessionRevoked):
		return NewHTTPError(http.StatusUnauthorized, "SESSION_REVOKED: sign in again", err)
	case errors.Is(err, identity.ErrInviteNotFound):
		return NewHTTPError(http.StatusNotFound, "INVITATION_NOT_FOUND: this invitation does not exist", err)
	case errors.Is(err, identity.ErrInviteUsed):
		return NewHTTPError(http.StatusConflict, "INVITATION_USED: redeemed invitations are kept as records", err)
	default:
		return NewHTTPError(http.StatusServiceUnavailable, "INVITATIONS_UNAVAILABLE: try again later", err)
	}
}

func (server *Server) handleAPICreateMemberInvite(writer http.ResponseWriter, request *http.Request) {
	principal, ok := server.requireInviteOwner(writer, request, true)
	if !ok {
		return
	}
	var body memberInviteRequest
	if !decodeAccountBody(writer, request, &body) {
		return
	}
	invite, token, err := server.createMemberInvitation(request.Context(), principal.Session, body)
	if err != nil {
		server.writeMemberInvitationError(writer, err)
		return
	}
	writeJSON(writer, http.StatusCreated, map[string]any{"invitation": inviteView(invite, time.Now().UTC()), "code": token})
}

func (server *Server) writeMemberInvitationError(writer http.ResponseWriter, err error) {
	var response HTTPError
	if errors.As(err, &response) {
		if response.Code >= 500 {
			server.log.Error("member invitation failed", "err", err)
		}
		writeAPIError(writer, response.Code, response.Msg)
		return
	}
	writeAPIError(writer, http.StatusServiceUnavailable, "INVITATIONS_UNAVAILABLE: try again later")
}

func (server *Server) handleAPIRevokeMemberInvite(writer http.ResponseWriter, request *http.Request) {
	principal, ok := server.requireInviteOwner(writer, request, true)
	if !ok {
		return
	}
	err := server.identity.RevokeMemberInvitation(request.Context(), principal.UserID, principal.Session.ID, chi.URLParam(request, "id"))
	if err != nil {
		server.writeMemberInvitationError(writer, memberInvitationError(err))
		return
	}
	writer.WriteHeader(http.StatusNoContent)
}
