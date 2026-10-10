package control

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"time"

	"tailscale.com/tailcfg"

	"github.com/xunara-net/xunara-server/identity"
)

type memberUpdateBody struct {
	LoginName         *string    `json:"loginName"`
	DisplayName       *string    `json:"displayName"`
	Email             *string    `json:"email"`
	Role              *string    `json:"role"`
	ExpectedUpdatedAt *time.Time `json:"expectedUpdatedAt"`
}

func (body memberUpdateBody) patch() (identity.MemberPatch, error) {
	patch := identity.MemberPatch{
		LoginName: body.LoginName, DisplayName: body.DisplayName, Email: body.Email,
		ExpectedUpdatedAt: body.ExpectedUpdatedAt,
	}
	if body.Role != nil {
		role, err := identity.ParseRole(*body.Role)
		if err != nil {
			return identity.MemberPatch{}, identity.ErrMemberInvalid
		}
		patch.Role = &role
	}
	return patch, nil
}

func (server *Server) lookupMemberReference(ctx context.Context, reference string) (identity.User, error) {
	if userID, err := strconv.ParseUint(reference, 10, 64); err == nil {
		return server.identity.LookupUser(ctx, tailcfg.UserID(userID))
	}
	return server.identity.LookupUserByLoginName(ctx, reference)
}

func memberUpdateFailure(err error) (int, string) {
	switch {
	case errors.Is(err, identity.ErrMemberConflict):
		return http.StatusConflict, "MEMBER_CHANGED: member changed; refresh and confirm again"
	case errors.Is(err, identity.ErrLastOwner):
		return http.StatusConflict, "LAST_OWNER: cannot remove the last owner"
	case errors.Is(err, identity.ErrMemberInvalid):
		return http.StatusBadRequest, "MEMBER_INVALID: invalid role, login name or member version"
	case errors.Is(err, identity.ErrLoginNameTaken):
		return http.StatusConflict, "LOGIN_NAME_TAKEN: login name already in use"
	case errors.Is(err, identity.ErrUserNotFound):
		return http.StatusNotFound, "MEMBER_NOT_FOUND: user not found"
	case errors.Is(err, identity.ErrSessionRevoked), errors.Is(err, identity.ErrSessionNotFound):
		return http.StatusUnauthorized, "SESSION_CHANGED: initiating session is no longer valid"
	case errors.Is(err, identity.ErrMemberOwnerRequired), errors.Is(err, identity.ErrNetworkWriterForbidden):
		return http.StatusForbidden, "MEMBER_WRITE_FORBIDDEN: owner or service key permissions changed"
	default:
		return http.StatusServiceUnavailable, "MEMBERS_UNAVAILABLE: could not check or update members; refresh before retrying"
	}
}

func (server *Server) writeMemberUpdateFailure(writer http.ResponseWriter, err error) {
	statusCode, message := memberUpdateFailure(err)
	if statusCode == http.StatusServiceUnavailable {
		server.log.Error("managing members", "err", err)
		writer.Header().Set("Retry-After", "5")
	}
	writer.Header().Set("Cache-Control", "no-store")
	writeAPIError(writer, statusCode, message)
}
