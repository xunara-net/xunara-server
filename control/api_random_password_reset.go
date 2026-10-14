package control

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/xunara-net/xunara-server/identity"
)

func passwordResetRetired(writer http.ResponseWriter, _ *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("Referrer-Policy", "no-referrer")
	writeAPIError(writer, http.StatusGone, "PASSWORD_RESET_RETIRED: reset codes are no longer supported; ask the platform administrator for a temporary password")
}

func (router *Router) handlePlatformRandomPasswordReset(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("Referrer-Policy", "no-referrer")
	if request.URL.RawQuery != "" {
		writeAPIError(writer, http.StatusBadRequest, "PASSWORD_RESET_REQUEST_INVALID: use a JSON body without query parameters")
		return
	}
	organization := chi.URLParam(request, "orgID")
	server := router.serverFor(organization)
	if server == nil {
		writeAPIError(writer, http.StatusNotFound, "ORGANIZATION_NOT_FOUND: unknown organization")
		return
	}
	userID, err := strconv.ParseUint(chi.URLParam(request, "userID"), 10, 64)
	if err != nil || userID == 0 || userID > uint64(^uint64(0)>>1) {
		writeAPIError(writer, http.StatusBadRequest, "PASSWORD_RESET_REQUEST_INVALID: invalid account")
		return
	}
	if !server.localLogin {
		writeAPIError(writer, http.StatusConflict, "PASSWORD_RESET_NOT_AVAILABLE: password sign-in is not enabled")
		return
	}
	var body struct {
		Reason            string    `json:"reason"`
		ExpectedUpdatedAt time.Time `json:"expected_updated_at"`
		OwnershipVerified bool      `json:"ownership_verified"`
	}
	if !decodeAccountBodyLimit(writer, request, &body, 4<<10) {
		return
	}
	if body.ExpectedUpdatedAt.IsZero() {
		writeAPIError(writer, http.StatusPreconditionRequired, "PASSWORD_RESET_VERSION_REQUIRED: refresh and review the account version")
		return
	}
	actor := "platform-token"
	if session, ok := request.Context().Value(platformSessionContextKey{}).(identity.Session); ok {
		actor = "platform-user:" + strconv.FormatUint(uint64(session.UserID), 10)
	}
	result, err := server.identity.ResetRandomPasswordByPlatform(request.Context(), tailcfgUserID(userID), identity.PasswordResetOptions{
		Reason: body.Reason, ExpectedUpdatedAt: body.ExpectedUpdatedAt, OwnershipVerified: body.OwnershipVerified,
	}, actor)
	if err != nil {
		switch {
		case errors.Is(err, identity.ErrMemberConflict):
			writeAPIError(writer, http.StatusConflict, "PASSWORD_RESET_CHANGED: account changed; refresh and review before resetting")
		case errors.Is(err, identity.ErrUserNotFound):
			writeAPIError(writer, http.StatusNotFound, "USER_NOT_FOUND: unknown account")
		case errors.Is(err, identity.ErrUserDisabled), errors.Is(err, identity.ErrCredentialNotFound):
			writeAPIError(writer, http.StatusConflict, "PASSWORD_RESET_NOT_AVAILABLE: account is disabled or has no local password")
		case errors.Is(err, identity.ErrMemberInvalid):
			writeAPIError(writer, http.StatusBadRequest, "PASSWORD_RESET_REQUEST_INVALID: verify ownership and provide a reason of 1 to 256 characters without control characters")
		default:
			writeAPIError(writer, http.StatusServiceUnavailable, "PASSWORD_RESET_UNAVAILABLE: outcome is unknown; refresh and review before resetting again")
		}
		return
	}
	// 只有成功提交后的本次授权响应包含新密码；查询和审计只能返回状态。
	writeJSON(writer, http.StatusOK, map[string]any{
		"org": organization, "id": uint64(result.User.ID), "updatedAt": result.User.UpdatedAt,
		"temporaryPassword": result.TemporaryPassword, "passwordChangeRequired": true,
		"passwordChanged": true, "sessionsRevoked": result.RevokedSessions,
	})
}

// 仅开放本人改密和退出所需的最小表面；不能仅靠前端跳转限制临时登录。
func passwordChangeRequestAllowed(request *http.Request, sessionID string) bool {
	switch request.Method {
	case http.MethodGet:
		return request.URL.Path == "/api/v1/account" || request.URL.Path == "/api/v1/account/sessions"
	case http.MethodPost:
		return request.URL.Path == "/api/v1/account/password" || request.URL.Path == "/api/v1/auth/logout"
	case http.MethodDelete:
		return request.URL.Path == "/api/v1/account/sessions/"+sessionID
	}
	return false
}
