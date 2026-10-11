package control

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/xunara-net/xunara-server/identity"
)

func (router *Router) handlePlatformPasswordReset(writer http.ResponseWriter, request *http.Request) {
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
	result, err := server.identity.IssuePasswordResetByPlatform(request.Context(), tailcfgUserID(userID), identity.PasswordResetOptions{
		Reason: body.Reason, ExpectedUpdatedAt: body.ExpectedUpdatedAt, OwnershipVerified: body.OwnershipVerified,
	})
	if err != nil {
		switch {
		case errors.Is(err, identity.ErrMemberConflict):
			writeAPIError(writer, http.StatusConflict, "PASSWORD_RESET_CHANGED: account changed; refresh and review before generating a code")
		case errors.Is(err, identity.ErrUserNotFound):
			writeAPIError(writer, http.StatusNotFound, "USER_NOT_FOUND: unknown account")
		case errors.Is(err, identity.ErrUserDisabled), errors.Is(err, identity.ErrCredentialNotFound):
			writeAPIError(writer, http.StatusConflict, "PASSWORD_RESET_NOT_AVAILABLE: account is disabled or has no local password")
		case errors.Is(err, identity.ErrMemberInvalid):
			writeAPIError(writer, http.StatusBadRequest, "PASSWORD_RESET_REQUEST_INVALID: verify ownership and provide a reason of 1 to 256 characters without control characters")
		default:
			writeAPIError(writer, http.StatusServiceUnavailable, "PASSWORD_RESET_UNAVAILABLE: issuance outcome is unknown; refresh to check pending status before generating again")
		}
		return
	}
	// 仅本次已授权响应包含原码；后续列表、审计与日志不得回显秘密。
	writeJSON(writer, http.StatusCreated, map[string]any{
		"org": organization, "id": uint64(result.User.ID), "updatedAt": result.User.UpdatedAt,
		"resetId": result.Status.ID, "code": result.Code, "expiresAt": result.Status.ExpiresAt,
		"createdAt": result.Status.CreatedAt, "passwordChanged": false, "sessionsRevoked": 0,
	})
}

// 重置码本身是限定用途的凭据，不接受 Cookie / API Key 代替，也不自动签发登录。
func (server *Server) handleAPIResetPassword(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("Referrer-Policy", "no-referrer")
	if !server.localLogin {
		writeAPIError(writer, http.StatusForbidden, "PASSWORD_RESET_NOT_AVAILABLE: password sign-in is not enabled")
		return
	}
	if request.URL.RawQuery != "" || request.Header.Get("Sec-Fetch-Site") == "cross-site" || !server.passwordResetOriginAllowed(request) {
		writeAPIError(writer, http.StatusForbidden, "PASSWORD_RESET_BODY_REQUIRED: submit the code only in a same-origin JSON body")
		return
	}
	if !server.admitPasswordReset(writer, request, "password-reset-ip:"+server.clientIP(request), 20) {
		return
	}
	var body struct {
		Code            string `json:"code"`
		NewPassword     string `json:"new_password"`
		ConfirmPassword string `json:"confirm_password"`
	}
	if !decodeAccountBodyLimit(writer, request, &body, 4<<10) {
		return
	}
	body.Code = strings.TrimSpace(body.Code)
	user, err := server.identity.LookupPasswordReset(request.Context(), body.Code)
	if err != nil {
		writePasswordResetError(writer, err)
		return
	}
	if !server.admitPasswordReset(writer, request, "password-reset-code:"+identity.HashSecret(body.Code), 5) {
		return
	}
	if body.NewPassword != body.ConfirmPassword {
		writeAPIError(writer, http.StatusBadRequest, "PASSWORD_CONFIRMATION_INVALID: enter the same new password twice")
		return
	}
	if err := identity.CheckPassword(user.LoginName, body.NewPassword); err != nil {
		writeAPIError(writer, http.StatusBadRequest, "PASSWORD_INVALID: choose a valid new password")
		return
	}
	hash, err := identity.HashPassword(body.NewPassword)
	if err != nil {
		writeAPIError(writer, http.StatusServiceUnavailable, "PASSWORD_RESET_UNAVAILABLE: could not prepare a new password")
		return
	}
	result, err := server.identity.RedeemPasswordReset(request.Context(), body.Code, hash)
	if err != nil {
		writePasswordResetError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"changed": true, "revoked_sessions": result.RevokedSessions})
}

func writePasswordResetError(writer http.ResponseWriter, err error) {
	if errors.Is(err, identity.ErrPasswordResetInvalid) {
		writeAPIError(writer, http.StatusBadRequest, "PASSWORD_RESET_INVALID: this code is unavailable; ask the platform administrator for a new code")
		return
	}
	writeAPIError(writer, http.StatusServiceUnavailable, "PASSWORD_RESET_UNAVAILABLE: outcome is unknown; check sign-in before trying again")
}

func (server *Server) admitPasswordReset(writer http.ResponseWriter, request *http.Request, scope string, count int) bool {
	allowed, retryAfter, err := server.store.AllowRate(scope, count, identity.PasswordResetTTL, time.Now())
	if err != nil {
		writeAPIError(writer, http.StatusServiceUnavailable, "PASSWORD_RESET_UNAVAILABLE: admission is temporarily unavailable")
		return false
	}
	if !allowed {
		writer.Header().Set("Retry-After", fmt.Sprintf("%d", int(retryAfter.Seconds())+1))
		writeAPIError(writer, http.StatusTooManyRequests, "PASSWORD_RESET_RATE_LIMITED: too many attempts; try later")
		return false
	}
	return true
}

func (server *Server) passwordResetOriginAllowed(request *http.Request) bool {
	if request.Header.Get("Origin") == "" {
		return true
	}
	origin, err := url.Parse(request.Header.Get("Origin"))
	scheme := "http"
	if server.secureCookies {
		scheme = "https"
	}
	return err == nil && origin.Scheme == scheme && strings.EqualFold(origin.Host, request.Host) &&
		origin.User == nil && origin.Path == "" && origin.RawQuery == "" && origin.Fragment == ""
}
