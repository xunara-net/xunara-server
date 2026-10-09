package control

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/mail"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/xunara-net/xunara-server/identity"
)

func (server *Server) requireAccountSession(writer http.ResponseWriter, request *http.Request, write bool) (apiPrincipal, bool) {
	writer.Header().Set("Cache-Control", "no-store")
	principal, ok := server.requireSelfScope(writer, request, identity.ScopeRead)
	if !ok {
		return apiPrincipal{}, false
	}
	if principal.Kind != "session" {
		writeAPIError(writer, http.StatusForbidden, "HUMAN_SESSION_REQUIRED: account changes require a human session")
		return apiPrincipal{}, false
	}
	if write && !checkCSRFHeader(request, server.accountSessionToken(request)) {
		writeAPIError(writer, http.StatusForbidden, "CSRF_INVALID: reload the account page and try again")
		return apiPrincipal{}, false
	}
	return principal, true
}

func (server *Server) accountSessionToken(request *http.Request) string {
	if authorization := request.Header.Get("Authorization"); authorization != "" {
		_, token, _ := strings.Cut(authorization, " ")
		return strings.TrimSpace(token)
	}
	return server.sessionToken(request)
}

func (server *Server) accountPayload(request *http.Request, user identity.User) map[string]any {
	_, hasPassword := server.identity.GetLocalCredential(user.ID)
	return map[string]any{
		"user":                    apiUserView(user),
		"password_change_enabled": server.localLogin && hasPassword,
		"csrf_token":              csrfTokenFor(server.accountSessionToken(request)),
	}
}

func (server *Server) handleAPIAccount(writer http.ResponseWriter, request *http.Request) {
	principal, ok := server.requireAccountSession(writer, request, false)
	if !ok {
		return
	}
	user, ok := server.identity.GetUser(principal.UserID)
	if !ok {
		writeAPIError(writer, http.StatusUnauthorized, "authentication required")
		return
	}
	writeJSON(writer, http.StatusOK, server.accountPayload(request, user))
}

func decodeAccountBody(writer http.ResponseWriter, request *http.Request, body any) bool {
	mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		writeAPIError(writer, http.StatusUnsupportedMediaType, "JSON_REQUIRED: send an application/json body")
		return false
	}
	request.Body = http.MaxBytesReader(writer, request.Body, 8<<10)
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	var extra any
	if decoder.Decode(body) != nil || decoder.Decode(&extra) != io.EOF {
		writeAPIError(writer, http.StatusBadRequest, "INVALID_ACCOUNT: invalid JSON body")
		return false
	}
	return true
}

func (server *Server) handleAPIUpdateAccount(writer http.ResponseWriter, request *http.Request) {
	principal, ok := server.requireAccountSession(writer, request, true)
	if !ok {
		return
	}
	var body struct {
		DisplayName *string `json:"display_name"`
		Email       *string `json:"email"`
	}
	if !decodeAccountBody(writer, request, &body) {
		return
	}
	if body.DisplayName == nil && body.Email == nil {
		writeAPIError(writer, http.StatusBadRequest, "INVALID_ACCOUNT: supply display_name or email")
		return
	}
	if body.DisplayName != nil {
		*body.DisplayName = strings.TrimSpace(*body.DisplayName)
		if !utf8.ValidString(*body.DisplayName) || utf8.RuneCountInString(*body.DisplayName) > 100 || strings.ContainsFunc(*body.DisplayName, unicode.IsControl) {
			writeAPIError(writer, http.StatusBadRequest, "INVALID_ACCOUNT: display name must be at most 100 characters without control characters")
			return
		}
	}
	if body.Email != nil {
		*body.Email = strings.TrimSpace(*body.Email)
		if *body.Email != "" {
			address, err := mail.ParseAddress(*body.Email)
			if err != nil || address.Name != "" || address.Address != *body.Email || len(*body.Email) > 254 || strings.ContainsFunc(*body.Email, unicode.IsControl) {
				writeAPIError(writer, http.StatusBadRequest, "INVALID_ACCOUNT: supply a valid contact email address")
				return
			}
		}
	}
	user, err := server.identity.UpdateUserProfile(request.Context(), principal.UserID, body.DisplayName, body.Email)
	if err != nil {
		if errors.Is(err, identity.ErrUserNotFound) {
			writeAPIError(writer, http.StatusUnauthorized, "authentication required")
			return
		}
		server.log.Error("updating account profile", "user", uint64(principal.UserID), "err", err)
		writeAPIError(writer, http.StatusInternalServerError, "ACCOUNT_UPDATE_FAILED: could not update account")
		return
	}
	writeJSON(writer, http.StatusOK, server.accountPayload(request, user))
}

func (server *Server) handleAPIChangePassword(writer http.ResponseWriter, request *http.Request) {
	principal, ok := server.requireAccountSession(writer, request, true)
	if !ok {
		return
	}
	if !server.localLogin {
		writeAPIError(writer, http.StatusForbidden, "PASSWORD_UNAVAILABLE: password sign-in is disabled")
		return
	}
	credential, ok := server.identity.GetLocalCredential(principal.UserID)
	if !ok {
		writeAPIError(writer, http.StatusForbidden, "PASSWORD_UNAVAILABLE: this account has no local password")
		return
	}
	var body struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if !decodeAccountBody(writer, request, &body) {
		return
	}
	for _, limit := range []struct {
		scope string
		count int
	}{
		{fmt.Sprintf("password-change-user:%d", principal.UserID), 5},
		{"password-change-ip:" + server.clientIP(request), 20},
	} {
		allowed, retryAfter, err := server.store.AllowRate(limit.scope, limit.count, 15*time.Minute, time.Now())
		if err != nil {
			server.log.Error("rate limiting password change", "err", err)
			writeAPIError(writer, http.StatusServiceUnavailable, "PASSWORD_CHANGE_FAILED: try again later")
			return
		}
		if !allowed {
			writer.Header().Set("Retry-After", fmt.Sprintf("%d", int(retryAfter.Seconds())+1))
			server.audit(principal.actor(), identity.AuditPasswordChangeFailed, fmt.Sprintf("user:%d", principal.UserID), "rate limited")
			writeAPIError(writer, http.StatusTooManyRequests, "PASSWORD_RATE_LIMITED: too many password change attempts; try again later")
			return
		}
	}
	if !identity.VerifyPassword(credential.PasswordHash, body.CurrentPassword) {
		server.audit(principal.actor(), identity.AuditPasswordChangeFailed, fmt.Sprintf("user:%d", principal.UserID), "wrong current password")
		writeAPIError(writer, http.StatusBadRequest, "CURRENT_PASSWORD_INVALID: current password is incorrect")
		return
	}
	user, ok := server.identity.GetUser(principal.UserID)
	if !ok {
		writeAPIError(writer, http.StatusUnauthorized, "authentication required")
		return
	}
	if err := identity.CheckPassword(user.LoginName, body.NewPassword); err != nil {
		writeAPIError(writer, http.StatusBadRequest, "PASSWORD_INVALID: "+err.Error())
		return
	}
	if body.NewPassword == body.CurrentPassword {
		writeAPIError(writer, http.StatusBadRequest, "PASSWORD_UNCHANGED: choose a different password")
		return
	}
	hash, err := identity.HashPassword(body.NewPassword)
	if err != nil {
		server.log.Error("hashing replacement password", "err", err)
		writeAPIError(writer, http.StatusInternalServerError, "PASSWORD_CHANGE_FAILED: could not change password")
		return
	}
	revoked, err := server.identity.ChangeLocalPassword(request.Context(), principal.UserID, principal.Session.ID, credential.PasswordHash, hash)
	if err != nil {
		if errors.Is(err, identity.ErrCredentialChanged) {
			writeAPIError(writer, http.StatusConflict, "ACCOUNT_CHANGED: account or session changed; sign in again")
			return
		}
		server.log.Error("changing account password", "user", uint64(principal.UserID), "err", err)
		writeAPIError(writer, http.StatusInternalServerError, "PASSWORD_CHANGE_FAILED: could not change password")
		return
	}
	server.clearSessionCookie(writer)
	writeJSON(writer, http.StatusOK, map[string]any{"changed": true, "revoked_sessions": revoked})
}
