package control

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/xunara-net/xunara-server/identity"
)

func (server *Server) handleAPIAccountIdentities(writer http.ResponseWriter, request *http.Request) {
	principal, ok := server.requireAccountSession(writer, request, false)
	if !ok {
		return
	}
	links, err := server.identity.ListAccountIdentities(request.Context(), principal.UserID)
	if err != nil {
		writeAPIError(writer, http.StatusServiceUnavailable, "IDENTITIES_UNAVAILABLE: could not read account bindings")
		return
	}
	providers := make([]map[string]any, 0)
	for _, providerID := range server.providers.IDs() {
		if providerID != identity.LocalProviderID {
			providers = append(providers, map[string]any{"id": providerID, "name": server.providerName(providerID)})
		}
	}
	items := make([]map[string]any, 0)
	for _, link := range links {
		if link.ProviderID == identity.LocalProviderID {
			continue
		}
		_, configured := server.providers.Get(link.ProviderID)
		items = append(items, map[string]any{
			"id": identity.IdentityReference(link), "provider_id": link.ProviderID,
			"provider_name": server.providerName(link.ProviderID), "email": link.Email,
			"display_name": link.DisplayName, "created_at": link.CreatedAt, "enabled": configured,
		})
	}
	writeJSON(writer, http.StatusOK, map[string]any{"items": items, "providers": providers, "csrf_token": csrfTokenFor(server.accountSessionToken(request))})
}

func (server *Server) handleAPIAccountIdentityBegin(writer http.ResponseWriter, request *http.Request) {
	principal, ok := server.requireAccountSession(writer, request, true)
	if !ok {
		return
	}
	// 绑定是浏览器回跳；Bearer 的人类会话不能替代回调中的同一浏览器 cookie。
	current, _, err := server.resolveCookieSession(request)
	if err != nil || current.ID != principal.Session.ID {
		writeAPIError(writer, http.StatusForbidden, "LINK_BROWSER_REQUIRED: use your signed-in browser")
		return
	}
	var body struct {
		ProviderID string `json:"provider_id"`
	}
	if !decodeAccountBody(writer, request, &body) {
		return
	}
	server.beginExternalAccountAuthorization(writer, request, identity.NewAuthTransactionOptions{
		ProviderID: body.ProviderID, RequestedAction: identity.AuthActionLink,
		AccountUserID: principal.UserID, AccountSessionID: principal.Session.ID,
		ReturnTo: "/security?identity_binding=linked",
	})
}

func (server *Server) handleAPIExternalInviteStart(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	var body struct {
		ProviderID string `json:"provider_id"`
		Invite     string `json:"invite"`
		FormToken  string `json:"registration_token"`
	}
	if !decodeAccountBody(writer, request, &body) {
		return
	}
	if !server.checkFormToken(formPurposeSignup, body.FormToken, time.Now()) {
		writeAPIError(writer, http.StatusForbidden, "CSRF_INVALID: reload the registration page")
		return
	}
	enabled, err := server.memberInvitationsEnabled(request.Context())
	if err != nil {
		writeAuthenticationError(writer, err)
		return
	}
	if !enabled {
		writeAPIError(writer, http.StatusForbidden, "INVITATIONS_DISABLED: invitation registration is not enabled here")
		return
	}
	allowed, _, err := server.store.AllowRate("signup-oidc-ip:"+server.clientIP(request), 20, loginAddressWindow, time.Now())
	if err != nil || !allowed {
		if err != nil {
			writeAPIError(writer, http.StatusServiceUnavailable, "AUTHORIZATION_UNAVAILABLE: try again later")
		} else {
			writeAPIError(writer, http.StatusTooManyRequests, "RATE_LIMITED: try again later")
		}
		return
	}
	invite, err := server.identity.FindRegistrationInvite(strings.TrimSpace(body.Invite))
	if err != nil {
		writeAPIError(writer, http.StatusBadRequest, "INVITATION_INVALID: this code is unavailable or expired")
		return
	}
	server.beginExternalAccountAuthorization(writer, request, identity.NewAuthTransactionOptions{
		ProviderID: body.ProviderID, RequestedAction: identity.AuthActionInvite,
		InviteTokenHash: invite.TokenHash, ReturnTo: "/dashboard",
	})
}

func (server *Server) beginExternalAccountAuthorization(writer http.ResponseWriter, request *http.Request, options identity.NewAuthTransactionOptions) {
	provider, ok := server.providers.Get(options.ProviderID)
	if !ok || options.ProviderID == identity.LocalProviderID {
		writeAPIError(writer, http.StatusBadRequest, "PROVIDER_INVALID: choose a configured external provider")
		return
	}
	if options.RequestedAction == identity.AuthActionLink {
		allowed, _, err := server.store.AllowRate(fmt.Sprintf("account-link:%d", options.AccountUserID), 20, loginAddressWindow, time.Now())
		if err != nil {
			writeAPIError(writer, http.StatusServiceUnavailable, "AUTHORIZATION_UNAVAILABLE: try again later")
			return
		}
		if !allowed {
			writeAPIError(writer, http.StatusTooManyRequests, "RATE_LIMITED: try again later")
			return
		}
	}
	options.RedirectURI, options.TTL = server.providerRedirects[options.ProviderID], server.authTTL
	authorization, secret, err := server.identity.CreateAccountAuthTransaction(request.Context(), options)
	if err != nil {
		server.writeAccountIdentityError(writer, err)
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), 20*time.Second)
	defer cancel()
	result, err := provider.Begin(ctx, &authorization)
	if err != nil || result == nil || result.URL == "" {
		// 不返回提供方原始诊断；其中可能含 code、token 或客户端密钥。
		writeAPIError(writer, http.StatusBadGateway, "PROVIDER_UNAVAILABLE: could not start authorization")
		return
	}
	server.setAuthCookie(writer, authorization.ID, secret, authorization.ExpiresAt)
	writeJSON(writer, http.StatusOK, map[string]any{"authorization_url": result.URL})
}

func (server *Server) handleAPIUnlinkAccountIdentity(writer http.ResponseWriter, request *http.Request) {
	principal, ok := server.requireAccountSession(writer, request, true)
	if !ok {
		return
	}
	revoked, err := server.identity.UnlinkAccountIdentity(request.Context(), principal.UserID, principal.Session.ID, chi.URLParam(request, "id"), identity.LoginMethods{
		Providers: server.providers.IDs(), Local: server.localLogin, Passkeys: server.passkeys != nil,
	})
	if err != nil {
		server.writeAccountIdentityError(writer, err)
		return
	}
	if revoked {
		server.clearSessionCookie(writer)
	}
	writeJSON(writer, http.StatusOK, map[string]any{"current_revoked": revoked})
}

func (server *Server) writeAccountIdentityError(writer http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, identity.ErrSessionRevoked), errors.Is(err, identity.ErrCredentialChanged):
		writeAPIError(writer, http.StatusUnauthorized, "SESSION_CHANGED: sign in again")
	case errors.Is(err, identity.ErrLastLoginMethod):
		writeAPIError(writer, http.StatusConflict, "LAST_LOGIN_METHOD: keep another usable password, passkey or external account")
	case errors.Is(err, identity.ErrAccountIdentityNotFound):
		writeAPIError(writer, http.StatusNotFound, "IDENTITY_NOT_FOUND: this binding does not belong to your account")
	default:
		server.log.Warn("account identity operation failed", "reason", fmt.Sprintf("%T", err))
		writeAPIError(writer, http.StatusServiceUnavailable, "IDENTITIES_UNAVAILABLE: could not commit account binding")
	}
}
