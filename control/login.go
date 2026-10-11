package control

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/xunara-net/xunara-server/identity"
)

// providerView is a provider as shown on the sign-in page.
type providerView struct {
	ID   string
	Name string
	URL  string
}

// handleLogin implements GET /login.
//
// It renders the sign-in page. An explicit ?provider=<id> starts that external
// provider's flow instead. The built-in local provider never authenticates on
// a GET: doing so would hand the tailnet to whoever can reach the URL, so
// local sign-in is a POST that has to present a password.
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	returnTo := loginReturnTo(r.URL.Query().Get("return_to"))

	if providerID := r.URL.Query().Get("provider"); providerID != "" && providerID != identity.LocalProviderID {
		s.startExternalLogin(w, r, providerID, returnTo)
		return
	}
	requiresSetup, ok := s.setupStateForPage(w, r)
	if !ok {
		return
	}
	// Someone who is already signed in does not need the form again.
	if _, ok := s.currentSession(r); ok {
		http.Redirect(w, r, returnTo, http.StatusFound)
		return
	}

	views := make([]providerView, 0, len(s.identityProviders().IDs()))
	for _, id := range s.identityProviders().IDs() {
		if id == identity.LocalProviderID {
			continue
		}
		views = append(views, providerView{
			ID:   id,
			Name: s.providerName(id),
			URL:  "/login?provider=" + url.QueryEscape(id) + "&return_to=" + url.QueryEscape(returnTo),
		})
	}

	data := map[string]any{
		"Title":      "Sign in",
		"Providers":  views,
		"Passkey":    s.passkeys != nil,
		"LocalLogin": s.localLogin,
		"Setup":      requiresSetup,
		"FormToken":  s.newFormToken(formPurposeLogin),
		"ReturnTo":   returnTo,
	}
	s.renderPublicPage(w, r, signInPageTemplate, data)
}

// startExternalLogin 复用持久事务发起 OIDC 或原生 OAuth2，不能在这里直接审批设备。
func (s *Server) startExternalLogin(w http.ResponseWriter, r *http.Request, providerID, returnTo string) {
	provider, ok := s.identityProviders().Get(providerID)
	if !ok {
		s.renderError(w, r, http.StatusBadRequest, "Unknown provider",
			"The requested identity provider is not configured on this server.")
		return
	}
	// 沿用持久限流键，让升级和混合提供方共享同一 IP 预算，不重置既有计数。
	allowed, retryAfter, err := s.store.AllowRate("login-oidc-ip:"+s.clientIP(r), loginAddressLimit, loginAddressWindow, time.Now())
	if err != nil {
		s.renderError(w, r, http.StatusServiceUnavailable, "Sign-in unavailable", "Please try again later.")
		return
	}
	if !allowed {
		w.Header().Set("Retry-After", fmt.Sprintf("%d", int(retryAfter.Seconds())+1))
		s.renderError(w, r, http.StatusTooManyRequests, "Too many attempts", "Too many sign-in attempts. Try again later.")
		return
	}

	tx, browserSecret, err := s.identity.CreateAuthTransaction(identity.NewAuthTransactionOptions{
		ProviderID:             providerID,
		RedirectURI:            s.providerRedirect(providerID),
		AuthenticationRevision: s.authenticationRevision(),
		ReturnTo:               returnTo,
		TTL:                    s.authTTL,
	})
	if err != nil {
		s.log.Error("creating auth transaction", "provider", providerID, "err", err)
		s.renderError(w, r, http.StatusInternalServerError, "Sign-in failed", "Please try again.")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	authReq, err := provider.Begin(ctx, &tx)
	if err != nil {
		s.audit("system", identity.AuditLoginFailed, "provider:"+providerID, loginFailureReason(err))
		s.log.Warn("starting login", "provider", providerID, "reason", loginFailureReason(err))
		s.renderError(w, r, http.StatusBadGateway, "Provider unavailable",
			"The identity provider could not be reached. Please try again later.")
		return
	}
	if authReq.URL == "" {
		// Only the local provider completes server-side, and it is not
		// offered here; refusing is safer than falling through.
		s.audit("system", identity.AuditLoginFailed, "provider:"+providerID, "provider cannot start a browser flow")
		s.renderError(w, r, http.StatusBadRequest, "Sign-in rejected",
			"This identity provider cannot complete a browser sign-in.")
		return
	}

	s.setAuthCookie(w, tx.ID, browserSecret, tx.ExpiresAt)
	http.Redirect(w, r, authReq.URL, http.StatusFound)
}

// Password sign-in rate limits. The counters live in the store, not in
// process memory, so every instance of the control plane enforces the same
// budget (AGENTS.md section 9).
const (
	loginAddressLimit  = 20
	loginAddressWindow = 10 * time.Minute
	loginNameLimit     = 10
	loginNameWindow    = 10 * time.Minute
)

// handlePasswordLogin implements POST /login for locally managed accounts.
//
// The answer is the same whether the login name is unknown, has no password,
// or the password is wrong: the endpoint must not confirm which accounts
// exist. The work done is the same too (see [identity.VerifyPasswordMissing]).
func (s *Server) handlePasswordLogin(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !s.localLogin {
		s.renderError(w, r, http.StatusNotFound, "Sign-in unavailable",
			"This server signs users in through an identity provider.")
		return
	}
	requiresSetup, err := s.localSetupRequired(r.Context())
	if err != nil {
		s.renderAuthenticationUnavailable(w, r)
		return
	}
	if requiresSetup {
		http.Redirect(w, r, "/setup", http.StatusFound)
		return
	}

	returnTo := loginReturnTo(r.PostFormValue("return_to"))
	login := strings.TrimSpace(r.PostFormValue("login"))
	password := r.PostFormValue("password")
	now := time.Now()

	reject := func(status int, title, message, detail string) {
		s.audit("system", identity.AuditLoginFailed, "provider:"+identity.LocalProviderID, detail)
		s.renderError(w, r, status, title, message)
	}

	if !s.checkFormToken(formPurposeLogin, r.PostFormValue("_csrf"), now) {
		reject(http.StatusForbidden, "Request rejected",
			"The form token is invalid. Reload the page and try again.", "invalid form token")
		return
	}

	result, err := s.signInWithPassword(r.Context(), s.clientIP(r), login, password, s.sessionClientInfo(r))
	if err != nil {
		switch {
		case errors.Is(err, errPasswordRejected):
			s.renderError(w, r, http.StatusUnauthorized, "Sign-in failed", "Wrong login name or password.")
		case errors.Is(err, errPasswordRateLimited):
			w.Header().Set("Retry-After", fmt.Sprintf("%d", result.retryAfter))
			s.renderError(w, r, http.StatusTooManyRequests, "Too many attempts", "Too many sign-in attempts. Wait a few minutes and try again.")
		default:
			w.Header().Set("Retry-After", "5")
			s.renderError(w, r, http.StatusServiceUnavailable, "Authentication unavailable", "Your login could not be checked. Please try again later.")
		}
		return
	}

	s.setSessionCookie(w, result.token, result.session.ExpiresAt)
	http.Redirect(w, r, returnTo, http.StatusFound)
}

// handleCallback 共用 OIDC/OAuth2 的持久认证链，适配器分别验证各自协议。
//
// The provider is taken from the path and cross-checked against the one the
// transaction was created for, so a callback can never be replayed onto a
// different provider.
func (s *Server) handleCallback(w http.ResponseWriter, r *http.Request) {
	providerID := chi.URLParam(r, "providerID")

	provider, ok := s.identityProviders().Get(providerID)
	if !ok {
		s.renderError(w, r, http.StatusNotFound, "Unknown provider",
			"The requested identity provider is not configured on this server.")
		return
	}
	if protocol, typed := provider.(interface{ Protocol() string }); typed && protocol.Protocol() == "oauth2" {
		// 别名路由不能绕过回调 allowlist；精确路径与换码时的固定 redirect_uri 保持一致。
		if r.URL.Path != "/oauth2/callback/"+providerID {
			s.renderError(w, r, http.StatusBadRequest, "Sign-in rejected", "Start again from the configured sign-in page.")
			return
		}
	}

	txID, browserSecret, ok := authCookieValue(r)
	if !ok {
		s.audit("system", identity.AuditLoginFailed, "provider:"+providerID, "missing browser binding")
		s.renderError(w, r, http.StatusBadRequest, "Sign-in expired",
			"This sign-in link is incomplete or has expired. Start again from your device.")
		return
	}

	tx, ok := s.identity.GetAuthTransaction(txID)
	if !ok || tx.ProviderID != providerID {
		s.audit("system", identity.AuditLoginFailed, "provider:"+providerID, "unknown transaction")
		s.renderError(w, r, http.StatusBadRequest, "Sign-in expired",
			"This sign-in link is incomplete or has expired. Start again from your device.")
		return
	}
	// The transaction is bound to the browser that started it: a callback
	// URL stolen from another browser cannot be completed here.
	if !identity.SecretEqual(tx.BrowserSessionHash, browserSecret) {
		s.audit("system", identity.AuditLoginFailed, "provider:"+providerID, "browser binding mismatch")
		s.renderError(w, r, http.StatusBadRequest, "Sign-in rejected",
			"This sign-in was started in a different browser. Start again from your device.")
		return
	}
	if tx.Consumed() {
		s.audit("system", identity.AuditLoginFailed, "provider:"+providerID, "transaction replayed")
		s.renderError(w, r, http.StatusBadRequest, "Sign-in already used",
			"This sign-in link has already been used. Start again from your device.")
		return
	}
	if tx.Expired(time.Now()) {
		s.audit("system", identity.AuditLoginFailed, "provider:"+providerID, "transaction expired")
		s.renderError(w, r, http.StatusBadRequest, "Sign-in expired",
			"This sign-in link has expired. Start again from your device.")
		return
	}

	query := r.URL.Query()
	if tx.RequestedAction == identity.AuthActionLink {
		// OAuth browser binding 还不够：切换账户、退出或吊销原会话都应中止绑定。
		current, _, err := s.resolveCookieSession(r)
		if err != nil || current.ID != tx.AccountSessionID || current.UserID != tx.AccountUserID {
			s.renderError(w, r, http.StatusForbidden, "Binding rejected", "Sign in with the account that started this binding and try again.")
			return
		}
	}
	s.finishLogin(w, r, tx, provider, &identity.CallbackRequest{
		Code:             query.Get("code"),
		State:            query.Get("state"),
		Error:            query.Get("error"),
		ErrorDescription: query.Get("error_description"),
		Values:           query,
	})
}

// finishLogin validates the provider answer, then creates the user (or finds
// it) and a browser session.
func (s *Server) finishLogin(w http.ResponseWriter, r *http.Request, tx identity.AuthTransaction, provider identity.IdentityProvider, cb *identity.CallbackRequest) {
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()

	result, err := provider.Callback(ctx, &tx, cb)
	if err != nil {
		s.audit("system", identity.AuditLoginFailed, "provider:"+provider.ID(), loginFailureReason(err))
		s.log.Warn("login rejected", "provider", provider.ID(), "reason", loginFailureReason(err))
		s.renderError(w, r, http.StatusForbidden, "Sign-in failed",
			"The identity provider did not confirm this sign-in. Start again from your device.")
		return
	}

	if result == nil || result.ProviderID != provider.ID() {
		s.renderError(w, r, http.StatusForbidden, "Sign-in failed", "The provider did not confirm this identity.")
		return
	}
	base := result.Email
	if protocol, typed := provider.(interface{ Protocol() string }); typed && protocol.Protocol() == "oauth2" {
		// OAuth2 邮箱只是展示属性，不能隐式成为 ACL principal；摘要也避免公开 raw subject。
		reference := identity.IdentityReference(identity.ExternalIdentity{ProviderID: result.ProviderID, Subject: result.Subject})
		base = result.ProviderID + "_" + reference[:16]
	} else if base == "" {
		base = result.ProviderID + "_" + result.Subject
	}
	completed, err := s.identity.CompleteExternalAuthentication(ctx, tx.ID, *result, identity.ExternalAuthenticationOptions{
		AllowCreate: s.memberRegistrationMode() == RegistrationOpen && s.selfServiceInfo() == nil,
		MaxUsers:    s.Plan().MaxUsers, LoginName: sanitizeLoginName(base), SessionTTL: s.sessionTTL,
		ClientInfo: s.sessionClientInfo(r),
	})
	if err != nil {
		status, message := http.StatusServiceUnavailable, "Your sign-in or binding could not be committed. Please try again."
		switch {
		case errors.Is(err, identity.ErrExternalRegistrationClosed):
			status, message = http.StatusForbidden, "This identity has no account here. Ask the owner for an invitation or bind it from your existing account."
			if s.selfServiceInfo() != nil {
				message = s.translateMessage(r, msgTenantSignupRequired)
			}
		case errors.Is(err, identity.ErrMemberLimitReached):
			status, message = http.StatusForbidden, s.translateMessage(r, MsgUserLimitReached)
		case errors.Is(err, identity.ErrExternalIdentityExists):
			status, message = http.StatusConflict, "This external identity already belongs to another account. Accounts are never merged by email."
		case errors.Is(err, identity.ErrInviteUsed), errors.Is(err, identity.ErrInviteExpired), errors.Is(err, identity.ErrInviteNotFound):
			status, message = http.StatusForbidden, "This invitation has expired, was revoked or has already been used. Ask the owner for a new code."
		case errors.Is(err, identity.ErrSessionRevoked), errors.Is(err, identity.ErrCredentialChanged), errors.Is(err, identity.ErrTransactionConsumed), errors.Is(err, identity.ErrUserDisabled):
			status, message = http.StatusForbidden, "This authorization or initiating session is no longer valid. Start again."
		}
		s.renderError(w, r, status, "Authorization failed", message)
		return
	}
	if !completed.Linked {
		s.setSessionCookie(w, completed.Token, completed.Session.ExpiresAt)
	}
	s.clearAuthCookie(w)

	http.Redirect(w, r, safeReturnTo(tx.ReturnTo), http.StatusFound)
}

// handleLogout implements POST /logout: revoke the session server-side, then
// clear the cookie.
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	session, token, err := s.resolveCookieSession(r)
	if errors.Is(err, identity.ErrSessionNotFound) {
		s.clearSessionCookie(w)
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	if err != nil {
		w.Header().Set("Retry-After", "5")
		w.Header().Set("Cache-Control", "no-store")
		s.renderError(w, r, http.StatusServiceUnavailable, "Authentication unavailable", "Your login could not be checked. Please try again later.")
		return
	}

	if !checkCSRF(r, token) {
		s.renderError(w, r, http.StatusForbidden, "Invalid form token", "Reload the page and try signing out again.")
		return
	}
	if _, err := s.identity.RevokeAccountSessions(r.Context(), session.UserID, session.ID, identity.SessionRevocation{
		Mode: identity.RevokeSingleSession, SessionID: session.ID,
	}); err != nil {
		s.renderError(w, r, http.StatusInternalServerError, "Sign out failed", "Your session could not be revoked. Please try again.")
		return
	}

	s.clearSessionCookie(w)
	http.Redirect(w, r, "/", http.StatusFound)
}

// sanitizeLoginName keeps login names to characters that are safe in HTML,
// ACL documents and URLs.
func sanitizeLoginName(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '@', r == '.', r == '_', r == '-', r == '+':
			b.WriteRune(r)
		}
	}
	return strings.Trim(b.String(), ".-_+@")
}

// safeReturnTo only accepts same-origin absolute paths: anything else could
// turn the login endpoint into an open redirect.
func safeReturnTo(raw string) string {
	if raw == "" || !strings.HasPrefix(raw, "/") || strings.HasPrefix(raw, "//") || strings.ContainsAny(raw, "\\") || strings.ContainsFunc(raw, func(character rune) bool {
		return character < 0x20 || character == 0x7f
	}) {
		return "/"
	}
	u, err := url.Parse(raw)
	if err != nil || u.IsAbs() || u.Host != "" || strings.HasPrefix(u.Path, "//") || strings.ContainsAny(u.Path, "\\") {
		return "/"
	}
	return raw
}

// loginReturnTo resolves where a successful sign-in lands. Someone who signs
// in wants the console; the landing page is only the answer when the input
// did not name anything better (or tried to leave the site).
func loginReturnTo(raw string) string {
	if strings.TrimSpace(raw) == "" {
		return "/console/"
	}
	return safeReturnTo(raw)
}

// providerName returns the display name of a provider.
func (s *Server) providerName(id string) string {
	if p, ok := s.identityProviders().Get(id); ok {
		if named, ok := p.(interface{ DisplayName() string }); ok {
			if name := named.DisplayName(); name != "" {
				return name
			}
		}
	}
	for _, settings := range s.authenticationConfig().Providers {
		if settings.ID == id && settings.DisplayName != "" {
			return settings.DisplayName
		}
	}
	return id
}

// loginFailureReason classifies a login failure into a bounded, greppable
// string. Provider-supplied text is never recorded verbatim (it could contain
// tokens or newlines).
func loginFailureReason(err error) string {
	switch {
	case errors.Is(err, identity.ErrStateMismatch):
		return "oauth state mismatch"
	case errors.Is(err, identity.ErrOAuth2Exchange):
		return "oauth2 exchange rejected"
	case errors.Is(err, identity.ErrOAuth2Token):
		return "oauth2 token rejected"
	case errors.Is(err, identity.ErrOAuth2Profile):
		return "oauth2 profile rejected"
	case errors.Is(err, identity.ErrNonceMismatch):
		return "oidc nonce mismatch"
	case errors.Is(err, identity.ErrTokenFromFuture):
		return "id token issued in the future"
	case errors.Is(err, identity.ErrTokenTooOld):
		return "id token too old"
	case errors.Is(err, identity.ErrTransactionExpired):
		return "transaction expired"
	case errors.Is(err, identity.ErrTransactionConsumed):
		return "transaction replayed"
	}
	var pe *identity.ProviderError
	if errors.As(err, &pe) {
		return "provider error: " + sanitizeToken(pe.Code)
	}
	return "callback rejected"
}

// sanitizeToken keeps an identifier to safe characters and a bounded length.
func sanitizeToken(s string) string {
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-' {
			b.WriteRune(r)
		}
		if b.Len() >= 32 {
			break
		}
	}
	if b.Len() == 0 {
		return "unknown"
	}
	return b.String()
}
