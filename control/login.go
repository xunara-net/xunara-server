package control

import (
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
	// Someone who is already signed in does not need the form again.
	if _, ok := s.currentSession(r); ok {
		http.Redirect(w, r, returnTo, http.StatusFound)
		return
	}

	views := make([]providerView, 0, len(s.providers.IDs()))
	for _, id := range s.providers.IDs() {
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
		"Setup":      s.setupRequired(),
		"FormToken":  s.newFormToken(formPurposeLogin),
		"ReturnTo":   returnTo,
	}
	s.renderPublicPage(w, r, signInPageTemplate, data)
}

// startExternalLogin starts an OIDC authorization for one provider.
func (s *Server) startExternalLogin(w http.ResponseWriter, r *http.Request, providerID, returnTo string) {
	provider, ok := s.providers.Get(providerID)
	if !ok {
		s.renderError(w, r, http.StatusBadRequest, "Unknown provider",
			"The requested identity provider is not configured on this server.")
		return
	}

	tx, browserSecret, err := s.identity.CreateAuthTransaction(identity.NewAuthTransactionOptions{
		ProviderID:  providerID,
		RedirectURI: s.providerRedirects[providerID],
		ReturnTo:    returnTo,
		TTL:         s.authTTL,
	})
	if err != nil {
		s.log.Error("creating auth transaction", "provider", providerID, "err", err)
		s.renderError(w, r, http.StatusInternalServerError, "Sign-in failed", "Please try again.")
		return
	}

	authReq, err := provider.Begin(r.Context(), &tx)
	if err != nil {
		s.audit("system", identity.AuditLoginFailed, "provider:"+providerID, loginFailureReason(err))
		s.log.Warn("starting login", "provider", providerID, "err", err)
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
	if !s.localLogin {
		s.renderError(w, r, http.StatusNotFound, "Sign-in unavailable",
			"This server signs users in through an identity provider.")
		return
	}
	if s.setupRequired() {
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

	// Two buckets: one lets a shared address through for a while, the other
	// stops a single account from being hammered from many addresses.
	for _, limit := range []struct {
		scope  string
		limit  int
		window time.Duration
	}{
		{"login-ip:" + s.clientIP(r), loginAddressLimit, loginAddressWindow},
		{"login-name:" + strings.ToLower(login), loginNameLimit, loginNameWindow},
	} {
		allowed, retryAfter, err := s.store.AllowRate(limit.scope, limit.limit, limit.window, now)
		if err != nil {
			s.log.Error("rate limiting sign-in", "err", err)
			break
		}
		if !allowed {
			w.Header().Set("Retry-After", fmt.Sprintf("%d", int(retryAfter.Seconds())+1))
			reject(http.StatusTooManyRequests, "Too many attempts",
				"Too many sign-in attempts. Wait a few minutes and try again.", "rate limited")
			return
		}
	}

	user, ok := s.identity.GetUserByLoginName(login)
	if !ok || login == "" {
		identity.VerifyPasswordMissing(password)
		reject(http.StatusUnauthorized, "Sign-in failed", "Wrong login name or password.", "unknown login name")
		return
	}
	credential, hasCredential := s.identity.GetLocalCredential(user.ID)
	if !hasCredential {
		// Same answer as an unknown login name: whether an account exists
		// and whether it has a password are not facts this endpoint hands
		// to an anonymous caller. The audit log records the real reason.
		identity.VerifyPasswordMissing(password)
		reject(http.StatusUnauthorized, "Sign-in failed", "Wrong login name or password.", "account has no password")
		return
	}
	if !identity.VerifyPassword(credential.PasswordHash, password) {
		reject(http.StatusUnauthorized, "Sign-in failed", "Wrong login name or password.",
			"wrong password for "+user.LoginName)
		return
	}

	session, token, err := s.identity.CreateLocalSession(r.Context(), user.ID, credential.PasswordHash, s.sessionTTL)
	if errors.Is(err, identity.ErrCredentialChanged) {
		reject(http.StatusUnauthorized, "Sign-in failed", "Wrong login name or password.", "credential changed during sign-in")
		return
	}
	if err != nil {
		s.log.Error("creating session", "user", int(user.ID), "err", err)
		s.renderError(w, r, http.StatusInternalServerError, "Sign-in failed", "Please try again.")
		return
	}

	actor := fmt.Sprintf("user:%d", user.ID)
	s.audit(actor, identity.AuditLoginSucceeded, "provider:"+identity.LocalProviderID, "authenticated "+user.LoginName)
	s.audit(actor, identity.AuditSessionCreated, "session:"+session.ID, "auth method "+identity.LocalProviderID)
	s.setSessionCookie(w, token, session.ExpiresAt)
	http.Redirect(w, r, returnTo, http.StatusFound)
}

// handleCallback implements GET /oidc/callback/{providerID}.
//
// The provider is taken from the path and cross-checked against the one the
// transaction was created for, so a callback can never be replayed onto a
// different provider.
func (s *Server) handleCallback(w http.ResponseWriter, r *http.Request) {
	providerID := chi.URLParam(r, "providerID")

	provider, ok := s.providers.Get(providerID)
	if !ok {
		s.renderError(w, r, http.StatusNotFound, "Unknown provider",
			"The requested identity provider is not configured on this server.")
		return
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
	ctx := r.Context()

	result, err := provider.Callback(ctx, &tx, cb)
	if err != nil {
		s.audit("system", identity.AuditLoginFailed, "provider:"+provider.ID(), loginFailureReason(err))
		s.log.Warn("login rejected", "provider", provider.ID(), "err", err)
		s.renderError(w, r, http.StatusForbidden, "Sign-in failed",
			"The identity provider did not confirm this sign-in. Start again from your device.")
		return
	}

	// Redeem the transaction exactly once, after the provider has confirmed
	// the identity: replayed callbacks and reused codes stop here.
	if _, err := s.identity.ConsumeAuthTransaction(tx.ID); err != nil {
		s.audit("system", identity.AuditLoginFailed, "provider:"+provider.ID(), loginFailureReason(err))
		s.renderError(w, r, http.StatusForbidden, "Sign-in failed",
			"This sign-in was already completed. Start again from your device.")
		return
	}

	user, err := s.userForIdentity(result)
	if err != nil {
		s.log.Error("resolving user", "provider", provider.ID(), "err", err)
		s.audit("system", identity.AuditLoginFailed, "provider:"+provider.ID(), "user resolution failed")
		// A quota refusal is the tenant's business, not an internal failure:
		// the person signing in must see why the account was not created.
		var he HTTPError
		if errors.As(err, &he) {
			s.renderError(w, r, he.Code, "Sign-in failed", s.translateMessage(r, he.Msg))
			return
		}
		s.renderError(w, r, http.StatusInternalServerError, "Sign-in failed", "Please try again.")
		return
	}

	session, token, err := s.identity.CreateSession(identity.NewSessionOptions{
		UserID:     user.ID,
		AuthMethod: provider.ID(),
		TTL:        s.sessionTTL,
	})
	if err != nil {
		s.log.Error("creating session", "user", int(user.ID), "err", err)
		s.renderError(w, r, http.StatusInternalServerError, "Sign-in failed", "Please try again.")
		return
	}

	actor := fmt.Sprintf("user:%d", user.ID)
	s.audit(actor, identity.AuditLoginSucceeded, "provider:"+provider.ID(), "authenticated "+user.LoginName)
	s.audit(actor, identity.AuditSessionCreated, "session:"+session.ID, "auth method "+provider.ID())

	s.setSessionCookie(w, token, session.ExpiresAt)
	s.clearAuthCookie(w)

	http.Redirect(w, r, safeReturnTo(tx.ReturnTo), http.StatusFound)
}

// handleLogout implements POST /logout: revoke the session server-side, then
// clear the cookie.
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	token := s.sessionToken(r)
	if token == "" {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	session, err := s.identity.GetSessionByToken(token)
	if err != nil {
		s.clearSessionCookie(w)
		http.Redirect(w, r, "/", http.StatusFound)
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

// userForIdentity maps an authenticated external identity to a user,
// creating one on first login.
//
// Email is an attribute and never a key: an account is only linked to an
// existing user when (provider, subject) matches (AGENTS.md section 6).
func (s *Server) userForIdentity(result *identity.IdentityResult) (identity.User, error) {
	if result == nil || result.ProviderID == "" || result.Subject == "" {
		return identity.User{}, fmt.Errorf("control: incomplete identity result")
	}

	if link, ok := s.identity.GetExternalIdentity(result.ProviderID, result.Subject); ok {
		user, ok := s.identity.GetUser(link.UserID)
		if !ok {
			return identity.User{}, fmt.Errorf("control: external identity (%s, %s) points at missing user %d",
				result.ProviderID, result.Subject, link.UserID)
		}
		if link.Email != result.Email || link.DisplayName != result.DisplayName {
			link.Email, link.DisplayName = result.Email, result.DisplayName
			if err := s.identity.LinkExternalIdentity(&link); err != nil {
				return identity.User{}, err
			}
		}
		if result.Email != "" && user.Email != result.Email {
			user.Email = result.Email
			if err := s.identity.UpdateUser(user); err != nil {
				return identity.User{}, err
			}
		}
		return user, nil
	}

	// A new sign-in may provision a member, so the plan's member quota applies
	// here exactly as it does to invitations: a tenant must not be able to
	// grow past its plan through the identity provider.
	if err := s.assertUserQuota(); err != nil {
		return identity.User{}, err
	}

	user := identity.User{
		LoginName:   s.uniqueLoginName(result),
		DisplayName: result.DisplayName,
		Email:       result.Email,
	}
	if user.DisplayName == "" {
		user.DisplayName = user.LoginName
	}
	if err := s.identity.CreateUser(&user); err != nil {
		return identity.User{}, err
	}

	link := identity.ExternalIdentity{
		ProviderID:  result.ProviderID,
		Subject:     result.Subject,
		UserID:      user.ID,
		Email:       result.Email,
		DisplayName: result.DisplayName,
	}
	if err := s.identity.LinkExternalIdentity(&link); err != nil {
		// Do not leave a user nobody can ever log in as.
		if delErr := s.identity.DeleteUser(user.ID); delErr != nil {
			s.log.Error("rolling back user after link failure", "user", int(user.ID), "err", delErr)
		}
		return identity.User{}, err
	}

	s.audit("system", identity.AuditUserCreated, fmt.Sprintf("user:%d", user.ID),
		"created on first login via "+result.ProviderID)
	return user, nil
}

// uniqueLoginName derives a login name from the identity result and makes it
// unique.
func (s *Server) uniqueLoginName(result *identity.IdentityResult) string {
	base := result.Email
	if base == "" {
		base = result.ProviderID + "_" + result.Subject
	}
	base = sanitizeLoginName(base)
	if base == "" {
		base = "user"
	}
	if _, taken := s.identity.GetUserByLoginName(base); !taken {
		return base
	}
	for i := 2; i < 1000; i++ {
		candidate := fmt.Sprintf("%s-%d", base, i)
		if _, taken := s.identity.GetUserByLoginName(candidate); !taken {
			return candidate
		}
	}
	// Practically unreachable; fall back to something unique.
	return fmt.Sprintf("%s-%d", base, time.Now().UnixNano())
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
	if raw == "" || !strings.HasPrefix(raw, "/") || strings.HasPrefix(raw, "//") || strings.HasPrefix(raw, "/\\") {
		return "/"
	}
	u, err := url.Parse(raw)
	if err != nil || u.IsAbs() || u.Host != "" {
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
	if p, ok := s.providers.Get(id); ok {
		if named, ok := p.(interface{ DisplayName() string }); ok {
			if name := named.DisplayName(); name != "" {
				return name
			}
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
