package control

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/xunara-net/xunara-server/identity"
	"github.com/xunara-net/xunara-server/state"
)

// First-run setup.
//
// A deployment whose sign-in is the built-in local provider starts with an
// administrator account that has no password: the account exists so the
// tailnet has an owner, but nobody can sign in until someone proves they can
// read the server's state directory. That proof is a one-time token written
// there at startup. Without it, "local login" would mean "whoever opens the
// URL owns the network".

const (
	// setupTokenFile is the token's file name inside the state directory. It
	// is created 0600 and removed as soon as the administrator exists.
	setupTokenFile = "setup-token"

	// setupTokenBytes is the token's entropy.
	setupTokenBytes = 32

	// setupRateLimit and setupRateWindow bound how fast a caller may try
	// tokens. The token is not guessable; the limit keeps the endpoint from
	// being a free work generator.
	setupRateLimit  = 10
	setupRateWindow = 10 * time.Minute
)

// initSetupToken arms the one-time token when the deployment needs one. It
// never logs the token: the path is enough for an operator with access to the
// state directory.
func (s *Server) initSetupToken() {
	if !s.localLogin {
		return
	}
	if s.identity.CountLocalCredentials() > 0 {
		// An administrator exists; a stale token must not stay armed.
		if err := s.clearSetupToken(); err != nil {
			s.log.Warn("removing stale setup token", "err", err)
		}
		return
	}

	path := s.setupTokenPath()
	if token, err := os.ReadFile(path); err == nil && len(strings.TrimSpace(string(token))) >= 16 {
		s.log.Info("administrator setup is pending", "token_file", path)
		return
	}

	token, err := identity.NewSecret(setupTokenBytes)
	if err != nil {
		s.log.Error("generating setup token", "err", err)
		return
	}
	if err := os.WriteFile(path, []byte(token+"\n"), 0o600); err != nil {
		s.log.Error("writing setup token", "path", path, "err", err)
		return
	}
	s.log.Warn("no administrator is configured; read the one-time setup token and finish setup in the browser",
		"token_file", path, "setup_url", "/setup")
}

// setupTokenPath is the file holding the one-time token.
func (s *Server) setupTokenPath() string {
	return filepath.Join(s.cfg.StateDir, setupTokenFile)
}

// readSetupToken returns the armed token, or "" when setup is not pending.
func (s *Server) readSetupToken() string {
	raw, err := os.ReadFile(s.setupTokenPath())
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(raw))
}

// clearSetupToken disarms the token. A missing file is not an error.
func (s *Server) clearSetupToken() error {
	if err := os.Remove(s.setupTokenPath()); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// setupRequired reports whether this deployment still needs its first
// administrator: local sign-in is enabled and no local password exists.
func (s *Server) setupRequired() bool {
	return s.localLogin && s.identity.CountLocalCredentials() == 0
}

// handleSetupPage implements GET /setup.
func (s *Server) handleSetupPage(w http.ResponseWriter, r *http.Request) {
	if !s.setupRequired() {
		// Nothing to set up: send the operator to sign in rather than to a
		// form that cannot work.
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	s.renderPublicPage(w, r, setupPageTemplate, map[string]any{
		"Title":     "Set up the administrator",
		"Token":     "",
		"Login":     "admin",
		"FormToken": s.newFormToken(formPurposeSetup),
		"TokenHint": s.setupTokenPath(),
	})
}

// form purposes bind a token to the form it was minted for, so a token
// harvested from one page cannot be replayed on another.
const (
	formPurposeLogin  = "login"
	formPurposeSetup  = "setup"
	formPurposeSignup = "signup"
)

// handleSetupSubmit implements POST /setup: it consumes the one-time token,
// gives the built-in administrator a password and signs them in.
func (s *Server) handleSetupSubmit(w http.ResponseWriter, r *http.Request) {
	if !s.setupRequired() {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	fail := func(status int, title, message string) {
		s.renderError(w, r, status, title, message)
	}

	allowed, retryAfter, err := s.store.AllowRate("setup:"+clientIP(r), setupRateLimit, setupRateWindow, time.Now())
	if err != nil {
		s.log.Error("rate limiting setup", "err", err)
	}
	if err == nil && !allowed {
		w.Header().Set("Retry-After", fmt.Sprintf("%d", int(retryAfter.Seconds())+1))
		fail(http.StatusTooManyRequests, "Too many attempts",
			"Too many setup attempts from this address. Try again later.")
		return
	}

	if !s.checkFormToken(formPurposeSetup, r.PostFormValue("_csrf"), time.Now()) {
		fail(http.StatusForbidden, "Request rejected",
			"The form token is invalid. Reload the page and try again.")
		return
	}

	armed := s.readSetupToken()
	submitted := strings.TrimSpace(r.PostFormValue("token"))
	if armed == "" || subtle.ConstantTimeCompare([]byte(armed), []byte(submitted)) != 1 {
		s.audit("system", identity.AuditLoginFailed, "setup", "invalid setup token")
		fail(http.StatusForbidden, "Setup rejected",
			"The one-time setup token is wrong. Read it from the server's state directory.")
		return
	}

	login := sanitizeLoginName(r.PostFormValue("login"))
	display := strings.TrimSpace(r.PostFormValue("display_name"))
	email := strings.TrimSpace(r.PostFormValue("email"))
	password := r.PostFormValue("password")
	confirm := r.PostFormValue("confirm")

	if login == "" {
		fail(http.StatusBadRequest, "Setup rejected", "Choose a login name (letters, digits, @ . _ - +).")
		return
	}
	if err := identity.CheckPassword(login, password); err != nil {
		fail(http.StatusBadRequest, "Setup rejected", passwordPolicyMessage(err))
		return
	}
	if password != confirm {
		fail(http.StatusBadRequest, "Setup rejected", "The two passwords do not match.")
		return
	}

	user, ok := s.identity.GetUser(state.DefaultUserID)
	if !ok {
		fail(http.StatusInternalServerError, "Setup failed", "The administrator account is missing.")
		return
	}
	if other, taken := s.identity.GetUserByLoginName(login); taken && other.ID != user.ID {
		fail(http.StatusConflict, "Setup rejected", "That login name is already taken.")
		return
	}

	hash, err := identity.HashPassword(password)
	if err != nil {
		s.log.Error("hashing administrator password", "err", err)
		fail(http.StatusInternalServerError, "Setup failed", "Please try again.")
		return
	}

	previousLogin, previousDisplay, previousEmail := user.LoginName, user.DisplayName, user.Email
	user.LoginName = login
	if display != "" {
		user.DisplayName = display
	}
	if email != "" {
		user.Email = email
	}
	// The account must be an owner: setup is the act that creates the
	// deployment's administrator, and the role is enforced here rather than
	// inherited from whatever the row happened to hold.
	user.Role = identity.RoleOwner
	if err := s.identity.UpdateUser(user); err != nil {
		s.log.Error("updating administrator", "err", err)
		fail(http.StatusInternalServerError, "Setup failed", "Please try again.")
		return
	}
	if err := s.identity.SetLocalCredential(&identity.LocalCredential{
		UserID:       user.ID,
		PasswordHash: hash,
	}); err != nil {
		s.log.Error("storing administrator password", "err", err)
		fail(http.StatusInternalServerError, "Setup failed", "Please try again.")
		return
	}

	// The token is single use: remove it before the session is created so a
	// failure after this point cannot leave a live token behind.
	if err := s.clearSetupToken(); err != nil {
		s.log.Error("clearing setup token", "err", err)
	}

	actor := fmt.Sprintf("user:%d", user.ID)
	s.audit(actor, identity.AuditAdminBootstrap, "user:"+login,
		fmt.Sprintf("administrator set up (was %q, display %q)", previousLogin, previousDisplay))
	if previousLogin != login || previousDisplay != user.DisplayName || previousEmail != user.Email {
		s.audit("system", identity.AuditUserUpdated, fmt.Sprintf("user:%d", user.ID),
			"login, display name or email changed during setup")
	}

	session, token, err := s.identity.CreateSession(identity.NewSessionOptions{
		UserID:     user.ID,
		AuthMethod: identity.LocalProviderID,
		TTL:        s.sessionTTL,
	})
	if err != nil {
		s.log.Error("creating session after setup", "err", err)
		fail(http.StatusInternalServerError, "Setup finished", "Sign in with the password you just set.")
		return
	}
	s.audit(actor, identity.AuditLoginSucceeded, "provider:"+identity.LocalProviderID, "authenticated "+login)
	s.audit(actor, identity.AuditSessionCreated, "session:"+session.ID, "auth method "+identity.LocalProviderID)
	s.setSessionCookie(w, token, session.ExpiresAt)

	http.Redirect(w, r, "/console/", http.StatusFound)
}

// passwordPolicyMessage turns a password policy error into page copy.
func passwordPolicyMessage(err error) string {
	switch {
	case errors.Is(err, identity.ErrPasswordTooShort):
		return fmt.Sprintf("The password must be at least %d characters.", identity.MinPasswordLength)
	case errors.Is(err, identity.ErrPasswordTooLong):
		return "The password is too long (at most 72 bytes)."
	default:
		return "Choose a different password: it must not be the login name."
	}
}
