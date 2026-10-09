package control

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/xunara-net/xunara-server/identity"
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
func (s *Server) initSetupToken(ctx context.Context) error {
	if !s.localLogin {
		return nil
	}
	required, err := s.localSetupRequired(ctx)
	if err != nil {
		return err
	}
	if !required {
		// An administrator exists; a stale token must not stay armed.
		if err := s.clearSetupToken(); err != nil {
			s.log.Warn("removing stale setup token", "err", err)
		}
		return nil
	}

	path := s.setupTokenPath()
	if _, err := s.loadSetupToken(); err == nil {
		s.log.Info("administrator setup is pending", "token_file", path)
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("control: reading setup token: %w", err)
	}

	token, err := identity.NewSecret(setupTokenBytes)
	if err != nil {
		return fmt.Errorf("control: generating setup token: %w", err)
	}
	// 先完整写入 0600 临时文件，再以不覆盖已有目标的硬链接发布。
	// 多实例启动采用同一个已发布令牌，不能截断文件或改写另一实例的证明。
	file, err := os.CreateTemp(s.cfg.StateDir, ".setup-token-*")
	if err != nil {
		return fmt.Errorf("control: creating setup token file: %w", err)
	}
	defer os.Remove(file.Name())
	defer file.Close()
	if _, err := file.WriteString(token + "\n"); err != nil {
		return fmt.Errorf("control: writing setup token: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("control: syncing setup token: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("control: closing setup token: %w", err)
	}
	if err := os.Link(file.Name(), path); err != nil && !errors.Is(err, os.ErrExist) {
		return fmt.Errorf("control: publishing setup token: %w", err)
	}
	if _, err := s.loadSetupToken(); err != nil {
		return fmt.Errorf("control: reading published setup token: %w", err)
	}
	s.log.Warn("no administrator is configured; read the one-time setup token and finish setup in the browser",
		"token_file", path, "setup_url", "/setup")
	return nil
}

// setupTokenPath is the file holding the one-time token.
func (s *Server) setupTokenPath() string {
	return filepath.Join(s.cfg.StateDir, setupTokenFile)
}

// loadSetupToken 校验文件类型、权限和证明长度，保留读取故障而不是返回空令牌。
func (s *Server) loadSetupToken() (string, error) {
	info, err := os.Lstat(s.setupTokenPath())
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		return "", errors.New("control: setup token must be a regular file with permissions 0600")
	}
	file, err := os.Open(s.setupTokenPath())
	if err != nil {
		return "", err
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, 128))
	if err != nil {
		return "", err
	}
	token := strings.TrimSpace(string(raw))
	decoded, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(decoded) != setupTokenBytes || len(raw) == 128 {
		return "", errors.New("control: invalid setup token file")
	}
	return token, nil
}

// clearSetupToken disarms the token. A missing file is not an error.
func (s *Server) clearSetupToken() error {
	if err := os.Remove(s.setupTokenPath()); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// setupStateForPage 为兼容 HTML 提供同一失败关闭的状态读取，不把故障当成初始化。
func (s *Server) setupStateForPage(w http.ResponseWriter, r *http.Request) (bool, bool) {
	w.Header().Set("Cache-Control", "no-store")
	required, err := s.localSetupRequired(r.Context())
	if err != nil {
		s.renderAuthenticationUnavailable(w, r)
		return false, false
	}
	return required, true
}

func (s *Server) renderAuthenticationUnavailable(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Retry-After", "5")
	s.renderError(w, r, http.StatusServiceUnavailable, "Authentication unavailable", "Your login could not be checked. Please try again later.")
}

// handleSetupPage implements GET /setup.
func (s *Server) handleSetupPage(w http.ResponseWriter, r *http.Request) {
	required, ok := s.setupStateForPage(w, r)
	if !ok {
		return
	}
	if !required {
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
		"Setup":     true,
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
	required, ok := s.setupStateForPage(w, r)
	if !ok {
		return
	}
	if !required {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	fail := func(status int, title, message string) {
		s.renderError(w, r, status, title, message)
	}

	allowed, retryAfter, err := s.store.AllowRate("setup:"+s.clientIP(r), setupRateLimit, setupRateWindow, time.Now())
	if err != nil {
		s.renderAuthenticationUnavailable(w, r)
		return
	}
	if !allowed {
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

	armed, err := s.loadSetupToken()
	if err != nil {
		s.renderAuthenticationUnavailable(w, r)
		return
	}
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

	_, session, token, err := s.claimLocalAccount(r.Context(), identity.ClaimAdministrator, login, display, email, password)
	switch {
	case errors.Is(err, identity.ErrUserNotFound):
		fail(http.StatusInternalServerError, "Setup failed", "The administrator account is missing.")
		return
	case errors.Is(err, identity.ErrLoginNameTaken):
		fail(http.StatusConflict, "Setup rejected", "That login name is already taken.")
		return
	case errors.Is(err, identity.ErrLocalAccountClaimed):
		fail(http.StatusConflict, "Setup rejected", "The administrator has already been initialized. Sign in instead.")
		return
	case err != nil:
		s.log.Error("setting up the administrator", "err", err)
		s.renderAuthenticationUnavailable(w, r)
		return
	}

	// 数据库完成事实已经使证明失效；文件清理失败不能留下可重放的认领权限。
	if err := s.clearSetupToken(); err != nil {
		s.log.Error("clearing setup token", "err", err)
	}
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
