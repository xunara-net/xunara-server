package control

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/xunara-net/xunara-server/identity"
)

// 注册入口共享 closed / invite / open 准入策略；独立租户开通不在此路径处理。
// 准入判断不代替提交检查，成员配额和邀请使用必须与账户写入共用事务。

const (
	signupRateLimit  = 20
	signupRateWindow = time.Hour
)

// handleSignupPage implements GET /signup.
func (s *Server) handleSignupPage(w http.ResponseWriter, r *http.Request) {
	if s.selfServiceInfo() != nil {
		http.Redirect(w, r, "/register", http.StatusSeeOther)
		return
	}
	if !s.localLogin {
		s.renderError(w, r, http.StatusNotFound, "Registration unavailable",
			"This server creates accounts through an identity provider.")
		return
	}
	if !s.registration.AllowsSignup() {
		s.renderError(w, r, http.StatusNotFound, "Registration unavailable",
			"This deployment creates accounts through an administrator.")
		return
	}
	required, ok := s.setupStateForPage(w, r)
	if !ok {
		return
	}
	if required {
		http.Redirect(w, r, "/setup", http.StatusFound)
		return
	}
	s.renderPublicPage(w, r, signupPageTemplate, map[string]any{
		"Title":          "Create your account",
		"Invite":         strings.TrimSpace(r.URL.Query().Get("invite")),
		"InviteRequired": s.registration.RequiresInvite(),
		"FormToken":      s.newFormToken(formPurposeSignup),
		"Setup":          false,
	})
}

// localSignupRequest is one attempt to create a local account from an
// invitation. It is shared by the HTML sign-up page and the JSON auth API so
// both entry points enforce exactly the same rules.
type localSignupRequest struct {
	Invite   string
	Login    string
	Display  string
	Email    string
	Password string
	// Confirm is the repeated password. The JSON API sets it equal to
	// Password, since an API client has no second form field to typo.
	Confirm string
}

// signupRejection is a registration failure that is safe to show the person
// trying to register: the message explains what to do next and never says
// whether an account or invitation exists beyond what the caller already has.
type signupRejection struct {
	Code    int
	Title   string
	Message string
}

func (e signupRejection) Error() string { return e.Message }

// signupAdmission 只记录注册路径，授权角色以提交事务内读取的邀请为准。
type signupAdmission struct {
	token string
}

// admitSignup applies the deployment's registration policy to one attempt.
// The two self-service modes differ in exactly one place — an invitation with
// its role, or nobody with the member role — and the closed mode creates
// nothing at all (registration.go).
func (s *Server) admitSignup(req localSignupRequest) (signupAdmission, error) {
	reject := func(code int, message string) error {
		return signupRejection{Code: code, Title: "Registration rejected", Message: message}
	}

	if s.selfServiceInfo() != nil {
		return signupAdmission{}, reject(http.StatusForbidden, msgTenantSignupRequired)
	}

	token := strings.TrimSpace(req.Invite)
	switch s.registration {
	case RegistrationInvite:
		_, err := s.identity.FindRegistrationInvite(token)
		switch {
		case errors.Is(err, identity.ErrInviteNotFound):
			s.audit("system", identity.AuditLoginFailed, "signup", "unknown invitation")
			return signupAdmission{}, reject(http.StatusForbidden,
				"That invitation code is not valid. Ask an administrator for a new link.")
		case errors.Is(err, identity.ErrInviteUsed):
			s.audit("system", identity.AuditLoginFailed, "signup", "invitation already used")
			return signupAdmission{}, reject(http.StatusForbidden,
				"That invitation has already been used. Ask an administrator for a new link.")
		case errors.Is(err, identity.ErrInviteExpired):
			s.audit("system", identity.AuditLoginFailed, "signup", "invitation expired")
			return signupAdmission{}, reject(http.StatusForbidden,
				"That invitation has expired. Ask an administrator for a new link.")
		case err != nil:
			return signupAdmission{}, fmt.Errorf("reading invitation: %w", err)
		}
		return signupAdmission{token: token}, nil
	case RegistrationOpen:
		// Self-service accounts start as members: an owner or admin is
		// promoted deliberately (console users page), never by signing up.
		return signupAdmission{}, nil
	default:
		s.audit("system", identity.AuditLoginFailed, "signup", "registration is closed")
		return signupAdmission{}, reject(http.StatusForbidden,
			"This deployment does not accept self-service registration. Ask an administrator for an account.")
	}
}

func (s *Server) signupLocalUser(ctx context.Context, req localSignupRequest) (identity.User, identity.Session, string, error) {
	reject := func(code int, message string) error {
		return signupRejection{Code: code, Title: "Registration rejected", Message: message}
	}

	admission, err := s.admitSignup(req)
	if err != nil {
		return identity.User{}, identity.Session{}, "", err
	}

	login := sanitizeLoginName(req.Login)
	display := strings.TrimSpace(req.Display)
	email := strings.TrimSpace(req.Email)
	password := req.Password
	confirm := req.Confirm

	if login == "" {
		return identity.User{}, identity.Session{}, "", reject(http.StatusBadRequest,
			"Choose a login name (letters, digits, @ . _ - +).")
	}
	if err := identity.CheckPassword(login, password); err != nil {
		return identity.User{}, identity.Session{}, "", reject(http.StatusBadRequest, passwordPolicyMessage(err))
	}
	if password != confirm {
		return identity.User{}, identity.Session{}, "", reject(http.StatusBadRequest,
			"The two passwords do not match.")
	}

	hash, err := identity.HashPassword(password)
	if err != nil {
		return identity.User{}, identity.Session{}, "", fmt.Errorf("hashing registration password: %w", err)
	}
	user, session, token, err := s.identity.RegisterLocalAccount(ctx, identity.LocalRegistration{
		LoginName: login, DisplayName: display, Email: email, PasswordHash: hash,
		InviteToken: admission.token, MaxUsers: s.Plan().MaxUsers, SessionTTL: s.sessionTTL,
	})
	switch {
	case errors.Is(err, identity.ErrMemberLimitReached):
		err = reject(http.StatusForbidden, MsgUserLimitReached)
	case errors.Is(err, identity.ErrLoginNameTaken):
		err = reject(http.StatusConflict, "That login name is already taken.")
	case errors.Is(err, identity.ErrInviteUsed):
		err = reject(http.StatusConflict, "That invitation has already been used. Ask an administrator for a new code.")
	case errors.Is(err, identity.ErrInviteExpired), errors.Is(err, identity.ErrInviteNotFound):
		err = reject(http.StatusForbidden, "That invitation is no longer valid. Ask an administrator for a new code.")
	}
	return user, session, token, err
}

// handleSignupSubmit implements POST /signup.
func (s *Server) handleSignupSubmit(w http.ResponseWriter, r *http.Request) {
	if !s.localLogin {
		s.renderError(w, r, http.StatusNotFound, "Registration unavailable",
			"This server creates accounts through an identity provider.")
		return
	}
	required, ok := s.setupStateForPage(w, r)
	if !ok {
		return
	}
	if required {
		http.Redirect(w, r, "/setup", http.StatusFound)
		return
	}

	now := time.Now()
	fail := func(status int, title, message string) {
		s.renderError(w, r, status, title, message)
	}

	allowed, retryAfter, err := s.store.AllowRate("signup:"+s.clientIP(r), signupRateLimit, signupRateWindow, now)
	if err != nil {
		s.log.Error("rate limiting registration", "err", err)
		fail(http.StatusServiceUnavailable, "Registration unavailable", "Please try again later.")
		return
	}
	if !allowed {
		w.Header().Set("Retry-After", fmt.Sprintf("%d", int(retryAfter.Seconds())+1))
		fail(http.StatusTooManyRequests, "Too many attempts",
			"Too many registration attempts from this address. Try again later.")
		return
	}

	if !s.checkFormToken(formPurposeSignup, r.PostFormValue("_csrf"), now) {
		fail(http.StatusForbidden, "Request rejected",
			"The form token is invalid. Reload the page and try again.")
		return
	}

	_, session, sessionToken, err := s.signupLocalUser(r.Context(), localSignupRequest{
		Invite:   r.PostFormValue("invite"),
		Login:    r.PostFormValue("login"),
		Display:  r.PostFormValue("display_name"),
		Email:    r.PostFormValue("email"),
		Password: r.PostFormValue("password"),
		Confirm:  r.PostFormValue("confirm"),
	})
	if err != nil {
		var rejection signupRejection
		switch {
		case errors.As(err, &rejection):
			fail(rejection.Code, rejection.Title, rejection.Message)
		default:
			s.log.Error("registration failed", "err", err)
			fail(http.StatusInternalServerError, "Registration failed", "Please try again.")
		}
		return
	}

	s.setSessionCookie(w, sessionToken, session.ExpiresAt)
	http.Redirect(w, r, "/console/", http.StatusFound)
}
