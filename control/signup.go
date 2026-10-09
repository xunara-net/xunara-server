package control

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/xunara-net/xunara-server/identity"
)

// Registration by invitation.
//
// The deployment has no external identity provider, so the only way to create
// an account is an invitation an administrator minted: it is single use,
// expires, and carries the role it grants. There is deliberately no open
// self-registration — a control plane that anyone can join is not a tailnet,
// it is a public network.

const (
	signupRateLimit  = 20
	signupRateWindow = time.Hour
)

// handleSignupPage implements GET /signup.
func (s *Server) handleSignupPage(w http.ResponseWriter, r *http.Request) {
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
	if s.setupRequired() {
		http.Redirect(w, r, "/setup", http.StatusFound)
		return
	}
	s.renderPublicPage(w, r, signupPageTemplate, map[string]any{
		"Title":          "Create your account",
		"Invite":         strings.TrimSpace(r.URL.Query().Get("invite")),
		"InviteRequired": s.registration.RequiresInvite(),
		"FormToken":      s.newFormToken(formPurposeSignup),
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

// errSignupNoSession reports that the account was created but a session could
// not be started; the caller sends the new user to the sign-in page.
var errSignupNoSession = errors.New("registration succeeded but no session could be started")

// signupLocalUser validates a registration attempt, creates the account and
// opens a session. The returned errors are either signupRejection, for
// problems the applicant caused, or internal errors to log and answer with a
// generic failure.
// signupAdmission is who an applicant becomes, decided before anything is
// created. An invitation carries its own role; open registration always
// grants the least privilege.
type signupAdmission struct {
	role identity.Role
	// invite is the invitation being redeemed. It is the zero value when the
	// attempt did not present one (open registration).
	invite identity.RegistrationInvite
	// token is the invitation token as presented, empty in open mode.
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

	token := strings.TrimSpace(req.Invite)
	switch s.registration {
	case RegistrationInvite:
		invite, err := s.identity.FindRegistrationInvite(token)
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
		return signupAdmission{role: invite.Role, invite: invite, token: token}, nil
	case RegistrationOpen:
		// Self-service accounts start as members: an owner or admin is
		// promoted deliberately (console users page), never by signing up.
		return signupAdmission{role: identity.RoleMember}, nil
	default:
		s.audit("system", identity.AuditLoginFailed, "signup", "registration is closed")
		return signupAdmission{}, reject(http.StatusForbidden,
			"This deployment does not accept self-service registration. Ask an administrator for an account.")
	}
}

func (s *Server) signupLocalUser(req localSignupRequest, now time.Time) (identity.User, identity.Session, string, error) {
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
	if _, taken := s.identity.GetUserByLoginName(login); taken {
		return identity.User{}, identity.Session{}, "", reject(http.StatusConflict,
			"That login name is already taken.")
	}
	if err := identity.CheckPassword(login, password); err != nil {
		return identity.User{}, identity.Session{}, "", reject(http.StatusBadRequest, passwordPolicyMessage(err))
	}
	if password != confirm {
		return identity.User{}, identity.Session{}, "", reject(http.StatusBadRequest,
			"The two passwords do not match.")
	}

	if err := s.assertUserQuota(); err != nil {
		var he HTTPError
		if errors.As(err, &he) {
			return identity.User{}, identity.Session{}, "", signupRejection{
				Code: he.Code, Title: "Registration rejected", Message: he.Msg,
			}
		}
		return identity.User{}, identity.Session{}, "", err
	}

	user, err := s.createLocalAccount(login, display, email, admission.role, password, now)
	if err != nil {
		return identity.User{}, identity.Session{}, "", err
	}

	// Redeem after the account exists, and roll the account back if the
	// invitation turns out to be gone: an account created by an invitation
	// nobody redeemed must not stay behind. Open registration has nothing to
	// redeem, which is the only difference between the two paths.
	if admission.token != "" {
		if _, err := s.identity.RedeemRegistrationInvite(admission.token, user.ID, now); err != nil {
			if delErr := s.identity.DeleteUser(user.ID); delErr != nil {
				s.log.Error("rolling back registered user", "user", int(user.ID), "err", delErr)
			}
			s.audit("system", identity.AuditLoginFailed, "signup", "invitation could not be redeemed")
			return identity.User{}, identity.Session{}, "", reject(http.StatusConflict,
				"That invitation has already been used. Ask an administrator for a new link.")
		}
	}

	if admission.invite.ID != "" {
		s.audit("system", identity.AuditUserRegistered, fmt.Sprintf("user:%d", user.ID),
			"registered with an invitation as "+string(user.Role))
		s.audit("system", identity.AuditInviteRedeemed, "invite:"+admission.invite.ID, "redeemed by user "+user.LoginName)
	} else {
		s.audit("system", identity.AuditUserRegistered, fmt.Sprintf("user:%d", user.ID),
			"self-service registration as "+string(user.Role))
	}

	session, sessionToken, err := s.identity.CreateSession(identity.NewSessionOptions{
		UserID:     user.ID,
		AuthMethod: identity.LocalProviderID,
		TTL:        s.sessionTTL,
	})
	if err != nil {
		s.log.Error("creating session after registration", "user", int(user.ID), "err", err)
		return user, identity.Session{}, "", errSignupNoSession
	}

	actor := fmt.Sprintf("user:%d", user.ID)
	s.audit(actor, identity.AuditLoginSucceeded, "provider:"+identity.LocalProviderID, "authenticated "+user.LoginName)
	s.audit(actor, identity.AuditSessionCreated, "session:"+session.ID, "auth method "+identity.LocalProviderID)

	return user, session, sessionToken, nil
}

// createLocalAccount creates a local account together with its password
// credential. It is the shared tail of every local sign-up path — invitation,
// open self-service registration and the platform's tenant provisioner — so a
// rule added here applies to all of them (AGENTS.md section 15). The caller
// has already validated the login name and the password policy, and has
// already applied its own quota gate.
//
// A failure after the user row exists rolls it back: an account that cannot
// sign in (because it has no credential) is worse than no account.
func (s *Server) createLocalAccount(login, display, email string, role identity.Role, password string, _ time.Time) (identity.User, error) {
	hash, err := identity.HashPassword(password)
	if err != nil {
		return identity.User{}, fmt.Errorf("hashing registration password: %w", err)
	}

	user := identity.User{
		LoginName:   login,
		DisplayName: display,
		Email:       email,
		Role:        role,
	}
	if user.DisplayName == "" {
		user.DisplayName = login
	}
	if err := s.identity.CreateUser(&user); err != nil {
		return identity.User{}, fmt.Errorf("creating registered user: %w", err)
	}

	if err := s.identity.SetLocalCredential(&identity.LocalCredential{
		UserID:       user.ID,
		PasswordHash: hash,
	}); err != nil {
		if delErr := s.identity.DeleteUser(user.ID); delErr != nil {
			s.log.Error("rolling back a user without a credential", "user", int(user.ID), "err", delErr)
		}
		return identity.User{}, fmt.Errorf("storing registration password: %w", err)
	}

	// Local accounts are reachable as the (local, login) external identity,
	// exactly like the built-in administrator, so later features that key on
	// an identity link see them too.
	link := identity.ExternalIdentity{
		ProviderID:  identity.LocalProviderID,
		Subject:     user.LoginName,
		UserID:      user.ID,
		Email:       user.Email,
		DisplayName: user.DisplayName,
	}
	if err := s.identity.LinkExternalIdentity(&link); err != nil {
		s.log.Error("linking registered identity", "user", int(user.ID), "err", err)
	}

	return user, nil
}

// handleSignupSubmit implements POST /signup.
func (s *Server) handleSignupSubmit(w http.ResponseWriter, r *http.Request) {
	if !s.localLogin {
		s.renderError(w, r, http.StatusNotFound, "Registration unavailable",
			"This server creates accounts through an identity provider.")
		return
	}
	if s.setupRequired() {
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
	}
	if err == nil && !allowed {
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

	_, session, sessionToken, err := s.signupLocalUser(localSignupRequest{
		Invite:   r.PostFormValue("invite"),
		Login:    r.PostFormValue("login"),
		Display:  r.PostFormValue("display_name"),
		Email:    r.PostFormValue("email"),
		Password: r.PostFormValue("password"),
		Confirm:  r.PostFormValue("confirm"),
	}, now)
	if err != nil {
		var rejection signupRejection
		switch {
		case errors.As(err, &rejection):
			fail(rejection.Code, rejection.Title, rejection.Message)
		case errors.Is(err, errSignupNoSession):
			http.Redirect(w, r, "/login", http.StatusFound)
		default:
			s.log.Error("registration failed", "err", err)
			fail(http.StatusInternalServerError, "Registration failed", "Please try again.")
		}
		return
	}

	s.setSessionCookie(w, sessionToken, session.ExpiresAt)
	http.Redirect(w, r, "/console/", http.StatusFound)
}
