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

// localSignupRequest is one attempt to create a local account from an
// invitation. The JSON auth API and self-service admission share the same rules.
type localSignupRequest struct {
	Invite   string
	Login    string
	Display  string
	Email    string
	Password string
	// Confirm is the repeated password. The JSON API sets it equal to
	// Password, since an API client has no second form field to typo.
	Confirm    string
	ClientInfo identity.SessionClientInfo
}

// signupRejection is a registration failure that is safe to show the person
// trying to register: the message explains what to do next and never says
// whether an account or invitation exists beyond what the caller already has.
type signupRejection struct {
	Code    int
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
		return signupRejection{Code: code, Message: message}
	}

	if s.selfServiceInfo() != nil && strings.TrimSpace(req.Invite) == "" {
		return signupAdmission{}, reject(http.StatusForbidden, msgTenantSignupRequired)
	}

	token := strings.TrimSpace(req.Invite)
	mode := s.memberRegistrationMode()
	// 开放加入仍允许明确兑换邀请角色；邀请码绝不能被忽略而静默降为匿名注册。
	if token != "" && mode.AllowsSignup() {
		mode = RegistrationInvite
	}
	switch mode {
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
	revision := s.authenticationRevision()
	reject := func(code int, message string) error {
		return signupRejection{Code: code, Message: message}
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
		AuthenticationRevision: revision,
		ClientInfo:             req.ClientInfo,
	})
	switch {
	case errors.Is(err, identity.ErrAuthenticationConfigChanged):
		err = reject(http.StatusConflict, "Registration settings changed. Reload the page before trying again.")
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
