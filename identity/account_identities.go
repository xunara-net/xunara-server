package identity

import (
	"errors"
	"time"
)

const (
	AuthActionLink        = "account.link"
	AuthActionInvite      = "account.invite"
	AuditIdentityLinked   = "identity.linked"
	AuditIdentityUnlinked = "identity.unlinked"
)

var (
	ErrExternalRegistrationClosed = errors.New("identity: external registration requires an invitation")
	ErrLastLoginMethod            = errors.New("identity: cannot remove the last usable login method")
	ErrAccountIdentityNotFound    = errors.New("identity: account identity not found")
)

type ExternalAuthenticationOptions struct {
	AllowCreate bool
	MaxUsers    int
	LoginName   string
	SessionTTL  time.Duration
	ClientInfo  SessionClientInfo
}

type ExternalAuthentication struct {
	User    User
	Session Session
	Token   string
	Linked  bool
}

// 提供方 subject 不出现在页面或 URL；管理引用不能用于认证。
func IdentityReference(link ExternalIdentity) string {
	return HashSecret(link.ProviderID + "\x00" + link.Subject)
}

type LoginMethods struct {
	Providers              []string
	Local                  bool
	Passkeys               bool
	AuthenticationRevision uint64
}
