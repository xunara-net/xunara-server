package identity

// 本模块复用 go-webauthn 验证器，负责配置校验、持久挑战和浏览器绑定。
// 通行密钥属于 Human Identity，不批准 Machine Identity；挑战跨实例单次消费。

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"tailscale.com/tailcfg"
)

// residentKeyRequired asks the authenticator to store the passkey itself
// (a discoverable credential), which is what lets the login ceremony be
// usernameless.
var residentKeyRequired = true

// PasskeyConfig configures passkey (WebAuthn) sign-in.
type PasskeyConfig struct {
	// DisplayName is what authenticators show as the relying party. Empty
	// falls back to the RP ID.
	DisplayName string
	// RPID is the relying party ID: a registrable domain the control plane is
	// served from, with no scheme or port (e.g. "login.example.com").
	RPID string
	// Origins are the exact browser origins allowed to answer a ceremony
	// (e.g. "https://login.example.com"). Plain http is only accepted for
	// loopback hosts, matching browser security.
	Origins []string
	// UserVerification is how strongly an assertion must verify the user.
	// Empty means [protocol.VerificationRequired].
	UserVerification protocol.UserVerificationRequirement
	// Timeout bounds one ceremony server-side. Zero uses the library default
	// (60s) and still enforces it.
	Timeout time.Duration
}

// PasskeyService performs passkey registration and login.
type PasskeyService struct {
	store            Store
	wa               *webauthn.WebAuthn
	userVerification protocol.UserVerificationRequirement
}

// normalizedPasskeyConfig is a validated configuration with defaults applied.
type normalizedPasskeyConfig struct {
	rpID             string
	origins          []string
	displayName      string
	timeout          time.Duration
	userVerification protocol.UserVerificationRequirement
}

// Validate reports whether the configuration can serve passkey ceremonies. It
// is the check [NewPasskeyService] performs, exported so deployment code can
// reject a derived configuration before opening state.
func (cfg PasskeyConfig) Validate() error {
	_, err := cfg.normalize()
	return err
}

// normalize validates the configuration and applies the documented defaults.
// A configuration mistake must be fatal at startup: a wrong relying party
// would otherwise silently refuse every ceremony.
func (cfg PasskeyConfig) normalize() (normalizedPasskeyConfig, error) {
	rpID := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(cfg.RPID), "."))
	if rpID == "" {
		return normalizedPasskeyConfig{}, errors.New("identity: passkey sign-in needs an RP ID")
	}
	if strings.ContainsAny(rpID, "/:@ ") {
		return normalizedPasskeyConfig{}, fmt.Errorf("identity: passkey RP ID %q must be a bare domain", cfg.RPID)
	}
	// Browsers refuse an IP address as RP ID, so accepting one here would
	// start a server whose ceremonies can never succeed.
	if net.ParseIP(rpID) != nil {
		return normalizedPasskeyConfig{}, fmt.Errorf("identity: passkey RP ID %q must be a domain, not an IP address", cfg.RPID)
	}
	if err := protocol.ValidateRPID(rpID); err != nil {
		return normalizedPasskeyConfig{}, fmt.Errorf("identity: passkey RP ID %q is not a valid domain: %w", cfg.RPID, err)
	}
	if len(cfg.Origins) == 0 {
		return normalizedPasskeyConfig{}, errors.New("identity: passkey sign-in needs at least one allowed origin")
	}

	origins := make([]string, 0, len(cfg.Origins))
	for _, raw := range cfg.Origins {
		origin, err := validatePasskeyOrigin(raw, rpID)
		if err != nil {
			return normalizedPasskeyConfig{}, err
		}
		origins = append(origins, origin)
	}

	displayName := strings.TrimSpace(cfg.DisplayName)
	if displayName == "" {
		displayName = rpID
	}

	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 60 * time.Second
	}

	userVerification := cfg.UserVerification
	if userVerification == "" {
		userVerification = protocol.VerificationRequired
	}
	switch userVerification {
	case protocol.VerificationRequired, protocol.VerificationPreferred, protocol.VerificationDiscouraged:
	default:
		return normalizedPasskeyConfig{}, fmt.Errorf("identity: unknown user verification requirement %q", cfg.UserVerification)
	}

	return normalizedPasskeyConfig{
		rpID:             rpID,
		origins:          origins,
		displayName:      displayName,
		timeout:          timeout,
		userVerification: userVerification,
	}, nil
}

// NewPasskeyService validates cfg and returns the service.
func NewPasskeyService(store Store, cfg PasskeyConfig) (*PasskeyService, error) {
	if store == nil {
		return nil, errors.New("identity: passkey service needs a store")
	}
	norm, err := cfg.normalize()
	if err != nil {
		return nil, err
	}

	wa, err := webauthn.New(&webauthn.Config{
		RPID:                  norm.rpID,
		RPDisplayName:         norm.displayName,
		RPOrigins:             norm.origins,
		AttestationPreference: protocol.PreferNoAttestation,
		Timeouts: webauthn.TimeoutsConfig{
			Registration: webauthn.TimeoutConfig{Enforce: true, Timeout: norm.timeout, TimeoutUVD: norm.timeout},
			Login:        webauthn.TimeoutConfig{Enforce: true, Timeout: norm.timeout, TimeoutUVD: norm.timeout},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("identity: configuring passkey sign-in: %w", err)
	}

	return &PasskeyService{store: store, wa: wa, userVerification: norm.userVerification}, nil
}

// validatePasskeyOrigin enforces that an allowed origin is a plain https (or
// loopback http) origin whose host is the RP ID or a subdomain of it, which is
// what the WebAuthn specification requires for the assertion to verify.
func validatePasskeyOrigin(raw, rpID string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	origin, err := url.Parse(trimmed)
	if err != nil || origin.Host == "" {
		return "", fmt.Errorf("identity: passkey origin %q is not an origin", raw)
	}
	if origin.User != nil || origin.RawQuery != "" || origin.Fragment != "" ||
		(origin.Path != "" && origin.Path != "/") {
		return "", fmt.Errorf("identity: passkey origin %q must not carry a path, query or credentials", raw)
	}

	host := strings.ToLower(origin.Hostname())
	if host != rpID && !strings.HasSuffix(host, "."+rpID) {
		return "", fmt.Errorf("identity: passkey origin %q is not under RP ID %q", raw, rpID)
	}

	switch origin.Scheme {
	case "https":
	case "http":
		if host != "localhost" && host != "127.0.0.1" && host != "::1" {
			return "", fmt.Errorf("identity: passkey origin %q must use https outside loopback", raw)
		}
	default:
		return "", fmt.Errorf("identity: passkey origin %q must use https", raw)
	}

	return origin.Scheme + "://" + origin.Host, nil
}

// BeginRegistration starts a registration ceremony for user and returns the
// browser options plus the ceremony and browser-binding secrets.
func (s *PasskeyService) BeginRegistration(user User) (options *protocol.CredentialCreation, ceremonyID, browserSecret string, err error) {
	if user.ID == 0 {
		return nil, "", "", errors.New("identity: passkey registration needs a user")
	}

	passkeys, err := s.store.ListAccountPasskeys(context.Background(), user.ID)
	if err != nil {
		return nil, "", "", err
	}
	adapter := s.newUser(user, passkeys)
	creation, session, err := s.wa.BeginRegistration(adapter,
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			ResidentKey:        protocol.ResidentKeyRequirementRequired,
			RequireResidentKey: &residentKeyRequired,
			UserVerification:   s.userVerification,
		}),
		webauthn.WithExclusions(webauthn.Credentials(adapter.credentials).CredentialDescriptors()),
	)
	if err != nil {
		return nil, "", "", fmt.Errorf("identity: starting passkey registration: %w", err)
	}
	ceremonyID, browserSecret, err = s.saveCeremony(PasskeyCeremonyRegister, user.ID, session)
	if err != nil {
		return nil, "", "", err
	}
	return creation, ceremonyID, browserSecret, nil
}

// FinishRegistration 验证签名后，仍须在事务中复核发起会话，才能保存新凭据。
// 挑战属于同一用户和浏览器；通过通行密钥认证不会推导任何机器信任。
func (s *PasskeyService) FinishRegistration(ceremonyID, browserSecret string, user User, initiatingID, name string, finish *http.Request) (Passkey, error) {
	ceremony, err := s.takeCeremony(ceremonyID, browserSecret, PasskeyCeremonyRegister)
	if err != nil {
		return Passkey{}, err
	}
	if ceremony.UserID != user.ID {
		// A ceremony belongs to the account that started it; never let one
		// user finish another's registration.
		return Passkey{}, ErrPasskeyCeremonyNotFound
	}
	session, err := decodeCeremonySession(ceremony)
	if err != nil {
		return Passkey{}, err
	}

	passkeys, err := s.store.ListAccountPasskeys(finish.Context(), user.ID)
	if err != nil {
		return Passkey{}, err
	}
	adapter := s.newUser(user, passkeys)
	credential, err := s.wa.FinishRegistration(adapter, session, finish)
	if err != nil {
		return Passkey{}, fmt.Errorf("identity: passkey registration failed: %w", err)
	}

	passkey := Passkey{
		UserID:       user.ID,
		Name:         strings.TrimSpace(name),
		CredentialID: credential.ID,
		Credential:   *credential,
	}
	return s.store.CreateAccountPasskey(finish.Context(), initiatingID, passkey)
}

// BeginLogin starts a usernameless login ceremony: the authenticator offers a
// discoverable passkey and the account is resolved from the credential.
func (s *PasskeyService) BeginLogin() (options *protocol.CredentialAssertion, ceremonyID, browserSecret string, err error) {
	assertion, session, err := s.wa.BeginDiscoverableLogin(
		webauthn.WithUserVerification(s.userVerification),
	)
	if err != nil {
		return nil, "", "", fmt.Errorf("identity: starting passkey login: %w", err)
	}
	ceremonyID, browserSecret, err = s.saveCeremony(PasskeyCeremonyLogin, 0, session)
	if err != nil {
		return nil, "", "", err
	}
	return assertion, ceremonyID, browserSecret, nil
}

// FinishLogin verifies an assertion and returns the user it signs in, together
// with the passkey that was used. The stored sign counter is advanced before
// the caller creates a session: a cloned authenticator must be detected on the
// next assertion, not skipped.
func (s *PasskeyService) FinishLogin(ceremonyID, browserSecret string, finish *http.Request) (User, Passkey, error) {
	ceremony, err := s.takeCeremony(ceremonyID, browserSecret, PasskeyCeremonyLogin)
	if err != nil {
		return User{}, Passkey{}, err
	}
	session, err := decodeCeremonySession(ceremony)
	if err != nil {
		return User{}, Passkey{}, err
	}

	var used Passkey
	handler := func(rawID, _ []byte) (webauthn.User, error) {
		passkey, ok := s.store.GetPasskeyByCredentialID(rawID)
		if !ok {
			return nil, ErrPasskeyNotFound
		}
		user, ok := s.store.GetUser(passkey.UserID)
		if !ok {
			return nil, ErrUserNotFound
		}
		used = passkey
		passkeys, err := s.store.ListAccountPasskeys(finish.Context(), user.ID)
		if err != nil {
			return nil, err
		}
		return s.newUser(user, passkeys), nil
	}

	_, credential, err := s.wa.FinishPasskeyLogin(handler, session, finish)
	if err != nil {
		return User{}, Passkey{}, fmt.Errorf("identity: passkey login failed: %w", err)
	}
	user, ok := s.store.GetUser(used.UserID)
	if !ok {
		return User{}, Passkey{}, ErrUserNotFound
	}

	if err := s.store.UpdatePasskey(used.ID, *credential, time.Now().UTC()); err != nil {
		return User{}, Passkey{}, err
	}
	used.Credential = *credential
	used.LastUsedAt = time.Now().UTC()
	return user, used, nil
}

// saveCeremony persists a started ceremony and returns its ID plus the browser
// secret the caller sets as a cookie.
func (s *PasskeyService) saveCeremony(kind PasskeyCeremonyKind, userID tailcfg.UserID, session *webauthn.SessionData) (string, string, error) {
	raw, err := json.Marshal(session)
	if err != nil {
		return "", "", fmt.Errorf("identity: encoding passkey ceremony: %w", err)
	}
	ceremony, browserSecret, err := s.store.CreatePasskeyCeremony(NewPasskeyCeremonyOptions{
		Kind:      kind,
		UserID:    userID,
		Session:   raw,
		ExpiresAt: session.Expires,
	})
	if err != nil {
		return "", "", err
	}
	return ceremony.ID, browserSecret, nil
}

// takeCeremony 先校验浏览器绑定，再原子消费挑战，防止跨实例重放。
// 仅猜到公共挑战 ID 不能消耗他人的挑战；绑定正确后的验证失败则需重新开始。
func (s *PasskeyService) takeCeremony(id, browserSecret string, kind PasskeyCeremonyKind) (PasskeyCeremony, error) {
	if id == "" || browserSecret == "" {
		return PasskeyCeremony{}, ErrPasskeyCeremonyNotFound
	}
	stored, ok := s.store.GetPasskeyCeremony(id)
	if !ok {
		return PasskeyCeremony{}, ErrPasskeyCeremonyNotFound
	}
	if stored.Kind != kind || !SecretEqual(stored.BrowserSessionHash, browserSecret) {
		return PasskeyCeremony{}, ErrPasskeyCeremonyNotFound
	}
	return s.store.ConsumePasskeyCeremony(id)
}

// decodeCeremonySession returns the library's session state.
func decodeCeremonySession(ceremony PasskeyCeremony) (webauthn.SessionData, error) {
	var session webauthn.SessionData
	if err := json.Unmarshal(ceremony.Session, &session); err != nil {
		return webauthn.SessionData{}, fmt.Errorf("identity: decoding passkey ceremony: %w", err)
	}
	return session, nil
}

// webauthnUser adapts an identity user and its stored passkeys to the
// library's User interface.
type webauthnUser struct {
	user        User
	credentials []webauthn.Credential
}

// newUser 只适配已成功读取的账户凭据，不以空列表掩盖存储读取错误。
func (s *PasskeyService) newUser(user User, passkeys []Passkey) webauthnUser {
	credentials := make([]webauthn.Credential, 0, len(passkeys))
	for _, passkey := range passkeys {
		credentials = append(credentials, passkey.Credential)
	}
	return webauthnUser{user: user, credentials: credentials}
}

// WebAuthnID is the opaque, stable user handle. It is an account handle for
// the authenticator, never an authorization key: login still requires a valid
// assertion and the session layer still gates every request.
func (u webauthnUser) WebAuthnID() []byte {
	var handle [8]byte
	binary.BigEndian.PutUint64(handle[:], uint64(u.user.ID))
	return handle[:]
}

// WebAuthnName is the human-palatable account name shown by the authenticator.
func (u webauthnUser) WebAuthnName() string { return u.user.LoginName }

// WebAuthnDisplayName is the account's display name.
func (u webauthnUser) WebAuthnDisplayName() string {
	if u.user.DisplayName != "" {
		return u.user.DisplayName
	}
	return u.user.LoginName
}

// WebAuthnCredentials returns the account's registered passkeys.
func (u webauthnUser) WebAuthnCredentials() []webauthn.Credential { return u.credentials }
