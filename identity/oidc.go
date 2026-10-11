package identity

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// External authentication rejection reasons. They exist so a login handler can audit the
// cause without ever telling the browser which check failed.
var (
	// ErrStateMismatch means the callback's state does not match the
	// transaction's.
	ErrStateMismatch = errors.New("identity: oauth state mismatch")
	// ErrNonceMismatch means the ID token's nonce does not match the one the
	// transaction sent.
	ErrNonceMismatch = errors.New("identity: oidc nonce mismatch")
	// ErrTokenFromFuture means the ID token's iat is beyond the allowed clock
	// skew.
	ErrTokenFromFuture = errors.New("identity: id token issued in the future")
	// ErrTokenTooOld means the ID token was issued too long before it was
	// presented.
	ErrTokenTooOld = errors.New("identity: id token too old")
)

// ProviderError is an authorization error returned by the provider itself.
type ProviderError struct {
	ProviderID  string
	Code        string
	Description string
}

// Error implements the error interface.
func (e *ProviderError) Error() string {
	return fmt.Sprintf("identity: provider %s returned %s: %s", e.ProviderID, e.Code, e.Description)
}

// OIDCConfig configures one generic OIDC provider.
type OIDCConfig struct {
	// ID is the provider identifier stored in (provider_id, subject). It
	// defaults to "oidc".
	ID string

	// DisplayName is shown on the login page.
	DisplayName string

	// Issuer is the exact iss value of the provider, discovered via
	// <issuer>/.well-known/openid-configuration.
	Issuer string

	// ClientID and ClientSecret are the credentials. An empty ClientSecret
	// means a public client that relies on PKCE.
	ClientID     string
	ClientSecret string

	// RedirectURL is the exact callback URL registered with the provider.
	// It is server configuration and is never taken from a request.
	RedirectURL string

	// Scopes defaults to openid profile email.
	Scopes []string

	// ClockSkew bounds how far the provider's clock may drift from ours when
	// checking iat. Defaults to 2 minutes.
	ClockSkew time.Duration

	// MaxTokenAge bounds how old an ID token may be at exchange time.
	// Defaults to 1 hour.
	MaxTokenAge time.Duration
}

// DefaultClockSkew is the tolerance applied to iat checks.
const DefaultClockSkew = 2 * time.Minute

// DefaultMaxTokenAge is how old an ID token may be when it is redeemed.
const DefaultMaxTokenAge = time.Hour

// OIDCProvider implements [IdentityProvider] for any OIDC-compliant issuer.
//
// Discovery and JWKS retrieval happen lazily on the first login attempt and are
// cached, so the control plane starts even when the identity provider is
// unreachable, and key rotation is handled by go-oidc's remote key set.
type OIDCProvider struct {
	cfg OIDCConfig

	mu       sync.Mutex
	provider *oidc.Provider
	oauth    *oauth2.Config
	verifier *oidc.IDTokenVerifier
}

var _ IdentityProvider = (*OIDCProvider)(nil)

// NewOIDCProvider validates the static configuration. It does not contact the
// issuer.
func NewOIDCProvider(cfg OIDCConfig) (*OIDCProvider, error) {
	if cfg.ID == "" {
		cfg.ID = "oidc"
	}
	if cfg.DisplayName == "" {
		cfg.DisplayName = cfg.ID
	}
	if cfg.Issuer == "" {
		return nil, fmt.Errorf("identity: OIDC provider %q needs an issuer", cfg.ID)
	}
	if cfg.ClientID == "" {
		return nil, fmt.Errorf("identity: OIDC provider %q needs a client ID", cfg.ID)
	}
	if cfg.RedirectURL == "" {
		return nil, fmt.Errorf("identity: OIDC provider %q needs a redirect URL", cfg.ID)
	}
	if err := ValidateSecureURL(cfg.Issuer); err != nil {
		return nil, fmt.Errorf("identity: OIDC provider %q: %w", cfg.ID, err)
	}
	if err := ValidateSecureURL(cfg.RedirectURL); err != nil {
		return nil, fmt.Errorf("identity: OIDC provider %q: %w", cfg.ID, err)
	}
	if len(cfg.Scopes) == 0 {
		cfg.Scopes = []string{oidc.ScopeOpenID, "profile", "email"}
	}
	if cfg.ClockSkew <= 0 {
		cfg.ClockSkew = DefaultClockSkew
	}
	if cfg.MaxTokenAge <= 0 {
		cfg.MaxTokenAge = DefaultMaxTokenAge
	}
	return &OIDCProvider{cfg: cfg}, nil
}

// ID implements [IdentityProvider].
func (p *OIDCProvider) ID() string { return p.cfg.ID }

func (provider *OIDCProvider) Protocol() string { return "oidc" }

// DisplayName returns the human-readable provider name.
func (p *OIDCProvider) DisplayName() string { return p.cfg.DisplayName }

// RedirectURL returns the fixed callback URL.
func (p *OIDCProvider) RedirectURL() string { return p.cfg.RedirectURL }

// connect discovers the issuer once and builds the OAuth and token verifiers.
func (p *OIDCProvider) connect(ctx context.Context) (*oauth2.Config, *oidc.IDTokenVerifier, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.provider == nil {
		provider, err := oidc.NewProvider(ctx, p.cfg.Issuer)
		if err != nil {
			return nil, nil, fmt.Errorf("identity: OIDC discovery for %q: %w", p.cfg.Issuer, err)
		}
		endpoint := provider.Endpoint()
		if err := ValidateSecureURL(endpoint.AuthURL); err != nil {
			return nil, nil, fmt.Errorf("identity: provider %q authorization endpoint: %w", p.cfg.ID, err)
		}
		if err := ValidateSecureURL(endpoint.TokenURL); err != nil {
			return nil, nil, fmt.Errorf("identity: provider %q token endpoint: %w", p.cfg.ID, err)
		}

		p.provider = provider
		p.oauth = &oauth2.Config{
			ClientID:     p.cfg.ClientID,
			ClientSecret: p.cfg.ClientSecret,
			Endpoint:     endpoint,
			RedirectURL:  p.cfg.RedirectURL,
			Scopes:       p.cfg.Scopes,
		}
		p.verifier = provider.Verifier(&oidc.Config{
			ClientID: p.cfg.ClientID,
			// Only asymmetric algorithms. This rules out the HS256
			// algorithm-confusion class where a token is signed with the
			// public client secret.
			SupportedSigningAlgs: []string{"RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "EdDSA"},
		})
	}
	return p.oauth, p.verifier, nil
}

// Begin implements [IdentityProvider].
func (p *OIDCProvider) Begin(ctx context.Context, tx *AuthTransaction) (*AuthorizationRequest, error) {
	if tx == nil {
		return nil, fmt.Errorf("identity: OIDC Begin needs a transaction")
	}

	oauth, _, err := p.connect(ctx)
	if err != nil {
		return nil, err
	}

	challenge := PKCEChallenge(tx.PKCEVerifier)
	if tx.PKCEChallenge != "" && !constantTimeEqual(tx.PKCEChallenge, challenge) {
		return nil, fmt.Errorf("identity: transaction PKCE material is inconsistent")
	}

	return &AuthorizationRequest{URL: oauth.AuthCodeURL(tx.State,
		oidc.Nonce(tx.Nonce),
		oauth2.S256ChallengeOption(tx.PKCEVerifier),
	)}, nil
}

// Callback implements [IdentityProvider].
func (p *OIDCProvider) Callback(ctx context.Context, tx *AuthTransaction, req *CallbackRequest) (*IdentityResult, error) {
	if tx == nil {
		return nil, fmt.Errorf("identity: OIDC Callback needs a transaction")
	}
	if req == nil {
		req = &CallbackRequest{}
	}
	if req.Error != "" {
		return nil, &ProviderError{ProviderID: p.cfg.ID, Code: req.Error, Description: req.ErrorDescription}
	}
	if req.Code == "" || req.State == "" {
		return nil, fmt.Errorf("identity: OIDC callback needs a code and a state")
	}
	if !constantTimeEqual(tx.State, req.State) {
		return nil, ErrStateMismatch
	}

	oauth, verifier, err := p.connect(ctx)
	if err != nil {
		return nil, err
	}

	// The code is redeemed with the PKCE verifier that matches the challenge
	// sent in Begin; a stolen code without the verifier is useless.
	token, err := oauth.Exchange(ctx, req.Code, oauth2.VerifierOption(tx.PKCEVerifier))
	if err != nil {
		return nil, fmt.Errorf("identity: exchanging the authorization code: %w", err)
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return nil, fmt.Errorf("identity: provider returned no id_token")
	}

	// Verifier.Verify checks the signature against the provider's JWKS
	// (refreshing on rotation), the issuer, the audience and exp/nbf.
	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("identity: verifying the id_token: %w", err)
	}

	if idToken.Nonce == "" || !constantTimeEqual(idToken.Nonce, tx.Nonce) {
		return nil, ErrNonceMismatch
	}
	if idToken.Subject == "" {
		return nil, fmt.Errorf("identity: id_token has no subject")
	}

	// Verify the remaining time claims ourselves: go-oidc does not check iat.
	now := time.Now()
	if idToken.IssuedAt.IsZero() {
		return nil, fmt.Errorf("identity: id_token has no iat")
	}
	if idToken.IssuedAt.After(now.Add(p.cfg.ClockSkew)) {
		return nil, ErrTokenFromFuture
	}
	if now.Sub(idToken.IssuedAt) > p.cfg.MaxTokenAge {
		return nil, ErrTokenTooOld
	}
	if !idToken.Expiry.After(now.Add(-p.cfg.ClockSkew)) {
		return nil, fmt.Errorf("identity: id_token is expired")
	}

	var claims struct {
		Email             string `json:"email"`
		EmailVerified     bool   `json:"email_verified"`
		Name              string `json:"name"`
		PreferredUsername string `json:"preferred_username"`
	}
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("identity: reading id_token claims: %w", err)
	}

	displayName := claims.Name
	if displayName == "" {
		displayName = claims.PreferredUsername
	}
	if displayName == "" {
		displayName = claims.Email
	}

	raw := map[string]any{}
	if err := idToken.Claims(&raw); err != nil {
		return nil, fmt.Errorf("identity: reading id_token claims: %w", err)
	}

	return &IdentityResult{
		ProviderID:  p.cfg.ID,
		Subject:     idToken.Subject,
		Email:       claims.Email,
		DisplayName: displayName,
		Claims:      raw,
	}, nil
}

// PKCEChallenge returns the S256 challenge for a verifier.
func PKCEChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64URL(sum[:])
}

// ValidateSecureURL requires https, or http on the loopback interface.
//
// Identity endpoints receive authorization codes, client secrets and tokens;
// plaintext transport to anything but a local development process is a
// vulnerability, and a configuration typo is exactly how it happens.
func ValidateSecureURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid URL %q: %w", raw, err)
	}
	if u.Host == "" || u.Scheme == "" {
		return fmt.Errorf("URL %q must be absolute", raw)
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		host := u.Hostname()
		if host == "localhost" || host == "127.0.0.1" || host == "::1" ||
			(strings.HasPrefix(host, "[") && host[1:] == "::1") {
			return nil
		}
		if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
			return nil
		}
		return fmt.Errorf("URL %q must use https (http is only allowed on loopback)", raw)
	default:
		return fmt.Errorf("URL %q must use https", raw)
	}
}

// constantTimeEqual compares two secrets without leaking their common prefix.
func constantTimeEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
