package control

import (
	"time"

	"github.com/xunara-net/xunara-server/idtoken"
)

// IDTokenStatus is the read-only administrative view of this deployment's
// identity-token issuer: the URL a relying party trusts, the keys currently
// published in the JWKS, and which of them signs new tokens.
//
// It carries no private key material — the JWKS is public by design — so the
// platform surface cannot widen what a node or a relying party can already
// learn. Unlike GET /.well-known/jwks.json it is authenticated and scoped, and
// it reports the issuer even when no key exists yet.
type IDTokenStatus struct {
	// Enabled is true when the deployment has an issuer URL. Without one it
	// cannot be a trust anchor, and /machine/id-token answers 501.
	Enabled bool `json:"enabled"`
	// Issuer is the value of a token's iss claim and the base of JWKSURL.
	Issuer string `json:"issuer,omitempty"`
	// JWKSURL is where relying parties fetch the public keys.
	JWKSURL string `json:"jwksUrl,omitempty"`
	// Algorithm is the JWS algorithm of every issued token.
	Algorithm string `json:"algorithm,omitempty"`
	// TokenTTLSeconds is how long an issued token is valid.
	TokenTTLSeconds int `json:"tokenTtlSeconds,omitempty"`
	// ActiveKeyID is the kid signing new tokens; empty when no key exists yet.
	ActiveKeyID string `json:"activeKeyId,omitempty"`
	// Keys are the keys published in the JWKS, newest last. Retired keys stay
	// published until the tokens they signed have expired.
	Keys []idtoken.KeyInfo `json:"keys"`
}

// IDTokenStatus reports the identity-token issuer's state.
//
// Reading it ensures the keyring exists (keys are generated lazily), exactly
// like a JWKS fetch; the alternative — an empty key set on a configured issuer
// — would make relying-party setup fail for a reason that is not real.
func (s *Server) IDTokenStatus() (IDTokenStatus, error) {
	status := IDTokenStatus{Keys: []idtoken.KeyInfo{}}
	if s.tokens == nil {
		return status, nil
	}

	now := time.Now().UTC()
	issuer := idtoken.TrimIssuer(s.cfg.ServerURL)
	status.Enabled = true
	status.Issuer = issuer
	status.JWKSURL = issuer + "/.well-known/jwks.json"
	status.Algorithm = idtoken.Algorithm
	status.TokenTTLSeconds = int(idtoken.TTL / time.Second)

	keys, err := s.tokens.Keys(now)
	if err != nil {
		return status, err
	}
	status.Keys = keys
	for _, key := range keys {
		if key.Active() {
			status.ActiveKeyID = key.KID
		}
	}
	return status, nil
}
