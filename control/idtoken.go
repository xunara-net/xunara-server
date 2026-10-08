package control

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4/jwt"
	"tailscale.com/tailcfg"

	"github.com/xunara-net/xunara-server/identity"
	"github.com/xunara-net/xunara-server/idtoken"
	"github.com/xunara-net/xunara-server/state"
)

// This file implements workload identity federation: the inner endpoint nodes
// call to prove their tailnet identity to a third party, plus the public
// metadata a relying party needs to verify the result.
//
// The official client runs `tailscale id-token <aud>`, which sends
// tailcfg.TokenRequest to POST /machine/id-token over its Noise session
// (reference/tailscale/ipn/localapi/localapi.go:serveIDToken). The response is
// a compact JWS whose claim set tailcfg.TokenResponse documents; the claim
// names and their meanings are copied from there, not invented here.
//
// Scope and trust: the issuer is this control plane's own URL. Any registered
// node may obtain a token for any audience, but only ever for *itself* — the
// request carries the node key, the Noise session carries the machine key, and
// both must belong to the same stored node (getAndValidateNode). There is no
// grant system yet deciding which nodes may federate (that belongs in the
// policy file, like upstream's `tsidp` capability), so an operator should
// only configure a relying party to trust this issuer when every node in the
// tailnet is meant to be able to authenticate as itself.

// maxIDTokenAudienceLen bounds the client-supplied audience. Audiences are
// identifiers (a URL, service account, or cloud provider ARN), not documents;
// the cap keeps a node from making the control plane sign megabytes of claims.
const maxIDTokenAudienceLen = 256

// idTokenClaims is the claim set of an issued token, in the shape
// tailcfg.TokenResponse documents: the registered claims from [jwt.Claims]
// plus the Tailscale-specific ones.
type idTokenClaims struct {
	jwt.Claims
	// Key is the node's public key ("nodekey:...").
	Key string `json:"key"`
	// Addresses are the node's tailnet IPs as /32 and /128 prefixes.
	Addresses []netip.Prefix `json:"addresses"`
	// NodeID is the stable node ID.
	NodeID tailcfg.NodeID `json:"nid"`
	// Node is the node's MagicDNS name, same value as the subject.
	Node string `json:"node"`
	// Domain is the tailnet name, in MapResponse.Domain's format. Empty when
	// the deployment runs without MagicDNS.
	Domain string `json:"domain,omitempty"`
	// Tags are "<domain>:<tag>" for a tagged node; empty for a user-owned
	// node. Always present so a relying party can key on the claim.
	Tags []string `json:"tags"`
	// User and UID identify the owning human, and are omitted for tagged
	// nodes, which belong to their tags rather than to a person (AGENTS.md
	// section 5).
	User string         `json:"user,omitempty"`
	UID  tailcfg.UserID `json:"uid,omitempty"`
}

// handleIDToken implements POST /machine/id-token inside a Noise session.
func (ns *noiseServer) handleIDToken(w http.ResponseWriter, req *http.Request) {
	tokens := ns.server.tokens
	if tokens == nil {
		httpError(w, NewHTTPError(http.StatusNotImplemented, "identity tokens are not supported by this server", nil))
		return
	}

	var tokenReq tailcfg.TokenRequest
	if err := json.NewDecoder(req.Body).Decode(&tokenReq); err != nil {
		httpError(w, err)
		return
	}
	if ns.rejectUnsupported(w, tokenReq.CapVersion, tokenReq.NodeKey) {
		return
	}

	audience := strings.TrimSpace(tokenReq.Audience)
	if audience == "" {
		httpError(w, NewHTTPError(http.StatusBadRequest, "no audience requested", nil))
		return
	}
	if len(audience) > maxIDTokenAudienceLen {
		httpError(w, NewHTTPError(http.StatusBadRequest, "audience is too long", nil))
		return
	}

	node, err := ns.getAndValidateNode(tailcfg.MapRequest{NodeKey: tokenReq.NodeKey})
	if err != nil {
		httpError(w, err)
		return
	}

	now := time.Now().UTC()
	// Rate limit before signing: a node may only ever get a token for itself,
	// but nothing stops it from asking thousands of times a second (spec
	// section 28). A rejection is not audited - a looping client would
	// otherwise be able to flood the audit log.
	allowed, retryAfter, err := ns.server.store.AllowRate(
		idTokenRateScope(node, audience), ns.server.cfg.IDTokenRateLimit, idTokenRateWindow, now)
	if err != nil {
		ns.server.log.Error("rate limiting an identity token request", "node", node.StableID, "err", err)
		httpError(w, NewHTTPError(http.StatusInternalServerError, "internal error", nil))
		return
	}
	if !allowed {
		w.Header().Set("Retry-After", strconv.Itoa(retryAfterSeconds(retryAfter)))
		httpError(w, NewHTTPError(http.StatusTooManyRequests, "identity token rate limit exceeded", nil))
		return
	}

	claims, err := ns.server.idTokenClaims(node, audience, now)
	if err != nil {
		ns.server.log.Error("building identity token claims", "node", node.StableID, "err", err)
		httpError(w, NewHTTPError(http.StatusInternalServerError, "internal error", nil))
		return
	}
	signed, err := tokens.Sign(now, claims)
	if err != nil {
		ns.server.log.Error("signing identity token", "node", node.StableID, "err", err)
		httpError(w, NewHTTPError(http.StatusInternalServerError, "internal error", nil))
		return
	}

	// The token is a bearer credential: it is never logged or audited. The
	// node and the audience it asked for are what an incident review needs.
	ns.server.audit(nodeActor(node), identity.AuditIDTokenIssued, nodeTarget(node),
		"aud="+truncateClean(audience, maxIDTokenAudienceLen))
	ns.server.log.Debug("issued identity token", "node", node.StableID, "aud", truncateClean(audience, maxIDTokenAudienceLen))

	writeJSON(w, http.StatusOK, tailcfg.TokenResponse{IDToken: signed})
}

// idTokenRateScope names the limiter bucket: one node asking for one
// audience. Node IDs are server-local, so two organizations sharing a
// database could not collide, and audiences are bounded at
// [maxIDTokenAudienceLen].
func idTokenRateScope(node state.Node, audience string) string {
	return "id-token:" + strconv.FormatUint(uint64(node.ID), 10) + ":" + audience
}

// retryAfterSeconds rounds a wait up to whole seconds for the Retry-After
// header; a client that retries exactly then must not be refused again.
func retryAfterSeconds(d time.Duration) int {
	seconds := int(d / time.Second)
	if d%time.Second != 0 || seconds == 0 {
		seconds++
	}
	return seconds
}

// idTokenClaims builds the claims for one node. It fails only when a fresh
// token identifier cannot be generated, which is a fatal system condition.
func (s *Server) idTokenClaims(node state.Node, audience string, now time.Time) (idTokenClaims, error) {
	jti, err := newTokenID()
	if err != nil {
		return idTokenClaims{}, err
	}

	domain := strings.Trim(s.cfg.Domain, ".")
	name := node.FQDN(domain)
	claims := idTokenClaims{
		Claims: jwt.Claims{
			Audience:  jwt.Audience{audience},
			Expiry:    jwt.NewNumericDate(now.Add(idtoken.TTL)),
			ID:        jti,
			IssuedAt:  jwt.NewNumericDate(now),
			Issuer:    idtoken.TrimIssuer(s.cfg.ServerURL),
			NotBefore: jwt.NewNumericDate(now),
			Subject:   name,
		},
		Key:       node.NodeKey.String(),
		Addresses: append([]netip.Prefix{}, nodePrefixes(node)...),
		NodeID:    tailcfg.NodeID(node.ID),
		Node:      name,
		Domain:    domain,
		Tags:      []string{},
	}

	// Tags are reported inside the tailnet's namespace, e.g.
	// "example.com:tag:server" for node tag "tag:server" (tailcfg.TokenResponse).
	for _, tag := range node.Tags {
		if domain != "" {
			claims.Tags = append(claims.Tags, domain+":"+tag)
		} else {
			claims.Tags = append(claims.Tags, tag)
		}
	}

	// A tagged node belongs to its tags, not to a human: user and uid are
	// omitted, and the tags above are the identity a relying party sees.
	if len(node.Tags) > 0 {
		return claims, nil
	}

	// The "emailish" user identifier: <provider>:<login name>, using the same
	// provider the registration response reports for this user (the identity
	// link that authenticated them; the built-in local provider is "local").
	// A user is never identified by a bare email address.
	profile := s.UserProfile(node.UserID)
	provider := state.DefaultProvider
	if links := s.identity.ListExternalIdentities(node.UserID); len(links) > 0 {
		provider = links[0].ProviderID
	}
	claims.User = provider + ":" + profile.LoginName
	claims.UID = node.UserID
	return claims, nil
}

// newTokenID returns a random JWT identifier.
func newTokenID() (string, error) {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf[:]), nil
}

// handleJWKS implements GET /.well-known/jwks.json: the public keys a relying
// party verifies identity tokens with. It is deliberately unauthenticated —
// it publishes public keys only.
func (s *Server) handleJWKS(w http.ResponseWriter, req *http.Request) {
	if s.tokens == nil {
		http.NotFound(w, req)
		return
	}

	set, err := s.tokens.JWKS(time.Now().UTC())
	if err != nil {
		// The key material never reaches the response; the operator gets the
		// reason through the log.
		s.log.Error("building identity-token JWKS", "err", err)
		httpError(w, NewHTTPError(http.StatusInternalServerError, "internal error", nil))
		return
	}

	// Retired keys stay published for idtoken.KeyGrace, so a relying party that
	// caches this response for less than that never misses a rotation.
	w.Header().Set("Cache-Control", "public, max-age=300")
	writeJSON(w, http.StatusOK, set)
}

// handleOpenIDConfiguration implements GET /.well-known/openid-configuration,
// the discovery document relying parties and cloud provider setup tools fetch
// to find the JWKS.
//
// It advertises exactly what this deployment is: an issuer of node identity
// tokens. There is no authorization endpoint, token endpoint or userinfo
// endpoint, so none is advertised (AGENTS.md section 3: never claim an API
// that does not exist). An RP that requires those endpoints is looking for a
// login provider, which is not what /machine/id-token is for.
func (s *Server) handleOpenIDConfiguration(w http.ResponseWriter, req *http.Request) {
	if s.tokens == nil {
		http.NotFound(w, req)
		return
	}

	issuer := idtoken.TrimIssuer(s.cfg.ServerURL)
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                issuer,
		"jwks_uri":                              issuer + "/.well-known/jwks.json",
		"id_token_signing_alg_values_supported": []string{idtoken.Algorithm},
		"subject_types_supported":               []string{"public"},
		"claims_supported": []string{
			// Registered claims.
			"sub", "aud", "exp", "iat", "iss", "jti", "nbf",
			// Tailscale-specific claims.
			"key", "addresses", "nid", "node", "domain", "tags", "user", "uid",
		},
	})
}
