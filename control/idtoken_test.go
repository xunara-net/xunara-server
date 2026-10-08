package control

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"

	"github.com/xunara-net/xunara-server/identity"
	"github.com/xunara-net/xunara-server/idtoken"
	"github.com/xunara-net/xunara-server/state"
)

// idTokenTestServer builds a server that can issue identity tokens: it needs
// an issuer URL (the relying party's trust anchor) and a MagicDNS domain (the
// namespace the per-node names live in).
func idTokenTestServer(t *testing.T) (*Server, *httptest.Server) {
	t.Helper()

	s := newServerWithConfig(t, Config{
		ServerURL: "https://login.example.com",
		Domain:    "example.com",
	})
	return s, newTestHTTPServer(t, s)
}

// requestIDToken asks the Noise endpoint for a token and returns the response.
func requestIDToken(t *testing.T, client *http.Client, nodeKey key.NodePublic, audience string) (tailcfg.TokenResponse, int) {
	t.Helper()

	body, status := doRaw(t, client, http.MethodPost, "/machine/id-token", tailcfg.TokenRequest{
		CapVersion: tailcfg.CurrentCapabilityVersion,
		NodeKey:    nodeKey,
		Audience:   audience,
	})
	if status != http.StatusOK {
		return tailcfg.TokenResponse{}, status
	}
	return decodeJSON[tailcfg.TokenResponse](t, body), status
}

// requestIDTokenWithHeaders is requestIDToken but exposes the response
// headers, so tests can assert Retry-After on a 429.
func requestIDTokenWithHeaders(t *testing.T, client *http.Client, nodeKey key.NodePublic, audience string) (tailcfg.TokenResponse, int, http.Header) {
	t.Helper()

	raw, err := json.Marshal(tailcfg.TokenRequest{
		CapVersion: tailcfg.CurrentCapabilityVersion,
		NodeKey:    nodeKey,
		Audience:   audience,
	})
	if err != nil {
		t.Fatalf("marshalling the token request: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://xunara.test/machine/id-token", bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("building the token request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("requesting a token: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading the token response: %v", err)
	}
	var token tailcfg.TokenResponse
	if resp.StatusCode == http.StatusOK {
		if err := json.Unmarshal(body, &token); err != nil {
			t.Fatalf("decoding the token response: %v", err)
		}
	}
	return token, resp.StatusCode, resp.Header
}

// getJSON performs an anonymous GET against the public HTTP server.
func getJSON[T any](t *testing.T, url string) (T, http.Header) {
	t.Helper()

	var zero T
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s: status %d", url, resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(&zero); err != nil {
		t.Fatalf("decoding %s: %v", url, err)
	}
	return zero, resp.Header
}

// fetchJWKS retrieves and decodes the public key set.
func fetchJWKS(t *testing.T, baseURL string) jose.JSONWebKeySet {
	t.Helper()

	set, _ := getJSON[jose.JSONWebKeySet](t, baseURL+"/.well-known/jwks.json")
	if len(set.Keys) == 0 {
		t.Fatal("JWKS is empty")
	}
	return set
}

// verifyWithJWKS verifies a token the way a relying party does: parse the
// header, pick the signing key out of the published set, and read the claims.
// It also returns the raw payload for assertions about the wire form.
func verifyWithJWKS(t *testing.T, baseURL, token string) (idTokenClaims, string) {
	t.Helper()

	parsed, err := jwt.ParseSigned(token, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		t.Fatalf("parsing token: %v", err)
	}
	if len(parsed.Headers) != 1 {
		t.Fatalf("token has %d signatures, want 1", len(parsed.Headers))
	}
	header := parsed.Headers[0]
	if header.Algorithm != string(jose.RS256) {
		t.Errorf("token alg = %q, want RS256", header.Algorithm)
	}

	set := fetchJWKS(t, baseURL)
	keys := set.Key(header.KeyID)
	if len(keys) == 0 {
		t.Fatalf("JWKS has no key %q", header.KeyID)
	}
	var claims idTokenClaims
	if err := parsed.Claims(keys[0].Key, &claims); err != nil {
		t.Fatalf("verifying token with JWKS key %q: %v", header.KeyID, err)
	}
	var decoded map[string]any
	if err := parsed.UnsafeClaimsWithoutVerification(&decoded); err != nil {
		t.Fatalf("reading token payload: %v", err)
	}
	payload, err := json.Marshal(decoded)
	if err != nil {
		t.Fatalf("re-encoding token payload: %v", err)
	}
	return claims, string(payload)
}

// TestIDTokenEndpointIssuesVerifiableToken is the end-to-end check a relying
// party performs: fetch the JWKS, verify the signature with it, and read the
// documented claims.
func TestIDTokenEndpointIssuesVerifiableToken(t *testing.T) {
	s, hs := idTokenTestServer(t)

	conn, client, nodeKey := registerNode(t, s, hs, "workload")
	defer conn.Close()

	audience := "https://api.example.com"
	resp, status := requestIDToken(t, client, nodeKey.Public(), audience)
	if status != http.StatusOK {
		t.Fatalf("id-token status = %d, want 200", status)
	}
	if resp.IDToken == "" {
		t.Fatal("id-token response has no token")
	}

	claims, payload := verifyWithJWKS(t, hs.URL, resp.IDToken)
	node := storedNode(t, s, nodeKey.Public())

	// The wire form matters as much as the decoded claims: a single audience
	// is a JSON string (not an array), and the tagged-node claim is always an
	// array so a relying party can key on its presence.
	if !strings.Contains(payload, `"aud":"`+audience+`"`) {
		t.Errorf("payload does not carry a single-string aud: %s", payload)
	}
	if !strings.Contains(payload, `"tags":[]`) {
		t.Errorf("payload does not carry tags as an empty array: %s", payload)
	}

	if got, want := claims.Issuer, "https://login.example.com"; got != want {
		t.Errorf("iss = %q, want %q", got, want)
	}
	if got, want := claims.Subject, "workload.example.com."; got != want {
		t.Errorf("sub = %q, want %q", got, want)
	}
	if got := claims.Node; got != claims.Subject {
		t.Errorf("node = %q, want the subject %q", got, claims.Subject)
	}
	if got, want := claims.Domain, "example.com"; got != want {
		t.Errorf("domain = %q, want %q", got, want)
	}
	if len(claims.Audience) != 1 || claims.Audience[0] != audience {
		t.Errorf("aud = %v, want [%s]", claims.Audience, audience)
	}
	if claims.ID == "" {
		t.Error("jti is empty")
	}
	if claims.IssuedAt == nil || claims.NotBefore == nil || claims.Expiry == nil {
		t.Fatalf("iat/nbf/exp must be present: %+v", claims.Claims)
	}
	issued := claims.IssuedAt.Time()
	if got := claims.Expiry.Time().Sub(issued); got != idtoken.TTL {
		t.Errorf("token lifetime = %v, want %v", got, idtoken.TTL)
	}
	if !claims.NotBefore.Time().Equal(issued) {
		t.Errorf("nbf = %v, want the issue time %v", claims.NotBefore.Time(), issued)
	}
	if skew := time.Since(issued); skew < 0 || skew > time.Minute {
		t.Errorf("token issue time %v is not now (%v)", issued, time.Since(issued))
	}

	if got, want := claims.Key, nodeKey.Public().String(); got != want {
		t.Errorf("key = %q, want %q", got, want)
	}
	if got, want := claims.NodeID, tailcfg.NodeID(node.ID); got != want {
		t.Errorf("nid = %d, want %d", got, want)
	}
	wantPrefixes := []string{node.IPv4.String() + "/32", node.IPv6.String() + "/128"}
	if len(claims.Addresses) != len(wantPrefixes) {
		t.Fatalf("addresses = %v, want %v", claims.Addresses, wantPrefixes)
	}
	for i, want := range wantPrefixes {
		if got := claims.Addresses[i].String(); got != want {
			t.Errorf("addresses[%d] = %q, want %q", i, got, want)
		}
	}

	// A user-owned node is attributed to its human: the local provider's user
	// for the single-user milestone, never a bare email address.
	if got, want := claims.User, identity.LocalProviderID+":"+identity.LocalLoginName; got != want {
		t.Errorf("user = %q, want %q", got, want)
	}
	if got, want := claims.UID, node.UserID; got != want {
		t.Errorf("uid = %d, want %d", got, want)
	}
	if len(claims.Tags) != 0 {
		t.Errorf("tags = %v, want an empty array for a user-owned node", claims.Tags)
	}

	// Issuance is auditable, and the audit record names the audience without
	// ever carrying the bearer token.
	var found bool
	for _, event := range s.identity.ListAudit(0) {
		if event.Action != identity.AuditIDTokenIssued {
			continue
		}
		found = true
		if event.Target != nodeTarget(node) {
			t.Errorf("audit target = %q, want %q", event.Target, nodeTarget(node))
		}
		if event.Detail != "aud="+audience {
			t.Errorf("audit detail = %q, want %q", event.Detail, "aud="+audience)
		}
		if strings.Contains(event.Detail, resp.IDToken) {
			t.Error("audit detail contains the token")
		}
	}
	if !found {
		t.Errorf("no %s audit event was recorded", identity.AuditIDTokenIssued)
	}
}

// TestIDTokenTaggedNode checks the tagged-node claim shape: tags in the
// tailnet namespace, and no human user or uid (AGENTS.md section 5).
func TestIDTokenTaggedNode(t *testing.T) {
	s, hs := idTokenTestServer(t)

	machineKey := key.NewMachine()
	nodeKey := key.NewNode()
	node := state.Node{
		MachineKey: machineKey.Public(),
		NodeKey:    nodeKey.Public(),
		UserID:     state.DefaultUserID,
		Hostname:   "tagged",
		Tags:       []string{"tag:server"},
		Method:     state.RegisterMethodAuthKey,
	}
	if err := s.store.CreateNode(&node); err != nil {
		t.Fatalf("CreateNode: %v", err)
	}

	conn := dialNoise(t, hs, machineKey)
	defer conn.Close()

	resp, status := requestIDToken(t, h2Client(conn), nodeKey.Public(), "https://ci.example.com")
	if status != http.StatusOK {
		t.Fatalf("id-token status = %d, want 200", status)
	}

	claims, payload := verifyWithJWKS(t, hs.URL, resp.IDToken)
	if !strings.Contains(payload, `"tags":["example.com:tag:server"]`) {
		t.Errorf("payload does not carry the namespaced tag: %s", payload)
	}
	if got, want := claims.Tags, []string{"example.com:tag:server"}; len(got) != 1 || got[0] != want[0] {
		t.Errorf("tags = %v, want %v", got, want)
	}
	if claims.User != "" {
		t.Errorf("tagged node has user = %q, want it omitted", claims.User)
	}
	if claims.UID != 0 {
		t.Errorf("tagged node has uid = %d, want it omitted", claims.UID)
	}
	if got, want := claims.Subject, "tagged.example.com."; got != want {
		t.Errorf("sub = %q, want %q", got, want)
	}
}

// TestIDTokenRequestsAreNodeBound checks the two ways a caller might try to
// obtain a token for a node it is not: another node's key on a registered
// session, and an unregistered Noise session.
func TestIDTokenRequestsAreNodeBound(t *testing.T) {
	s, hs := idTokenTestServer(t)

	conn, client, nodeKey := registerNode(t, s, hs, "first")
	defer conn.Close()
	otherConn, otherClient, otherKey := registerNode(t, s, hs, "second")
	defer otherConn.Close()

	if _, status := requestIDToken(t, client, otherKey.Public(), "https://api.example.com"); status != http.StatusNotFound {
		t.Errorf("token for another node's key status = %d, want 404", status)
	}
	if _, status := requestIDToken(t, otherClient, nodeKey.Public(), "https://api.example.com"); status != http.StatusNotFound {
		t.Errorf("token for another node's key status = %d, want 404", status)
	}

	// A Noise session that never registered must not be able to ask for a
	// token with a registered node's key.
	strangerConn := dialNoise(t, hs, key.NewMachine())
	defer strangerConn.Close()
	if _, status := requestIDToken(t, h2Client(strangerConn), nodeKey.Public(), "https://api.example.com"); status != http.StatusNotFound {
		t.Errorf("unregistered session status = %d, want 404", status)
	}
}

// TestIDTokenRejectsBadAudience checks audience validation: it is a required,
// bounded identifier, and the shared version gate still applies.
func TestIDTokenRejectsBadAudience(t *testing.T) {
	s, hs := idTokenTestServer(t)

	conn, client, nodeKey := registerNode(t, s, hs, "audience")
	defer conn.Close()

	for name, audience := range map[string]string{
		"empty":    "",
		"blank":    "   ",
		"too long": strings.Repeat("a", maxIDTokenAudienceLen+1),
	} {
		body, status := doRaw(t, client, http.MethodPost, "/machine/id-token", tailcfg.TokenRequest{
			CapVersion: tailcfg.CurrentCapabilityVersion,
			NodeKey:    nodeKey.Public(),
			Audience:   audience,
		})
		if status != http.StatusBadRequest {
			t.Errorf("%s audience status = %d (%s), want 400", name, status, body)
		}
	}

	if _, status := doRaw(t, client, http.MethodPost, "/machine/id-token", tailcfg.TokenRequest{
		CapVersion: MinSupportedCapabilityVersion - 1,
		NodeKey:    nodeKey.Public(),
		Audience:   "https://api.example.com",
	}); status != http.StatusBadRequest {
		t.Errorf("unsupported version status = %d, want 400", status)
	}
}

// TestIDTokenDisabledWithoutIssuer checks that a deployment with no externally
// reachable URL says so explicitly rather than signing a token with an empty
// issuer.
func TestIDTokenDisabledWithoutIssuer(t *testing.T) {
	s := newServerWithoutIssuer(t)

	hs := newTestHTTPServer(t, s)
	conn, client, nodeKey := registerNode(t, s, hs, "no-issuer")
	defer conn.Close()

	if body, status := doRaw(t, client, http.MethodPost, "/machine/id-token", tailcfg.TokenRequest{
		CapVersion: tailcfg.CurrentCapabilityVersion,
		NodeKey:    nodeKey.Public(),
		Audience:   "https://api.example.com",
	}); status != http.StatusNotImplemented {
		t.Errorf("id-token without issuer status = %d (%s), want 501", status, body)
	}

	// The public metadata does not exist either, so a relying party fails
	// closed instead of trusting an issuer that cannot sign.
	for _, path := range []string{"/.well-known/jwks.json", "/.well-known/openid-configuration"} {
		resp, err := http.Get(hs.URL + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("GET %s status = %d, want 404", path, resp.StatusCode)
		}
	}
}

// newServerWithoutIssuer builds a server with no externally reachable URL,
// hence no identity-token issuer. newServerWithConfig always fills in a URL,
// so this is the one shape tests cannot reach through it.
func newServerWithoutIssuer(t *testing.T) *Server {
	t.Helper()

	s, err := New(Config{StateDir: t.TempDir()})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	// The console needs a signed-in operator; this helper builds the server
	// without the test defaults, so seed the account itself.
	if err := seedTestCredential(s); err != nil {
		t.Fatalf("seeding the test credential: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	s.Start(ctx)
	return s
}

// TestIDTokenJWKSPublishesPublicMaterialOnly checks the JWKS document shape:
// public RSA parameters for each key, and nothing else.
func TestIDTokenJWKSPublishesPublicMaterialOnly(t *testing.T) {
	s, hs := idTokenTestServer(t)

	// Any issuance path creates the keyring; a registered node asking for a
	// token is the one this test would otherwise duplicate.
	conn, client, nodeKey := registerNode(t, s, hs, "jwks")
	defer conn.Close()
	if _, status := requestIDToken(t, client, nodeKey.Public(), "https://api.example.com"); status != http.StatusOK {
		t.Fatalf("id-token status = %d, want 200", status)
	}

	resp, err := http.Get(hs.URL + "/.well-known/jwks.json")
	if err != nil {
		t.Fatalf("GET jwks: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("jwks status = %d, want 200", resp.StatusCode)
	}
	if got := resp.Header.Get("Cache-Control"); got == "" {
		t.Error("jwks response has no Cache-Control header")
	}

	var raw struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		t.Fatalf("decoding jwks: %v", err)
	}
	if len(raw.Keys) != 1 {
		t.Fatalf("jwks has %d keys, want 1", len(raw.Keys))
	}
	entry := raw.Keys[0]
	for _, field := range []string{"n", "e", "kid", "kty", "alg", "use"} {
		if _, ok := entry[field]; !ok {
			t.Errorf("jwks key lacks %q: %v", field, entry)
		}
	}
	for _, field := range []string{"d", "p", "q", "dp", "dq", "qi"} {
		if _, ok := entry[field]; ok {
			t.Errorf("jwks key leaks private field %q", field)
		}
	}
	if entry["alg"] != idtoken.Algorithm || entry["use"] != "sig" {
		t.Errorf("jwks key alg/use = %v/%v, want %s/sig", entry["alg"], entry["use"], idtoken.Algorithm)
	}
}

// TestIDTokenOpenIDConfiguration checks the discovery document: it points at
// the JWKS and claims only the issuer role, not a login provider's endpoints.
func TestIDTokenOpenIDConfiguration(t *testing.T) {
	_, hs := idTokenTestServer(t)

	doc, header := getJSON[map[string]any](t, hs.URL+"/.well-known/openid-configuration")
	if got, want := doc["issuer"], "https://login.example.com"; got != want {
		t.Errorf("issuer = %v, want %v", got, want)
	}
	if got, want := doc["jwks_uri"], "https://login.example.com/.well-known/jwks.json"; got != want {
		t.Errorf("jwks_uri = %v, want %v", got, want)
	}
	algs, ok := doc["id_token_signing_alg_values_supported"].([]any)
	if !ok || len(algs) != 1 || algs[0] != idtoken.Algorithm {
		t.Errorf("id_token_signing_alg_values_supported = %v, want [%s]", doc["id_token_signing_alg_values_supported"], idtoken.Algorithm)
	}
	claimsSupported, ok := doc["claims_supported"].([]any)
	if !ok {
		t.Fatalf("claims_supported = %v, want a list", doc["claims_supported"])
	}
	supported := make(map[string]bool, len(claimsSupported))
	for _, claim := range claimsSupported {
		supported[claim.(string)] = true
	}
	for _, claim := range []string{"sub", "aud", "exp", "iat", "iss", "jti", "nbf", "key", "addresses", "nid", "node", "domain", "tags", "user", "uid"} {
		if !supported[claim] {
			t.Errorf("claims_supported lacks %q", claim)
		}
	}
	for _, endpoint := range []string{"authorization_endpoint", "token_endpoint", "userinfo_endpoint", "registration_endpoint"} {
		if _, ok := doc[endpoint]; ok {
			t.Errorf("discovery document advertises %s, which this server does not implement", endpoint)
		}
	}
	if got := header.Get("Content-Type"); got == "" {
		t.Error("discovery response has no Content-Type")
	}
}

// TestIDTokenRateLimit checks the per (node, audience) fixed window: the limit
// holds, the rejection carries Retry-After, and other nodes/audiences have
// their own buckets (spec section 28).
func TestIDTokenRateLimit(t *testing.T) {
	s := newServerWithConfig(t, Config{
		ServerURL:        "https://login.example.com",
		Domain:           "example.com",
		IDTokenRateLimit: 2,
	})
	hs := newTestHTTPServer(t, s)

	conn, client, nodeKey := registerNode(t, s, hs, "limited")
	defer conn.Close()

	for i := 0; i < 2; i++ {
		if _, status, _ := requestIDTokenWithHeaders(t, client, nodeKey.Public(), "https://api.example.com"); status != http.StatusOK {
			t.Fatalf("token %d status = %d, want 200", i+1, status)
		}
	}
	_, status, header := requestIDTokenWithHeaders(t, client, nodeKey.Public(), "https://api.example.com")
	if status != http.StatusTooManyRequests {
		t.Fatalf("third token status = %d, want 429", status)
	}
	retry, err := strconv.Atoi(header.Get("Retry-After"))
	if err != nil || retry < 1 || retry > 60 {
		t.Errorf("Retry-After = %q, want 1..60 seconds", header.Get("Retry-After"))
	}

	// A different audience and a different node each have their own bucket.
	if _, status, _ := requestIDTokenWithHeaders(t, client, nodeKey.Public(), "https://other.example.com"); status != http.StatusOK {
		t.Errorf("other audience status = %d, want 200", status)
	}
	otherConn, otherClient, otherKey := registerNode(t, s, hs, "unlimited")
	defer otherConn.Close()
	if _, status, _ := requestIDTokenWithHeaders(t, otherClient, otherKey.Public(), "https://api.example.com"); status != http.StatusOK {
		t.Errorf("other node status = %d, want 200", status)
	}
}

// TestIDTokenRateLimitDefaultsAndValidation checks the config surface: zero
// means the default (never "unlimited") and a negative value refuses startup.
func TestIDTokenRateLimitDefaultsAndValidation(t *testing.T) {
	s := newServerWithConfig(t, Config{ServerURL: "https://login.example.com", Domain: "example.com"})
	if got := s.cfg.IDTokenRateLimit; got != DefaultIDTokenRateLimit {
		t.Errorf("default rate limit = %d, want %d", got, DefaultIDTokenRateLimit)
	}

	if _, err := New(Config{ServerURL: "http://login.test", StateDir: t.TempDir(), IDTokenRateLimit: -1}); err == nil {
		t.Error("a negative rate limit was accepted")
	}
}
