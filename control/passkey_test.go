package control

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/go-webauthn/webauthn/protocol"
	"tailscale.com/tailcfg"

	"github.com/xunara-net/xunara-server/identity"
)

// The control tests speak to the HTTP surface, so the relying party is a
// loopback origin: the test client speaks plain http, and Secure cookies would
// not survive that.
const (
	testPasskeyRPID   = "localhost"
	testPasskeyOrigin = "http://localhost:8080"
)

func testPasskeyConfig() *identity.PasskeyConfig {
	return &identity.PasskeyConfig{
		DisplayName: "Xunara Test",
		RPID:        testPasskeyRPID,
		Origins:     []string{testPasskeyOrigin},
	}
}

// newPasskeyClient is a browser-like client: a cookie jar keeps the ceremony
// and session cookies across requests, and redirects are reported, not
// followed.
func newPasskeyClient(t *testing.T) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("creating cookie jar: %v", err)
	}
	return &http.Client{
		Jar:           jar,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// postJSONRequest performs a JSON POST and returns the response (body still
// open, closed at cleanup).
func postJSONRequest(t *testing.T, client *http.Client, rawURL string, body []byte, csrf string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, rawURL, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if csrf != "" {
		req.Header.Set("X-CSRF-Token", csrf)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", rawURL, err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

// readBody reads a response body for assertions.
func readBody(t *testing.T, resp *http.Response) []byte {
	t.Helper()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading body: %v", err)
	}
	return raw
}

// passkeyLocalLogin signs in through the built-in local provider (the sign-in
// page is a chooser once passkey sign-in is enabled, so the password form is
// submitted explicitly).
func passkeyLocalLogin(t *testing.T, client *http.Client, baseURL, returnTo string) {
	t.Helper()
	resp := submitLocalLogin(t, client, baseURL, returnTo)
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != returnTo {
		t.Fatalf("local login = %d %q, want 302 %q", resp.StatusCode, resp.Header.Get("Location"), returnTo)
	}
}

// sessionCookieFromJar returns the browser's session token.
func sessionCookieFromJar(t *testing.T, client *http.Client, baseURL string) string {
	t.Helper()
	u, err := url.Parse(baseURL)
	if err != nil {
		t.Fatalf("parsing %s: %v", baseURL, err)
	}
	for _, c := range client.Jar.Cookies(u) {
		if c.Name == sessionCookieName {
			return c.Value
		}
	}
	t.Fatalf("no %s cookie in the jar", sessionCookieName)
	return ""
}

// registerPasskey runs the console registration ceremony and returns the
// stored credential.
func registerPasskey(t *testing.T, s *Server, hs *httptest.Server, client *http.Client, authenticator *softwareAuthenticator, name string) identity.Passkey {
	t.Helper()
	token := sessionCookieFromJar(t, client, hs.URL)
	csrf := csrfTokenFor(token)

	begin := postJSONRequest(t, client, hs.URL+"/console/passkeys/begin", []byte("{}"), csrf)
	if begin.StatusCode != http.StatusOK {
		t.Fatalf("POST /console/passkeys/begin = %d (%s)", begin.StatusCode, readBody(t, begin))
	}
	options := decodeJSON[struct {
		Options protocol.CredentialCreation `json:"options"`
	}](t, readBody(t, begin)).Options
	if options.Response.Challenge == nil {
		t.Fatal("begin returned no challenge")
	}

	credential := authenticator.creationBody(t, testPasskeyRPID, testPasskeyOrigin, &options)
	body := append([]byte(`{"name":`+fmt.Sprintf("%q", name)+`,"credential":`), credential...)
	body = append(body, '}')

	finish := postJSONRequest(t, client, hs.URL+"/console/passkeys/finish", body, csrf)
	if finish.StatusCode != http.StatusOK {
		t.Fatalf("POST /console/passkeys/finish = %d (%s)", finish.StatusCode, readBody(t, finish))
	}

	passkeys := s.identity.ListPasskeys(sessionUserID(t, s, token))
	if len(passkeys) == 0 {
		t.Fatal("registration succeeded but no passkey is stored")
	}
	return passkeys[len(passkeys)-1]
}

// sessionUserID resolves a session token to its user on the server.
func sessionUserID(t *testing.T, s *Server, token string) tailcfg.UserID {
	t.Helper()
	session, err := s.identity.GetSessionByToken(token)
	if err != nil {
		t.Fatalf("session %q is not valid: %v", token, err)
	}
	return session.UserID
}

// TestPasskeyRegisterAndLoginFlow walks the full browser flow: sign in, add a
// passkey in the console, then sign in with it from a fresh browser.
func TestPasskeyRegisterAndLoginFlow(t *testing.T) {
	s := newServerWithConfig(t, Config{ServerURL: testPasskeyOrigin, Passkeys: testPasskeyConfig()})
	hs := newTestHTTPServer(t, s)

	client := newPasskeyClient(t)

	// With passkey sign-in enabled the page offers both the password form
	// and the passkey button.
	resp := getRequest(t, client, hs.URL+"/login", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /login = %d, want 200", resp.StatusCode)
	}
	page := bodyString(t, resp)
	if !strings.Contains(page, "Sign in with a passkey") || !strings.Contains(page, `name="password"`) {
		t.Fatalf("sign-in page does not offer both methods:\n%s", page)
	}
	if !strings.Contains(page, "navigator.credentials.get") {
		t.Fatalf("sign-in page is missing the WebAuthn script:\n%s", page)
	}

	passkeyLocalLogin(t, client, hs.URL, "/console/passkeys")
	authenticator := newSoftwareAuthenticator(t)
	registered := registerPasskey(t, s, hs, client, authenticator, "Test Key")

	// The console lists the label and never the credential material.
	resp = getRequest(t, client, hs.URL+"/console/passkeys", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /console/passkeys = %d, want 200", resp.StatusCode)
	}
	if page := bodyString(t, resp); !strings.Contains(page, "Test Key") || !strings.Contains(page, "navigator.credentials.create") {
		t.Fatalf("console page does not list the passkey with its script:\n%s", page)
	}

	// A fresh browser (no session) signs in with the passkey.
	login := newPasskeyClient(t)
	begin := postJSONRequest(t, login, hs.URL+"/passkey/login/begin", []byte("{}"), "")
	if begin.StatusCode != http.StatusOK {
		t.Fatalf("POST /passkey/login/begin = %d (%s)", begin.StatusCode, readBody(t, begin))
	}
	ceremonyCookie := cookieNamed(t, begin, passkeyCookieName)
	if !ceremonyCookie.HttpOnly {
		t.Error("ceremony cookie must be HttpOnly")
	}
	assertionOptions := decodeJSON[struct {
		Options protocol.CredentialAssertion `json:"options"`
	}](t, readBody(t, begin)).Options

	assertion := authenticator.assertionBody(t, testPasskeyRPID, testPasskeyOrigin, &assertionOptions, userHandle(registered.UserID))
	finish := postJSONRequest(t, login, hs.URL+"/passkey/login/finish?return_to=%2Fconsole%2F", assertion, "")
	if finish.StatusCode != http.StatusOK {
		t.Fatalf("POST /passkey/login/finish = %d (%s)", finish.StatusCode, readBody(t, finish))
	}
	redirect := decodeJSON[map[string]string](t, readBody(t, finish))["redirect"]
	if redirect != "/console/" {
		t.Errorf("login redirect = %q, want /console/", redirect)
	}

	token := sessionCookieFromJar(t, login, hs.URL)
	session, err := s.identity.GetSessionByToken(token)
	if err != nil {
		t.Fatalf("passkey login did not create a session: %v", err)
	}
	if session.AuthMethod != "passkey" || session.UserID != registered.UserID {
		t.Errorf("session = %+v, want user %d signed in with passkey", session, registered.UserID)
	}
	if used := s.identity.ListPasskeys(registered.UserID)[0]; used.LastUsedAt.IsZero() {
		t.Error("passkey login did not record LastUsedAt")
	}

	// The challenge is single-use: replaying the same assertion with the
	// ceremony cookie fails even though the body and cookie are intact.
	replayReq, err := http.NewRequest(http.MethodPost, hs.URL+"/passkey/login/finish", bytes.NewReader(assertion))
	if err != nil {
		t.Fatalf("building replay request: %v", err)
	}
	replayReq.Header.Set("Content-Type", "application/json")
	replayReq.AddCookie(ceremonyCookie)
	replayResp, err := login.Do(replayReq)
	if err != nil {
		t.Fatalf("replay POST: %v", err)
	}
	t.Cleanup(func() { replayResp.Body.Close() })
	if replayResp.StatusCode != http.StatusBadRequest {
		t.Errorf("replayed assertion status = %d, want 400", replayResp.StatusCode)
	}

	// Audit: registration, sign-in and session creation are all recorded.
	if _, ok := findAudit(t, s, identity.AuditPasskeyRegistered); !ok {
		t.Error("no passkey.registered audit event")
	}
	var passkeyLogin *identity.AuditEvent
	for _, event := range auditEvents(t, s) {
		if event.Action == identity.AuditLoginSucceeded && strings.Contains(event.Detail, "method=passkey") {
			logged := event
			passkeyLogin = &logged
		}
	}
	if passkeyLogin == nil {
		t.Fatal("no login.succeeded audit event for the passkey method")
	}
	if passkeyLogin.Actor != fmt.Sprintf("user:%d", registered.UserID) {
		t.Errorf("passkey login actor = %q, want the user", passkeyLogin.Actor)
	}
	if _, ok := findAudit(t, s, identity.AuditSessionCreated); !ok {
		t.Error("no session.created audit event")
	}
}

// TestPasskeyLoginRequiresTheStartingBrowser checks the ceremony binding: a
// different browser cannot finish a ceremony it did not start.
func TestPasskeyLoginRequiresTheStartingBrowser(t *testing.T) {
	s := newServerWithConfig(t, Config{ServerURL: testPasskeyOrigin, Passkeys: testPasskeyConfig()})
	hs := newTestHTTPServer(t, s)

	starter := newPasskeyClient(t)
	begin := postJSONRequest(t, starter, hs.URL+"/passkey/login/begin", []byte("{}"), "")
	if begin.StatusCode != http.StatusOK {
		t.Fatalf("POST /passkey/login/begin = %d", begin.StatusCode)
	}
	_ = readBody(t, begin)

	// The assertion body is irrelevant: the missing cookie is rejected before
	// the credential is looked at.
	other := newPasskeyClient(t)
	finish := postJSONRequest(t, other, hs.URL+"/passkey/login/finish", []byte(`{"id":"x","rawId":"x","type":"public-key","response":{}}`), "")
	if finish.StatusCode != http.StatusBadRequest {
		t.Fatalf("finish from another browser = %d, want 400", finish.StatusCode)
	}
	if _, ok := findAudit(t, s, identity.AuditLoginFailed); !ok {
		t.Error("no login.failed audit event for the missing browser binding")
	}
}

// TestPasskeyDisabled checks the fail-closed default: without configuration
// there are no endpoints and no button.
func TestPasskeyDisabled(t *testing.T) {
	s := newTestServer(t)
	hs := newTestHTTPServer(t, s)

	client := newPasskeyClient(t)
	resp := postJSONRequest(t, client, hs.URL+"/passkey/login/begin", []byte("{}"), "")
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("POST /passkey/login/begin without configuration = %d, want 404", resp.StatusCode)
	}

	cookie := loginLocal(t, client, hs.URL, "/console/passkeys")
	resp = getRequest(t, client, hs.URL+"/console/passkeys", cookie)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /console/passkeys = %d, want 200", resp.StatusCode)
	}
	if page := bodyString(t, resp); !strings.Contains(page, "not configured") {
		t.Fatalf("console page does not say passkeys are disabled:\n%s", page)
	}
}

// TestPasskeyDeleteOnlyOwnCredentials checks that a user cannot delete another
// account's passkey by guessing its ID.
func TestPasskeyDeleteOnlyOwnCredentials(t *testing.T) {
	s := newServerWithConfig(t, Config{ServerURL: testPasskeyOrigin, Passkeys: testPasskeyConfig()})
	hs := newTestHTTPServer(t, s)

	client := newPasskeyClient(t)
	passkeyLocalLogin(t, client, hs.URL, "/console/passkeys")
	registered := registerPasskey(t, s, hs, client, newSoftwareAuthenticator(t), "Alice Key")

	// A second account with its own session tries to delete Alice's passkey.
	bob := identity.User{LoginName: "bob@example.com", DisplayName: "Bob"}
	if err := s.identity.CreateUser(&bob); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	_, token, err := s.identity.CreateSession(identity.NewSessionOptions{
		UserID:     bob.ID,
		AuthMethod: "local",
		TTL:        time.Hour,
	})
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	resp := postForm(t, client, hs.URL+"/console/passkeys/"+registered.ID+"/delete",
		url.Values{"csrf": {csrfTokenFor(token)}},
		&http.Cookie{Name: sessionCookieName, Value: token})
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("cross-account delete = %d, want 404", resp.StatusCode)
	}
	if got := s.identity.ListPasskeys(registered.UserID); len(got) != 1 {
		t.Fatalf("Alice's passkey was removed by another account: %v", got)
	}

	// The owner can delete it, and the deletion is audited.
	ownerToken := sessionCookieFromJar(t, client, hs.URL)
	resp = postForm(t, client, hs.URL+"/console/passkeys/"+registered.ID+"/delete",
		url.Values{"csrf": {csrfTokenFor(ownerToken)}},
		&http.Cookie{Name: sessionCookieName, Value: ownerToken})
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("owner delete = %d, want 302", resp.StatusCode)
	}
	if got := s.identity.ListPasskeys(registered.UserID); len(got) != 0 {
		t.Fatalf("passkey still stored after delete: %v", got)
	}
	if _, ok := findAudit(t, s, identity.AuditPasskeyDeleted); !ok {
		t.Error("no passkey.deleted audit event")
	}
}

// softwareAuthenticator is a minimal ES256 authenticator: it answers
// registration and assertion ceremonies exactly as a platform passkey would
// (the same helper the identity tests use, adapted to raw JSON bodies).
type softwareAuthenticator struct {
	key          *ecdsa.PrivateKey
	credentialID []byte
	signCount    uint32
}

func newSoftwareAuthenticator(t *testing.T) *softwareAuthenticator {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating authenticator key: %v", err)
	}
	return &softwareAuthenticator{key: key, credentialID: []byte("control-credential-1")}
}

func passkeyB64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func (a *softwareAuthenticator) coseKey(t *testing.T) []byte {
	t.Helper()
	x := a.key.PublicKey.X.FillBytes(make([]byte, 32))
	y := a.key.PublicKey.Y.FillBytes(make([]byte, 32))
	raw, err := cbor.Marshal(map[int]any{1: 2, 3: -7, -1: 1, -2: x, -3: y})
	if err != nil {
		t.Fatalf("encoding COSE key: %v", err)
	}
	return raw
}

func (a *softwareAuthenticator) authData(t *testing.T, rpID string, flags byte, attested bool) []byte {
	t.Helper()
	rpIDHash := sha256.Sum256([]byte(rpID))
	out := append([]byte{}, rpIDHash[:]...)
	out = append(out, flags)
	out = binary.BigEndian.AppendUint32(out, a.signCount)
	if !attested {
		return out
	}
	out = append(out, make([]byte, 16)...) // AAGUID
	out = binary.BigEndian.AppendUint16(out, uint16(len(a.credentialID)))
	out = append(out, a.credentialID...)
	return append(out, a.coseKey(t)...)
}

func (a *softwareAuthenticator) clientData(t *testing.T, kind, challenge, origin string) []byte {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"type":        kind,
		"challenge":   challenge,
		"origin":      origin,
		"crossOrigin": false,
	})
	if err != nil {
		t.Fatalf("encoding client data: %v", err)
	}
	return raw
}

// creationBody answers a registration ceremony with the JSON the endpoints
// accept.
func (a *softwareAuthenticator) creationBody(t *testing.T, rpID, origin string, options *protocol.CredentialCreation) []byte {
	t.Helper()
	data := a.clientData(t, "webauthn.create", passkeyB64(options.Response.Challenge), origin)
	attObj, err := cbor.Marshal(map[string]any{
		"fmt":      "none",
		"attStmt":  map[string]any{},
		"authData": a.authData(t, rpID, 0x01|0x04|0x40, true), // UP | UV | AT
	})
	if err != nil {
		t.Fatalf("encoding attestation object: %v", err)
	}
	raw, err := json.Marshal(map[string]any{
		"id":    passkeyB64(a.credentialID),
		"rawId": passkeyB64(a.credentialID),
		"type":  "public-key",
		"response": map[string]any{
			"clientDataJSON":    passkeyB64(data),
			"attestationObject": passkeyB64(attObj),
		},
	})
	if err != nil {
		t.Fatalf("encoding registration body: %v", err)
	}
	return raw
}

// assertionBody answers a login ceremony.
func (a *softwareAuthenticator) assertionBody(t *testing.T, rpID, origin string, options *protocol.CredentialAssertion, userHandle []byte) []byte {
	t.Helper()
	a.signCount++
	data := a.clientData(t, "webauthn.get", passkeyB64(options.Response.Challenge), origin)
	authData := a.authData(t, rpID, 0x01|0x04, false) // UP | UV

	digest := sha256.Sum256(data)
	signed := append(append([]byte{}, authData...), digest[:]...)
	hashed := sha256.Sum256(signed)
	signature, err := ecdsa.SignASN1(rand.Reader, a.key, hashed[:])
	if err != nil {
		t.Fatalf("signing assertion: %v", err)
	}

	raw, err := json.Marshal(map[string]any{
		"id":    passkeyB64(a.credentialID),
		"rawId": passkeyB64(a.credentialID),
		"type":  "public-key",
		"response": map[string]any{
			"clientDataJSON":    passkeyB64(data),
			"authenticatorData": passkeyB64(authData),
			"signature":         passkeyB64(signature),
			"userHandle":        passkeyB64(userHandle),
		},
	})
	if err != nil {
		t.Fatalf("encoding assertion body: %v", err)
	}
	return raw
}

// userHandle mirrors the adapter's stable per-user handle.
func userHandle(userID tailcfg.UserID) []byte {
	var handle [8]byte
	binary.BigEndian.PutUint64(handle[:], uint64(userID))
	return handle[:]
}
