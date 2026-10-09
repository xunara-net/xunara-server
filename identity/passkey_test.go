package identity

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/go-webauthn/webauthn/protocol"
)

// softwareAuthenticator is a minimal ES256 authenticator: it registers one
// credential and answers assertions exactly as a platform passkey would, so
// the ceremony logic (and the library's verification) is exercised without a
// browser.
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
	return &softwareAuthenticator{key: key, credentialID: []byte("credential-1")}
}

// coseKey renders the public key as a COSE EC2 key, the encoding a
// registration response carries.
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

// authData renders authenticator data: RP ID hash, flags, counter and, for a
// registration, the attested credential.
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

// clientData renders the collected client data for a ceremony.
func clientData(t *testing.T, kind, challenge, origin string) []byte {
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

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// creationRequest answers a registration ceremony.
func (a *softwareAuthenticator) creationRequest(t *testing.T, rpID, origin string, options *protocol.CredentialCreation) *http.Request {
	t.Helper()
	data := clientData(t, "webauthn.create", b64(options.Response.Challenge), origin)
	attObj, err := cbor.Marshal(map[string]any{
		"fmt":      "none",
		"attStmt":  map[string]any{},
		"authData": a.authData(t, rpID, 0x01|0x04|0x40, true), // UP | UV | AT
	})
	if err != nil {
		t.Fatalf("encoding attestation object: %v", err)
	}
	return jsonRequest(t, map[string]any{
		"id":    b64(a.credentialID),
		"rawId": b64(a.credentialID),
		"type":  "public-key",
		"response": map[string]any{
			"clientDataJSON":    b64(data),
			"attestationObject": b64(attObj),
		},
	})
}

// assertionRequest answers a login ceremony.
func (a *softwareAuthenticator) assertionRequest(t *testing.T, rpID, origin string, options *protocol.CredentialAssertion, userHandle []byte) *http.Request {
	t.Helper()
	a.signCount++
	data := clientData(t, "webauthn.get", b64(options.Response.Challenge), origin)
	authData := a.authData(t, rpID, 0x01|0x04, false) // UP | UV

	digest := sha256.Sum256(data)
	signed := append(append([]byte{}, authData...), digest[:]...)
	hashed := sha256.Sum256(signed)
	signature, err := ecdsa.SignASN1(rand.Reader, a.key, hashed[:])
	if err != nil {
		t.Fatalf("signing assertion: %v", err)
	}

	return jsonRequest(t, map[string]any{
		"id":    b64(a.credentialID),
		"rawId": b64(a.credentialID),
		"type":  "public-key",
		"response": map[string]any{
			"clientDataJSON":    b64(data),
			"authenticatorData": b64(authData),
			"signature":         b64(signature),
			"userHandle":        b64(userHandle),
		},
	})
}

// jsonRequest wraps a body as the POST request the library parses.
func jsonRequest(t *testing.T, body any) *http.Request {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("encoding response: %v", err)
	}
	return httptest.NewRequest("POST", "/", bytes.NewReader(raw))
}

// userHandle is the opaque WebAuthn handle of a user, mirroring the adapter.
func userHandle(user User) []byte {
	var handle [8]byte
	binary.BigEndian.PutUint64(handle[:], uint64(user.ID))
	return handle[:]
}

// testPasskeyService returns a service configured for the test domain.
func testPasskeyService(t *testing.T, store Store) *PasskeyService {
	t.Helper()
	svc, err := NewPasskeyService(store, PasskeyConfig{
		DisplayName: "Xunara Test",
		RPID:        "login.example.com",
		Origins:     []string{"https://login.example.com"},
	})
	if err != nil {
		t.Fatalf("NewPasskeyService: %v", err)
	}
	return svc
}

// TestPasskeyConfigValidation checks the fail-closed startup rules.
func TestPasskeyConfigValidation(t *testing.T) {
	store := openTestStore(t)

	valid := PasskeyConfig{RPID: "login.example.com", Origins: []string{"https://login.example.com"}}
	if err := valid.Validate(); err != nil {
		t.Fatalf("Validate(valid): %v", err)
	}
	if _, err := NewPasskeyService(store, valid); err != nil {
		t.Fatalf("NewPasskeyService(valid): %v", err)
	}

	cases := []struct {
		name string
		cfg  PasskeyConfig
	}{
		{"no RP ID", PasskeyConfig{Origins: []string{"https://login.example.com"}}},
		{"RP ID is an IP address", PasskeyConfig{RPID: "192.168.1.10", Origins: []string{"http://192.168.1.10:8080"}}},
		{"RP ID with a scheme", PasskeyConfig{RPID: "https://login.example.com", Origins: []string{"https://login.example.com"}}},
		{"no origins", PasskeyConfig{RPID: "login.example.com"}},
		{"origin with a path", PasskeyConfig{RPID: "login.example.com", Origins: []string{"https://login.example.com/console"}}},
		{"origin outside the RP ID", PasskeyConfig{RPID: "login.example.com", Origins: []string{"https://attacker.example"}}},
		{"plain http outside loopback", PasskeyConfig{RPID: "login.example.com", Origins: []string{"http://login.example.com"}}},
		{"unknown user verification", PasskeyConfig{
			RPID: "login.example.com", Origins: []string{"https://login.example.com"},
			UserVerification: protocol.UserVerificationRequirement("sometimes"),
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewPasskeyService(store, tc.cfg); err == nil {
				t.Fatal("NewPasskeyService accepted an invalid configuration")
			}
		})
	}

	// http is allowed for loopback, where browsers accept it.
	loopback := PasskeyConfig{RPID: "localhost", Origins: []string{"http://localhost:8080"}}
	if err := loopback.Validate(); err != nil {
		t.Errorf("Validate(loopback): %v", err)
	}
	if _, err := NewPasskeyService(store, loopback); err != nil {
		t.Errorf("NewPasskeyService(loopback): %v", err)
	}
}

// TestPasskeyRegisterAndLogin runs both ceremonies end to end, including the
// browser binding, single use, and the persisted sign counter.
func TestPasskeyRegisterAndLogin(t *testing.T) {
	store := openTestStore(t)
	svc := testPasskeyService(t, store)

	alice := User{LoginName: "alice@example.com", DisplayName: "Alice"}
	if err := store.CreateUser(&alice); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	authenticator := newSoftwareAuthenticator(t)
	initiatingID := passkeyTestSessionID(t, store, alice)

	creation, ceremonyID, browserSecret, err := svc.BeginRegistration(alice)
	if err != nil {
		t.Fatalf("BeginRegistration: %v", err)
	}
	if creation == nil || ceremonyID == "" || browserSecret == "" {
		t.Fatalf("BeginRegistration returned %v / %q / %q", creation, ceremonyID, browserSecret)
	}

	// A guessed ceremony ID or a missing browser binding cannot finish.
	if _, err := svc.FinishRegistration(ceremonyID, "not-the-secret", alice, initiatingID, "Laptop",
		authenticator.creationRequest(t, "login.example.com", "https://login.example.com", creation)); !errors.Is(err, ErrPasskeyCeremonyNotFound) {
		t.Errorf("FinishRegistration with a wrong browser binding = %v", err)
	}

	passkey, err := svc.FinishRegistration(ceremonyID, browserSecret, alice, initiatingID, "Laptop",
		authenticator.creationRequest(t, "login.example.com", "https://login.example.com", creation))
	if err != nil {
		t.Fatalf("FinishRegistration: %v", err)
	}
	if passkey.ID == "" || passkey.UserID != alice.ID || passkey.Name != "Laptop" {
		t.Fatalf("registered passkey = %+v", passkey)
	}
	if stored, ok := store.GetPasskeyByCredentialID(authenticator.credentialID); !ok || stored.ID != passkey.ID {
		t.Fatal("the passkey was not stored under its credential ID")
	}

	// The challenge response is single use.
	if _, err := svc.FinishRegistration(ceremonyID, browserSecret, alice, initiatingID, "Laptop",
		authenticator.creationRequest(t, "login.example.com", "https://login.example.com", creation)); !errors.Is(err, ErrPasskeyCeremonyConsumed) {
		t.Errorf("replayed registration = %v, want ErrPasskeyCeremonyConsumed", err)
	}

	// A ceremony belongs to the account that started it. Another account
	// cannot finish it (and the attempt burns it rather than leaving it for
	// replay).
	bob := User{LoginName: "bob@example.com"}
	if err := store.CreateUser(&bob); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	stolenCreation, stolenID, stolenSecret, err := svc.BeginRegistration(alice)
	if err != nil {
		t.Fatalf("BeginRegistration: %v", err)
	}
	if _, err := svc.FinishRegistration(stolenID, stolenSecret, bob, initiatingID, "Stolen",
		authenticator.creationRequest(t, "login.example.com", "https://login.example.com", stolenCreation)); !errors.Is(err, ErrPasskeyCeremonyNotFound) {
		t.Errorf("FinishRegistration by another user = %v", err)
	}
	if _, err := svc.FinishRegistration(stolenID, stolenSecret, alice, initiatingID, "Laptop",
		authenticator.creationRequest(t, "login.example.com", "https://login.example.com", stolenCreation)); !errors.Is(err, ErrPasskeyCeremonyConsumed) {
		t.Errorf("ceremony survived a foreign finish attempt: %v", err)
	}

	// A registration ceremony cannot be used to log in, and vice versa.
	assertion, loginID, loginSecret, err := svc.BeginLogin()
	if err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}
	if assertion == nil || assertion.Response.Challenge == nil {
		t.Fatalf("BeginLogin returned %+v", assertion)
	}
	if _, _, err := svc.FinishLogin(loginID, "not-the-secret",
		authenticator.assertionRequest(t, "login.example.com", "https://login.example.com", assertion, userHandle(alice))); !errors.Is(err, ErrPasskeyCeremonyNotFound) {
		t.Errorf("FinishLogin with a wrong browser binding = %v", err)
	}

	user, used, err := svc.FinishLogin(loginID, loginSecret,
		authenticator.assertionRequest(t, "login.example.com", "https://login.example.com", assertion, userHandle(alice)))
	if err != nil {
		t.Fatalf("FinishLogin: %v", err)
	}
	if user.ID != alice.ID || user.LoginName != alice.LoginName {
		t.Errorf("FinishLogin signed in %+v, want alice", user)
	}
	if used.ID != passkey.ID {
		t.Errorf("FinishLogin used passkey %q, want %q", used.ID, passkey.ID)
	}
	stored, _ := store.GetPasskeyByCredentialID(authenticator.credentialID)
	if stored.Credential.Authenticator.SignCount != authenticator.signCount {
		t.Errorf("stored sign count = %d, want %d", stored.Credential.Authenticator.SignCount, authenticator.signCount)
	}
	if stored.LastUsedAt.IsZero() {
		t.Error("FinishLogin did not record the last use")
	}

	if _, _, err := svc.FinishLogin(loginID, loginSecret,
		authenticator.assertionRequest(t, "login.example.com", "https://login.example.com", assertion, userHandle(alice))); !errors.Is(err, ErrPasskeyCeremonyConsumed) {
		t.Errorf("replayed login = %v, want ErrPasskeyCeremonyConsumed", err)
	}
}

// TestPasskeyLoginUnknownCredential checks that an assertion for a credential
// this server never registered is refused.
func TestPasskeyLoginUnknownCredential(t *testing.T) {
	store := openTestStore(t)
	svc := testPasskeyService(t, store)

	assertion, ceremonyID, browserSecret, err := svc.BeginLogin()
	if err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}
	stranger := newSoftwareAuthenticator(t)
	if _, _, err := svc.FinishLogin(ceremonyID, browserSecret,
		stranger.assertionRequest(t, "login.example.com", "https://login.example.com", assertion, []byte("12345678"))); err == nil {
		t.Error("an unknown credential was accepted")
	}
}

// TestPasskeyLoginWrongRPID checks that an assertion collected for another
// relying party does not verify.
func TestPasskeyLoginWrongRPID(t *testing.T) {
	store := openTestStore(t)
	svc := testPasskeyService(t, store)

	alice := User{LoginName: "alice@example.com"}
	if err := store.CreateUser(&alice); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	authenticator := newSoftwareAuthenticator(t)
	initiatingID := passkeyTestSessionID(t, store, alice)

	creation, ceremonyID, browserSecret, err := svc.BeginRegistration(alice)
	if err != nil {
		t.Fatalf("BeginRegistration: %v", err)
	}
	if _, err := svc.FinishRegistration(ceremonyID, browserSecret, alice, initiatingID, "Laptop",
		authenticator.creationRequest(t, "login.example.com", "https://login.example.com", creation)); err != nil {
		t.Fatalf("FinishRegistration: %v", err)
	}

	assertion, loginID, loginSecret, err := svc.BeginLogin()
	if err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}
	if _, _, err := svc.FinishLogin(loginID, loginSecret,
		authenticator.assertionRequest(t, "other.example.com", "https://login.example.com", assertion, userHandle(alice))); err == nil {
		t.Error("an assertion for another RP ID was accepted")
	}
}

// TestPasskeyLoginForeignOrigin checks that an assertion collected at another
// origin does not verify even when the RP ID matches.
func TestPasskeyLoginForeignOrigin(t *testing.T) {
	store := openTestStore(t)
	svc := testPasskeyService(t, store)

	alice := User{LoginName: "alice@example.com"}
	if err := store.CreateUser(&alice); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	authenticator := newSoftwareAuthenticator(t)
	initiatingID := passkeyTestSessionID(t, store, alice)

	creation, ceremonyID, browserSecret, err := svc.BeginRegistration(alice)
	if err != nil {
		t.Fatalf("BeginRegistration: %v", err)
	}
	if _, err := svc.FinishRegistration(ceremonyID, browserSecret, alice, initiatingID, "Laptop",
		authenticator.creationRequest(t, "login.example.com", "https://login.example.com", creation)); err != nil {
		t.Fatalf("FinishRegistration: %v", err)
	}

	assertion, loginID, loginSecret, err := svc.BeginLogin()
	if err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}
	if _, _, err := svc.FinishLogin(loginID, loginSecret,
		authenticator.assertionRequest(t, "login.example.com", "https://evil.example.com", assertion, userHandle(alice))); err == nil {
		t.Error("an assertion from a foreign origin was accepted")
	}
}

// TestPasskeyHandleIsStable checks that the user handle is the stable,
// opaque account handle the authenticator round-trips.
func TestPasskeyHandleIsStable(t *testing.T) {
	svc := testPasskeyService(t, openTestStore(t))
	user := User{ID: 42, LoginName: "alice@example.com"}

	first := svc.newUser(user, nil).WebAuthnID()
	second := svc.newUser(user, nil).WebAuthnID()
	if len(first) != 8 || !bytes.Equal(first, second) {
		t.Errorf("handles = %v / %v, want a stable 8-byte value", first, second)
	}
	if binary.BigEndian.Uint64(first) != uint64(user.ID) {
		t.Errorf("handle %v does not encode the user ID", first)
	}
	if new(big.Int).SetBytes(first).Int64() <= 0 {
		t.Error("handle is not a positive opaque value")
	}
}
