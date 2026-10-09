package control

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"tailscale.com/tailcfg"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/xunara-net/xunara-server/identity"
	"github.com/xunara-net/xunara-server/state"
)

func TestAccountPasskeysHumanCSRFAndTenant(t *testing.T) {
	server := newServerWithConfig(t, Config{ServerURL: testPasskeyOrigin, Passkeys: testPasskeyConfig()})
	cookie, token := seedUserSession(t, server, state.DefaultUserID)
	_, apiToken := seedAPIKey(t, server)
	foreignTenant := newTestServer(t)
	for _, operation := range []struct{ method, path string }{
		{http.MethodGet, "/api/v1/account/passkeys"},
		{http.MethodPost, "/api/v1/account/passkeys/begin"},
		{http.MethodPost, "/api/v1/account/passkeys/finish"},
		{http.MethodDelete, "/api/v1/account/passkeys/missing"},
	} {
		if response := accountRequest(t, server, operation.method, operation.path, nil, nil, nil); response.Code != http.StatusUnauthorized {
			t.Fatalf("anonymous operation: %s, %d", operation.path, response.Code)
		}
		if response := accountRequest(t, foreignTenant, operation.method, operation.path, nil, cookie, nil); response.Code != http.StatusUnauthorized {
			t.Fatal("foreign tenant accepted a session with the same numeric user ID")
		}
		response := accountRequest(t, server, operation.method, operation.path, nil, cookie, map[string]string{
			"Authorization": "Bearer " + apiToken, "X-CSRF-Token": csrfTokenFor(token),
		})
		if response.Code != http.StatusForbidden || !strings.Contains(response.Body.String(), "HUMAN_SESSION_REQUIRED") {
			t.Fatal("service identity was allowed to manage a passkey")
		}
		if operation.method != http.MethodGet {
			for _, csrf := range []string{"", "wrong"} {
				response := accountRequest(t, server, operation.method, operation.path, nil, cookie, map[string]string{"X-CSRF-Token": csrf})
				if response.Code != http.StatusForbidden || !strings.Contains(response.Body.String(), "CSRF_INVALID") {
					t.Fatal("passkey write accepted invalid CSRF")
				}
			}
		}
	}
}

func TestAccountPasskeysMemberAccess(t *testing.T) {
	server := newServerWithConfig(t, Config{ServerURL: testPasskeyOrigin, Passkeys: testPasskeyConfig()})
	memberID := seedRoleUser(t, server, "member", identity.RoleMember)
	cookie, token := seedUserSession(t, server, memberID)
	for _, operation := range []struct{ method, path string }{
		{http.MethodGet, "/api/v1/account/passkeys"},
		{http.MethodPost, "/api/v1/account/passkeys/begin"},
	} {
		response := accountRequest(t, server, operation.method, operation.path, "{}", cookie, map[string]string{"X-CSRF-Token": csrfTokenFor(token)})
		if response.Code != http.StatusOK {
			t.Fatalf("member cannot manage own credentials: %d", response.Code)
		}
	}
}

func TestPasskeyJSONLoginSnapshot(t *testing.T) {
	server := newServerWithConfig(t, Config{ServerURL: testPasskeyOrigin, Passkeys: testPasskeyConfig()})
	httpServer := newTestHTTPServer(t, server)
	client := newPasskeyClient(t)
	passkeyLocalLogin(t, client, httpServer.URL, "/security")
	authenticator := newSoftwareAuthenticator(t)
	registered := registerPasskey(t, server, httpServer, client, authenticator, "中文标签")
	loginClient := newPasskeyClient(t)
	begin := postJSONRequest(t, loginClient, httpServer.URL+"/api/v1/auth/passkey/begin", []byte("{}"), "")
	options := decodeJSON[struct{ Options protocol.CredentialAssertion }](t, readBody(t, begin)).Options
	assertion := authenticator.assertionBody(t, testPasskeyRPID, testPasskeyOrigin, &options, userHandle(registered.UserID))
	finish := postJSONRequest(t, loginClient, httpServer.URL+"/api/v1/auth/passkey/finish", assertion, "")
	if finish.StatusCode != http.StatusOK || finish.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("JSON login failed: %d", finish.StatusCode)
	}
	payload := decodeJSON[struct {
		Authenticated bool
		Session       struct {
			AuthMethod string `json:"auth_method"`
		}
		User struct{ ID uint64 }
	}](t, readBody(t, finish))
	if !payload.Authenticated || payload.Session.AuthMethod != "passkey" || payload.User.ID != uint64(registered.UserID) {
		t.Fatal("passkey login did not return the shared session snapshot")
	}
	list := getRequest(t, loginClient, httpServer.URL+"/api/v1/account/passkeys", nil)
	body := readBody(t, list)
	if !strings.Contains(string(body), "last_used_at") || strings.Contains(string(body), "credential") || strings.Contains(string(body), "PublicKey") {
		t.Fatal("list has an invalid presentation contract")
	}
	for _, secret := range []string{sessionCookieFromJar(t, loginClient, httpServer.URL), identity.HashSecret(sessionCookieFromJar(t, loginClient, httpServer.URL))} {
		if strings.Contains(string(body), secret) {
			t.Fatal("list exposed a session secret")
		}
	}
	if len(server.store.ListNodes()) != 0 || len(server.identity.ListPendingDeviceAuthorizations(time.Now())) != 0 {
		t.Fatal("human passkey login created a machine authorization")
	}
}

func TestAccountPasskeyInputsAndDeprecatedConsoleAliases(t *testing.T) {
	server := newServerWithConfig(t, Config{ServerURL: testPasskeyOrigin, Passkeys: testPasskeyConfig()})
	cookie, token := seedUserSession(t, server, state.DefaultUserID)
	headers := map[string]string{"X-CSRF-Token": csrfTokenFor(token)}
	for _, body := range []any{
		`{}`, `{"credential":null}`, `{"credential":{},"user_id":2}`, `{"credential":{}} {}`,
		map[string]any{"name": strings.Repeat("长", 65), "credential": map[string]any{}},
		map[string]any{"name": "bad\x00name", "credential": map[string]any{}},
		map[string]any{"name": "valid", "credential": map[string]any{"id": strings.Repeat("x", 65<<10)}},
	} {
		if response := accountRequest(t, server, http.MethodPost, "/api/v1/account/passkeys/finish", body, cookie, headers); response.Code != http.StatusBadRequest {
			t.Fatalf("invalid registration body: %d", response.Code)
		}
	}
	if response := accountRequest(t, server, http.MethodPost, "/api/v1/account/passkeys/finish", "{}", cookie, map[string]string{
		"X-CSRF-Token": csrfTokenFor(token), "Content-Type": "text/plain",
	}); response.Code != http.StatusUnsupportedMediaType {
		t.Fatal("registration accepted a non-JSON body")
	}
	for _, path := range []string{"/console/passkeys/begin", "/console/passkeys/finish", "/console/passkeys/old/delete"} {
		response := accountRequest(t, server, http.MethodPost, path, "{}", cookie, headers)
		if response.Header().Get("Deprecation") == "" || !strings.Contains(response.Header().Get("Link"), `rel="deprecation"`) {
			t.Fatalf("old alias has no migration warning: %s", path)
		}
		if response := accountRequest(t, server, http.MethodPost, path, "{}", cookie, nil); response.Code != http.StatusForbidden {
			t.Fatal("compatibility alias bypassed CSRF")
		}
	}
}

func TestDeprecatedPasskeyAliasesUseAccountCore(t *testing.T) {
	server := newServerWithConfig(t, Config{ServerURL: testPasskeyOrigin, Passkeys: testPasskeyConfig()})
	httpServer := newTestHTTPServer(t, server)
	client := newPasskeyClient(t)
	passkeyLocalLogin(t, client, httpServer.URL, "/security")
	csrf := csrfTokenFor(sessionCookieFromJar(t, client, httpServer.URL))
	begin := postJSONRequest(t, client, httpServer.URL+"/console/passkeys/begin", []byte("{}"), csrf)
	if begin.StatusCode != http.StatusOK || begin.Header.Get("Deprecation") == "" {
		t.Fatal("legacy begin has no compatible response or migration notice")
	}
	options := decodeJSON[struct{ Options protocol.CredentialCreation }](t, readBody(t, begin)).Options
	authenticator := newSoftwareAuthenticator(t)
	credential := authenticator.creationBody(t, testPasskeyRPID, testPasskeyOrigin, &options)
	body, err := json.Marshal(map[string]any{"name": "旧地址迁移测试", "credential": json.RawMessage(credential)})
	if err != nil {
		t.Fatal(err)
	}
	finish := postJSONRequest(t, client, httpServer.URL+"/console/passkeys/finish", body, csrf)
	if finish.StatusCode != http.StatusOK || finish.Header.Get("Deprecation") == "" {
		t.Fatal("legacy registration did not preserve its response status")
	}
	payload := decodeJSON[struct{ Passkey struct{ ID, Name string } }](t, readBody(t, finish))
	if payload.Passkey.ID == "" || payload.Passkey.Name != "旧地址迁移测试" {
		t.Fatal("legacy registration did not preserve its JSON shape")
	}
	deleted := postForm(t, client, httpServer.URL+"/console/passkeys/"+payload.Passkey.ID+"/delete", url.Values{"csrf": {csrf}}, nil)
	if deleted.StatusCode != http.StatusFound || deleted.Header.Get("Location") != "/security" || deleted.Header.Get("Deprecation") == "" {
		t.Fatal("legacy form did not use account deletion and the new UI")
	}
	actions := map[string]int{}
	for _, event := range server.identity.ListAudit(0) {
		actions[event.Action]++
	}
	if actions[identity.AuditPasskeyRegistered] != 1 || actions[identity.AuditPasskeyDeleted] != 1 {
		t.Fatal("compatibility aliases duplicated account audits")
	}
}

type failingAccountPasskeysStore struct {
	identity.Store
	listError    error
	deleteError  error
	beforeChange func()
}

func (store *failingAccountPasskeysStore) ListAccountPasskeys(ctx context.Context, userID tailcfg.UserID) ([]identity.Passkey, error) {
	if store.listError != nil {
		return nil, store.listError
	}
	return store.Store.ListAccountPasskeys(ctx, userID)
}

func (store *failingAccountPasskeysStore) DeleteAccountPasskey(ctx context.Context, userID tailcfg.UserID, initiatingID, passkeyID string) error {
	if store.beforeChange != nil {
		store.beforeChange()
	}
	if store.deleteError != nil {
		return store.deleteError
	}
	return store.Store.DeleteAccountPasskey(ctx, userID, initiatingID, passkeyID)
}

func TestAccountPasskeyReadAndWriteFailure(t *testing.T) {
	server := newTestServer(t)
	cookie, token := seedUserSession(t, server, state.DefaultUserID)
	current, _ := server.identity.GetSessionByToken(token)
	store := &failingAccountPasskeysStore{Store: server.identity, listError: errors.New("injected read failure"), deleteError: errors.New("injected write failure")}
	server.identity = store
	response := accountRequest(t, server, http.MethodGet, "/api/v1/account/passkeys", nil, cookie, nil)
	if response.Code != http.StatusInternalServerError || strings.Contains(response.Body.String(), `"passkeys":[]`) {
		t.Fatal("read failure was shown as an empty success")
	}
	headers := map[string]string{"X-CSRF-Token": csrfTokenFor(token)}
	response = accountRequest(t, server, http.MethodDelete, "/api/v1/account/passkeys/missing", nil, cookie, headers)
	if response.Code != http.StatusInternalServerError {
		t.Fatal("delete failure was ignored")
	}
	store.deleteError = nil
	store.beforeChange = func() {
		if err := store.Store.RevokeSession(current.ID, "test"); err != nil {
			t.Fatal(err)
		}
	}
	response = accountRequest(t, server, http.MethodDelete, "/api/v1/account/passkeys/missing", nil, cookie, headers)
	if response.Code != http.StatusUnauthorized || !strings.Contains(response.Body.String(), "SESSION_CHANGED") {
		t.Fatal("revoked initiating session was accepted after authentication")
	}
}

func TestPasskeyLoginRateLimit(t *testing.T) {
	server := newServerWithConfig(t, Config{ServerURL: testPasskeyOrigin, Passkeys: testPasskeyConfig()})
	for attempt := 0; attempt < 20; attempt++ {
		if response := accountRequest(t, server, http.MethodPost, "/api/v1/auth/passkey/begin", "{}", nil, nil); response.Code != http.StatusOK {
			t.Fatal("login begin failed before the rate limit")
		}
	}
	response := accountRequest(t, server, http.MethodPost, "/api/v1/auth/passkey/begin", "{}", nil, nil)
	if response.Code != http.StatusTooManyRequests || response.Header().Get("Retry-After") == "" {
		t.Fatal("passkey login did not enforce a persistent rate limit")
	}
}
