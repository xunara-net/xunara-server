package control

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/xunara-net/xunara-server/identity"
	"github.com/xunara-net/xunara-server/plan"
)

const platformTestOrigin = "https://admin.test"
const platformTestRecovery = "platform-test-recovery"

func platformAuthRouter(test *testing.T) *Router {
	test.Helper()
	server := newServerWithConfig(test, Config{AllowLocalLogin: true})
	router, err := NewRouter(RouterConfig{
		Orgs:               []OrgSite{{ID: "acme", Server: server, Domains: []string{"admin.test"}}},
		PlatformAdminToken: platformTestRecovery,
		PlatformAuth:       &PlatformAuthConfig{Path: filepath.Join(test.TempDir(), "platform.db"), Origin: platformTestOrigin},
	})
	if err != nil {
		test.Fatal(err)
	}
	test.Cleanup(func() { router.Close() })
	return router
}

func platformAuthRequest(test *testing.T, handler http.Handler, method, path, token string, body any, cookie *http.Cookie) *httptest.ResponseRecorder {
	test.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		test.Fatal(err)
	}
	request := httptest.NewRequest(method, platformTestOrigin+path, bytes.NewReader(raw))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", platformTestOrigin)
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	if cookie != nil {
		request.AddCookie(cookie)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder
}

func platformLoginToken(test *testing.T, router *Router) string {
	test.Helper()
	recorder := platformAuthRequest(test, router.Handler(), "POST", platformAuthPath+"/token", platformTestRecovery, map[string]any{}, nil)
	return platformSessionToken(test, recorder)
}

func platformSessionToken(test *testing.T, recorder *httptest.ResponseRecorder) string {
	test.Helper()
	if recorder.Code != 200 {
		test.Fatalf("login %d: %s", recorder.Code, recorder.Body.String())
	}
	var result struct {
		Token     string    `json:"token"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &result); err != nil {
		test.Fatal(err)
	}
	if result.Token == "" || result.Token == platformTestRecovery || time.Until(result.ExpiresAt) > platformSessionTTL+time.Second {
		test.Fatal("login leaked recovery credential or invalid lifetime")
	}
	return result.Token
}

func registerPlatformKey(test *testing.T, router *Router, token, name string, authenticator *softwareAuthenticator) identity.Passkey {
	test.Helper()
	recorder := platformAuthRequest(test, router.Handler(), "POST", platformAuthPath+"/passkeys/begin", token, map[string]any{}, nil)
	if recorder.Code != 200 {
		test.Fatalf("begin registration %d: %s", recorder.Code, recorder.Body.String())
	}
	var result struct {
		Options protocol.CredentialCreation `json:"options"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &result); err != nil {
		test.Fatal(err)
	}
	cookies := recorder.Result().Cookies()
	if len(cookies) != 1 || !cookies[0].Secure || !cookies[0].HttpOnly || cookies[0].Domain != "" || cookies[0].Path != platformAuthPath {
		test.Fatal("platform challenge browser binding is not isolated")
	}
	body := authenticator.creationBody(test, "admin.test", platformTestOrigin, &result.Options)
	recorder = platformAuthRequest(test, router.Handler(), "POST", platformAuthPath+"/passkeys/finish", token, map[string]any{"name": name, "credential": json.RawMessage(body)}, cookies[0])
	if recorder.Code != 201 {
		test.Fatalf("finish registration %d: %s", recorder.Code, recorder.Body.String())
	}
	key, ok := router.platformAuth.store.GetPasskeyByCredentialID(authenticator.credentialID)
	if !ok || key.Name != name {
		test.Fatal("key was not saved")
	}
	return key
}

func platformPasskeyLogin(test *testing.T, router *Router, key identity.Passkey, authenticator *softwareAuthenticator) (*httptest.ResponseRecorder, []byte, *http.Cookie) {
	test.Helper()
	recorder := platformAuthRequest(test, router.Handler(), "POST", platformAuthPath+"/passkey/begin", "", map[string]any{}, nil)
	if recorder.Code != 200 {
		test.Fatalf("begin login %d: %s", recorder.Code, recorder.Body.String())
	}
	var result struct {
		Options protocol.CredentialAssertion `json:"options"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &result); err != nil {
		test.Fatal(err)
	}
	cookie := recorder.Result().Cookies()[0]
	handle := append(append([]byte(identity.PlatformPasskeyNamespace), 0), userHandle(key.UserID)...)
	body := authenticator.assertionBody(test, "admin.test", platformTestOrigin, &result.Options, handle)
	return platformAuthRequest(test, router.Handler(), "POST", platformAuthPath+"/passkey/finish", "", json.RawMessage(body), cookie), body, cookie
}

func TestPlatformPasskeysMultiplePersistentAndUnbindRevokes(test *testing.T) {
	router := platformAuthRouter(test)
	token := platformLoginToken(test, router)
	first, second := newSoftwareAuthenticator(test), newSoftwareAuthenticator(test)
	second.credentialID = []byte("second-platform-key")
	firstKey := registerPlatformKey(test, router, token, "手机", first)
	secondKey := registerPlatformKey(test, router, token, "安全密钥", second)
	keys, err := router.platformAuth.store.ListAccountPasskeys(test.Context(), firstKey.UserID)
	if err != nil || len(keys) != 2 {
		test.Fatal("multiple keys were not retained", err)
	}
	for _, key := range keys {
		if _, ok := router.serverFor("acme").identity.GetPasskeyByCredentialID(key.Credential.ID); ok {
			test.Fatal("platform credential leaked into tenant")
		}
	}
	login, assertion, cookie := platformPasskeyLogin(test, router, firstKey, first)
	passkeyToken := platformSessionToken(test, login)
	if recorder := platformAuthRequest(test, router.Handler(), "GET", "/api/platform/v1/users", passkeyToken, nil, nil); recorder.Code != 200 {
		test.Fatal("passkey session cannot administer")
	}
	if recorder := platformAuthRequest(test, router.Handler(), "POST", platformAuthPath+"/passkey/finish", "", json.RawMessage(assertion), cookie); recorder.Code != 400 {
		test.Fatal("login challenge replay accepted")
	}
	peer, err := openPlatformAuthentication(test.Context(), PlatformAuthConfig{Path: router.cfg.PlatformAuth.Path, Origin: platformTestOrigin})
	if err != nil {
		test.Fatal(err)
	}
	defer peer.database.Close()
	if _, err := peer.store.GetSessionByToken(passkeyToken); err != nil {
		test.Fatal("durable session did not survive a new connection", err)
	}
	if keys, err := peer.store.ListAccountPasskeys(test.Context(), firstKey.UserID); err != nil || len(keys) != 2 {
		test.Fatal("keys are not durable", err)
	}
	recorder := platformAuthRequest(test, router.Handler(), "DELETE", platformAuthPath+"/passkeys/"+firstKey.ID, token, nil, nil)
	if recorder.Code != 200 {
		test.Fatalf("unbind %d %s", recorder.Code, recorder.Body.String())
	}
	if _, err := peer.store.GetSessionByToken(passkeyToken); err == nil {
		test.Fatal("unbound passkey session is still usable across connections")
	}
	if _, err := peer.store.GetSessionByToken(token); err != nil {
		test.Fatal("recovery session was revoked")
	}
	login, _, _ = platformPasskeyLogin(test, router, firstKey, first)
	if login.Code != 400 {
		test.Fatal("unbound key still logs in")
	}
	login, _, _ = platformPasskeyLogin(test, router, secondKey, second)
	platformSessionToken(test, login)
}

func TestPlatformAuthenticationRejectsTenantAndOrigin(test *testing.T) {
	router := platformAuthRouter(test)
	tenant := router.serverFor("acme")
	_, tenantToken, err := tenant.identity.CreateSession(identity.NewSessionOptions{UserID: 1, AuthMethod: "passkey"})
	if err != nil {
		test.Fatal(err)
	}
	if recorder := platformAuthRequest(test, router.Handler(), "GET", "/api/platform/v1/users", tenantToken, nil, nil); recorder.Code != 401 {
		test.Fatal("tenant session obtained platform access")
	}
	if recorder := platformAuthRequest(test, router.Handler(), "POST", platformAuthPath+"/token", tenantToken, nil, nil); recorder.Code != 401 {
		test.Fatal("tenant session bootstrapped a platform identity")
	}
	token := platformLoginToken(test, router)
	for _, invalid := range []string{"", "https://other.test"} {
		request := httptest.NewRequest("POST", platformTestOrigin+platformAuthPath+"/passkeys/begin", strings.NewReader("{}"))
		request.Header.Set("Authorization", "Bearer "+token)
		request.Header.Set("Origin", invalid)
		recorder := httptest.NewRecorder()
		router.Handler().ServeHTTP(recorder, request)
		if recorder.Code != 403 {
			test.Fatal("foreign/missing origin accepted")
		}
	}
	request := httptest.NewRequest("GET", "https://other.test/api/platform/v1/users", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	recorder := httptest.NewRecorder()
	router.Handler().ServeHTTP(recorder, request)
	if recorder.Code != 401 {
		test.Fatal("administrator session accepted on a different host")
	}
	if recorder := platformAuthRequest(test, router.Handler(), "GET", platformAuthPath+"/passkeys", platformTestRecovery, nil, nil); recorder.Code != 403 {
		test.Fatal("permanent service credential treated as human session")
	}
	if recorder := platformAuthRequest(test, router.Handler(), "POST", platformAuthPath+"/logout", token, nil, nil); recorder.Code != 204 {
		test.Fatal("logout failed", recorder.Body.String())
	}
	if recorder := platformAuthRequest(test, router.Handler(), "GET", "/api/platform/v1/users", token, nil, nil); recorder.Code != 401 {
		test.Fatal("signed-out administrator session still works")
	}
}

func TestPlatformPasskeyRegistrationInitiatingSessionAndReplay(test *testing.T) {
	router := platformAuthRouter(test)
	token, otherToken := platformLoginToken(test, router), platformLoginToken(test, router)
	recorder := platformAuthRequest(test, router.Handler(), "POST", platformAuthPath+"/passkeys/begin", token, nil, nil)
	if recorder.Code != 200 {
		test.Fatal(recorder.Body.String())
	}
	var options struct {
		Options protocol.CredentialCreation `json:"options"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &options); err != nil {
		test.Fatal(err)
	}
	cookie := recorder.Result().Cookies()[0]
	credential := newSoftwareAuthenticator(test).creationBody(test, "admin.test", platformTestOrigin, &options.Options)
	body := map[string]any{"name": "平台密钥", "credential": json.RawMessage(credential)}
	for _, wrongCookie := range []*http.Cookie{nil, {Name: platformCeremonyCookie, Value: strings.Replace(cookie.Value, ".", ".wrong", 1)}} {
		if answer := platformAuthRequest(test, router.Handler(), "POST", platformAuthPath+"/passkeys/finish", token, body, wrongCookie); answer.Code != 400 {
			test.Fatal("wrong browser accepted")
		}
	}
	if answer := platformAuthRequest(test, router.Handler(), "POST", platformAuthPath+"/passkeys/finish", otherToken, body, cookie); answer.Code != 400 {
		test.Fatal("another initiating session accepted")
	}
	if answer := platformAuthRequest(test, router.Handler(), "POST", platformAuthPath+"/passkeys/finish", token, body, cookie); answer.Code != 201 {
		test.Fatal("valid registration failed", answer.Body.String())
	}
	if answer := platformAuthRequest(test, router.Handler(), "POST", platformAuthPath+"/passkeys/finish", token, body, cookie); answer.Code != 400 {
		test.Fatal("registration replay accepted")
	}
}

func TestPlatformPasskeyRejectsTenantUserHandle(test *testing.T) {
	router := platformAuthRouter(test)
	token := platformLoginToken(test, router)
	authenticator := newSoftwareAuthenticator(test)
	key := registerPlatformKey(test, router, token, "平台", authenticator)
	begin := platformAuthRequest(test, router.Handler(), "POST", platformAuthPath+"/passkey/begin", "", nil, nil)
	if begin.Code != 200 {
		test.Fatal(begin.Body.String())
	}
	var options struct {
		Options protocol.CredentialAssertion `json:"options"`
	}
	if err := json.Unmarshal(begin.Body.Bytes(), &options); err != nil {
		test.Fatal(err)
	}
	// 即使签名和 credential ID 都正确，旧租户八字节 handle 也不能成为平台身份。
	assertion := authenticator.assertionBody(test, "admin.test", platformTestOrigin, &options.Options, userHandle(key.UserID))
	answer := platformAuthRequest(test, router.Handler(), "POST", platformAuthPath+"/passkey/finish", "", json.RawMessage(assertion), begin.Result().Cookies()[0])
	if answer.Code != 400 {
		test.Fatal("tenant user handle accepted for platform credential", answer.Code)
	}
	valid, _, _ := platformPasskeyLogin(test, router, key, authenticator)
	platformSessionToken(test, valid)
}

func TestPlatformCreateUserRolesAndIsolation(test *testing.T) {
	router := platformAuthRouter(test)
	token := platformLoginToken(test, router)
	for _, role := range []string{"member", "admin", "owner"} {
		body := map[string]any{"login": "new-" + role, "display_name": "新成员", "email": "member@example.com", "role": role, "password": "correct horse battery staple"}
		recorder := platformAuthRequest(test, router.Handler(), "POST", "/api/platform/v1/organizations/acme/users", token, body, nil)
		if recorder.Code != 201 {
			test.Fatalf("create %d: %s", recorder.Code, recorder.Body.String())
		}
		user, ok := router.serverFor("acme").identity.GetUserByLoginName("new-" + role)
		if !ok || string(user.Role) != role {
			test.Fatal("role not persisted")
		}
		credential, ok := router.serverFor("acme").identity.GetLocalCredential(user.ID)
		if !ok || !identity.VerifyPassword(credential.PasswordHash, "correct horse battery staple") {
			test.Fatal("new account cannot authenticate")
		}
		if sessions, _ := router.serverFor("acme").identity.ListAccountSessions(test.Context(), user.ID); len(sessions) != 0 {
			test.Fatal("platform silently logged in as the created user")
		}
		if _, ok := router.platformAuth.store.GetUserByLoginName(user.LoginName); ok {
			test.Fatal("created tenant member became platform admin")
		}
		if strings.Contains(recorder.Body.String(), "password") || strings.Contains(recorder.Body.String(), "correct horse") {
			test.Fatal("password returned")
		}
		if repeat := platformAuthRequest(test, router.Handler(), "POST", "/api/platform/v1/organizations/acme/users", token, body, nil); repeat.Code != 409 {
			test.Fatal("duplicate login accepted")
		}
	}
}

func TestPlatformCreateUserQuotaAndValidation(test *testing.T) {
	router := platformAuthRouter(test)
	server := router.serverFor("acme")
	body := map[string]any{"login": "limited-member", "role": "member", "password": "correct horse battery staple"}
	server.setPlanSource(func(string) plan.Plan { return plan.DefaultCatalog().Default() })
	if answer := platformAuthRequest(test, router.Handler(), "POST", "/api/platform/v1/organizations/acme/users", platformTestRecovery, body, nil); answer.Code != 403 || !strings.Contains(answer.Body.String(), "USER_LIMIT_REACHED") {
		test.Fatal("free member quota bypassed", answer.Code, answer.Body.String())
	}
	server.setPlanSource(nil)
	for _, invalid := range []map[string]any{
		{"login": "bad login", "role": "member", "password": "correct horse battery staple"},
		{"login": "valid", "role": "platform-admin", "password": "correct horse battery staple"},
		{"login": "valid", "role": "member", "password": "short"},
		{"login": "valid", "role": "member", "password": "correct horse battery staple", "email": "not-an-email"},
	} {
		if answer := platformAuthRequest(test, router.Handler(), "POST", "/api/platform/v1/organizations/acme/users", platformTestRecovery, invalid, nil); answer.Code != 400 {
			test.Fatal("invalid member accepted", answer.Code, answer.Body.String())
		}
	}
	if answer := platformAuthRequest(test, router.Handler(), "POST", "/api/platform/v1/organizations/unknown/users", platformTestRecovery, body, nil); answer.Code != 404 {
		test.Fatal("unknown network accepted")
	}
	server.localLogin = false
	if answer := platformAuthRequest(test, router.Handler(), "POST", "/api/platform/v1/organizations/acme/users", platformTestRecovery, body, nil); answer.Code != 403 {
		test.Fatal("password-disabled network accepted local account")
	}
	if len(server.identity.ListUsers()) != 1 {
		test.Fatal("rejected creation changed users")
	}
}

func TestPlatformAuthenticationRateLimitAndExpiredSession(test *testing.T) {
	router := platformAuthRouter(test)
	session, expiredToken, err := router.platformAuth.store.CreatePlatformSession(test.Context(), time.Nanosecond, identity.SessionClientInfo{})
	if err != nil {
		test.Fatal(err)
	}
	if !session.ExpiresAt.Before(time.Now()) {
		test.Fatal("fixture not expired")
	}
	if answer := platformAuthRequest(test, router.Handler(), "GET", "/api/platform/v1/users", expiredToken, nil, nil); answer.Code != 401 {
		test.Fatal("expired administrator session still works")
	}
	for attempt := 0; attempt < 20; attempt++ {
		if answer := platformAuthRequest(test, router.Handler(), "POST", platformAuthPath+"/token", "wrong", nil, nil); answer.Code != 401 {
			test.Fatal("unexpected rate admission", answer.Code)
		}
	}
	if answer := platformAuthRequest(test, router.Handler(), "POST", platformAuthPath+"/token", platformTestRecovery, nil, nil); answer.Code != 429 {
		test.Fatal("rate limit not enforced")
	}
}

func TestPlatformAuthenticationRecentVerificationAndStorageFailure(test *testing.T) {
	router := platformAuthRouter(test)
	token := platformLoginToken(test, router)
	session, err := router.platformAuth.store.GetSessionByToken(token)
	if err != nil {
		test.Fatal(err)
	}
	if _, err := router.platformAuth.database.DB().Exec("UPDATE sessions SET created_at = ? WHERE id = ?", time.Now().Add(-16*time.Minute).UnixNano(), session.ID); err != nil {
		test.Fatal(err)
	}
	if answer := platformAuthRequest(test, router.Handler(), "POST", platformAuthPath+"/passkeys/begin", token, nil, nil); answer.Code != 403 || !strings.Contains(answer.Body.String(), "PLATFORM_REAUTH_REQUIRED") {
		test.Fatal("old authentication permitted binding", answer.Code)
	}
	if answer := platformAuthRequest(test, router.Handler(), "POST", platformAuthPath+"/logout", token, nil, nil); answer.Code != 204 {
		test.Fatal("recent-auth gate blocked logout")
	}
	token = platformLoginToken(test, router)
	if err := router.platformAuth.database.Close(); err != nil {
		test.Fatal(err)
	}
	if answer := platformAuthRequest(test, router.Handler(), "GET", "/api/platform/v1/users", token, nil, nil); answer.Code != 503 {
		test.Fatal("storage outage was hidden as invalid identity", answer.Code)
	}
	if answer := platformAuthRequest(test, router.Handler(), "POST", platformAuthPath+"/token", platformTestRecovery, nil, nil); answer.Code != 503 {
		test.Fatal("rate storage outage admitted login", answer.Code)
	}
}
