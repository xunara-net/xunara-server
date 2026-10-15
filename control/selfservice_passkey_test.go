package control

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/xunara-net/xunara-server/identity"
)

const sharedPasskeyOrigin = "https://app.xunara.test"

func sharedPasskeyRouter(test *testing.T) *Router {
	test.Helper()
	config := identity.PasskeyConfig{DisplayName: "Xunara", RPID: "app.xunara.test", Origins: []string{sharedPasskeyOrigin}}
	prepare := func(server *Server) error {
		service, err := identity.NewPasskeyService(server.identity, config)
		server.passkeys = service
		return err
	}
	router, _ := selfServiceRouterWith(test, selfServiceTestOptions{
		cfg: &SelfServiceConfig{DomainSuffix: "old.example.test", ConsoleURL: sharedPasskeyOrigin}, prepareTenant: prepare,
	})
	if err := prepare(router.serverFor("portal")); err != nil {
		test.Fatal("cannot prepare shared relying party")
	}
	return router
}

func registerSharedPasskey(test *testing.T, router *Router, login string, authenticator *softwareAuthenticator) identity.User {
	test.Helper()
	created := tenantConsoleRequest(test, router, http.MethodPost, selfServiceSignupPath,
		selfServiceRequest{Login: login, Password: "SharedAccount-Strong-2026"})
	if created.Code != http.StatusCreated {
		test.Fatalf("account fixture status: %d", created.Code)
	}
	server := router.serverFor(login)
	user, err := server.identity.LookupUserByLoginName(test.Context(), login)
	if err != nil {
		test.Fatal("account fixture unavailable")
	}
	session, err := server.identity.GetSessionByToken(created.Result().Cookies()[0].Value)
	if err != nil {
		test.Fatal("account fixture session unavailable")
	}
	options, ceremonyID, secret, err := server.passkeys.BeginRegistrationForSession(user, session.ID)
	if err != nil {
		test.Fatal("registration fixture cannot start")
	}
	body := authenticator.creationBody(test, "app.xunara.test", sharedPasskeyOrigin, options)
	request := httptest.NewRequest(http.MethodPost, sharedPasskeyOrigin+"/api/v1/account/passkeys/finish", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	if _, err := server.passkeys.FinishRegistration(ceremonyID, secret, user, session.ID, "test credential", request); err != nil {
		test.Fatal("registration fixture cannot finish")
	}
	return user
}

func beginSharedPasskey(test *testing.T, router *Router, login string) (protocol.CredentialAssertion, *http.Cookie) {
	test.Helper()
	response := tenantConsoleRequest(test, router, http.MethodPost, selfServicePasskeyBeginPath, accountPasskeyRequest{Login: login})
	if response.Code != http.StatusOK {
		test.Fatalf("account ceremony status: %d", response.Code)
	}
	var payload struct {
		Options protocol.CredentialAssertion `json:"options"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		test.Fatal("invalid account ceremony response")
	}
	cookies := response.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != passkeyCookieName || cookies[0].Path != "/" || !cookies[0].HttpOnly || !cookies[0].Secure ||
		strings.Contains(cookies[0].Value, login) || strings.Contains(response.Body.String(), `"console_path"`) || len(payload.Options.Response.AllowedCredentials) != 0 {
		test.Fatal("account ceremony leaked an account or routing hint")
	}
	return payload.Options, cookies[0]
}

func finishSharedPasskey(test *testing.T, router *Router, login string, assertion []byte, cookie *http.Cookie) *httptest.ResponseRecorder {
	test.Helper()
	var cookies []*http.Cookie
	if cookie != nil {
		cookies = append(cookies, cookie)
	}
	return tenantConsoleRequest(test, router, http.MethodPost, selfServicePasskeyFinishPath,
		accountPasskeyRequest{Login: login, Credential: assertion}, cookies...)
}

func TestSelfServicePasskeyUsesActualAccountAndScopedSession(test *testing.T) {
	router := sharedPasskeyRouter(test)
	authenticator := newSoftwareAuthenticator(test)
	user := registerSharedPasskey(test, router, "alpha", authenticator)
	options, cookie := beginSharedPasskey(test, router, "alpha")
	assertion := authenticator.assertionBody(test, "app.xunara.test", sharedPasskeyOrigin, &options, userHandle(user.ID))
	other := finishSharedPasskey(test, router, "alpha", assertion, nil)
	if other.Code != http.StatusBadRequest {
		test.Fatal("missing starting browser accepted")
	}
	response := finishSharedPasskey(test, router, "alpha", assertion, cookie)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"console_path":"/t/alpha"`) ||
		!strings.Contains(response.Body.String(), `"auth_method":"passkey"`) {
		test.Fatalf("account passkey finish status: %d", response.Code)
	}
	for _, returned := range response.Result().Cookies() {
		if returned.Name == sessionCookieName {
			test.Fatal("managed login established a root session")
		}
	}
	active := tenantConsoleRequest(test, router, http.MethodGet, "/t/alpha/api/v1/auth/session", nil, response.Result().Cookies()...)
	root := tenantConsoleRequest(test, router, http.MethodGet, "/api/v1/auth/session", nil, response.Result().Cookies()...)
	if !strings.Contains(active.Body.String(), `"authenticated":true`) || strings.Contains(root.Body.String(), `"authenticated":true`) {
		test.Fatal("account passkey session escaped its scope")
	}
	if replay := finishSharedPasskey(test, router, "alpha", assertion, cookie); replay.Code != http.StatusBadRequest {
		test.Fatal("account assertion replay accepted")
	}
}

func TestSelfServicePasskeyRejectsCrossTenantKeysWithEqualUserAndCredentialIDs(test *testing.T) {
	router := sharedPasskeyRouter(test)
	alphaKey, betaKey := newSoftwareAuthenticator(test), newSoftwareAuthenticator(test)
	alpha := registerSharedPasskey(test, router, "alpha", alphaKey)
	beta := registerSharedPasskey(test, router, "beta", betaKey)
	if alpha.ID != beta.ID || !bytes.Equal(alphaKey.credentialID, betaKey.credentialID) {
		test.Fatal("test must exercise equal IDs in independent identity stores")
	}
	options, cookie := beginSharedPasskey(test, router, "beta")
	foreign := alphaKey.assertionBody(test, "app.xunara.test", sharedPasskeyOrigin, &options, userHandle(alpha.ID))
	if rejected := finishSharedPasskey(test, router, "beta", foreign, cookie); rejected.Code != http.StatusBadRequest {
		test.Fatal("foreign public-key proof accepted based on matching IDs")
	}
	options, cookie = beginSharedPasskey(test, router, "beta")
	valid := betaKey.assertionBody(test, "app.xunara.test", sharedPasskeyOrigin, &options, userHandle(beta.ID))
	if response := finishSharedPasskey(test, router, "beta", valid, cookie); response.Code != http.StatusOK ||
		!strings.Contains(response.Body.String(), `"console_path":"/t/beta"`) {
		test.Fatal("second account cannot sign in at the common entry")
	}
	options, cookie = beginSharedPasskey(test, router, "alpha")
	valid = alphaKey.assertionBody(test, "app.xunara.test", sharedPasskeyOrigin, &options, userHandle(alpha.ID))
	if changed := finishSharedPasskey(test, router, "beta", valid, cookie); changed.Code != http.StatusBadRequest {
		test.Fatal("changing the login name reused another identity store ceremony")
	}
}

func TestSelfServicePasskeyUnknownAccountRateLimitAndJSONBoundary(test *testing.T) {
	router := sharedPasskeyRouter(test)
	for attempt := 0; attempt < 20; attempt++ {
		beginSharedPasskey(test, router, "missing")
	}
	if limited := tenantConsoleRequest(test, router, http.MethodPost, selfServicePasskeyBeginPath, accountPasskeyRequest{Login: "missing"}); limited.Code != http.StatusTooManyRequests || limited.Header().Get("Retry-After") == "" {
		test.Fatal("anonymous ceremonies are not persistently rate limited")
	}
	for _, path := range []string{selfServicePasskeyBeginPath, selfServicePasskeyFinishPath, selfServiceLoginPath} {
		request := httptest.NewRequest(http.MethodPost, sharedPasskeyOrigin+path, strings.NewReader(`{"login":"missing"}`))
		request.Header.Set("Content-Type", "text/plain")
		response := httptest.NewRecorder()
		router.Handler().ServeHTTP(response, request)
		if response.Code != http.StatusUnsupportedMediaType {
			test.Fatal("plain form can submit a shared account sign-in")
		}
		request = httptest.NewRequest(http.MethodPost, "https://foreign.test"+path, strings.NewReader(`{}`))
		request.Header.Set("Content-Type", "application/json")
		response = httptest.NewRecorder()
		router.Handler().ServeHTTP(response, request)
		if response.Code != http.StatusNotFound {
			test.Fatal("foreign Host reached a shared account authentication endpoint")
		}
	}
}

func TestTenantLoginBookmarksAlwaysUseCanonicalAccountEntry(test *testing.T) {
	router, _ := selfServiceRouter(test, &SelfServiceConfig{DomainSuffix: "old.example.test", ConsoleURL: sharedPasskeyOrigin})
	created := tenantConsoleRequest(test, router, http.MethodPost, selfServiceSignupPath,
		selfServiceRequest{Login: "alpha", Password: "SharedAccount-Strong-2026"})
	if created.Code != http.StatusCreated {
		test.Fatal("tenant fixture cannot be created")
	}
	for _, tenant := range []string{"alpha", "deleted", "gggg"} {
		for _, method := range []string{http.MethodGet, http.MethodHead} {
			response := tenantConsoleRequest(test, router, method, "/t/"+tenant+"/login", nil)
			if response.Code != http.StatusFound || response.Header().Get("Location") != "/login" || response.Header().Get("Cache-Control") != "no-store" {
				test.Fatal("legacy login still fixes a tenant or exposes its existence")
			}
		}
		post := tenantConsoleRequest(test, router, http.MethodPost, "/t/"+tenant+"/login", map[string]string{"password": "not-forwarded"})
		if post.Code != http.StatusMethodNotAllowed || post.Header().Get("Location") != "" {
			test.Fatal("legacy login forwards a password body")
		}
	}
	query := url.Values{"return_to": {"/network"}, "signed_out": {"current"}, "token": {"do-not-forward"}}
	response := tenantConsoleRequest(test, router, http.MethodGet, "/t/alpha/login?"+query.Encode(), nil)
	destination, err := url.Parse(response.Header().Get("Location"))
	if err != nil || destination.Path != "/login" || destination.Query().Get("return_to") != "/t/alpha/network" ||
		destination.Query().Get("signed_out") != "current" || destination.Query().Get("token") != "" {
		test.Fatal("legacy navigation hints are not safely bounded")
	}
	for _, target := range []string{"https://foreign.test", "//foreign.test", "/\\foreign.test", "/login", "/"} {
		if actual := canonicalAccountLogin(url.Values{"return_to": {target}}, "/t/alpha"); actual != "/login" {
			test.Fatal("invalid or recursive return target reached canonical login")
		}
	}
	writer := &tenantConsoleWriter{ResponseWriter: httptest.NewRecorder(), orgID: "alpha", secure: true}
	writer.Header().Set("Location", "/login?return_to=%2Fregister%2Fapproval")
	writer.WriteHeader(http.StatusFound)
	destination, err = url.Parse(writer.Header().Get("Location"))
	if err != nil || destination.Path != "/login" || destination.Query().Get("return_to") != "/t/alpha/register/approval" {
		test.Fatal("device authorization login generated a tenant login page")
	}
}
