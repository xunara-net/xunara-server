package control

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xunara-net/xunara-server/identity"
	"github.com/xunara-net/xunara-server/plan"
	"github.com/xunara-net/xunara-server/state"
)

// 仅用于隔离 HTTP 验收的提供方，授权码与令牌快照不属于生产认证状态存储。
type nativeOAuth2Fixture struct {
	server    *httptest.Server
	mu        sync.Mutex
	sequence  int
	subject   int64
	codes     map[string]url.Values
	tokens    map[string]int64
	exchanges int
}

func newNativeOAuth2Fixture(test *testing.T) *nativeOAuth2Fixture {
	test.Helper()
	fixture := &nativeOAuth2Fixture{subject: 42, codes: make(map[string]url.Values), tokens: make(map[string]int64)}
	fixture.server = httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		fixture.mu.Lock()
		defer fixture.mu.Unlock()
		writer.Header().Set("Content-Type", "application/json")
		if request.URL.RawQuery != "" {
			test.Error("OAuth2 backchannel leaked a query parameter")
		}
		if request.URL.Path == "/token" && request.Method == http.MethodPost {
			fixture.exchanges++
			if err := request.ParseForm(); err != nil {
				test.Error("invalid token request")
			}
			code := request.PostForm.Get("code")
			authorization, exists := fixture.codes[code]
			if !exists || request.PostForm.Get("grant_type") != "authorization_code" || request.PostForm.Get("client_id") != "native-client" || request.PostForm.Get("client_secret") != "native-secret-not-public" || request.PostForm.Get("redirect_uri") != authorization.Get("redirect_uri") || identity.PKCEChallenge(request.PostForm.Get("code_verifier")) != authorization.Get("code_challenge") {
				writer.WriteHeader(http.StatusBadRequest)
				fmt.Fprint(writer, `{"error":"invalid_grant"}`)
				return
			}
			delete(fixture.codes, code)
			token := "bearer-" + code
			fixture.tokens[token] = fixture.subject
			json.NewEncoder(writer).Encode(map[string]any{"access_token": token, "token_type": "Bearer", "expires_in": 60})
			return
		}
		if request.URL.Path == "/user" && request.Method == http.MethodGet {
			subject, exists := fixture.tokens[strings.TrimPrefix(request.Header.Get("Authorization"), "Bearer ")]
			if !exists {
				writer.WriteHeader(http.StatusUnauthorized)
				return
			}
			json.NewEncoder(writer).Encode(map[string]any{"id": subject, "name": "OAuth2 成员", "email": "same@example.test", "site_admin": true, "api_key": "must-not-retain"})
			return
		}
		writer.WriteHeader(http.StatusNotFound)
	}))
	test.Cleanup(fixture.server.Close)
	return fixture
}

func (fixture *nativeOAuth2Fixture) config(id string) identity.OAuth2Config {
	return identity.OAuth2Config{ID: id, Type: "generic", ClientID: "native-client", ClientSecret: "native-secret-not-public",
		AuthURL: fixture.server.URL + "/authorize", TokenURL: fixture.server.URL + "/token", UserInfoURL: fixture.server.URL + "/user", SubjectField: "id", NameField: "name", EmailField: "email"}
}

func (fixture *nativeOAuth2Fixture) callback(test *testing.T, start *httptest.ResponseRecorder) string {
	test.Helper()
	if start.Code != http.StatusOK && start.Code != http.StatusFound {
		test.Fatalf("OAuth2 start failed: %d", start.Code)
	}
	target := start.Header().Get("Location")
	if start.Code == http.StatusOK {
		var payload struct {
			URL string `json:"authorization_url"`
		}
		if err := json.Unmarshal(start.Body.Bytes(), &payload); err != nil {
			test.Fatal(err)
		}
		target = payload.URL
	}
	parsed, err := url.Parse(target)
	if err != nil {
		test.Fatal(err)
	}
	parameters := parsed.Query()
	if parameters.Get("state") == "" || parameters.Get("code_challenge_method") != "S256" || parameters.Get("code_challenge") == "" || strings.Contains(target, "native-secret-not-public") {
		test.Fatal("OAuth2 authorization not bound")
	}
	fixture.mu.Lock()
	fixture.sequence++
	code := "code-" + strconv.Itoa(fixture.sequence)
	fixture.codes[code] = parameters
	fixture.mu.Unlock()
	redirect, err := url.Parse(parameters.Get("redirect_uri"))
	if err != nil {
		test.Fatal(err)
	}
	return redirect.Path + "?code=" + code + "&state=" + url.QueryEscape(parameters.Get("state"))
}

func nativeAuthCookies(test *testing.T, start *httptest.ResponseRecorder, session *http.Cookie) map[string]string {
	test.Helper()
	binding := cookieNamed(test, start.Result(), authCookieName)
	value := binding.Name + "=" + binding.Value
	if session != nil {
		value += "; " + session.Name + "=" + session.Value
	}
	return map[string]string{"Cookie": value}
}

func TestOAuth2HTTPBindingLoginInviteUnlinkAndBoundaries(test *testing.T) {
	fixture := newNativeOAuth2Fixture(test)
	pro := proPlan(test)
	server := newServerWithConfig(test, Config{ServerURL: "https://console.example", OAuth2Providers: []identity.OAuth2Config{fixture.config("native"), fixture.config("other")},
		AllowLocalLogin: true, Registration: RegistrationInvite, PlanSource: func(string) plan.Plan { return pro }})
	ownerCookie, ownerToken := seedUserSession(test, server, state.DefaultUserID)
	initialBindings := len(server.identity.ListExternalIdentities(state.DefaultUserID))
	headers := map[string]string{"X-CSRF-Token": csrfTokenFor(ownerToken)}
	body := map[string]string{"provider_id": "native"}
	if response := accountRequest(test, server, http.MethodPost, "/api/v1/account/identities/begin", body, ownerCookie, nil); response.Code != http.StatusForbidden {
		test.Fatal("binding bypassed CSRF")
	}
	start := accountRequest(test, server, http.MethodPost, "/api/v1/account/identities/begin", body, ownerCookie, headers)
	callback := fixture.callback(test, start)
	if response := accountRequest(test, server, http.MethodGet, callback, nil, nil, nativeAuthCookies(test, start, nil)); response.Code != http.StatusForbidden {
		test.Fatal("binding bypassed initiating human session")
	}
	if response := accountRequest(test, server, http.MethodGet, strings.Replace(callback, "/oauth2/", "/oidc/", 1), nil, nil, nativeAuthCookies(test, start, ownerCookie)); response.Code != http.StatusBadRequest {
		test.Fatal("legacy callback alias bypassed exact allowlist")
	}
	if fixture.exchanges != 0 {
		test.Fatal("invalid binding reached token endpoint")
	}
	response := accountRequest(test, server, http.MethodGet, callback, nil, nil, nativeAuthCookies(test, start, ownerCookie))
	if response.Code != http.StatusFound || response.Header().Get("Location") != "/security?identity_binding=linked" {
		test.Fatalf("native OAuth2 account binding failed: %d", response.Code)
	}
	links, err := server.identity.ListAccountIdentities(test.Context(), state.DefaultUserID)
	binding, exists := server.identity.GetExternalIdentity("native", "42")
	if err != nil || len(links) != initialBindings+1 || !exists || binding.UserID != state.DefaultUserID || len(server.identity.ListUsers()) != 1 || len(server.store.ListNodes()) != 0 {
		test.Fatalf("binding invariant failed: bindings=%d users=%d nodes=%d read_error=%t", len(links), len(server.identity.ListUsers()), len(server.store.ListNodes()), err != nil)
	}
	if response := accountRequest(test, server, http.MethodGet, callback, nil, nil, nativeAuthCookies(test, start, ownerCookie)); response.Code != http.StatusBadRequest {
		test.Fatal("consumed transaction replay accepted")
	}
	start = accountRequest(test, server, http.MethodGet, "/api/v1/auth/start?provider=native&return_to=%2Fdevices", nil, nil, nil)
	response = accountRequest(test, server, http.MethodGet, fixture.callback(test, start), nil, nil, nativeAuthCookies(test, start, nil))
	ssoCookie := cookieNamed(test, response.Result(), sessionCookieName)
	session, err := server.identity.GetSessionByToken(ssoCookie.Value)
	if response.Code != http.StatusFound || response.Header().Get("Location") != "/devices" || err != nil || session.UserID != state.DefaultUserID || session.AuthMethod != "native" {
		test.Fatal("bound native OAuth2 login lost account/return path")
	}
	// 相同 subject、相同 email 但不同 provider 不能命中 owner，invite 模式仍拒绝陌生人。
	start = accountRequest(test, server, http.MethodGet, "/api/v1/auth/start?provider=other", nil, nil, nil)
	response = accountRequest(test, server, http.MethodGet, fixture.callback(test, start), nil, nil, nativeAuthCookies(test, start, nil))
	if response.Code != http.StatusForbidden || len(server.identity.ListUsers()) != 1 {
		test.Fatal("ordinary OAuth2 login bypassed invite admission or provider boundary")
	}
	invite, inviteCode, err := server.identity.CreateRegistrationInvite(identity.NewRegistrationInviteOptions{Role: identity.RoleMember, CreatedBy: "owner-fixture", TTL: time.Hour})
	if err != nil {
		test.Fatal(err)
	}
	start = accountRequest(test, server, http.MethodPost, "/api/v1/auth/invite/start", map[string]string{"provider_id": "other", "invite": inviteCode, "registration_token": server.newFormToken(formPurposeSignup)}, nil, nil)
	response = accountRequest(test, server, http.MethodGet, fixture.callback(test, start), nil, nil, nativeAuthCookies(test, start, nil))
	memberCookie := cookieNamed(test, response.Result(), sessionCookieName)
	memberSession, err := server.identity.GetSessionByToken(memberCookie.Value)
	if response.Code != http.StatusFound || err != nil || memberSession.UserID == state.DefaultUserID || len(server.identity.ListUsers()) != 2 {
		test.Fatal("native OAuth2 invite did not atomically create a distinct member")
	}
	member, _ := server.identity.GetUser(memberSession.UserID)
	if member.Role != identity.RoleMember || member.Email != binding.Email || member.LoginName == member.Email || !strings.HasPrefix(member.LoginName, "other_") {
		test.Fatal("provider claims elevated role, merged email or selected an email-derived ACL principal")
	}
	used, exists := server.identity.GetRegistrationInvite(invite.ID)
	if !exists || !used.Redeemed() {
		test.Fatal("OAuth2 invitation not redeemed")
	}
	memberBinding, exists := server.identity.GetExternalIdentity("other", "42")
	if !exists || memberBinding.UserID != memberSession.UserID {
		test.Fatal("invited member lost its provider/subject binding")
	}
	response = accountRequest(test, server, http.MethodDelete, "/api/v1/account/identities/"+identity.IdentityReference(memberBinding), nil, memberCookie, map[string]string{"X-CSRF-Token": csrfTokenFor(memberCookie.Value)})
	if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), "LAST_LOGIN_METHOD") {
		test.Fatal("native OAuth2 last usable login method removed")
	}
	response = accountRequest(test, server, http.MethodDelete, "/api/v1/account/identities/"+identity.IdentityReference(binding), nil, ownerCookie, headers)
	if response.Code != http.StatusOK {
		test.Fatalf("native OAuth2 unlink failed: %d", response.Code)
	}
	if _, err := server.identity.GetSessionByToken(ssoCookie.Value); err == nil {
		test.Fatal("unlink retained the provider's existing sessions")
	}
	if _, err := server.identity.GetSessionByToken(ownerCookie.Value); err != nil || len(server.store.ListNodes()) != 0 {
		test.Fatal("unlink revoked unrelated human session or touched devices")
	}
}
