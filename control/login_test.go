package control

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"tailscale.com/tailcfg"
	"tailscale.com/types/key"

	"github.com/xunara-net/xunara-server/identity"
	"github.com/xunara-net/xunara-server/state"
)

// noRedirectClient returns an HTTP client that reports redirects instead of
// following them, so tests can assert on Location and Set-Cookie.
func noRedirectClient() *http.Client {
	return &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// cookieNamed returns the named cookie from a response.
func cookieNamed(t *testing.T, resp *http.Response, name string) *http.Cookie {
	t.Helper()
	for _, c := range resp.Cookies() {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("response has no %q cookie (cookies: %v)", name, resp.Cookies())
	return nil
}

// getRequest performs a GET with an optional cookie and no redirect following.
func getRequest(t *testing.T, client *http.Client, rawURL string, cookie *http.Cookie) *http.Response {
	t.Helper()

	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	if cookie != nil {
		req.AddCookie(cookie)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", rawURL, err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

// postForm performs a form POST with an optional cookie and no redirect
// following.
func postForm(t *testing.T, client *http.Client, rawURL string, form url.Values, cookie *http.Cookie) *http.Response {
	t.Helper()

	req, err := http.NewRequest(http.MethodPost, rawURL, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if cookie != nil {
		req.AddCookie(cookie)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", rawURL, err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

// bodyString reads a response body for assertions.
func bodyString(t *testing.T, resp *http.Response) string {
	t.Helper()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading body: %v", err)
	}
	return string(raw)
}

// 登录测试直接使用公开 JSON API，不能伪造旧页面的重定向响应。
func loginLocal(t *testing.T, client *http.Client, baseURL, returnTo string) *http.Cookie {
	t.Helper()
	response := submitLocalLogin(t, client, baseURL, returnTo)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("JSON login = %d", response.StatusCode)
	}
	return cookieNamed(t, response, sessionCookieName)
}

func submitLocalLogin(t *testing.T, client *http.Client, baseURL, _ string) *http.Response {
	t.Helper()
	return postJSON(t, client, baseURL+"/api/v1/auth/login", apiLoginRequest{
		Login: state.DefaultUserProfile(state.DefaultUserID).LoginName, Password: testLocalPassword,
	}, nil)
}

// testLocalPassword is the password the built-in account gets in tests. A
// production deployment starts without one and asks for it at /setup; tests
// seed it so the password sign-in flow can be exercised.
const testLocalPassword = "xunara-test-password-2026"

// seedTestCredential gives the built-in local account a password, so a test
// server behaves like a deployment that has been set up.
func seedTestCredential(s *Server) error {
	hash, err := identity.HashPassword(testLocalPassword)
	if err != nil {
		return err
	}
	if err := s.Identity().SetLocalCredential(&identity.LocalCredential{
		UserID:       state.DefaultUserID,
		PasswordHash: hash,
	}); err != nil {
		return err
	}
	// Setup is finished the moment a password exists; a token left over from
	// construction would arm an endpoint that can no longer be used.
	return s.clearSetupToken()
}

// auditActionSet returns the set of actions in the audit log.
func auditActionSet(t *testing.T, s *Server) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	for _, e := range s.Identity().ListAudit(0) {
		out[e.Action] = true
	}
	return out
}

func TestSafeReturnTo(t *testing.T) {
	ok := []string{"/", "/register/abc", "/console?tab=machines"}
	for _, raw := range ok {
		if got := safeReturnTo(raw); got != raw {
			t.Errorf("safeReturnTo(%q) = %q", raw, got)
		}
	}
	bad := []string{"", "https://evil.example", "//evil.example", "/\\evil", "javascript:alert(1)", "register/abc"}
	for _, raw := range bad {
		if got := safeReturnTo(raw); got != "/" {
			t.Errorf("safeReturnTo(%q) = %q, want /", raw, got)
		}
	}
	for _, raw := range bad[1:] {
		if got := loginReturnTo(raw); got != "/" {
			t.Errorf("loginReturnTo(%q) = %q, want /", raw, got)
		}
	}
	for raw, want := range map[string]string{
		"":              "/dashboard",
		"/register/abc": "/register/abc",
		"/":             "/",
	} {
		if got := loginReturnTo(raw); got != want {
			t.Errorf("loginReturnTo(%q) = %q, want %q", raw, got, want)
		}
	}
}

// fakeProvider is a scriptable IdentityProvider for control-plane tests.
type fakeProvider struct {
	id     string
	result identity.IdentityResult

	beginURL    string
	callbackErr error
}

func (p *fakeProvider) ID() string { return p.id }

func (p *fakeProvider) Begin(_ context.Context, tx *identity.AuthTransaction) (*identity.AuthorizationRequest, error) {
	return &identity.AuthorizationRequest{URL: p.beginURL + "?state=" + url.QueryEscape(tx.State)}, nil
}

func (p *fakeProvider) Callback(_ context.Context, tx *identity.AuthTransaction, req *identity.CallbackRequest) (*identity.IdentityResult, error) {
	if p.callbackErr != nil {
		return nil, p.callbackErr
	}
	if req.State != tx.State {
		return nil, identity.ErrStateMismatch
	}
	result := p.result
	return &result, nil
}

func TestOIDCBrowserLoginFlow(t *testing.T) {
	provider := &fakeProvider{
		id:       "fake",
		beginURL: "https://idp.example/authorize",
		result: identity.IdentityResult{
			ProviderID:  "fake",
			Subject:     "subject-1",
			Email:       "Alice@Example.com",
			DisplayName: "Alice",
		},
	}
	s := newServerWithConfig(t, Config{Providers: []identity.IdentityProvider{provider}, Registration: RegistrationOpen})
	hs := newTestHTTPServer(t, s)
	client := noRedirectClient()

	// 1. /login redirects to the provider and binds the browser.
	resp := getRequest(t, client, hs.URL+"/api/v1/auth/start?provider=fake&return_to=/register/xyz", nil)
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("login status = %d, want 302", resp.StatusCode)
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil || loc.Host != "idp.example" || loc.Path != "/authorize" || loc.Query().Get("state") == "" {
		t.Fatalf("authorization redirect = %q (%v)", resp.Header.Get("Location"), err)
	}
	authCookie := cookieNamed(t, resp, authCookieName)

	// 2. The provider redirects back; the callback creates user + session.
	state := loc.Query().Get("state")
	cbURL := hs.URL + "/oidc/callback/fake?code=abc&state=" + url.QueryEscape(state)
	cb := getRequest(t, client, cbURL, authCookie)
	if cb.StatusCode != http.StatusFound || cb.Header.Get("Location") != "/register/xyz" {
		t.Fatalf("callback = %d %q, want 302 /register/xyz", cb.StatusCode, cb.Header.Get("Location"))
	}
	sessionCookie := cookieNamed(t, cb, sessionCookieName)
	session, err := s.Identity().GetSessionByToken(sessionCookie.Value)
	if err != nil {
		t.Fatalf("session: %v", err)
	}

	user, ok := s.Identity().GetUser(session.UserID)
	if !ok || user.LoginName != "alice@example.com" || user.Email != "Alice@Example.com" {
		t.Fatalf("user = %+v, %v", user, ok)
	}
	if _, ok := s.Identity().GetExternalIdentity("fake", "subject-1"); !ok {
		t.Error("external identity was not linked")
	}

	// 3. The callback cannot be replayed.
	replay := getRequest(t, client, cbURL, authCookie)
	if replay.StatusCode != http.StatusBadRequest {
		t.Errorf("replayed callback status = %d, want 400", replay.StatusCode)
	}

	// 4. A callback in a browser without the binding cookie is rejected.
	if resp := getRequest(t, client, cbURL, nil); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("unbound callback status = %d, want 400", resp.StatusCode)
	}

	// 5. An unknown provider path is 404.
	if resp := getRequest(t, client, hs.URL+"/oidc/callback/other", authCookie); resp.StatusCode != http.StatusNotFound {
		t.Errorf("unknown provider status = %d, want 404", resp.StatusCode)
	}
}

func TestLoginSecondIdentityGetsItsOwnUser(t *testing.T) {
	provider := &fakeProvider{id: "fake", beginURL: "https://idp.example/authorize"}
	s := newServerWithConfig(t, Config{Providers: []identity.IdentityProvider{provider}, Registration: RegistrationOpen})
	hs := newTestHTTPServer(t, s)
	client := noRedirectClient()

	login := func(t *testing.T, subject, email string) identity.User {
		t.Helper()
		provider.result = identity.IdentityResult{
			ProviderID: "fake", Subject: subject, Email: email, DisplayName: subject,
		}
		resp := getRequest(t, client, hs.URL+"/api/v1/auth/start?provider=fake", nil)
		authCookie := cookieNamed(t, resp, authCookieName)
		state := ""
		if u, err := url.Parse(resp.Header.Get("Location")); err == nil {
			state = u.Query().Get("state")
		}
		cb := getRequest(t, client, hs.URL+"/oidc/callback/fake?code=x&state="+url.QueryEscape(state), authCookie)
		if cb.StatusCode != http.StatusFound {
			t.Fatalf("callback status = %d", cb.StatusCode)
		}
		session, err := s.Identity().GetSessionByToken(cookieNamed(t, cb, sessionCookieName).Value)
		if err != nil {
			t.Fatalf("session: %v", err)
		}
		user, ok := s.Identity().GetUser(session.UserID)
		if !ok {
			t.Fatal("user not found")
		}
		return user
	}

	alice := login(t, "subject-a", "alice@example.com")
	// Same email, different subject: a new user, never an automatic merge.
	bob := login(t, "subject-b", "alice@example.com")
	if alice.ID == bob.ID {
		t.Fatalf("two subjects with the same email were merged into user %d", alice.ID)
	}
	if bob.LoginName != "alice@example.com-2" {
		t.Errorf("second login name = %q", bob.LoginName)
	}
}

func nodeKeyOfRegistration(t *testing.T, s *Server, authID string) key.NodePublic {
	t.Helper()

	da, ok := s.Identity().GetDeviceAuthorization(authID)
	if !ok {
		t.Fatalf("device authorization %s not found", authID)
	}
	var nodeKey key.NodePublic
	if err := nodeKey.UnmarshalText([]byte(da.NodeKey)); err != nil {
		t.Fatalf("parsing node key: %v", err)
	}
	return nodeKey
}

func TestNodeToRegisterResponseUsesTrustPlaneIdentity(t *testing.T) {
	s := newTestServer(t)
	hs := newTestHTTPServer(t, s)

	conn, _, nodeKey := registerNode(t, s, hs, "device-c")
	defer conn.Close()
	node, ok := s.Store().GetNodeByNodeKey(nodeKey.Public())
	if !ok {
		t.Fatal("node not found")
	}

	resp, err := s.handleRegister(context.Background(), tailcfg.RegisterRequest{
		Version: tailcfg.CurrentCapabilityVersion,
		NodeKey: nodeKey.Public(),
	}, node.MachineKey)
	if err != nil {
		t.Fatalf("handleRegister: %v", err)
	}
	profile := s.UserProfile(node.UserID)
	if resp.Login.LoginName != profile.LoginName || resp.User.DisplayName != profile.DisplayName {
		t.Errorf("register response login = %+v, want profile %+v", resp.Login, profile)
	}
}
