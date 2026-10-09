package control

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

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

// loginLocal completes a local login and returns the session cookie.
func loginLocal(t *testing.T, client *http.Client, baseURL, returnTo string) *http.Cookie {
	t.Helper()

	resp := submitLocalLogin(t, client, baseURL, returnTo)
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("POST /login status = %d, want 302", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != returnTo {
		t.Fatalf("login redirect = %q, want %q", loc, returnTo)
	}
	return cookieNamed(t, resp, sessionCookieName)
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

// hiddenValue returns the value of a hidden input in a rendered page.
func hiddenValue(t *testing.T, page, name string) string {
	t.Helper()

	marker := `name="` + name + `" value="`
	i := strings.Index(page, marker)
	if i < 0 {
		t.Fatalf("page has no hidden input %q:\n%.800s", name, page)
	}
	rest := page[i+len(marker):]
	j := strings.Index(rest, `"`)
	if j < 0 {
		t.Fatalf("malformed hidden input %q in page", name)
	}
	return rest[:j]
}

// submitLocalLogin renders the sign-in form, fills it in with the built-in
// account's password and posts it, returning the (unfollowed) response.
func submitLocalLogin(t *testing.T, client *http.Client, baseURL, returnTo string) *http.Response {
	t.Helper()

	page := getRequest(t, client, baseURL+"/login?return_to="+url.QueryEscape(returnTo), nil)
	if page.StatusCode != http.StatusOK {
		t.Fatalf("GET /login status = %d, want 200", page.StatusCode)
	}
	form := url.Values{
		"_csrf":     {hiddenValue(t, bodyString(t, page), "_csrf")},
		"login":     {state.DefaultUserProfile(state.DefaultUserID).LoginName},
		"password":  {testLocalPassword},
		"return_to": {returnTo},
	}
	return postForm(t, client, baseURL+"/login", form, nil)
}

func TestLocalLoginCreatesServerSideSession(t *testing.T) {
	s := newTestServer(t)
	hs := newTestHTTPServer(t, s)
	client := noRedirectClient()

	// The sign-in page is a form, not an automatic login: a GET must never
	// hand out a session, or anyone who can reach the URL owns the tailnet.
	page := getRequest(t, client, hs.URL+"/login", nil)
	if page.StatusCode != http.StatusOK {
		t.Fatalf("GET /login = %d, want 200", page.StatusCode)
	}
	if page.Header.Get("Set-Cookie") != "" {
		t.Error("GET /login handed out a cookie")
	}
	body := bodyString(t, page)
	for _, want := range []string{`name="login"`, `name="password"`, `name="_csrf"`} {
		if !strings.Contains(body, want) {
			t.Errorf("sign-in page lacks %q", want)
		}
	}

	// A wrong password is refused, with the same wording an unknown account
	// gets.
	form := url.Values{
		"_csrf":    {hiddenValue(t, body, "_csrf")},
		"login":    {state.DefaultUserProfile(state.DefaultUserID).LoginName},
		"password": {"definitely-not-the-password"},
	}
	if bad := postForm(t, client, hs.URL+"/login", form, nil); bad.StatusCode != http.StatusUnauthorized {
		t.Errorf("wrong password status = %d, want 401", bad.StatusCode)
	}
	if !auditActionSet(t, s)[identity.AuditLoginFailed] {
		t.Error("failed sign-in was not audited")
	}

	resp := submitLocalLogin(t, client, hs.URL, "/")
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/" {
		t.Fatalf("login = %d %q, want 302 /", resp.StatusCode, resp.Header.Get("Location"))
	}
	cookie := cookieNamed(t, resp, sessionCookieName)
	if !cookie.HttpOnly {
		t.Error("session cookie must be HttpOnly")
	}

	session, err := s.Identity().GetSessionByToken(cookie.Value)
	if err != nil {
		t.Fatalf("session token is not valid server-side: %v", err)
	}
	if session.UserID != state.DefaultUserID || session.AuthMethod != identity.LocalProviderID {
		t.Errorf("session = %+v", session)
	}

	actions := auditActionSet(t, s)
	if !actions[identity.AuditLoginSucceeded] || !actions[identity.AuditSessionCreated] {
		t.Errorf("audit actions = %v", actions)
	}

	// Logout revokes the session server-side, not just the cookie.
	out := postForm(t, client, hs.URL+"/logout", url.Values{"csrf": {csrfTokenFor(cookie.Value)}}, cookie)
	if out.StatusCode != http.StatusFound {
		t.Fatalf("logout status = %d, want 302", out.StatusCode)
	}
	if _, err := s.Identity().GetSessionByToken(cookie.Value); err == nil {
		t.Error("session is still valid after logout")
	}
	if !auditActionSet(t, s)[identity.AuditSessionRevoked] {
		t.Error("logout was not audited")
	}
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

func TestLoginRefusesUnknownProviderAndBadReturnTo(t *testing.T) {
	s := newTestServer(t)
	hs := newTestHTTPServer(t, s)
	client := noRedirectClient()

	// Unknown provider: rejected, never silently redirected elsewhere.
	resp := getRequest(t, client, hs.URL+"/login?provider=nope", nil)
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("unknown provider status = %d, want 400", resp.StatusCode)
	}

	// Open-redirect attempts all collapse to "/": the form carries the
	// sanitized path, so posting it can never leave the site.
	for _, bad := range []string{"https://evil.example/x", "//evil.example", "javascript:alert(1)", "/\\evil"} {
		resp := getRequest(t, client, hs.URL+"/login?return_to="+url.QueryEscape(bad), nil)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("return_to %q status = %d, want 200", bad, resp.StatusCode)
		}
		if got := hiddenValue(t, bodyString(t, resp), "return_to"); got != "/" {
			t.Errorf("return_to %q rendered as %q, want /", bad, got)
		}
	}

	// A visitor who just opens /login lands in the console after signing in.
	resp = getRequest(t, client, hs.URL+"/login", nil)
	if got := hiddenValue(t, bodyString(t, resp), "return_to"); got != "/console/" {
		t.Errorf("plain /login return_to = %q, want /console/", got)
	}

	// A signed-in visitor does not get the form again.
	cookie := loginLocal(t, client, hs.URL, "/console/")
	resp = getRequest(t, client, hs.URL+"/login?return_to=/console/machines", cookie)
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/console/machines" {
		t.Errorf("signed-in GET /login = %d %q, want 302 /console/machines",
			resp.StatusCode, resp.Header.Get("Location"))
	}
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
		"":              "/console/",
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
	s := newServerWithConfig(t, Config{Providers: []identity.IdentityProvider{provider}})
	hs := newTestHTTPServer(t, s)
	client := noRedirectClient()

	// 1. /login redirects to the provider and binds the browser.
	resp := getRequest(t, client, hs.URL+"/login?provider=fake&return_to=/register/xyz", nil)
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
	s := newServerWithConfig(t, Config{Providers: []identity.IdentityProvider{provider}})
	hs := newTestHTTPServer(t, s)
	client := noRedirectClient()

	login := func(t *testing.T, subject, email string) identity.User {
		t.Helper()
		provider.result = identity.IdentityResult{
			ProviderID: "fake", Subject: subject, Email: email, DisplayName: subject,
		}
		resp := getRequest(t, client, hs.URL+"/login?provider=fake", nil)
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

func TestDeviceApprovalRequiresLoginAndCSRF(t *testing.T) {
	s := newTestServer(t)
	hs := newTestHTTPServer(t, s)
	client := noRedirectClient()

	conn, _, _, authID := startRegistration(t, hs, "device-a")
	defer conn.Close()

	// Without a session the page redirects to login, preserving the return
	// path.
	resp := getRequest(t, client, hs.URL+"/register/"+authID, nil)
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("anonymous register page = %d, want 302", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "/login?return_to="+url.QueryEscape("/register/"+authID) {
		t.Fatalf("redirect = %q", loc)
	}

	// A POST without a session must not approve anything.
	form := url.Values{}
	if resp := postForm(t, client, hs.URL+"/register/"+authID+"/approve", form, nil); resp.StatusCode != http.StatusFound {
		t.Errorf("anonymous approve status = %d, want 302 to login", resp.StatusCode)
	}
	if _, ok := s.Store().GetNodeByNodeKey(nodeKeyOfRegistration(t, s, authID)); ok {
		t.Fatal("anonymous approval created a node")
	}

	sessionCookie := loginLocal(t, client, hs.URL, "/register/"+authID)

	// The page carries the device details and a CSRF token.
	page := getRequest(t, client, hs.URL+"/register/"+authID, sessionCookie)
	if page.StatusCode != http.StatusOK {
		t.Fatalf("register page = %d", page.StatusCode)
	}
	html := bodyString(t, page)
	if !strings.Contains(html, "device-a") {
		t.Errorf("approval page does not show the hostname: %s", html)
	}
	csrf := extractCSRF(t, html)

	// A wrong CSRF token is rejected.
	bad := postForm(t, client, hs.URL+"/register/"+authID+"/approve", url.Values{"csrf": {"wrong"}}, sessionCookie)
	if bad.StatusCode != http.StatusForbidden {
		t.Errorf("bad CSRF status = %d, want 403", bad.StatusCode)
	}

	// The real approval creates the node for the signed-in user.
	good := postForm(t, client, hs.URL+"/register/"+authID+"/approve", url.Values{"csrf": {csrf}}, sessionCookie)
	if good.StatusCode != http.StatusOK {
		t.Fatalf("approve status = %d (%s)", good.StatusCode, bodyString(t, good))
	}

	node, ok := s.Store().GetNodeByNodeKey(nodeKeyOfRegistration(t, s, authID))
	if !ok {
		t.Fatal("approval did not create a node")
	}
	if node.UserID != state.DefaultUserID {
		t.Errorf("node user = %d, want the approving user %d", node.UserID, state.DefaultUserID)
	}
	if !auditActionSet(t, s)[identity.AuditNodeApproved] {
		t.Error("approval was not audited")
	}

	// Approving twice is idempotent.
	if again := postForm(t, client, hs.URL+"/register/"+authID+"/approve", url.Values{"csrf": {csrf}}, sessionCookie); again.StatusCode != http.StatusOK {
		t.Errorf("second approve status = %d, want 200", again.StatusCode)
	}
}

// nodeKeyOfRegistration returns the node key of the pending registration with
// the given authorization ID.
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

// extractCSRF pulls the CSRF form value out of the approval page.
func extractCSRF(t *testing.T, html string) string {
	t.Helper()

	const marker = `name="csrf" value="`
	i := strings.Index(html, marker)
	if i < 0 {
		t.Fatalf("no CSRF token in page: %s", html)
	}
	rest := html[i+len(marker):]
	j := strings.Index(rest, `"`)
	if j < 0 {
		t.Fatalf("malformed CSRF token in page")
	}
	return rest[:j]
}

func TestDeviceDenial(t *testing.T) {
	s := newTestServer(t)
	hs := newTestHTTPServer(t, s)
	client := noRedirectClient()

	conn, _, nodeKey, authID := startRegistration(t, hs, "device-b")
	defer conn.Close()

	sessionCookie := loginLocal(t, client, hs.URL, "/register/"+authID)
	page := getRequest(t, client, hs.URL+"/register/"+authID, sessionCookie)
	csrf := extractCSRF(t, bodyString(t, page))

	resp := postForm(t, client, hs.URL+"/register/"+authID+"/deny", url.Values{"csrf": {csrf}}, sessionCookie)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("deny status = %d", resp.StatusCode)
	}
	if _, ok := s.Store().GetNodeByNodeKey(nodeKey.Public()); ok {
		t.Fatal("denied registration created a node")
	}

	da, ok := s.Identity().GetDeviceAuthorization(authID)
	if !ok || da.State != identity.DeviceDenied {
		t.Fatalf("device authorization = %+v, %v", da, ok)
	}
	if !auditActionSet(t, s)[identity.AuditDeviceDenied] {
		t.Error("denial was not audited")
	}

	// A follow-up after denial is refused, not silently restarted. The
	// machine key must be the one that started the registration, or the
	// server would (correctly) treat it as a different machine.
	da2, ok := s.Identity().GetDeviceAuthorization(authID)
	if !ok {
		t.Fatal("device authorization missing")
	}
	var machineKey key.MachinePublic
	if err := machineKey.UnmarshalText([]byte(da2.MachineKey)); err != nil {
		t.Fatalf("parsing machine key: %v", err)
	}
	resp2, err := s.handleRegister(context.Background(), tailcfg.RegisterRequest{
		Version:  tailcfg.CurrentCapabilityVersion,
		NodeKey:  nodeKey.Public(),
		Followup: s.authURL(authID),
	}, machineKey)
	if err == nil {
		t.Fatalf("follow-up after denial = %+v, want an error", resp2)
	}
}

func TestRegisterPageUnknownAndExpired(t *testing.T) {
	s := newTestServer(t)
	hs := newTestHTTPServer(t, s)
	client := noRedirectClient()

	if resp := getRequest(t, client, hs.URL+"/register/does-not-exist", nil); resp.StatusCode != http.StatusNotFound {
		t.Errorf("unknown auth ID status = %d, want 404", resp.StatusCode)
	}

	expired, err := s.Identity().CreateDeviceAuthorization(identity.NewDeviceAuthorizationOptions{
		ID: "expired-one", MachineKey: key.NewMachine().Public().String(),
		NodeKey: key.NewNode().Public().String(), TTL: time.Millisecond,
	})
	if err != nil {
		t.Fatalf("CreateDeviceAuthorization: %v", err)
	}
	time.Sleep(5 * time.Millisecond)
	resp := getRequest(t, client, hs.URL+"/register/"+expired.ID, nil)
	if resp.StatusCode != http.StatusGone {
		t.Errorf("expired auth ID status = %d, want 410", resp.StatusCode)
	}
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
