package control

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/xunara-net/xunara-server/identity"
	"github.com/xunara-net/xunara-server/state"
)

// newUnconfiguredServer builds a server the way a fresh deployment starts:
// the built-in account exists, but it has no password and setup is pending.
func newUnconfiguredServer(t *testing.T) *Server {
	t.Helper()

	s, err := New(Config{ServerURL: "http://login.test", StateDir: t.TempDir()})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	ctx, cancel := context.WithCancel(context.Background())
	s.Start(ctx)
	t.Cleanup(cancel)
	return s
}

// getHTML performs a GET that asks for HTML, the way a browser does.
func getHTML(t *testing.T, client *http.Client, rawURL string, cookies ...*http.Cookie) *http.Response {
	t.Helper()

	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	req.Header.Set("Accept", "text/html,application/xhtml+xml")
	for _, cookie := range cookies {
		if cookie != nil {
			req.AddCookie(cookie)
		}
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", rawURL, err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

// TestLandingPageIsTheFrontDoor checks that / is a page for people, not the
// console and not a JSON blob, and that it offers the two ways in.
func TestLandingPageIsTheFrontDoor(t *testing.T) {
	s := newTestServer(t)
	hs := newTestHTTPServer(t, s)

	resp := getHTML(t, noRedirectClient(), hs.URL+"/")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET / = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("GET / content type = %q, want HTML", ct)
	}
	if resp.Header.Get("Set-Cookie") != "" {
		t.Error("GET / handed out a cookie")
	}
	body := bodyString(t, resp)
	for _, want := range []string{
		"Self-hosted Tailscale control plane",
		"tailscale up --login-server",
		`href="/login?return_to=%2Fconsole%2F"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("landing page lacks %q", want)
		}
	}
	if strings.Contains(body, "<h1>Console</h1>") {
		t.Error("landing page renders the console")
	}
}

// TestRootKeepsJSONForClients checks the machine-readable reply survives for
// callers that do not ask for HTML.
func TestRootKeepsJSONForClients(t *testing.T) {
	s := newTestServer(t)
	hs := newTestHTTPServer(t, s)

	resp := getRequest(t, noRedirectClient(), hs.URL+"/", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET / status = %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("GET / content type = %q, want JSON", ct)
	}
	body := bodyString(t, resp)
	for _, want := range []string{`"name":"Xunara"`, `"console":"/console/"`, `"version"`} {
		if !strings.Contains(body, want) {
			t.Errorf("root JSON lacks %q: %s", want, body)
		}
	}
}

// TestPublicPagesChinese checks the pages outside the console render in
// Chinese for a browser that asks for it.
func TestPublicPagesChinese(t *testing.T) {
	s := newTestServer(t)
	hs := newTestHTTPServer(t, s)
	fresh := newUnconfiguredServer(t)
	freshHS := newTestHTTPServer(t, fresh)
	client := noRedirectClient()

	for _, tc := range []struct {
		name string
		url  string
		want []string
	}{
		{"landing", hs.URL + "/", []string{"自托管 Tailscale 控制面", "把设备接入这里", "登录控制台"}},
		{"sign in", hs.URL + "/login", []string{"<h1>登录</h1>", "登录控制台以管理此网络。", "密码"}},
		{"setup", freshHS.URL + "/setup", []string{"初始化管理员", "一次性初始化令牌", "重复密码"}},
		{"signup", hs.URL + "/signup", []string{"创建账号", "邀请码", "重复密码"}},
		{"error", hs.URL + "/register/unknown-link", []string{"未知登录链接", "返回登录"}},
		{"not found", hs.URL + "/no-such-page", []string{"页面不存在", "返回登录"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			request, err := http.NewRequest(http.MethodGet, tc.url, nil)
			if err != nil {
				t.Fatalf("building request: %v", err)
			}
			request.Header.Set("Accept", "text/html,application/xhtml+xml")
			request.Header.Set("Accept-Language", "zh-CN,zh;q=0.9")
			resp, err := client.Do(request)
			if err != nil {
				t.Fatalf("GET %s: %v", tc.url, err)
			}
			t.Cleanup(func() { resp.Body.Close() })
			body := bodyString(t, resp)
			for _, want := range tc.want {
				if !strings.Contains(body, want) {
					t.Errorf("%s does not contain %q:\n%.1200s", tc.url, want, body)
				}
			}
		})
	}
}

// TestSetupCreatesTheAdministrator walks first-run setup: the one-time token
// is required, the account gets the password, and the token stops working.
func TestSetupCreatesTheAdministrator(t *testing.T) {
	s := newUnconfiguredServer(t)
	hs := newTestHTTPServer(t, s)
	client := noRedirectClient()

	token := s.readSetupToken()
	if len(token) < 16 {
		t.Fatalf("startup did not arm a setup token (got %q)", token)
	}

	page := getHTML(t, client, hs.URL+"/setup")
	if page.StatusCode != http.StatusOK {
		t.Fatalf("GET /setup = %d, want 200", page.StatusCode)
	}
	body := bodyString(t, page)
	if !strings.Contains(body, "One-time setup token") {
		t.Fatalf("setup page lacks the token field:\n%s", body)
	}

	// A wrong token is refused, and the account is still unconfigured.
	wrong := url.Values{
		"_csrf":        {hiddenValue(t, body, "_csrf")},
		"token":        {token + "x"},
		"login":        {"admin"},
		"display_name": {"Owner"},
		"password":     {"correct horse battery"},
		"confirm":      {"correct horse battery"},
	}
	if resp := postForm(t, client, hs.URL+"/setup", wrong, nil); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("wrong setup token status = %d, want 403", resp.StatusCode)
	}
	if !s.setupRequired() {
		t.Fatal("a rejected setup finished the deployment")
	}

	// Missing the token entirely (an operator removed the file) also fails.
	armed := s.readSetupToken()
	if armed != token {
		t.Fatalf("setup token changed after a failed attempt: %q", armed)
	}

	form := url.Values{
		"_csrf":        {hiddenValue(t, body, "_csrf")},
		"token":        {token},
		"login":        {"admin"},
		"display_name": {"Owner"},
		"email":        {"owner@example.com"},
		"password":     {"correct horse battery"},
		"confirm":      {"correct horse battery"},
	}
	resp := postForm(t, client, hs.URL+"/setup", form, nil)
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/console/" {
		t.Fatalf("setup = %d %q, want 302 /console/", resp.StatusCode, resp.Header.Get("Location"))
	}
	cookie := cookieNamed(t, resp, sessionCookieName)
	session, err := s.Identity().GetSessionByToken(cookie.Value)
	if err != nil {
		t.Fatalf("setup session is not valid: %v", err)
	}

	user, ok := s.Identity().GetUser(session.UserID)
	if !ok || user.LoginName != "admin" || user.DisplayName != "Owner" {
		t.Fatalf("administrator = %+v, %v", user, ok)
	}
	if user.Role != identity.RoleOwner {
		t.Errorf("administrator role = %q, want owner", user.Role)
	}
	if _, ok := s.Identity().GetLocalCredential(user.ID); !ok {
		t.Error("setup did not store the password")
	}
	if s.setupRequired() {
		t.Error("setup is still required after setup")
	}
	if token := s.readSetupToken(); token != "" {
		t.Errorf("the one-time token was not cleared: %q", token)
	}
	actions := auditActionSet(t, s)
	if !actions[identity.AuditAdminBootstrap] || !actions[identity.AuditLoginSucceeded] {
		t.Errorf("setup audit actions = %v", actions)
	}

	// The endpoint is spent: /setup now sends the operator to sign in, and
	// the sign-in page no longer suggests setup.
	again := getHTML(t, client, hs.URL+"/setup")
	if again.StatusCode != http.StatusFound || again.Header.Get("Location") != "/login" {
		t.Errorf("GET /setup after setup = %d %q, want 302 /login", again.StatusCode, again.Header.Get("Location"))
	}
	signIn := bodyString(t, getHTML(t, client, hs.URL+"/login"))
	if strings.Contains(signIn, "has no administrator yet") {
		t.Error("sign-in page still reports a missing administrator")
	}

	// The new administrator can sign in with the password it just set.
	if resp := submitLocalLoginAs(t, client, hs.URL, "admin", "correct horse battery", "/console/"); resp.StatusCode != http.StatusFound {
		t.Errorf("sign in as the new administrator = %d, want 302", resp.StatusCode)
	}
}

// TestSetupIsRateLimited checks the endpoint stops being a free work
// generator for an anonymous caller.
func TestSetupIsRateLimited(t *testing.T) {
	s := newUnconfiguredServer(t)
	hs := newTestHTTPServer(t, s)
	client := noRedirectClient()

	var last *http.Response
	for i := 0; i < setupRateLimit+1; i++ {
		last = postForm(t, client, hs.URL+"/setup", url.Values{
			"_csrf":    {"not-a-token"},
			"token":    {"guess"},
			"login":    {"admin"},
			"password": {"correct horse battery"},
			"confirm":  {"correct horse battery"},
		}, nil)
	}
	if last.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("attempt %d status = %d, want 429", setupRateLimit+1, last.StatusCode)
	}
	if last.Header.Get("Retry-After") == "" {
		t.Error("rate limited response has no Retry-After header")
	}
}

// TestSignupRedeemsAnInvitation covers registration by invitation: it needs a
// valid invitation, creates exactly one account, and the invitation is spent.
func TestSignupRedeemsAnInvitation(t *testing.T) {
	s := newTestServer(t)
	hs := newTestHTTPServer(t, s)
	client := noRedirectClient()

	invite, token, err := s.Identity().CreateRegistrationInvite(identity.NewRegistrationInviteOptions{
		Role:      identity.RoleMember,
		Note:      "for alice",
		CreatedBy: "user:1",
		TTL:       time.Hour,
	})
	if err != nil {
		t.Fatalf("CreateRegistrationInvite: %v", err)
	}
	if !strings.HasPrefix(token, identity.InvitePrefix) {
		t.Errorf("invitation token = %q, want the %q prefix", token, identity.InvitePrefix)
	}

	// The invitation page prefills the code from the link.
	page := getHTML(t, client, hs.URL+"/signup?invite="+url.QueryEscape(token))
	if page.StatusCode != http.StatusOK {
		t.Fatalf("GET /signup = %d, want 200", page.StatusCode)
	}
	body := bodyString(t, page)
	if !strings.Contains(body, token) {
		t.Fatalf("signup page does not prefill the invitation:\n%s", body)
	}

	// A mismatched confirmation is rejected before anything is created.
	form := url.Values{
		"_csrf":    {hiddenValue(t, body, "_csrf")},
		"invite":   {token},
		"login":    {"alice"},
		"password": {"alice-password-1"},
		"confirm":  {"alice-password-2"},
	}
	if resp := postForm(t, client, hs.URL+"/signup", form, nil); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("mismatched passwords status = %d, want 400", resp.StatusCode)
	}
	if _, ok := s.Identity().GetUserByLoginName("alice"); ok {
		t.Fatal("a rejected registration created a user")
	}

	form.Set("confirm", "alice-password-1")
	resp := postForm(t, client, hs.URL+"/signup", form, nil)
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/console/" {
		t.Fatalf("signup = %d %q, want 302 /console/", resp.StatusCode, resp.Header.Get("Location"))
	}
	cookie := cookieNamed(t, resp, sessionCookieName)
	session, err := s.Identity().GetSessionByToken(cookie.Value)
	if err != nil {
		t.Fatalf("registration session is not valid: %v", err)
	}

	user, ok := s.Identity().GetUser(session.UserID)
	if !ok || user.LoginName != "alice" || user.Role != identity.RoleMember {
		t.Fatalf("registered user = %+v, %v", user, ok)
	}
	if _, ok := s.Identity().GetLocalCredential(user.ID); !ok {
		t.Error("registration did not store the password")
	}
	if _, ok := s.Identity().GetExternalIdentity(identity.LocalProviderID, "alice"); !ok {
		t.Error("registration did not link the local identity")
	}
	redeemed, ok := s.Identity().GetRegistrationInvite(invite.ID)
	if !ok || !redeemed.Redeemed() || redeemed.UsedBy != user.ID {
		t.Fatalf("invitation after signup = %+v, %v", redeemed, ok)
	}
	if !auditActionSet(t, s)[identity.AuditUserRegistered] {
		t.Error("registration was not audited")
	}

	// The same invitation cannot be used twice, and the second attempt
	// leaves no account behind.
	retry := postForm(t, client, hs.URL+"/signup", url.Values{
		"_csrf":    {hiddenValue(t, body, "_csrf")},
		"invite":   {token},
		"login":    {"bob"},
		"password": {"bob-password-123"},
		"confirm":  {"bob-password-123"},
	}, nil)
	if retry.StatusCode != http.StatusForbidden {
		t.Fatalf("reused invitation status = %d, want 403", retry.StatusCode)
	}
	if _, ok := s.Identity().GetUserByLoginName("bob"); ok {
		t.Error("a rejected registration created a user")
	}
}

// TestSignupRejectsBadInvitations checks the three ways an invitation can be
// unusable, and that none of them creates an account.
func TestSignupRejectsBadInvitations(t *testing.T) {
	s := newTestServer(t)
	hs := newTestHTTPServer(t, s)
	client := noRedirectClient()

	expired, expiredToken, err := s.Identity().CreateRegistrationInvite(identity.NewRegistrationInviteOptions{
		Role: identity.RoleMember,
		TTL:  time.Millisecond,
	})
	if err != nil {
		t.Fatalf("CreateRegistrationInvite: %v", err)
	}
	time.Sleep(5 * time.Millisecond)

	for _, tc := range []struct {
		name  string
		token string
		want  int
	}{
		{"unknown", identity.InvitePrefix + "nope", http.StatusForbidden},
		{"expired", expiredToken, http.StatusForbidden},
		{"empty", "", http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			page := getHTML(t, client, hs.URL+"/signup")
			resp := postForm(t, client, hs.URL+"/signup", url.Values{
				"_csrf":    {hiddenValue(t, bodyString(t, page), "_csrf")},
				"invite":   {tc.token},
				"login":    {"someone"},
				"password": {"someone-password"},
				"confirm":  {"someone-password"},
			}, nil)
			if resp.StatusCode != tc.want {
				t.Fatalf("invitation %s status = %d, want %d", tc.name, resp.StatusCode, tc.want)
			}
			if _, ok := s.Identity().GetUserByLoginName("someone"); ok {
				t.Fatal("a rejected registration created a user")
			}
		})
	}
	if _, ok := s.Identity().GetRegistrationInvite(expired.ID); !ok {
		t.Error("the expired invitation disappeared")
	}
}

// TestPasswordLoginDoesNotRevealAccounts checks that an unknown login name
// and an account without a password are answered identically.
func TestPasswordLoginDoesNotRevealAccounts(t *testing.T) {
	s := newTestServer(t)
	hs := newTestHTTPServer(t, s)
	client := noRedirectClient()

	// A user that exists but has no password (for example one created by an
	// identity provider).
	providerUser := identity.User{LoginName: "provider-user", DisplayName: "Provider User"}
	if err := s.Identity().CreateUser(&providerUser); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	page := getHTML(t, client, hs.URL+"/login")
	csrf := hiddenValue(t, bodyString(t, page), "_csrf")

	answers := map[string]string{}
	for _, login := range []string{"provider-user", "no-such-user"} {
		resp := postForm(t, client, hs.URL+"/login", url.Values{
			"_csrf":    {csrf},
			"login":    {login},
			"password": {"whatever-password"},
		}, nil)
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("login %q status = %d, want 401", login, resp.StatusCode)
		}
		answers[login] = bodyString(t, resp)
	}
	if !strings.Contains(answers["no-such-user"], "Wrong login name or password.") {
		t.Error("unknown account does not get the generic message")
	}
	if answers["provider-user"] != answers["no-such-user"] {
		t.Errorf("the two answers differ:\n%q\n%q", answers["provider-user"], answers["no-such-user"])
	}
}

// TestPasswordLoginRejectsMissingCSRF checks the sign-in form cannot be
// driven from another site.
func TestPasswordLoginRejectsMissingCSRF(t *testing.T) {
	s := newTestServer(t)
	hs := newTestHTTPServer(t, s)

	resp := postForm(t, noRedirectClient(), hs.URL+"/login", url.Values{
		"login":    {state.DefaultUserProfile(state.DefaultUserID).LoginName},
		"password": {testLocalPassword},
	}, nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("login without a form token = %d, want 403", resp.StatusCode)
	}
	if resp.Header.Get("Set-Cookie") != "" {
		t.Error("a rejected sign-in handed out a cookie")
	}
}

// submitLocalLoginAs posts the sign-in form for an explicit login name, for
// tests that are not about the built-in account.
func submitLocalLoginAs(t *testing.T, client *http.Client, baseURL, login, password, returnTo string) *http.Response {
	t.Helper()

	page := getHTML(t, client, baseURL+"/login")
	if page.StatusCode != http.StatusOK {
		t.Fatalf("GET /login = %d, want 200", page.StatusCode)
	}
	return postForm(t, client, baseURL+"/login", url.Values{
		"_csrf":     {hiddenValue(t, bodyString(t, page), "_csrf")},
		"login":     {login},
		"password":  {password},
		"return_to": {returnTo},
	}, nil)
}

// TestConsoleInvitations walks invitation management from the console: create
// (the link is shown once), redeem, and revoke.
func TestConsoleInvitations(t *testing.T) {
	s := newTestServer(t)
	hs := newTestHTTPServer(t, s)
	client := noRedirectClient()
	// The default local account is the owner, so it may write.
	admin := loginLocal(t, client, hs.URL, "/console/users")

	page := bodyString(t, getRequest(t, client, hs.URL+"/console/users", admin))
	csrf := extractCSRF(t, page)
	if !strings.Contains(page, "Create an invitation") {
		t.Fatalf("users page lacks the invitation form:\n%s", page)
	}

	create := postForm(t, client, hs.URL+"/console/invites", url.Values{
		"csrf": {csrf},
		"role": {"member"},
		"note": {"for bob"},
		"ttl":  {"168"},
	}, admin)
	if create.StatusCode != http.StatusOK {
		t.Fatalf("create invitation status = %d (%s)", create.StatusCode, bodyString(t, create))
	}
	created := bodyString(t, create)
	token := linkTokenFromPage(t, created)
	if !strings.HasPrefix(token, identity.InvitePrefix) {
		t.Fatalf("invitation link carries %q, want a %s token", token, identity.InvitePrefix)
	}
	if !strings.Contains(created, "for bob") || !strings.Contains(created, "open") {
		t.Errorf("the new invitation is not listed as open:\n%s", created)
	}

	// The token is shown once: the list only ever holds the hash.
	reloaded := bodyString(t, getRequest(t, client, hs.URL+"/console/users", admin))
	if strings.Contains(reloaded, token) {
		t.Errorf("the invitation token is stored and re-rendered:\n%s", reloaded)
	}
	if !strings.Contains(reloaded, "for bob") {
		t.Errorf("the invitation is missing from the list:\n%s", reloaded)
	}

	// A read-only member cannot mint one.
	member := identity.User{LoginName: "member-user", DisplayName: "Member", Role: identity.RoleMember}
	if err := s.Identity().CreateUser(&member); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	hash, err := identity.HashPassword("member-password-1")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if err := s.Identity().SetLocalCredential(&identity.LocalCredential{UserID: member.ID, PasswordHash: hash}); err != nil {
		t.Fatalf("SetLocalCredential: %v", err)
	}
	memberClient := noRedirectClient()
	memberLogin := submitLocalLoginAs(t, memberClient, hs.URL, "member-user", "member-password-1", "/console/users")
	if memberLogin.StatusCode != http.StatusFound {
		t.Fatalf("member sign-in = %d", memberLogin.StatusCode)
	}
	cookie := cookieNamed(t, memberLogin, sessionCookieName)
	forbidden := postForm(t, memberClient, hs.URL+"/console/invites", url.Values{
		"csrf": {csrf},
		"role": {"member"},
		"ttl":  {"24"},
	}, cookie)
	if forbidden.StatusCode != http.StatusForbidden {
		t.Errorf("member may create invitations: status = %d", forbidden.StatusCode)
	}

	// Redeeming the invitation creates the account and marks it used.
	form := url.Values{
		"_csrf":    {hiddenValue(t, bodyString(t, getHTML(t, client, hs.URL+"/signup")), "_csrf")},
		"invite":   {token},
		"login":    {"bob"},
		"password": {"bob-password-123"},
		"confirm":  {"bob-password-123"},
	}
	signup := postForm(t, client, hs.URL+"/signup", form, nil)
	if signup.StatusCode != http.StatusFound {
		t.Fatalf("signup status = %d (%s)", signup.StatusCode, bodyString(t, signup))
	}
	after := bodyString(t, getRequest(t, client, hs.URL+"/console/users", admin))
	if !strings.Contains(after, "redeemed") || !strings.Contains(after, "bob") {
		t.Errorf("the console does not show the redeemed invitation:\n%s", after)
	}

	// A redeemed invitation cannot be revoked; a new one can.
	invites := s.Identity().ListRegistrationInvites()
	if len(invites) != 1 {
		t.Fatalf("invites = %+v", invites)
	}
	revoked := postForm(t, client, hs.URL+"/console/invites/"+invites[0].ID+"/delete",
		url.Values{"csrf": {csrf}}, admin)
	if revoked.StatusCode != http.StatusConflict {
		t.Errorf("revoking a redeemed invitation = %d, want 409", revoked.StatusCode)
	}

	fresh, freshToken, err := s.Identity().CreateRegistrationInvite(identity.NewRegistrationInviteOptions{
		Role: identity.RoleAdmin, TTL: time.Hour,
	})
	if err != nil {
		t.Fatalf("CreateRegistrationInvite: %v", err)
	}
	revoked = postForm(t, client, hs.URL+"/console/invites/"+fresh.ID+"/delete", url.Values{"csrf": {csrf}}, admin)
	if revoked.StatusCode != http.StatusOK {
		t.Fatalf("revoking an open invitation = %d (%s)", revoked.StatusCode, bodyString(t, revoked))
	}
	if _, err := s.Identity().FindRegistrationInvite(freshToken); err == nil {
		t.Error("the revoked invitation still resolves")
	}
}

// linkTokenFromPage pulls the invitation token out of the one-time link the
// console printed.
func linkTokenFromPage(t *testing.T, page string) string {
	t.Helper()

	const marker = "/signup?invite="
	i := strings.Index(page, marker)
	if i < 0 {
		t.Fatalf("page has no invitation link:\n%s", page)
	}
	rest := page[i+len(marker):]
	end := strings.IndexAny(rest, `"<&`)
	if end < 0 {
		t.Fatalf("malformed invitation link in page")
	}
	token, err := url.QueryUnescape(rest[:end])
	if err != nil {
		t.Fatalf("decoding invitation token: %v", err)
	}
	return token
}

// TestConsoleDoesNotTranslateRuntimeData checks that a login name that reads
// like UI copy is printed verbatim: a user called "Cancel" must not become
// a button label.
func TestConsoleDoesNotTranslateRuntimeData(t *testing.T) {
	s := newTestServer(t)
	hs := newTestHTTPServer(t, s)
	client := noRedirectClient()
	cookie := loginLocal(t, client, hs.URL, "/console/users")

	user := identity.User{LoginName: "Cancel", DisplayName: "Sign out"}
	if err := s.Identity().CreateUser(&user); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	request, err := http.NewRequest(http.MethodGet, hs.URL+"/console/users", nil)
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	request.Header.Set("Accept-Language", "zh-CN,zh;q=0.9")
	request.AddCookie(cookie)
	resp, err := client.Do(request)
	if err != nil {
		t.Fatalf("GET /console/users: %v", err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	body := bodyString(t, resp)

	if !strings.Contains(body, "登录名") {
		t.Errorf("the page is not Chinese; the test would not prove anything:\n%.800s", body)
	}
	if !strings.Contains(body, `<span translate="no">Cancel</span>`) {
		t.Errorf("the login name was translated or lost:\n%.1200s", body)
	}
	if !strings.Contains(body, `translate="no">Sign out</span>`) {
		t.Errorf("the display name was translated or lost:\n%.1200s", body)
	}
}
