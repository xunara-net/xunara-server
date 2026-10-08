package control

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/xunara-net/xunara-server/identity"
	"github.com/xunara-net/xunara-server/state"
)

// consoleAtHost performs a console request addressed to an explicit host, so
// the router dispatches it to the intended organization.
func consoleAtHost(t *testing.T, client *http.Client, method string, hs *httptest.Server, host, path string, form url.Values, cookie *http.Cookie) *http.Response {
	t.Helper()

	var body *strings.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	} else {
		body = strings.NewReader("")
	}
	req, err := http.NewRequest(method, hs.URL+path, body)
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	req.Host = host
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if cookie != nil {
		req.AddCookie(cookie)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

// loginLocalAtHost completes a local login through the router, whose
// organizations are selected by Host.
func loginLocalAtHost(t *testing.T, client *http.Client, hs *httptest.Server, host, returnTo string) *http.Cookie {
	t.Helper()

	page := consoleAtHost(t, client, http.MethodGet, hs, host, "/login?return_to="+url.QueryEscape(returnTo), nil, nil)
	if page.StatusCode != http.StatusOK {
		t.Fatalf("GET /login (host %s) status = %d, want 200", host, page.StatusCode)
	}
	form := url.Values{
		"_csrf":     {hiddenValue(t, bodyString(t, page), "_csrf")},
		"login":     {state.DefaultUserProfile(state.DefaultUserID).LoginName},
		"password":  {testLocalPassword},
		"return_to": {returnTo},
	}
	resp := consoleAtHost(t, client, http.MethodPost, hs, host, "/login", form, nil)
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("POST /login (host %s) status = %d, want 302", host, resp.StatusCode)
	}
	return cookieNamed(t, resp, sessionCookieName)
}

// TestConsoleSharesPage drives the share console end to end across two
// organizations: create on the source side, accept and revoke on the target.
func TestConsoleSharesPage(t *testing.T) {
	_, hs, acme, globex := newShareRouter(t, t.TempDir())
	client := noRedirectClient()

	const (
		acmeHost   = "login.acme.example.com"
		globexHost = "login.globex.example.com"
	)
	machine := seedAPIMachine(t, acme, "laptop", nil)
	acmeCookie := loginLocalAtHost(t, client, hs, acmeHost, "/console/shares")

	page := bodyString(t, consoleAtHost(t, client, http.MethodGet, hs, acmeHost, "/console/shares", nil, acmeCookie))
	if !strings.Contains(page, "Share a machine") || !strings.Contains(page, machine.StableID) {
		t.Fatalf("share page lacks the create form or the machine list:\n%s", page)
	}
	if strings.Contains(page, "Sharing is not enabled") {
		t.Fatal("share-enabled router rendered the disabled notice")
	}

	csrf := extractCSRF(t, page)
	resp := consoleAtHost(t, client, http.MethodPost, hs, acmeHost, "/console/shares", url.Values{
		"csrf":                {csrf},
		"node":                {machine.StableID},
		"target_organization": {"globex"},
		"provider":            {testShareProvider},
		"subject":             {testShareSubject},
	}, acmeCookie)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("create status = %d", resp.StatusCode)
	}
	page = bodyString(t, resp)
	if !strings.Contains(page, "created; waiting for") || !strings.Contains(page, "Globex") {
		t.Fatalf("create page lacks the notice or the target name:\n%s", page)
	}

	// The target user sees the invite and can accept it.
	user := seedExternalUser(t, globex, "user@globex.example.com", testShareProvider, testShareSubject)
	globexCookie, _ := seedUserSession(t, globex, user)
	page = bodyString(t, consoleAtHost(t, client, http.MethodGet, hs, globexHost, "/console/shares", nil, globexCookie))
	if !strings.Contains(page, "Accept") || !strings.Contains(page, "laptop") {
		t.Fatalf("target page lacks the invite:\n%s", page)
	}
	csrf = extractCSRF(t, page)
	shares := globex.shares.ListShares(ShareFilter{TargetOrg: "globex"})
	if len(shares) != 1 {
		t.Fatalf("registry shares = %d, want 1", len(shares))
	}
	id := shares[0].ID

	resp = consoleAtHost(t, client, http.MethodPost, hs, globexHost, "/console/shares/"+id+"/accept", url.Values{"csrf": {csrf}}, globexCookie)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("accept status = %d", resp.StatusCode)
	}
	page = bodyString(t, resp)
	if !strings.Contains(page, "is now accepted") {
		t.Fatalf("accept page lacks the notice:\n%s", page)
	}

	// Revoke is idempotent and reports the terminal state.
	csrf = extractCSRF(t, page)
	resp = consoleAtHost(t, client, http.MethodPost, hs, globexHost, "/console/shares/"+id+"/revoke", url.Values{"csrf": {csrf}}, globexCookie)
	if resp.StatusCode != http.StatusOK || !strings.Contains(bodyString(t, resp), "is now revoked") {
		t.Fatalf("revoke status = %d", resp.StatusCode)
	}

	// The CSRF token is load-bearing: a write without it is rejected.
	resp = consoleAtHost(t, client, http.MethodPost, hs, acmeHost, "/console/shares", url.Values{
		"node":                {machine.StableID},
		"target_organization": {"globex"},
		"provider":            {testShareProvider},
		"subject":             {testShareSubject},
	}, acmeCookie)
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("create without CSRF status = %d, want 403", resp.StatusCode)
	}
}

// TestConsoleSharesReadOnly checks that a member may look but not act.
func TestConsoleSharesReadOnly(t *testing.T) {
	_, hs, _, globex := newShareRouter(t, t.TempDir())
	client := noRedirectClient()
	member := seedRoleUser(t, globex, "member@globex.example.com", identity.RoleMember)
	cookie, _ := seedUserSession(t, globex, member)

	page := bodyString(t, consoleAtHost(t, client, http.MethodGet, hs, "login.globex.example.com", "/console/shares", nil, cookie))
	if !strings.Contains(page, "read-only") {
		t.Fatalf("member page lacks the read-only notice:\n%s", page)
	}
	if strings.Contains(page, `action="/console/shares"`) || strings.Contains(page, "/accept") {
		t.Errorf("member page renders write controls:\n%s", page)
	}
	resp := consoleAtHost(t, client, http.MethodPost, hs, "login.globex.example.com", "/console/shares", url.Values{
		"node":                {"whatever"},
		"target_organization": {"acme"},
		"provider":            {testShareProvider},
		"subject":             {testShareSubject},
	}, cookie)
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("member create status = %d, want 403", resp.StatusCode)
	}
}

// TestConsoleSharesDisabled checks the disabled page on a deployment without
// the platform share registry.
func TestConsoleSharesDisabled(t *testing.T) {
	s := newTestServer(t)
	hs := newTestHTTPServer(t, s)
	client := noRedirectClient()
	cookie := loginLocal(t, client, hs.URL, "/console/shares")

	page := bodyString(t, getRequest(t, client, hs.URL+"/console/shares", cookie))
	if !strings.Contains(page, "Sharing is not enabled") {
		t.Fatalf("disabled page lacks the explanation:\n%s", page)
	}
	if strings.Contains(page, "Share a machine") {
		t.Error("disabled page renders the create form")
	}
}
