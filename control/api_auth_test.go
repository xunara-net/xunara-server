package control

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/xunara-net/xunara-server/identity"
	"github.com/xunara-net/xunara-server/state"
)

// postJSON performs a JSON POST with an optional cookie and no redirect
// following, mirroring how xunara-web talks to the control plane.
func postJSON(t *testing.T, client *http.Client, rawURL string, body any, cookie *http.Cookie) *http.Response {
	t.Helper()

	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshalling request body: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, rawURL, bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
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

// decodeJSONBody decodes a response body into v and returns the raw bytes.
func decodeJSONBody(t *testing.T, resp *http.Response, v any) []byte {
	t.Helper()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading body: %v", err)
	}
	if v != nil {
		if err := json.Unmarshal(raw, v); err != nil {
			t.Fatalf("decoding JSON body (%s): %v", raw, err)
		}
	}
	return raw
}

// TestAPIAuthSessionAnonymous covers the console's first request: an
// unauthenticated session probe answers 200 with authenticated=false and the
// sign-in options, not a 401.
func TestAPIAuthSessionAnonymous(t *testing.T) {
	s := newTestServer(t)
	hs := newTestHTTPServer(t, s)
	client := noRedirectClient()

	resp := getRequest(t, client, hs.URL+"/api/v1/auth/session", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/v1/auth/session = %d, want 200", resp.StatusCode)
	}
	var body struct {
		Authenticated bool `json:"authenticated"`
		LocalLogin    bool `json:"local_login"`
		Registration  string
	}
	decodeJSONBody(t, resp, &body)
	if body.Authenticated {
		t.Errorf("anonymous probe reports authenticated=true")
	}
	if !body.LocalLogin {
		t.Errorf("test deployment reports local_login=false")
	}
	if body.Registration != "invite" {
		t.Errorf("registration = %q, want %q", body.Registration, "invite")
	}
}

// TestAPIAuthLoginSessionLogout walks the browser flow the console uses:
// sign in, carry the cookie into the session probe, read the plan, sign out.
func TestAPIAuthLoginSessionLogout(t *testing.T) {
	s := newTestServer(t)
	hs := newTestHTTPServer(t, s)
	client := noRedirectClient()

	login := state.DefaultUserProfile(state.DefaultUserID).LoginName
	resp := postJSON(t, client, hs.URL+"/api/v1/auth/login", map[string]string{
		"login":    login,
		"password": testLocalPassword,
	}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /api/v1/auth/login = %d (%s), want 200", resp.StatusCode, bodyString(t, resp))
	}
	cookie := cookieNamed(t, resp, sessionCookieName)
	if !cookie.HttpOnly {
		t.Errorf("session cookie is not HttpOnly")
	}

	var session struct {
		Authenticated bool `json:"authenticated"`
		User          struct {
			LoginName string `json:"login_name"`
			Role      string `json:"role"`
		} `json:"user"`
		Session struct {
			ID string `json:"id"`
		} `json:"session"`
		Capabilities []string `json:"capabilities"`
	}
	decodeJSONBody(t, resp, &session)
	if !session.Authenticated || session.User.LoginName != login {
		t.Fatalf("login payload = %+v, want an authenticated session for %s", session, login)
	}
	if session.Session.ID == "" {
		t.Errorf("login payload carries no session id")
	}

	probe := getRequest(t, client, hs.URL+"/api/v1/auth/session", cookie)
	var probed struct {
		Authenticated bool `json:"authenticated"`
	}
	decodeJSONBody(t, probe, &probed)
	if !probed.Authenticated {
		t.Fatalf("session probe with cookie reports authenticated=false")
	}

	planResp := getRequest(t, client, hs.URL+"/api/v1/plan", cookie)
	if planResp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/v1/plan = %d, want 200", planResp.StatusCode)
	}
	var planBody struct {
		MaxDevices int `json:"max_devices"`
	}
	decodeJSONBody(t, planResp, &planBody)

	logout := postJSON(t, client, hs.URL+"/api/v1/auth/logout", map[string]string{}, cookie)
	if logout.StatusCode != http.StatusNoContent {
		t.Fatalf("POST /api/v1/auth/logout = %d, want 204", logout.StatusCode)
	}
	after := getRequest(t, client, hs.URL+"/api/v1/auth/session", cookie)
	var afterBody struct {
		Authenticated bool `json:"authenticated"`
	}
	decodeJSONBody(t, after, &afterBody)
	if afterBody.Authenticated {
		t.Fatalf("session probe after logout reports authenticated=true")
	}
}

// TestAPIAuthLoginRejectsWrongPassword pins the uniform answer: no cookie and
// a generic message.
func TestAPIAuthLoginRejectsWrongPassword(t *testing.T) {
	s := newTestServer(t)
	hs := newTestHTTPServer(t, s)
	client := noRedirectClient()

	login := state.DefaultUserProfile(state.DefaultUserID).LoginName
	resp := postJSON(t, client, hs.URL+"/api/v1/auth/login", map[string]string{
		"login":    login,
		"password": "not-the-password",
	}, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong password = %d, want 401", resp.StatusCode)
	}
	for _, c := range resp.Cookies() {
		if c.Name == sessionCookieName && c.Value != "" {
			t.Fatalf("failed login still set a session cookie")
		}
	}
	body := string(decodeJSONBody(t, resp, nil))
	if bytes.Contains([]byte(body), []byte("not-the-password")) {
		t.Errorf("error body echoes the password: %s", body)
	}
}

// TestAPIAuthSignupRedeemsInvitation covers the JSON registration flow,
// including that an invitation is single use.
func TestAPIAuthSignupRedeemsInvitation(t *testing.T) {
	s := newTestServer(t)
	hs := newTestHTTPServer(t, s)
	client := noRedirectClient()

	_, token, err := s.Identity().CreateRegistrationInvite(identity.NewRegistrationInviteOptions{
		Role:      identity.RoleMember,
		Note:      "for the api test",
		CreatedBy: "user:1",
		TTL:       time.Hour,
	})
	if err != nil {
		t.Fatalf("CreateRegistrationInvite: %v", err)
	}

	signup := map[string]string{
		"invite":       token,
		"login":        "api-alice",
		"display_name": "Alice",
		"email":        "alice@example.com",
		"password":     "correct horse battery staple",
	}
	resp := postJSON(t, client, hs.URL+"/api/v1/auth/signup", signup, nil)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("POST /api/v1/auth/signup = %d (%s), want 201", resp.StatusCode, bodyString(t, resp))
	}
	cookie := cookieNamed(t, resp, sessionCookieName)

	var session struct {
		Authenticated bool `json:"authenticated"`
		User          struct {
			LoginName string `json:"login_name"`
			Role      string `json:"role"`
		} `json:"user"`
	}
	decodeJSONBody(t, resp, &session)
	if !session.Authenticated || session.User.LoginName != "api-alice" || session.User.Role != string(identity.RoleMember) {
		t.Fatalf("signup payload = %+v, want a member session for api-alice", session)
	}

	// The invitation is spent: the same token cannot create a second account.
	second := postJSON(t, client, hs.URL+"/api/v1/auth/signup", signup, nil)
	if second.StatusCode == http.StatusCreated {
		t.Fatalf("reused invitation created a second account")
	}

	// The new account can sign in with its password.
	loginResp := postJSON(t, client, hs.URL+"/api/v1/auth/login", map[string]string{
		"login":    "api-alice",
		"password": "correct horse battery staple",
	}, nil)
	if loginResp.StatusCode != http.StatusOK {
		t.Fatalf("signing in the registered account = %d, want 200", loginResp.StatusCode)
	}
	_ = cookie
}

// TestAPICapabilitiesIsPublic covers the pre-login capability probe.
func TestAPICapabilitiesIsPublic(t *testing.T) {
	s := newTestServer(t)
	hs := newTestHTTPServer(t, s)
	client := noRedirectClient()

	resp := getRequest(t, client, hs.URL+"/api/v1/capabilities", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/v1/capabilities = %d, want 200", resp.StatusCode)
	}
	var body struct {
		Capabilities []string `json:"capabilities"`
		Registration string   `json:"registration"`
	}
	decodeJSONBody(t, resp, &body)
	found := false
	for _, c := range body.Capabilities {
		if c == "auth.password" {
			found = true
		}
	}
	if !found {
		t.Fatalf("capabilities %v lack auth.password", body.Capabilities)
	}
	if body.Registration != "invite" {
		t.Errorf("registration = %q, want %q", body.Registration, "invite")
	}
}
