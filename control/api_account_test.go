package control

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/xunara-net/xunara-server/identity"
	"github.com/xunara-net/xunara-server/state"
)

func accountRequest(t *testing.T, server *Server, method, path string, body any, cookie *http.Cookie, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	var raw []byte
	if text, ok := body.(string); ok {
		raw = []byte(text)
	} else if body != nil {
		var err error
		raw, err = json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
	}
	request := httptest.NewRequest(method, path, bytes.NewReader(raw))
	request.Header.Set("Content-Type", "application/json")
	if cookie != nil {
		request.AddCookie(cookie)
	}
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	return response
}

func TestAccountMemberProfile(t *testing.T) {
	server := newTestServer(t)
	memberID := seedRoleUser(t, server, "member", identity.RoleMember)
	cookie, token := seedUserSession(t, server, memberID)
	response := accountRequest(t, server, http.MethodGet, "/api/v1/account", nil, cookie, nil)
	if response.Code != http.StatusOK || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("account read: %d", response.Code)
	}
	payload := decodeAPI(t, response.Result())
	if payload["csrf_token"] != csrfTokenFor(token) || payload["password_change_enabled"] != false {
		t.Fatalf("account metadata: %v", payload)
	}
	response = accountRequest(t, server, http.MethodPatch, "/api/v1/account", map[string]any{
		"display_name": "  我的昵称  ", "email": "  contact@example.test  ",
	}, cookie, map[string]string{"X-CSRF-Token": csrfTokenFor(token)})
	if response.Code != http.StatusOK {
		t.Fatalf("self-service profile: %d %s", response.Code, response.Body.String())
	}
	user, _ := server.identity.GetUser(memberID)
	if user.LoginName != "member" || user.DisplayName != "我的昵称" || user.Email != "contact@example.test" || user.Role != identity.RoleMember {
		t.Fatalf("updated identity: %+v", user)
	}
	owner, _ := server.identity.GetUser(state.DefaultUserID)
	if owner.DisplayName == user.DisplayName || owner.Email == user.Email {
		t.Fatal("self-service update changed another user")
	}
	if profile := server.UserProfile(memberID); profile.LoginName != user.LoginName || profile.DisplayName != user.DisplayName {
		t.Fatal("client profile no longer follows the existing user mapping")
	}
	if !auditActionSet(t, server)[identity.AuditUserUpdated] {
		t.Fatal("profile change was not audited")
	}
	response = accountRequest(t, server, http.MethodPatch, "/api/v1/account", map[string]string{"email": ""}, cookie, map[string]string{"X-CSRF-Token": csrfTokenFor(token)})
	if response.Code != http.StatusOK {
		t.Fatal("clearing contact email failed")
	}
}

func TestAccountRequiresHumanAndCSRF(t *testing.T) {
	server := newTestServer(t)
	cookie, token := seedUserSession(t, server, state.DefaultUserID)
	_, apiToken := seedAPIKey(t, server)
	for _, operation := range []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/api/v1/account"},
		{http.MethodPatch, "/api/v1/account"},
		{http.MethodPost, "/api/v1/account/password"},
	} {
		response := accountRequest(t, server, operation.method, operation.path, map[string]string{}, nil, nil)
		if response.Code != http.StatusUnauthorized {
			t.Fatalf("anonymous %s: %d", operation.path, response.Code)
		}
		response = accountRequest(t, server, operation.method, operation.path, map[string]string{}, cookie, map[string]string{
			"Authorization": "Bearer " + apiToken, "X-CSRF-Token": csrfTokenFor(token),
		})
		if response.Code != http.StatusForbidden || !strings.Contains(response.Body.String(), "HUMAN_SESSION_REQUIRED") {
			t.Fatalf("service identity %s: %d", operation.path, response.Code)
		}
		if operation.method != http.MethodGet {
			response = accountRequest(t, server, operation.method, operation.path, map[string]string{}, cookie, nil)
			if response.Code != http.StatusForbidden || !strings.Contains(response.Body.String(), "CSRF_INVALID") {
				t.Fatalf("missing CSRF %s: %d", operation.path, response.Code)
			}
		}
	}
	response := accountRequest(t, server, http.MethodPatch, "/api/v1/account", map[string]string{"display_name": "Bearer human"}, nil, map[string]string{
		"Authorization": "Bearer " + token, "X-CSRF-Token": csrfTokenFor(token),
	})
	if response.Code != http.StatusOK {
		t.Fatalf("human bearer session: %d", response.Code)
	}
	other := newTestServer(t)
	response = accountRequest(t, other, http.MethodGet, "/api/v1/account", nil, cookie, nil)
	if response.Code != http.StatusUnauthorized {
		t.Fatal("a different tenant accepted a human session with the same numeric user ID")
	}
}

func TestAccountProfileInputAllowlist(t *testing.T) {
	server := newTestServer(t)
	cookie, token := seedUserSession(t, server, state.DefaultUserID)
	headers := map[string]string{"X-CSRF-Token": csrfTokenFor(token)}
	for _, body := range []any{
		map[string]string{}, map[string]any{"display_name": nil},
		map[string]string{"role": "owner"}, map[string]string{"login_name": "renamed"},
		map[string]int{"id": 2}, map[string]string{"organization": "other"},
		map[string]string{"display_name": strings.Repeat("长", 101)},
		map[string]string{"display_name": "bad\x00name"},
		map[string]string{"email": "not-an-address"},
		map[string]string{"email": "Someone <mail@example.test>"},
		map[string]string{"email": "mail@example.test\nother@example.test"},
		`{"email":""}{"role":"owner"}`, strings.Repeat("x", 8193),
	} {
		response := accountRequest(t, server, http.MethodPatch, "/api/v1/account", body, cookie, headers)
		if response.Code != http.StatusBadRequest {
			t.Errorf("invalid account body returned %d", response.Code)
		}
	}
	response := accountRequest(t, server, http.MethodPatch, "/api/v1/account", `{"email":""}`, cookie, map[string]string{
		"X-CSRF-Token": csrfTokenFor(token), "Content-Type": "text/plain",
	})
	if response.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("non-JSON account: %d", response.Code)
	}
}

func TestAccountLegacyUserManagementOwnerOnly(t *testing.T) {
	server := newTestServer(t)
	adminID := seedRoleUser(t, server, "administrator", identity.RoleAdmin)
	cookie, token := seedUserSession(t, server, adminID)
	response := accountRequest(t, server, http.MethodPatch, "/api/v1/users/1", map[string]string{"displayName": "changed by admin"}, cookie, nil)
	if response.Code != http.StatusForbidden {
		t.Fatal("an admin could manage another human account through the legacy API")
	}
	request := httptest.NewRequest(http.MethodPost, "/console/users/1", strings.NewReader(url.Values{
		"csrf": {csrfTokenFor(token)}, "displayName": {"changed by admin"},
	}.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(cookie)
	response = httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatal("an admin could bypass account permissions through the HTML console")
	}
	response = accountRequest(t, server, http.MethodPatch, "/api/v1/account", map[string]string{"display_name": "own admin profile"}, cookie, map[string]string{"X-CSRF-Token": csrfTokenFor(token)})
	if response.Code != http.StatusOK {
		t.Fatal("an admin could not manage their own profile")
	}
}

func TestAccountPasswordChangeAndRelogin(t *testing.T) {
	server := newTestServer(t)
	cookie, token := seedUserSession(t, server, state.DefaultUserID)
	_, otherToken := seedUserSession(t, server, state.DefaultUserID)
	_, apiToken := seedAPIKey(t, server)
	newPassword := "replacement account password"
	response := accountRequest(t, server, http.MethodPost, "/api/v1/account/password", map[string]string{
		"current_password": testLocalPassword, "new_password": newPassword,
	}, cookie, map[string]string{"X-CSRF-Token": csrfTokenFor(token)})
	if response.Code != http.StatusOK {
		t.Fatalf("password change: %d %s", response.Code, response.Body.String())
	}
	payload := decodeAPI(t, response.Result())
	if payload["changed"] != true || payload["revoked_sessions"] != float64(2) || cookieNamed(t, response.Result(), sessionCookieName).MaxAge != -1 {
		t.Fatalf("password change payload: %v", payload)
	}
	for _, oldToken := range []string{token, otherToken} {
		if _, err := server.identity.GetSessionByToken(oldToken); !errors.Is(err, identity.ErrSessionNotFound) {
			t.Fatal("password change retained an old browser session")
		}
	}
	if _, err := server.identity.GetAPIKeyByToken(apiToken); err != nil {
		t.Fatal("password change affected an independent service identity")
	}
	user, _ := server.identity.GetUser(state.DefaultUserID)
	for _, password := range []string{testLocalPassword, newPassword} {
		response = accountRequest(t, server, http.MethodPost, "/api/v1/auth/login", map[string]string{"login": user.LoginName, "password": password}, nil, nil)
		if password == testLocalPassword && response.Code != http.StatusUnauthorized {
			t.Fatal("old password still signs in")
		}
		if password == newPassword && response.Code != http.StatusOK {
			t.Fatalf("new password cannot sign in: %d", response.Code)
		}
	}
	newCookie := cookieNamed(t, response.Result(), sessionCookieName)
	request := httptest.NewRequest(http.MethodGet, "/api/v1/account", nil)
	request.AddCookie(cookie)
	request.AddCookie(newCookie)
	response = httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatal("a stale parent-domain cookie shadowed the new host-only login")
	}
	if !auditActionSet(t, server)[identity.AuditPasswordChanged] {
		t.Fatal("password change was not audited")
	}
	credential, _ := server.identity.GetLocalCredential(user.ID)
	for _, event := range server.identity.ListAudit(0) {
		for _, secret := range []string{testLocalPassword, newPassword, string(credential.PasswordHash)} {
			if strings.Contains(event.Detail, secret) {
				t.Fatal("audit contains a password or hash")
			}
		}
	}
}

func TestAccountPasswordValidationAndLimit(t *testing.T) {
	for _, test := range []struct {
		name    string
		current string
		new     string
		code    string
	}{
		{"wrong current", "incorrect current password", "replacement account password", "CURRENT_PASSWORD_INVALID"},
		{"short new", testLocalPassword, "short", "PASSWORD_INVALID"},
		{"long new", testLocalPassword, strings.Repeat("长", 25), "PASSWORD_INVALID"},
		{"unchanged", testLocalPassword, testLocalPassword, "PASSWORD_UNCHANGED"},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := newTestServer(t)
			cookie, token := seedUserSession(t, server, state.DefaultUserID)
			response := accountRequest(t, server, http.MethodPost, "/api/v1/account/password", map[string]string{
				"current_password": test.current, "new_password": test.new,
			}, cookie, map[string]string{"X-CSRF-Token": csrfTokenFor(token)})
			if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), test.code) {
				t.Fatalf("validation: %d %s", response.Code, response.Body.String())
			}
			if _, err := server.identity.GetSessionByToken(token); err != nil {
				t.Fatal("a rejected change revoked the caller")
			}
		})
	}
	server := newTestServer(t)
	cookie, token := seedUserSession(t, server, state.DefaultUserID)
	for attempt := range 6 {
		response := accountRequest(t, server, http.MethodPost, "/api/v1/account/password", map[string]string{
			"current_password": "incorrect current password", "new_password": "replacement account password",
		}, cookie, map[string]string{"X-CSRF-Token": csrfTokenFor(token)})
		if attempt < 5 && response.Code != http.StatusBadRequest {
			t.Fatal("rate limiter rejected an allowed attempt")
		}
		if attempt == 5 && (response.Code != http.StatusTooManyRequests || response.Header().Get("Retry-After") == "") {
			t.Fatal("password rate limiter did not reject the sixth attempt")
		}
	}
}

func TestAccountPasswordUnavailableAndLimiterFailure(t *testing.T) {
	server := newTestServer(t)
	memberID := seedRoleUser(t, server, "external-user", identity.RoleMember)
	cookie, token := seedUserSession(t, server, memberID)
	response := accountRequest(t, server, http.MethodPost, "/api/v1/account/password", map[string]string{
		"current_password": "anything", "new_password": "replacement account password",
	}, cookie, map[string]string{"X-CSRF-Token": csrfTokenFor(token)})
	if response.Code != http.StatusForbidden || !strings.Contains(response.Body.String(), "PASSWORD_UNAVAILABLE") {
		t.Fatal("password endpoint can bootstrap an externally authenticated account")
	}
	if _, ok := server.identity.GetLocalCredential(memberID); ok {
		t.Fatal("a local credential was created")
	}
	cookie, token = seedUserSession(t, server, state.DefaultUserID)
	if _, err := server.store.(*state.SQLiteStore).DB().Exec("CREATE TRIGGER reject_password_limit BEFORE INSERT ON rate_limits BEGIN SELECT RAISE(ABORT, 'injected failure'); END"); err != nil {
		t.Fatal(err)
	}
	response = accountRequest(t, server, http.MethodPost, "/api/v1/account/password", map[string]string{
		"current_password": testLocalPassword, "new_password": "replacement account password",
	}, cookie, map[string]string{"X-CSRF-Token": csrfTokenFor(token)})
	if response.Code != http.StatusServiceUnavailable {
		t.Fatal("password change failed open when rate storage failed")
	}
}

func TestAccountMemberCanChangeOwnPassword(t *testing.T) {
	server := newTestServer(t)
	memberID := seedRoleUser(t, server, "member", identity.RoleMember)
	hash, err := bcrypt.GenerateFromPassword([]byte("original member password"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.identity.SetLocalCredential(&identity.LocalCredential{UserID: memberID, PasswordHash: hash}); err != nil {
		t.Fatal(err)
	}
	cookie, token := seedUserSession(t, server, memberID)
	response := accountRequest(t, server, http.MethodPost, "/api/v1/account/password", map[string]string{
		"current_password": "original member password", "new_password": "replacement member password",
	}, cookie, map[string]string{"X-CSRF-Token": csrfTokenFor(token)})
	if response.Code != http.StatusOK {
		t.Fatalf("member cannot change own password: %d", response.Code)
	}
	user, _ := server.identity.GetUser(memberID)
	if user.Role != identity.RoleMember {
		t.Fatal("changing a password changed the member's role")
	}
}
