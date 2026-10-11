package control

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/xunara-net/xunara-server/identity"
	"github.com/xunara-net/xunara-server/state"
)

func passwordResetRouter(test *testing.T) (*Router, *Server, *Server, string) {
	test.Helper()
	first := newServerWithConfig(test, Config{ServerURL: "http://first.reset.test", AllowLocalLogin: true})
	second := newServerWithConfig(test, Config{ServerURL: "http://second.reset.test", AllowLocalLogin: true})
	const token = "isolated-password-reset-platform-token"
	router, err := NewRouter(RouterConfig{PlatformAdminToken: token, Orgs: []OrgSite{
		{ID: "first", Name: "First", Domains: []string{"first.reset.test"}, Server: first},
		{ID: "second", Name: "Second", Domains: []string{"second.reset.test"}, Server: second},
	}})
	if err != nil {
		test.Fatal(err)
	}
	test.Cleanup(func() { router.Close() })
	return router, first, second, token
}

func resetAPIRequest(test *testing.T, handler http.Handler, host, path, token string, body any, cookie *http.Cookie, headers map[string]string) *httptest.ResponseRecorder {
	test.Helper()
	data, err := json.Marshal(body)
	if err != nil {
		test.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "http://"+host+path, bytes.NewReader(data))
	request.Header.Set("Content-Type", "application/json")
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	if cookie != nil {
		request.AddCookie(cookie)
	}
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func resetIssueBody(user identity.User) map[string]any {
	return map[string]any{"reason": "独立渠道核实持有人", "expected_updated_at": user.UpdatedAt, "ownership_verified": true}
}

func TestPlatformPasswordResetAuthorizationCASAndOneTimeVisibility(test *testing.T) {
	router, server, _, token := passwordResetRouter(test)
	owner, _ := server.identity.GetUser(state.DefaultUserID)
	ownerCookie, _ := seedUserSession(test, server, owner.ID)
	serviceToken := seedAPIKeyForUser(test, server, owner.ID)
	path := "/api/platform/v1/organizations/first/users/1/password-reset"
	for _, credential := range []struct {
		token  string
		cookie *http.Cookie
	}{{}, {cookie: ownerCookie}, {token: serviceToken}} {
		if response := resetAPIRequest(test, router.Handler(), "first.reset.test", path, credential.token, resetIssueBody(owner), credential.cookie, nil); response.Code != http.StatusUnauthorized {
			test.Fatal("non-platform identity could generate a reset code")
		}
	}
	for _, scenario := range []struct {
		body   any
		status int
	}{
		{map[string]any{"reason": "missing version", "ownership_verified": true}, http.StatusPreconditionRequired},
		{map[string]any{"reason": "unchecked", "expected_updated_at": owner.UpdatedAt}, http.StatusBadRequest},
		{map[string]any{"reason": "", "expected_updated_at": owner.UpdatedAt, "ownership_verified": true}, http.StatusBadRequest},
		{map[string]any{"reason": "stale", "expected_updated_at": owner.UpdatedAt.Add(time.Nanosecond), "ownership_verified": true}, http.StatusConflict},
		{map[string]any{"reason": "invalid", "expected_updated_at": owner.UpdatedAt, "ownership_verified": true, "password": "must not accept"}, http.StatusBadRequest},
	} {
		if response := resetAPIRequest(test, router.Handler(), "first.reset.test", path, token, scenario.body, nil, nil); response.Code != scenario.status {
			test.Fatalf("invalid request status = %d, want %d", response.Code, scenario.status)
		}
	}
	response := resetAPIRequest(test, router.Handler(), "first.reset.test", path, token, resetIssueBody(owner), nil, nil)
	if response.Code != http.StatusCreated || response.Header().Get("Cache-Control") != "no-store" {
		test.Fatal("platform could not generate a reset code")
	}
	var issued struct {
		Code            string    `json:"code"`
		UpdatedAt       time.Time `json:"updatedAt"`
		PasswordChanged bool      `json:"passwordChanged"`
		SessionsRevoked int64     `json:"sessionsRevoked"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &issued); err != nil || issued.Code == "" || issued.PasswordChanged || issued.SessionsRevoked != 0 || !issued.UpdatedAt.After(owner.UpdatedAt) {
		test.Fatal("invalid issuance acknowledgement")
	}
	if response := resetAPIRequest(test, router.Handler(), "first.reset.test", path, token, resetIssueBody(owner), nil, nil); response.Code != http.StatusConflict {
		test.Fatal("duplicate stale generation was not rejected")
	}
	listing := platformAPIRequest(test, router.Handler(), http.MethodGet, "/api/platform/v1/users", token)
	if listing.Code != http.StatusOK || strings.Contains(listing.Body.String(), issued.Code) || !strings.Contains(listing.Body.String(), "passwordResetExpiresAt") {
		test.Fatal("pending status is missing or reveals a code")
	}
	for _, event := range server.identity.ListAudit(0) {
		if strings.Contains(event.Detail, issued.Code) {
			test.Fatal("reset code leaked in audit")
		}
	}
	if current := accountRequest(test, server, http.MethodGet, "/api/v1/account", nil, ownerCookie, nil); current.Code != http.StatusOK {
		test.Fatal("generating a code invalidated an existing login")
	}
}

func TestPasswordResetRedeemsOnlyInTargetTenantAndDoesNotSignIn(test *testing.T) {
	router, first, second, platformToken := passwordResetRouter(test)
	owner, _ := first.identity.GetUser(state.DefaultUserID)
	issued, err := first.identity.IssuePasswordResetByPlatform(test.Context(), owner.ID, identity.PasswordResetOptions{Reason: "核实", ExpectedUpdatedAt: owner.UpdatedAt, OwnershipVerified: true})
	if err != nil {
		test.Fatal(err)
	}
	firstCookie, _ := seedUserSession(test, first, owner.ID)
	secondCookie, _ := seedUserSession(test, second, owner.ID)
	serviceToken := seedAPIKeyForUser(test, first, owner.ID)
	const replacement = "replacement reset password 2026"
	body := map[string]any{"code": issued.Code, "new_password": replacement, "confirm_password": replacement}
	other := resetAPIRequest(test, router.Handler(), "second.reset.test", "/api/v1/auth/password-reset", "", body, nil, nil)
	if other.Code != http.StatusBadRequest || !strings.Contains(other.Body.String(), "PASSWORD_RESET_INVALID") {
		test.Fatal("same user ID allowed cross-tenant redemption")
	}
	response := resetAPIRequest(test, router.Handler(), "first.reset.test", "/api/v1/auth/password-reset", "", body, nil, map[string]string{"Origin": "http://first.reset.test"})
	if response.Code != http.StatusOK || response.Header().Get("Set-Cookie") != "" || response.Header().Get("Cache-Control") != "no-store" {
		test.Fatal("valid redemption failed or created a login")
	}
	if replay := resetAPIRequest(test, router.Handler(), "first.reset.test", "/api/v1/auth/password-reset", "", body, nil, nil); replay.Code != http.StatusBadRequest {
		test.Fatal("reset code replay succeeded")
	}
	if current := accountRequest(test, first, http.MethodGet, "/api/v1/account", nil, firstCookie, nil); current.Code != http.StatusUnauthorized {
		test.Fatal("old login remained live after reset")
	}
	if current := accountRequest(test, second, http.MethodGet, "/api/v1/account", nil, secondCookie, nil); current.Code != http.StatusOK {
		test.Fatal("reset signed out a different tenant")
	}
	if response := accountRequest(test, first, http.MethodPost, "/api/v1/auth/login", apiLoginRequest{Login: owner.LoginName, Password: testLocalPassword}, nil, nil); response.Code != http.StatusUnauthorized {
		test.Fatal("old password still authenticates")
	}
	if response := accountRequest(test, first, http.MethodPost, "/api/v1/auth/login", apiLoginRequest{Login: owner.LoginName, Password: replacement}, nil, nil); response.Code != http.StatusOK {
		test.Fatal("new password cannot use normal sign-in")
	}
	if _, err := first.identity.GetAPIKeyByToken(serviceToken); err != nil {
		test.Fatal("human recovery revoked an independent service key")
	}
	if listing := platformAPIRequest(test, router.Handler(), http.MethodGet, "/api/platform/v1/users", platformToken); listing.Code != http.StatusOK || strings.Contains(listing.Body.String(), "passwordResetExpiresAt") {
		test.Fatal("consumed code still appears pending")
	}
}

func TestPasswordResetRequestValidationAndAdmissionFailures(test *testing.T) {
	server := newServerWithConfig(test, Config{AllowLocalLogin: true})
	owner, _ := server.identity.GetUser(state.DefaultUserID)
	issued, err := server.identity.IssuePasswordResetByPlatform(test.Context(), owner.ID, identity.PasswordResetOptions{Reason: "核实", ExpectedUpdatedAt: owner.UpdatedAt, OwnershipVerified: true})
	if err != nil {
		test.Fatal(err)
	}
	body := map[string]any{"code": issued.Code, "new_password": "replacement reset password", "confirm_password": "replacement reset password"}
	for _, headers := range []map[string]string{{"Origin": "http://external.test"}, {"Origin": "null"}, {"Origin": "http://login.test/"}, {"Sec-Fetch-Site": "cross-site"}} {
		if response := resetAPIRequest(test, server.Handler(), "login.test", "/api/v1/auth/password-reset", "", body, nil, headers); response.Code != http.StatusForbidden {
			test.Fatal("cross-origin reset accepted")
		}
	}
	if response := resetAPIRequest(test, server.Handler(), "login.test", "/api/v1/auth/password-reset?code=not-a-secret", "", body, nil, nil); response.Code != http.StatusForbidden {
		test.Fatal("query-based recovery accepted")
	}
	for _, invalid := range []map[string]any{
		{"code": "invalid", "new_password": "long reset password", "confirm_password": "long reset password"},
		{"code": issued.Code, "new_password": "short", "confirm_password": "short"},
		{"code": issued.Code, "new_password": "long reset password", "confirm_password": "different"},
		{"code": issued.Code, "new_password": "long reset password", "confirm_password": "long reset password", "user_id": 1},
	} {
		if response := resetAPIRequest(test, server.Handler(), "login.test", "/api/v1/auth/password-reset", "", invalid, nil, nil); response.Code != http.StatusBadRequest {
			test.Fatal("invalid body accepted")
		}
	}
	database := server.store.(*state.SQLiteStore).DB()
	if _, err := database.Exec("CREATE TRIGGER reset_rate_fault BEFORE UPDATE ON rate_limits BEGIN SELECT RAISE(ABORT, 'private reset rate diagnostic'); END"); err != nil {
		test.Fatal(err)
	}
	response := resetAPIRequest(test, server.Handler(), "login.test", "/api/v1/auth/password-reset", "", body, nil, nil)
	if response.Code != http.StatusServiceUnavailable || strings.Contains(response.Body.String(), "private reset") || strings.Contains(response.Body.String(), issued.Code) {
		test.Fatal("admission failure granted a reset or leaked diagnostics")
	}
	if _, err := server.identity.LookupPasswordReset(test.Context(), issued.Code); err != nil {
		test.Fatal("failed admission consumed the code")
	}
	if _, err := database.Exec("DROP TRIGGER reset_rate_fault"); err != nil {
		test.Fatal(err)
	}
	for attempt := 0; attempt < 21; attempt++ {
		response = resetAPIRequest(test, server.Handler(), "login.test", "/api/v1/auth/password-reset", "", map[string]any{"code": "invalid-" + strconv.Itoa(attempt)}, nil, nil)
	}
	if response.Code != http.StatusTooManyRequests || response.Header().Get("Retry-After") == "" {
		test.Fatal("persistent IP admission did not limit invalid resets")
	}
}
