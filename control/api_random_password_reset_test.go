package control

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	xunarav2 "github.com/xunara-net/xunara-server/api/gen/xunara/v2"
	"github.com/xunara-net/xunara-server/identity"
	"github.com/xunara-net/xunara-server/state"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func randomResetRouter(test *testing.T) (*Router, *Server, *Server, string) {
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

func randomResetRequest(test *testing.T, handler http.Handler, host, path, token string, body any, cookie *http.Cookie) *httptest.ResponseRecorder {
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
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func randomResetBody(user identity.User) map[string]any {
	return map[string]any{"reason": "独立渠道核实持有人", "expected_updated_at": user.UpdatedAt, "ownership_verified": true}
}

func TestPlatformRandomPasswordResetAuthorizationCASAndPrivateAcknowledgement(test *testing.T) {
	router, server, _, token := randomResetRouter(test)
	owner, _ := server.identity.GetUser(state.DefaultUserID)
	ownerCookie, _ := seedUserSession(test, server, owner.ID)
	serviceToken := seedAPIKeyForUser(test, server, owner.ID)
	path := "/api/platform/v1/organizations/first/users/1/password-reset/random"
	for _, credential := range []struct {
		token  string
		cookie *http.Cookie
	}{{}, {cookie: ownerCookie}, {token: serviceToken}} {
		if response := randomResetRequest(test, router.Handler(), "first.reset.test", path, credential.token, randomResetBody(owner), credential.cookie); response.Code != http.StatusUnauthorized {
			test.Fatal("non-platform identity could directly reset a password")
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
		if response := randomResetRequest(test, router.Handler(), "first.reset.test", path, token, scenario.body, nil); response.Code != scenario.status {
			test.Fatalf("invalid request status = %d, want %d", response.Code, scenario.status)
		}
	}
	response := randomResetRequest(test, router.Handler(), "first.reset.test", path, token, randomResetBody(owner), nil)
	if response.Code != http.StatusOK || response.Header().Get("Cache-Control") != "no-store" || response.Header().Get("Referrer-Policy") != "no-referrer" {
		test.Fatal("platform could not reset with a private response")
	}
	var result struct {
		TemporaryPassword      string    `json:"temporaryPassword"`
		UpdatedAt              time.Time `json:"updatedAt"`
		PasswordChanged        bool      `json:"passwordChanged"`
		PasswordChangeRequired bool      `json:"passwordChangeRequired"`
		SessionsRevoked        int64     `json:"sessionsRevoked"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil || len(result.TemporaryPassword) != 32 || !result.PasswordChanged || !result.PasswordChangeRequired || result.SessionsRevoked != 1 || !result.UpdatedAt.After(owner.UpdatedAt) {
		test.Fatal("invalid direct reset acknowledgement")
	}
	if response := randomResetRequest(test, router.Handler(), "first.reset.test", path, token, randomResetBody(owner), nil); response.Code != http.StatusConflict {
		test.Fatal("duplicate stale reset was not rejected")
	}
	listing := platformAPIRequest(test, router.Handler(), http.MethodGet, "/api/platform/v1/users", token)
	if listing.Code != http.StatusOK || strings.Contains(listing.Body.String(), result.TemporaryPassword) || !strings.Contains(listing.Body.String(), `"passwordResetMode":"temporary_password"`) || !strings.Contains(listing.Body.String(), `"passwordChangeRequired":true`) {
		test.Fatal("status is missing or exposes the password")
	}
	if current := accountRequest(test, server, http.MethodGet, "/api/v1/account", nil, ownerCookie, nil); current.Code != http.StatusUnauthorized {
		test.Fatal("direct reset left the old login usable")
	}
}

func TestTemporaryPasswordRequiresChangeAcrossHumanSurfacesAndNotServices(test *testing.T) {
	_, server, foreign, _ := randomResetRouter(test)
	owner, _ := server.identity.GetUser(state.DefaultUserID)
	foreignCookie, _ := seedUserSession(test, foreign, owner.ID)
	serviceToken := seedAPIKeyForUser(test, server, owner.ID)
	result, err := server.identity.ResetRandomPasswordByPlatform(test.Context(), owner.ID, identity.PasswordResetOptions{Reason: "核实", ExpectedUpdatedAt: owner.UpdatedAt, OwnershipVerified: true}, "platform-token")
	if err != nil {
		test.Fatal(err)
	}
	login := map[string]string{"login": owner.LoginName, "password": result.TemporaryPassword}
	if response := accountRequest(test, foreign, http.MethodPost, "/api/v1/auth/login", login, nil, nil); response.Code != http.StatusUnauthorized {
		test.Fatal("temporary password authenticated another tenant's numeric ID")
	}
	response := accountRequest(test, server, http.MethodPost, "/api/v1/auth/login", login, nil, nil)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"password_change_required":true`) {
		test.Fatal("temporary password login did not report forced change")
	}
	cookie := cookieNamed(test, response.Result(), sessionCookieName)
	for _, authMethod := range []string{identity.LocalProviderID, "passkey", "external"} {
		test.Run(authMethod, func(test *testing.T) {
			active := cookie
			if authMethod != identity.LocalProviderID {
				_, token, err := server.identity.CreateSession(identity.NewSessionOptions{UserID: owner.ID, AuthMethod: authMethod})
				if err != nil {
					test.Fatal(err)
				}
				active = &http.Cookie{Name: sessionCookieName, Value: token}
			}
			for _, path := range []string{"/api/v1/overview", "/api/v1/machines", "/api/v1/account/identities", "/api/v1/account/passkeys", "/api/v2/network/addresses"} {
				response := accountRequest(test, server, http.MethodGet, path, nil, active, nil)
				if response.Code != http.StatusForbidden || !strings.Contains(response.Body.String(), "PASSWORD_CHANGE_REQUIRED") {
					test.Fatalf("temporary human login bypassed %s", path)
				}
			}
			if response := accountRequest(test, server, http.MethodPatch, "/api/v1/account", map[string]string{"display_name": "not allowed"}, active, map[string]string{"X-CSRF-Token": csrfTokenFor(active.Value)}); response.Code != http.StatusForbidden {
				test.Fatal("temporary login changed its profile")
			}
		})
	}
	for _, operation := range []struct{ method, path string }{{http.MethodGet, "/console/"}, {http.MethodPost, "/console/machines/1/delete"}, {http.MethodPost, "/register/test/approve"}} {
		response := accountRequest(test, server, operation.method, operation.path, nil, cookie, nil)
		if operation.path == "/console/machines/1/delete" {
			if response.Code != http.StatusGone {
				test.Fatal("retired form accepted a temporary human login")
			}
			continue
		}
		if response.Code != http.StatusFound || response.Header().Get("Location") != "/change-password" {
			test.Fatal("legacy console or device approval bypassed forced change")
		}
	}
	grpcClient := startGRPCTestServer(test, server.RegisterPlatformGRPC)
	if _, err := grpcClient.GetMeta(grpcCtx(cookie.Value), &xunarav2.GetMetaRequest{}); status.Code(err) != codes.PermissionDenied {
		test.Fatal("gRPC accepted a temporary human session")
	}
	if _, err := grpcClient.GetMeta(grpcCtx(serviceToken), &xunarav2.GetMetaRequest{}); err != nil {
		test.Fatal("human reset revoked independent gRPC service access")
	}
	if response := accountRequest(test, foreign, http.MethodGet, "/api/v1/account", nil, foreignCookie, nil); response.Code != http.StatusOK {
		test.Fatal("human reset revoked another tenant's login")
	}
	if response := accountRequest(test, server, http.MethodGet, "/key?v=130", nil, cookie, nil); response.Code != http.StatusOK {
		test.Fatal("human restriction changed official client key discovery")
	}
	account := accountRequest(test, server, http.MethodGet, "/api/v1/account", nil, cookie, nil)
	if account.Code != http.StatusOK {
		test.Fatal("temporary login cannot read its own change metadata")
	}
	body := map[string]string{"current_password": result.TemporaryPassword, "new_password": "my independent replacement password"}
	if response := accountRequest(test, server, http.MethodPost, "/api/v1/account/password", body, cookie, nil); response.Code != http.StatusForbidden {
		test.Fatal("temporary password change did not require CSRF")
	}
	changed := accountRequest(test, server, http.MethodPost, "/api/v1/account/password", body, cookie, map[string]string{"X-CSRF-Token": csrfTokenFor(cookie.Value)})
	if changed.Code != http.StatusOK {
		test.Fatal("personal password change failed")
	}
	if response := accountRequest(test, server, http.MethodGet, "/api/v1/account", nil, cookie, nil); response.Code != http.StatusUnauthorized {
		test.Fatal("password change left a temporary session usable")
	}
	login["password"] = body["new_password"]
	response = accountRequest(test, server, http.MethodPost, "/api/v1/auth/login", login, nil, nil)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"password_change_required":false`) {
		test.Fatal("personal password did not restore normal console access")
	}
	login["password"] = result.TemporaryPassword
	if response := accountRequest(test, server, http.MethodPost, "/api/v1/auth/login", login, nil, nil); response.Code != http.StatusUnauthorized {
		test.Fatal("temporary password remained usable after personal change")
	}
}

func TestTemporaryPasswordSessionCanOnlySignOutItself(test *testing.T) {
	server := newTestServer(test)
	owner, _ := server.identity.GetUser(state.DefaultUserID)
	if _, err := server.identity.ResetRandomPasswordByPlatform(test.Context(), owner.ID, identity.PasswordResetOptions{Reason: "核实", ExpectedUpdatedAt: owner.UpdatedAt, OwnershipVerified: true}, "platform-token"); err != nil {
		test.Fatal(err)
	}
	cookie, token := seedUserSession(test, server, owner.ID)
	otherCookie, _ := seedUserSession(test, server, owner.ID)
	response := accountRequest(test, server, http.MethodGet, "/api/v1/account/sessions", nil, cookie, nil)
	if response.Code != http.StatusOK {
		test.Fatal("temporary session cannot read its logout metadata")
	}
	principal, err := server.principalForToken(test.Context(), otherCookie.Value)
	if err != nil {
		test.Fatal(err)
	}
	if response := accountRequest(test, server, http.MethodDelete, "/api/v1/account/sessions/"+principal.Session.ID, nil, cookie, map[string]string{"X-CSRF-Token": csrfTokenFor(token)}); response.Code != http.StatusForbidden {
		test.Fatal("temporary session revoked another login")
	}
	principal, err = server.principalForToken(test.Context(), token)
	if err != nil {
		test.Fatal(err)
	}
	if response := accountRequest(test, server, http.MethodDelete, "/api/v1/account/sessions/"+principal.Session.ID, nil, cookie, map[string]string{"X-CSRF-Token": csrfTokenFor(token)}); response.Code != http.StatusOK {
		test.Fatal("temporary session cannot sign out itself")
	}
}

func TestLegacyPasswordResetEndpointsRetiredWithoutMutation(test *testing.T) {
	router, server, _, token := randomResetRouter(test)
	owner, _ := server.identity.GetUser(state.DefaultUserID)
	cookie, _ := seedUserSession(test, server, owner.ID)
	for _, path := range []string{"/api/v1/auth/password-reset", "/api/platform/v1/organizations/first/users/1/password-reset"} {
		response := randomResetRequest(test, router.Handler(), "first.reset.test", path, token, randomResetBody(owner), nil)
		if response.Code != http.StatusGone || !strings.Contains(response.Body.String(), "PASSWORD_RESET_RETIRED") {
			test.Fatal("legacy code endpoint still accepts writes")
		}
	}
	current, _ := server.identity.GetUser(owner.ID)
	if current != owner || accountRequest(test, server, http.MethodGet, "/api/v1/account", nil, cookie, nil).Code != http.StatusOK {
		test.Fatal("retired endpoint mutated the original account")
	}
	providers := accountRequest(test, server, http.MethodGet, "/api/v1/auth/providers", nil, nil, nil)
	if !strings.Contains(providers.Body.String(), `"password_reset":false`) || strings.Contains(strings.Join(server.apiCapabilities(), " "), "account.password_reset") {
		test.Fatal("public capability still advertises reset codes")
	}
}
