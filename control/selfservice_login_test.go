package control

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/xunara-net/xunara-server/identity"
)

func TestAccountLoginFindsTenantWithoutNetworkIdentifier(test *testing.T) {
	router := nativeTestRouter(test)
	response := postJSONAtHost(test, router.Handler(), "app.xunara.test", selfServiceLoginPath,
		apiLoginRequest{Login: "ALICE", Password: testLocalPassword})
	var payload struct {
		ConsolePath string `json:"console_path"`
		Session     struct {
			Authenticated bool `json:"authenticated"`
			User          struct {
				Login string `json:"login_name"`
			} `json:"user"`
		} `json:"session"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil || response.Code != http.StatusOK || !payload.Session.Authenticated || payload.ConsolePath != "/t/alice" || payload.Session.User.Login != "alice" {
		test.Fatalf("ordinary account login: %d %s", response.Code, response.Body.String())
	}
	if cookies := response.Result().Cookies(); len(cookies) != 1 || cookies[0].Name != tenantCookieName(sessionCookieName, "alice") {
		test.Fatal("global login established an unscoped root session")
	}
	for _, credentials := range []apiLoginRequest{{Login: "missing", Password: testLocalPassword}, {Login: "alice", Password: "wrong-password"}} {
		failure := postJSONAtHost(test, router.Handler(), "app.xunara.test", selfServiceLoginPath, credentials)
		if failure.Code != http.StatusUnauthorized || len(failure.Result().Cookies()) != 0 {
			test.Fatalf("invalid account login: %d %s", failure.Code, failure.Body.String())
		}
	}
	// 同名历史账户不按密码挑一个，更不能回到入口管理员。
	seedRoleUser(test, router.nativeGateway.front, "alice", identity.RoleAdmin)
	ambiguous := postJSONAtHost(test, router.Handler(), "app.xunara.test", selfServiceLoginPath,
		apiLoginRequest{Login: "alice", Password: testLocalPassword})
	if ambiguous.Code != http.StatusUnauthorized || len(ambiguous.Result().Cookies()) != 0 {
		test.Fatal("ambiguous login selected a tenant")
	}
	foreign := postJSONAtHost(test, router.Handler(), "acme.xunara.test", selfServiceLoginPath,
		apiLoginRequest{Login: "alice", Password: testLocalPassword})
	if foreign.Code != http.StatusNotFound {
		test.Fatal("another host exposed the global account login")
	}
}

func TestAccountLoginStorageErrorDoesNotGuessDefault(test *testing.T) {
	router := nativeTestRouter(test)
	if err := router.orgByID("acme").site.Server.Close(); err != nil {
		test.Fatal(err)
	}
	response := postJSONAtHost(test, router.Handler(), "app.xunara.test", selfServiceLoginPath,
		apiLoginRequest{Login: "alice", Password: testLocalPassword})
	if response.Code != http.StatusServiceUnavailable || len(response.Result().Cookies()) != 0 {
		test.Fatalf("storage error = %d %s", response.Code, response.Body.String())
	}
}

func TestCookieDeviceApprovalRequiresSessionCSRF(test *testing.T) {
	server := newTestServer(test)
	_, token, err := server.identity.CreateSession(identity.NewSessionOptions{UserID: 1})
	if err != nil {
		test.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "http://login.test/api/v1/devices", nil)
	request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token})
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	var list pendingDevicesView
	if err := json.Unmarshal(response.Body.Bytes(), &list); err != nil || response.Code != http.StatusOK || list.CSRFToken != csrfTokenFor(token) {
		test.Fatalf("approval metadata = %d %s", response.Code, response.Body.String())
	}
	decision := httptest.NewRequest(http.MethodPost, "http://login.test/api/v1/devices/untrusted/approve", nil)
	decision.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token})
	rejected := httptest.NewRecorder()
	server.Handler().ServeHTTP(rejected, decision)
	if rejected.Code != http.StatusForbidden {
		test.Fatalf("cookie approval without CSRF = %d", rejected.Code)
	}
}
