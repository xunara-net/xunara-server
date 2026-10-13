package control

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func tenantConsoleRequest(t *testing.T, router *Router, method, path string, body any, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(method, "https://app.xunara.test"+path, bytes.NewReader(encoded))
	request.Header.Set("Content-Type", "application/json")
	for _, cookie := range cookies {
		request.AddCookie(cookie)
	}
	response := httptest.NewRecorder()
	router.Handler().ServeHTTP(response, request)
	return response
}

func TestTenantConsoleSignupAndPasswordRelogin(t *testing.T) {
	router, _ := selfServiceRouter(t, &SelfServiceConfig{
		DomainSuffix: "old-address.example.test", ConsoleURL: "https://app.xunara.test",
	})
	body := selfServiceRequest{Login: "shared-owner", Password: "SharedOwner-Strong-2026"}
	created := tenantConsoleRequest(t, router, http.MethodPost, selfServiceSignupPath, body)
	if created.Code != http.StatusCreated {
		t.Fatalf("signup status: %d", created.Code)
	}
	var result struct {
		Handoff      bool `json:"handoff"`
		Organization struct {
			URL        string `json:"url"`
			ConsoleURL string `json:"console_url"`
		} `json:"organization"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if !result.Handoff || result.Organization.ConsoleURL != "https://app.xunara.test/t/shared-owner" ||
		result.Organization.URL != "https://shared-owner.old-address.example.test" {
		t.Fatal("browser entry changed the native client URL or retained the unreachable redirect")
	}
	cookies := created.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != tenantCookieName(sessionCookieName, body.Login) ||
		cookies[0].Domain != "" || cookies[0].Path != "/t/shared-owner/" || !cookies[0].HttpOnly || !cookies[0].Secure {
		t.Fatal("tenant cookie is not isolated")
	}
	active := tenantConsoleRequest(t, router, http.MethodGet, "/t/shared-owner/api/v1/auth/session", nil, cookies...)
	if !strings.Contains(active.Body.String(), `"authenticated":true`) || !strings.Contains(active.Body.String(), `"organization_id":"shared-owner"`) {
		t.Fatal("signup session is not usable in the shared console")
	}
	// 不依赖注册 Cookie；关闭浏览器后，仍必须能用刚创建的账号真正再次登录。
	login := tenantConsoleRequest(t, router, http.MethodPost, "/t/shared-owner/api/v1/auth/login", map[string]string{
		"login": body.Login, "password": body.Password,
	})
	if login.Code != http.StatusOK || !strings.Contains(login.Body.String(), `"authenticated":true`) {
		t.Fatalf("relogin status: %d", login.Code)
	}
	root := tenantConsoleRequest(t, router, http.MethodGet, "/api/v1/auth/session", nil, cookies...)
	if strings.Contains(root.Body.String(), `"authenticated":true`) {
		t.Fatal("tenant session signed into the portal owner")
	}
	plain := *cookies[0]
	plain.Name = sessionCookieName
	for _, path := range []string{"/t/shared-owner/api/v1/auth/session", "/t/acme/api/v1/auth/session"} {
		response := tenantConsoleRequest(t, router, http.MethodGet, path, nil, &plain)
		if strings.Contains(response.Body.String(), `"authenticated":true`) {
			t.Fatal("root cookie bypassed tenant console isolation")
		}
	}
	for _, path := range []string{"/t/shared-owner/key", "/t/shared-owner/ts2021", "/t/shared-owner/api/platform/v1/organizations", "/t/unknown/api/v1/auth/session"} {
		if response := tenantConsoleRequest(t, router, http.MethodGet, path, nil, cookies...); response.Code != http.StatusNotFound {
			t.Fatalf("unexpected shared surface: %s (%d)", path, response.Code)
		}
	}
	wrong := httptest.NewRequest(http.MethodGet, "https://shared-owner.old-address.example.test/t/shared-owner/api/v1/auth/session", nil)
	response := httptest.NewRecorder()
	router.Handler().ServeHTTP(response, wrong)
	if response.Code != http.StatusNotFound {
		t.Fatal("noncanonical host served the shared console")
	}
}

func TestTenantConsoleWriterClearsScopedCookiesAndRedirects(t *testing.T) {
	response := httptest.NewRecorder()
	writer := &tenantConsoleWriter{ResponseWriter: response, orgID: "alice", secure: true}
	http.SetCookie(writer, &http.Cookie{Name: sessionCookieName, Value: "", MaxAge: -1, Path: "/", Domain: "example.test", HttpOnly: true})
	writer.Header().Set("Location", "/dashboard")
	writer.WriteHeader(http.StatusFound)
	cookie := response.Result().Cookies()[0]
	if cookie.Name != "xunara_session_tenant_alice" || cookie.Path != "/t/alice/" || cookie.Domain != "" || cookie.MaxAge != -1 ||
		response.Header().Get("Location") != "/t/alice/dashboard" {
		t.Fatal("logout or callback escaped its tenant scope")
	}
}
