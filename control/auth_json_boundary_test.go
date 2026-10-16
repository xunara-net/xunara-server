package control

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/xunara-net/xunara-server/identity"
	"github.com/xunara-net/xunara-server/state"
)

func TestAuthJSONRejectsSimpleFormContentTypes(test *testing.T) {
	server := newServerWithConfig(test, Config{Registration: RegistrationOpen})
	password := testLocalPassword + "="
	hash, err := identity.HashPassword(password)
	if err != nil {
		test.Fatal(err)
	}
	if err := server.identity.SetLocalCredential(&identity.LocalCredential{UserID: state.DefaultUserID, PasswordHash: hash}); err != nil {
		test.Fatal(err)
	}
	login := state.DefaultUserProfile(state.DefaultUserID).LoginName
	raw, err := json.Marshal(apiLoginRequest{Login: login, Password: password})
	if err != nil {
		test.Fatal(err)
	}
	before := len(server.identity.ListSessions(state.DefaultUserID))
	// text/plain 的 HTML 表单可构造以等号结尾的有效 JSON，不能只依赖 CORS 或 JSON 解码。
	for _, contentType := range []string{"text/plain", "application/x-www-form-urlencoded", "multipart/form-data; boundary=test", ""} {
		for _, endpoint := range []string{"/api/v1/auth/login", "/api/v1/auth/signup"} {
			response := accountRequest(test, server, http.MethodPost, endpoint, string(raw)+"\r\n", nil, map[string]string{
				"Content-Type": contentType, "Origin": "https://untrusted.invalid",
			})
			if response.Code != http.StatusUnsupportedMediaType || len(response.Result().Cookies()) != 0 ||
				!strings.Contains(response.Body.String(), "JSON_REQUIRED") {
				test.Fatalf("%s accepted a simple browser form instead of requiring JSON (%d)", endpoint, response.Code)
			}
		}
	}
	if len(server.identity.ListSessions(state.DefaultUserID)) != before {
		test.Fatal("simple form created a human session")
	}
	for _, contentType := range []string{"application/json", "application/json; charset=utf-8"} {
		response := accountRequest(test, server, http.MethodPost, "/api/v1/auth/login", string(raw), nil, map[string]string{"Content-Type": contentType})
		if response.Code != http.StatusOK {
			test.Fatal("valid JSON password login was rejected")
		}
	}
}
