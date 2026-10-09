package control

import (
	"net/http"
	"strings"
	"testing"

	"github.com/xunara-net/xunara-server/identity"
	"github.com/xunara-net/xunara-server/state"
)

func TestAuthAdmissionFailsClosedWhenRateStorageIsUnavailable(t *testing.T) {
	provider := &fakeProvider{id: "fake", beginURL: "https://idp.example/authorize"}
	server := newServerWithConfig(t, Config{Providers: []identity.IdentityProvider{provider}, AllowLocalLogin: true})
	// 不在 Start 后替换 Store 指针：配置观察器也在读取它，夹具本身不能引入竞态。
	if _, err := server.store.(*state.SQLiteStore).DB().Exec("CREATE TRIGGER unavailable_auth_rate BEFORE INSERT ON rate_limits BEGIN SELECT RAISE(ABORT, 'private rate storage diagnostic'); END"); err != nil {
		t.Fatal(err)
	}
	host := newTestHTTPServer(t, server)
	client := noRedirectClient()
	for _, endpoint := range []string{"/api/v1/auth/start?provider=fake", "/login?provider=fake"} {
		response := getRequest(t, client, host.URL+endpoint, nil)
		if response.StatusCode != http.StatusServiceUnavailable || strings.Contains(bodyString(t, response), "private rate storage") {
			t.Fatal("external login ignored or exposed rate storage failure")
		}
		for _, cookie := range response.Cookies() {
			if cookie.Name == authCookieName || cookie.Name == sessionCookieName {
				t.Fatal("failed admission created a browser binding")
			}
		}
	}
	response := postJSON(t, client, host.URL+"/api/v1/auth/signup", apiSignupRequest{Login: "blocked-registration", Password: "fixture-password-42"}, nil)
	if response.StatusCode != http.StatusServiceUnavailable {
		t.Fatal("JSON registration ignored rate storage failure")
	}
	response = postForm(t, client, host.URL+"/signup", nil, nil)
	if response.StatusCode != http.StatusServiceUnavailable || len(server.identity.ListUsers()) != 1 {
		t.Fatal("HTML registration ignored rate storage failure")
	}
}

func TestExternalLoginAdmissionIsRateLimited(t *testing.T) {
	provider := &fakeProvider{id: "fake", beginURL: "https://idp.example/authorize"}
	server := newServerWithConfig(t, Config{Providers: []identity.IdentityProvider{provider}})
	host := newTestHTTPServer(t, server)
	for attempt := 0; attempt <= loginAddressLimit; attempt++ {
		response := getRequest(t, noRedirectClient(), host.URL+"/api/v1/auth/start?provider=fake", nil)
		if attempt < loginAddressLimit {
			if response.StatusCode != http.StatusFound {
				t.Fatalf("allowed start = %d", response.StatusCode)
			}
		} else if response.StatusCode != http.StatusTooManyRequests || response.Header.Get("Retry-After") == "" {
			t.Fatal("exhausted authorization budget was ignored")
		}
	}
}
