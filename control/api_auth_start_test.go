package control

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/xunara-net/xunara-server/identity"
)

func TestAPIExternalLoginStart(t *testing.T) {
	provider := &fakeProvider{
		id: "fake", beginURL: "https://idp.example/authorize",
		result: identity.IdentityResult{ProviderID: "fake", Subject: "subject-api", DisplayName: "API applicant"},
	}
	server := newServerWithConfig(t, Config{Providers: []identity.IdentityProvider{provider}})
	host := newTestHTTPServer(t, server)
	client := noRedirectClient()
	var payload struct {
		Providers []struct {
			StartURL string `json:"start_url"`
		}
	}
	decodeJSONBody(t, getRequest(t, client, host.URL+"/api/v1/auth/providers", nil), &payload)
	if len(payload.Providers) != 1 || payload.Providers[0].StartURL != "/api/v1/auth/start?provider=fake" {
		t.Fatalf("unexpected provider entry: %+v", payload)
	}
	for _, target := range []string{"", "/security?tab=sessions#current", "/register/device-id", "//attacker.test", "/%2f/attacker.test", "/path\\attacker.test", "/security\n"} {
		t.Run(target, func(t *testing.T) {
			response := getRequest(t, client, host.URL+payload.Providers[0].StartURL+"&return_to="+url.QueryEscape(target), nil)
			if response.StatusCode != http.StatusFound || response.Header.Get("Cache-Control") != "no-store" {
				t.Fatalf("start = %d, cache = %q", response.StatusCode, response.Header.Get("Cache-Control"))
			}
			authorization, err := url.Parse(response.Header.Get("Location"))
			if err != nil || authorization.Host != "idp.example" || authorization.Query().Get("state") == "" {
				t.Fatal("start did not reach the provider")
			}
			binding := cookieNamed(t, response, authCookieName)
			callback := getRequest(t, client, host.URL+"/oidc/callback/fake?code=code&state="+url.QueryEscape(authorization.Query().Get("state")), binding)
			want := safeReturnTo(target)
			if target == "" {
				want = "/dashboard"
			}
			if callback.StatusCode != http.StatusFound || callback.Header.Get("Location") != want {
				t.Fatalf("callback = %d %q, want 302 %q", callback.StatusCode, callback.Header.Get("Location"), want)
			}
		})
	}
}

func TestAPIExternalLoginStartRejectsLocalAndUnknownProviders(t *testing.T) {
	server := newTestServer(t)
	host := newTestHTTPServer(t, server)
	for _, providerID := range []string{"", "local", "unknown"} {
		response := getRequest(t, noRedirectClient(), host.URL+"/api/v1/auth/start?provider="+url.QueryEscape(providerID), nil)
		if response.StatusCode != http.StatusBadRequest {
			t.Fatalf("provider %q = %d, want 400", providerID, response.StatusCode)
		}
		for _, cookie := range response.Cookies() {
			if cookie.Name == authCookieName || cookie.Name == sessionCookieName {
				t.Fatal("rejected provider created a browser identity")
			}
		}
	}
}
