package control

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/xunara-net/xunara-server/identity"
)

type runtimeIdentityFixtureTransport struct{ target *url.URL }

func (transport runtimeIdentityFixtureTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	copy := request.Clone(request.Context())
	endpoint := *request.URL
	endpoint.Scheme, endpoint.Host = transport.target.Scheme, transport.target.Host
	copy.URL, copy.Host = &endpoint, transport.target.Host
	return http.DefaultTransport.RoundTrip(copy)
}

func TestRuntimeOAuth2ProviderUsesExistingBindingAndCallbackChain(test *testing.T) {
	fixture := newNativeOAuth2Fixture(test)
	server := newServerWithConfig(test, Config{ServerURL: "https://app.example.test"})
	cookie, token := seedUserSession(test, server, 1)
	created := authenticationSettingsRequest(test, server, http.MethodPost, "/api/v1/authentication/providers", map[string]any{
		"revision": 0, "id": "native-runtime", "type": "generic", "client_id": "native-client", "client_secret": "native-secret-not-public", "enabled": true,
		"auth_url": "https://1.1.1.1/authorize", "token_url": "https://1.1.1.1/token", "userinfo_url": "https://1.1.1.1/user", "subject_field": "id", "name_field": "name", "email_field": "email",
	}, token)
	if created.Code != http.StatusCreated {
		test.Fatalf("runtime provider: %d %s", created.Code, created.Body.String())
	}
	provider, _ := server.identityProviders().Get("native-runtime")
	target, _ := url.Parse(fixture.server.URL)
	// 只替换隔离夹具的传输；产品 API 没有绕过公网/TLS 校验的配置字段。
	provider.(*managedIdentityProvider).client.Transport = runtimeIdentityFixtureTransport{target}
	start := accountRequest(test, server, http.MethodPost, "/api/v1/account/identities/begin", map[string]string{"provider_id": "native-runtime"}, cookie, map[string]string{"X-CSRF-Token": csrfTokenFor(token)})
	callback := fixture.callback(test, start)
	completed := accountRequest(test, server, http.MethodGet, callback, nil, nil, nativeAuthCookies(test, start, cookie))
	if completed.Code != http.StatusFound || len(server.identity.ListUsers()) != 1 {
		test.Fatalf("runtime provider binding: %d", completed.Code)
	}
	if link, exists := server.identity.GetExternalIdentity("native-runtime", "42"); !exists || link.UserID != 1 {
		test.Fatal("runtime OAuth2 identity did not bind to the signed-in human account")
	}
	if replay := accountRequest(test, server, http.MethodGet, callback, nil, nil, nativeAuthCookies(test, start, cookie)); replay.Code == http.StatusFound {
		test.Fatal("runtime provider callback replay was accepted")
	}
	start = accountRequest(test, server, http.MethodPost, "/api/v1/account/identities/begin", map[string]string{"provider_id": "native-runtime"}, cookie, map[string]string{"X-CSRF-Token": csrfTokenFor(token)})
	callback = fixture.callback(test, start)
	rotated := authenticationSettingsRequest(test, server, http.MethodPatch, "/api/v1/authentication/providers/native-runtime", map[string]any{"revision": 1, "client_secret": "rotated-private-secret"}, token)
	if rotated.Code != http.StatusOK {
		test.Fatal("provider secret did not rotate")
	}
	denied := accountRequest(test, server, http.MethodGet, callback, nil, nil, nativeAuthCookies(test, start, cookie))
	if denied.Code == http.StatusFound || strings.Contains(denied.Body.String(), "rotated-private-secret") {
		test.Fatal("old callback survived configuration rotation or leaked the secret")
	}
	if _, err := server.identity.GetSessionByToken(token); err != nil {
		test.Fatal("provider rotation revoked an unrelated human session")
	}
	if !auditActionSet(test, server)[identity.AuditIdentityLinked] {
		test.Fatal("runtime provider binding was not audited")
	}
}
