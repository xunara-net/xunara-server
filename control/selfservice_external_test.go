package control

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/xunara-net/xunara-server/identity"
	"github.com/xunara-net/xunara-server/state"
)

func TestSelfServiceExternalFirstLoginCannotJoinPortal(t *testing.T) {
	provider := &fakeProvider{
		id: "fake", beginURL: "https://idp.example/authorize",
		result: identity.IdentityResult{ProviderID: "fake", Subject: "portal-subject", Email: "same-email@example.test"},
	}
	server := newServerWithConfig(t, Config{Providers: []identity.IdentityProvider{provider}, AllowLocalLogin: true, Registration: RegistrationOpen})
	server.setSelfService(&SelfServiceInfo{})
	owner, ok := server.identity.GetUser(state.DefaultUserID)
	if !ok {
		t.Fatal("owner fixture is missing")
	}
	owner.Email = provider.result.Email
	if err := server.identity.UpdateUser(owner); err != nil {
		t.Fatal(err)
	}
	host := newTestHTTPServer(t, server)
	client := noRedirectClient()
	callback := func(entry string) *http.Response {
		started := getRequest(t, client, host.URL+entry, nil)
		if started.StatusCode != http.StatusFound {
			t.Fatalf("external start = %d", started.StatusCode)
		}
		authorization, err := url.Parse(started.Header.Get("Location"))
		if err != nil {
			t.Fatal(err)
		}
		return getRequest(t, client, host.URL+"/oidc/callback/fake?code=fixture&state="+url.QueryEscape(authorization.Query().Get("state")), cookieNamed(t, started, authCookieName))
	}
	for _, entry := range []string{"/api/v1/auth/start?provider=fake", "/login?provider=fake"} {
		response := callback(entry)
		if response.StatusCode != http.StatusForbidden || !strings.Contains(bodyString(t, response), "TENANT_SIGNUP_REQUIRED") {
			t.Fatal("unknown external identity joined the self-service portal")
		}
		for _, cookie := range response.Cookies() {
			if cookie.Name == sessionCookieName && cookie.Value != "" {
				t.Fatal("rejected portal signup created a session cookie")
			}
		}
	}
	if len(server.identity.ListUsers()) != 1 || len(server.identity.ListSessions(owner.ID)) != 0 || len(server.store.ListNodes()) != 0 {
		t.Fatal("rejected portal signup created an account, session or trusted device")
	}
	if _, ok := server.identity.GetExternalIdentity(provider.ID(), provider.result.Subject); ok {
		t.Fatal("same email was used to link an unknown subject to the owner")
	}
	if err := server.identity.LinkExternalIdentity(&identity.ExternalIdentity{
		ProviderID: provider.ID(), Subject: provider.result.Subject, UserID: owner.ID, Email: owner.Email,
	}); err != nil {
		t.Fatal(err)
	}
	response := callback("/api/v1/auth/start?provider=fake")
	if response.StatusCode != http.StatusFound || response.Header.Get("Location") != "/dashboard" {
		t.Fatal("explicitly bound owner identity can no longer sign in")
	}
	session, err := server.identity.GetSessionByToken(cookieNamed(t, response, sessionCookieName).Value)
	if err != nil || session.UserID != owner.ID || len(server.identity.ListUsers()) != 1 {
		t.Fatal("explicit binding changed the owner or created another user")
	}
}
