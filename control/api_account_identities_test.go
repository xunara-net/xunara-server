package control

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/xunara-net/xunara-server/identity"
	"github.com/xunara-net/xunara-server/plan"
	"github.com/xunara-net/xunara-server/state"
)

func completeAccountAuthorization(t *testing.T, server *Server, start *httptest.ResponseRecorder, session *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	if start.Code != http.StatusOK {
		t.Fatalf("start: %d %s", start.Code, start.Body.String())
	}
	var payload map[string]any
	if err := json.Unmarshal(start.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	target, err := url.Parse(payload["authorization_url"].(string))
	if err != nil {
		t.Fatal(err)
	}
	binding := cookieNamed(t, start.Result(), authCookieName)
	cookies := binding.Name + "=" + binding.Value
	if session != nil {
		cookies += "; " + session.Name + "=" + session.Value
	}
	return accountRequest(t, server, http.MethodGet, "/oidc/callback/fake?code=fixture&state="+url.QueryEscape(target.Query().Get("state")), nil, nil, map[string]string{"Cookie": cookies})
}

func TestAccountIdentityHTTPBindingRequiresSameHumanSession(t *testing.T) {
	provider := &fakeProvider{id: "fake", beginURL: "https://idp.example/authorize", result: identity.IdentityResult{ProviderID: "fake", Subject: "never-public-subject", Email: "same@example.test"}}
	server := newServerWithConfig(t, Config{Providers: []identity.IdentityProvider{provider}, AllowLocalLogin: true})
	cookie, token := seedUserSession(t, server, state.DefaultUserID)
	body := map[string]string{"provider_id": "fake"}
	headers := map[string]string{"X-CSRF-Token": csrfTokenFor(token)}
	if response := accountRequest(t, server, http.MethodPost, "/api/v1/account/identities/begin", body, cookie, nil); response.Code != http.StatusForbidden {
		t.Fatal("missing CSRF accepted")
	}
	start := accountRequest(t, server, http.MethodPost, "/api/v1/account/identities/begin", body, cookie, headers)
	if response := completeAccountAuthorization(t, server, start, nil); response.Code != http.StatusForbidden {
		t.Fatal("stolen auth binding was enough to link an account")
	}
	other := seedRoleUser(t, server, "other", identity.RoleMember)
	otherCookie, _ := seedUserSession(t, server, other)
	if response := completeAccountAuthorization(t, server, start, otherCookie); response.Code != http.StatusForbidden {
		t.Fatal("account switch was not rejected")
	}
	response := completeAccountAuthorization(t, server, start, cookie)
	if response.Code != http.StatusFound || response.Header().Get("Location") != "/security?identity_binding=linked" {
		t.Fatalf("bind callback: %d %s", response.Code, response.Body.String())
	}
	for _, cookie := range response.Result().Cookies() {
		if cookie.Name == sessionCookieName && cookie.Value != "" {
			t.Fatal("binding replaced the current session")
		}
	}
	linked, ok := server.identity.GetExternalIdentity(provider.ID(), provider.result.Subject)
	if !ok || linked.UserID != state.DefaultUserID || len(server.identity.ListUsers()) != 2 {
		t.Fatal("binding changed user mapping")
	}
	listed := accountRequest(t, server, http.MethodGet, "/api/v1/account/identities", nil, cookie, nil)
	if listed.Code != http.StatusOK || strings.Contains(listed.Body.String(), provider.result.Subject) || strings.Contains(listed.Body.String(), "client_secret") {
		t.Fatal("binding metadata exposes provider subject or secret")
	}
	if response := accountRequest(t, server, http.MethodDelete, "/api/v1/account/identities/"+identity.IdentityReference(linked), nil, otherCookie, map[string]string{"X-CSRF-Token": csrfTokenFor(otherCookie.Value)}); response.Code != http.StatusNotFound {
		t.Fatal("another user could unlink this account")
	}
}

func TestExternalInvitationHTTPOnboardingAndClosedAdmission(t *testing.T) {
	provider := &fakeProvider{id: "fake", beginURL: "https://idp.example/authorize", result: identity.IdentityResult{ProviderID: "fake", Subject: "invite-subject", Email: "same@example.test"}}
	pro := proPlan(t)
	server := newServerWithConfig(t, Config{Providers: []identity.IdentityProvider{provider}, Registration: RegistrationInvite, PlanSource: func(string) plan.Plan { return pro }})
	cookie, token := seedUserSession(t, server, state.DefaultUserID)
	list := accountRequest(t, server, http.MethodGet, "/api/v1/member-invitations", nil, cookie, nil)
	if list.Code != http.StatusOK || decodeAPI(t, list.Result())["enabled"] != true {
		t.Fatal("OIDC-only tenant cannot invite members")
	}
	created := accountRequest(t, server, http.MethodPost, "/api/v1/member-invitations", map[string]any{"role": "admin", "ttl_hours": 24}, cookie, map[string]string{"X-CSRF-Token": csrfTokenFor(token)})
	if created.Code != http.StatusCreated {
		t.Fatalf("invitation create: %d %s", created.Code, created.Body.String())
	}
	code := decodeAPI(t, created.Result())["code"].(string)
	body := map[string]string{"provider_id": provider.ID(), "invite": code, "registration_token": server.newFormToken(formPurposeSignup)}
	start := accountRequest(t, server, http.MethodPost, "/api/v1/auth/invite/start", body, nil, nil)
	if strings.Contains(start.Body.String(), code) {
		t.Fatal("invite leaked into authorization URL")
	}
	response := completeAccountAuthorization(t, server, start, nil)
	if response.Code != http.StatusFound {
		t.Fatalf("invitation callback: %d %s", response.Code, response.Body.String())
	}
	session, err := server.identity.GetSessionByToken(cookieNamed(t, response.Result(), sessionCookieName).Value)
	if err != nil {
		t.Fatal(err)
	}
	user, ok := server.identity.GetUser(session.UserID)
	if !ok || user.Role != identity.RoleAdmin || user.ID == state.DefaultUserID || len(server.identity.ListUsers()) != 2 {
		t.Fatal("invitation lost role or linked an existing user by email")
	}
	if response := accountRequest(t, server, http.MethodPost, "/api/v1/auth/invite/start", body, nil, nil); response.Code != http.StatusBadRequest {
		t.Fatal("used invitation accepted")
	}
	provider.result.Subject = "uninvited-subject"
	authorization := accountRequest(t, server, http.MethodGet, "/api/v1/auth/start?provider=fake", nil, nil, nil)
	target, _ := url.Parse(authorization.Header().Get("Location"))
	authCookie := cookieNamed(t, authorization.Result(), authCookieName)
	response = accountRequest(t, server, http.MethodGet, "/oidc/callback/fake?code=fixture&state="+url.QueryEscape(target.Query().Get("state")), nil, authCookie, nil)
	if response.Code != http.StatusForbidden || len(server.identity.ListUsers()) != 2 {
		t.Fatal("plain OIDC login bypassed invitation admission")
	}
}

func TestExternalInvitationRevokedAfterBegin(t *testing.T) {
	provider := &fakeProvider{id: "fake", beginURL: "https://idp.example/authorize", result: identity.IdentityResult{ProviderID: "fake", Subject: "later-revoked"}}
	server := newServerWithConfig(t, Config{Providers: []identity.IdentityProvider{provider}})
	invite, code, err := server.identity.CreateRegistrationInvite(identity.NewRegistrationInviteOptions{Role: identity.RoleMember, TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	start := accountRequest(t, server, http.MethodPost, "/api/v1/auth/invite/start", map[string]string{"provider_id": provider.ID(), "invite": code, "registration_token": server.newFormToken(formPurposeSignup)}, nil, nil)
	if err := server.identity.RevokeRegistrationInvite(invite.ID); err != nil {
		t.Fatal(err)
	}
	response := completeAccountAuthorization(t, server, start, nil)
	if response.Code != http.StatusForbidden || len(server.identity.ListUsers()) != 1 {
		t.Fatal("invitation revocation during OAuth was ignored")
	}
}
