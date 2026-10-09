package control

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/xunara-net/xunara-server/identity"
	"github.com/xunara-net/xunara-server/plan"
	"github.com/xunara-net/xunara-server/state"
)

func memberInviteRequestForTest(t *testing.T, client *http.Client, method, endpoint, token, csrf string, body any) *http.Response {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(method, endpoint, bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	if csrf != "" {
		request.Header.Set("X-CSRF-Token", csrf)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { response.Body.Close() })
	return response
}

func inviteOwnerToken(t *testing.T, server *Server) string {
	t.Helper()
	_, token, err := server.identity.CreateSession(identity.NewSessionOptions{UserID: state.DefaultUserID, TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func TestAPIMemberInvitationsCreateRedeemAndRevoke(t *testing.T) {
	server := newTestServer(t)
	host := newTestHTTPServer(t, server)
	client := noRedirectClient()
	token := inviteOwnerToken(t, server)
	endpoint := host.URL + "/api/v1/member-invitations"
	csrf := csrfTokenFor(token)
	created := memberInviteRequestForTest(t, client, http.MethodPost, endpoint, token, csrf,
		memberInviteRequest{Role: "admin", Note: "运营同事", TTLHours: 24})
	if created.StatusCode != http.StatusCreated || created.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("creation = %d", created.StatusCode)
	}
	var creation struct {
		Code       string `json:"code"`
		Invitation struct {
			ID string `json:"id"`
		} `json:"invitation"`
	}
	decodeJSONBody(t, created, &creation)
	if !strings.HasPrefix(creation.Code, identity.InvitePrefix) || creation.Invitation.ID == "" {
		t.Fatal("creation omitted the one-time code or ID")
	}
	listing := memberInviteRequestForTest(t, client, http.MethodGet, endpoint, token, "", nil)
	listed := bodyString(t, listing)
	if listing.StatusCode != http.StatusOK || strings.Contains(listed, creation.Code) || strings.Contains(listed, "TokenHash") || !strings.Contains(listed, "pending") || !strings.Contains(listed, csrf) {
		t.Fatal("invitation listing exposed a code or omitted its status/CSRF")
	}
	signup := postJSON(t, client, host.URL+"/api/v1/auth/signup", apiSignupRequest{
		Invite: creation.Code, Login: "invited-admin", Password: "invite-fixture-password-42",
	}, nil)
	if signup.StatusCode != http.StatusCreated {
		t.Fatalf("invitation registration = %d", signup.StatusCode)
	}
	user, ok := server.identity.GetUserByLoginName("invited-admin")
	if !ok || user.Role != identity.RoleAdmin {
		t.Fatal("invited account did not receive the intended role")
	}
	replay := postJSON(t, client, host.URL+"/api/v1/auth/signup", apiSignupRequest{
		Invite: creation.Code, Login: "invited-replay", Password: "invite-fixture-password-42",
	}, nil)
	if replay.StatusCode != http.StatusForbidden {
		t.Fatalf("invite replay = %d", replay.StatusCode)
	}
	revokeUsed := memberInviteRequestForTest(t, client, http.MethodDelete, endpoint+"/"+creation.Invitation.ID, token, csrf, nil)
	if revokeUsed.StatusCode != http.StatusConflict {
		t.Fatalf("redeemed invitation revocation = %d", revokeUsed.StatusCode)
	}
	fresh := memberInviteRequestForTest(t, client, http.MethodPost, endpoint, token, csrf,
		memberInviteRequest{Role: "member", TTLHours: 1})
	decodeJSONBody(t, fresh, &creation)
	revoke := memberInviteRequestForTest(t, client, http.MethodDelete, endpoint+"/"+creation.Invitation.ID, token, csrf, nil)
	if revoke.StatusCode != http.StatusNoContent {
		t.Fatalf("unused invitation revocation = %d", revoke.StatusCode)
	}
	if _, err := server.identity.FindRegistrationInvite(creation.Code); !errors.Is(err, identity.ErrInviteNotFound) {
		t.Fatal("revoked invitation remains usable")
	}
}

func TestAPIMemberInvitationsRequireOwnerHumanSessionAndCSRF(t *testing.T) {
	server := newTestServer(t)
	host := newTestHTTPServer(t, server)
	endpoint := host.URL + "/api/v1/member-invitations"
	owner := inviteOwnerToken(t, server)
	_, service, err := server.identity.CreateAPIKey(identity.NewAPIKeyOptions{
		UserID: state.DefaultUserID, Name: "fixture", Scopes: []string{identity.ScopeRead, identity.ScopeWrite},
	})
	if err != nil {
		t.Fatal(err)
	}
	credentials := []string{service}
	for _, role := range []identity.Role{identity.RoleAdmin, identity.RoleMember} {
		user := identity.User{LoginName: "invite-" + string(role), Role: role}
		if err := server.identity.CreateUser(&user); err != nil {
			t.Fatal(err)
		}
		_, token, err := server.identity.CreateSession(identity.NewSessionOptions{UserID: user.ID, TTL: time.Hour})
		if err != nil {
			t.Fatal(err)
		}
		credentials = append(credentials, token)
	}
	for _, token := range credentials {
		for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodDelete} {
			target := endpoint
			if method == http.MethodDelete {
				target += "/fixture"
			}
			response := memberInviteRequestForTest(t, noRedirectClient(), method, target, token, csrfTokenFor(token), memberInviteRequest{Role: "member", TTLHours: 1})
			if response.StatusCode != http.StatusForbidden {
				t.Fatalf("non-owner/session credential accepted for %s: %d", method, response.StatusCode)
			}
		}
	}
	for _, csrf := range []string{"", "wrong-csrf"} {
		response := memberInviteRequestForTest(t, noRedirectClient(), http.MethodPost, endpoint, owner, csrf, memberInviteRequest{Role: "member", TTLHours: 1})
		if response.StatusCode != http.StatusForbidden {
			t.Fatal("invitation created without a session-bound CSRF token")
		}
	}
	if len(server.identity.ListRegistrationInvites()) != 0 {
		t.Fatal("denied requests created invitations")
	}
}

func TestAPIMemberInvitationsModeQuotaValidationAndTenantBoundary(t *testing.T) {
	for _, mode := range []RegistrationMode{RegistrationClosed, RegistrationOpen} {
		server := newServerWithConfig(t, Config{Registration: mode})
		host := newTestHTTPServer(t, server)
		token := inviteOwnerToken(t, server)
		response := memberInviteRequestForTest(t, noRedirectClient(), http.MethodPost, host.URL+"/api/v1/member-invitations", token, csrfTokenFor(token), memberInviteRequest{Role: "member", TTLHours: 1})
		if response.StatusCode != http.StatusForbidden {
			t.Fatal("invitations bypassed the tenant registration mode")
		}
	}
	free := freePlan(t)
	server := newServerWithConfig(t, Config{PlanSource: func(string) plan.Plan { return free }})
	host := newTestHTTPServer(t, server)
	token := inviteOwnerToken(t, server)
	endpoint := host.URL + "/api/v1/member-invitations"
	response := memberInviteRequestForTest(t, noRedirectClient(), http.MethodPost, endpoint, token, csrfTokenFor(token), memberInviteRequest{Role: "member", TTLHours: 1})
	if response.StatusCode != http.StatusForbidden || !strings.Contains(bodyString(t, response), "USER_LIMIT_REACHED") {
		t.Fatal("Free single-member plan issued an invitation")
	}
	for _, body := range []memberInviteRequest{
		{Role: "owner", TTLHours: 1}, {Role: "unknown", TTLHours: 1}, {Role: "member", TTLHours: 0},
		{Role: "member", TTLHours: 8761}, {Role: "member", TTLHours: 1, Note: strings.Repeat("中", 201)},
	} {
		response := memberInviteRequestForTest(t, noRedirectClient(), http.MethodPost, endpoint, token, csrfTokenFor(token), body)
		if response.StatusCode != http.StatusBadRequest {
			t.Fatalf("invalid invitation request = %d", response.StatusCode)
		}
	}
	other := newTestServer(t)
	otherHost := newTestHTTPServer(t, other)
	if response := memberInviteRequestForTest(t, noRedirectClient(), http.MethodGet, otherHost.URL+"/api/v1/member-invitations", token, "", nil); response.StatusCode != http.StatusUnauthorized {
		t.Fatal("owner session crossed the tenant boundary")
	}
	_, code, err := server.identity.CreateRegistrationInvite(identity.NewRegistrationInviteOptions{Role: identity.RoleMember, TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if signup := postJSON(t, noRedirectClient(), otherHost.URL+"/api/v1/auth/signup", apiSignupRequest{Invite: code, Login: "cross-tenant", Password: "invite-fixture-password-42"}, nil); signup.StatusCode != http.StatusForbidden {
		t.Fatal("invitation code crossed the tenant boundary")
	}
}

func TestAPIMemberInvitationReadFailureIsNotAnEmptyList(t *testing.T) {
	server := newTestServer(t)
	token := inviteOwnerToken(t, server)
	if _, err := server.store.(*state.SQLiteStore).DB().Exec("ALTER TABLE registration_invites RENAME TO unavailable_registration_invites"); err != nil {
		t.Fatal(err)
	}
	host := newTestHTTPServer(t, server)
	response := memberInviteRequestForTest(t, noRedirectClient(), http.MethodGet, host.URL+"/api/v1/member-invitations", token, "", nil)
	body := bodyString(t, response)
	if response.StatusCode != http.StatusServiceUnavailable || strings.Contains(body, "registration_invites") || strings.Contains(body, "items") {
		t.Fatal("storage outage was exposed or reported as an empty list")
	}
}
