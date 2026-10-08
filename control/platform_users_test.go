package control

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/xunara-net/xunara-server/identity"
)

// platformAPIRequest performs one platform API request with the admin token.
func platformAPIRequest(t *testing.T, handler http.Handler, method, path, token string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, "http://platform.test"+path, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	return recorder
}

// TestPlatformUsersListsEveryTenant covers the admin SPA's user table: every
// account of every organization, with its plan and live session count.
func TestPlatformUsersListsEveryTenant(t *testing.T) {
	router, _, token := newAdminTestRouter(t)
	handler := router.Handler()

	server := router.serverFor("acme")
	if server == nil {
		t.Fatal("test router has no acme organization")
	}
	second := identity.User{LoginName: "bob", DisplayName: "Bob", Role: identity.RoleMember}
	if err := server.identity.CreateUser(&second); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if _, _, err := server.identity.CreateSession(identity.NewSessionOptions{
		UserID: second.ID, AuthMethod: identity.LocalProviderID, TTL: time.Hour,
	}); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	recorder := platformAPIRequest(t, handler, http.MethodGet, "/api/platform/v1/users", token)
	if recorder.Code != http.StatusOK {
		t.Fatalf("GET /api/platform/v1/users = %d (%s)", recorder.Code, recorder.Body.String())
	}
	var body struct {
		Users []platformUser `json:"users"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("decoding users: %v", err)
	}
	if len(body.Users) != 2 {
		t.Fatalf("users = %d, want the two accounts of acme", len(body.Users))
	}
	var bob *platformUser
	for i := range body.Users {
		if body.Users[i].Login == "bob" {
			bob = &body.Users[i]
		}
	}
	if bob == nil {
		t.Fatalf("bob is missing from %+v", body.Users)
	}
	if bob.Sessions != 1 || bob.Org != "acme" || bob.Plan != planIDForTest(t, router) {
		t.Errorf("bob = %+v, want one session on acme with the tenant plan", bob)
	}
}

// planIDForTest reads the plan assigned to acme.
func planIDForTest(t *testing.T, router *Router) string {
	t.Helper()
	if router.cfg.Plans == nil {
		return ""
	}
	return router.cfg.Plans.Plan(t.Context(), "acme").ID
}

// TestPlatformUsersRequireTheToken pins that the user API is not a tenant
// surface: without the platform token it answers 401.
func TestPlatformUsersRequireTheToken(t *testing.T) {
	router, _, _ := newAdminTestRouter(t)
	recorder := platformAPIRequest(t, router.Handler(), http.MethodGet, "/api/platform/v1/users", "wrong-token")
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("GET users without the platform token = %d, want 401", recorder.Code)
	}
}

// TestPlatformRevokeUserSessions covers the force-logout action.
func TestPlatformRevokeUserSessions(t *testing.T) {
	router, _, token := newAdminTestRouter(t)
	handler := router.Handler()
	server := router.serverFor("acme")
	if server == nil {
		t.Fatal("test router has no acme organization")
	}

	user := identity.User{LoginName: "carol", DisplayName: "Carol", Role: identity.RoleMember}
	if err := server.identity.CreateUser(&user); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if _, _, err := server.identity.CreateSession(identity.NewSessionOptions{
		UserID: user.ID, AuthMethod: identity.LocalProviderID, TTL: time.Hour,
	}); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	recorder := platformAPIRequest(t, handler, http.MethodPost,
		"/api/platform/v1/organizations/acme/users/"+itoa(user.ID)+"/revoke", token)
	if recorder.Code != http.StatusOK {
		t.Fatalf("revoke = %d (%s), want 200", recorder.Code, recorder.Body.String())
	}
	var body struct {
		Revoked int64 `json:"revoked"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("decoding revoke answer: %v", err)
	}
	if body.Revoked != 1 {
		t.Errorf("revoked = %d, want 1", body.Revoked)
	}
	for _, session := range server.identity.ListSessions(user.ID) {
		if session.RevokedAt.IsZero() {
			t.Errorf("session %s is still live after the revoke", session.ID)
		}
	}
}

// TestPlatformDeleteUserGuardsTheLastOwner pins the two lockout guards.
func TestPlatformDeleteUserGuardsTheLastOwner(t *testing.T) {
	router, _, token := newAdminTestRouter(t)
	handler := router.Handler()
	server := router.serverFor("acme")
	if server == nil {
		t.Fatal("test router has no acme organization")
	}

	users := server.identity.ListUsers()
	if len(users) != 1 || users[0].Role != identity.RoleOwner {
		t.Fatalf("test setup wants exactly one owner, got %+v", users)
	}

	recorder := platformAPIRequest(t, handler, http.MethodDelete,
		"/api/platform/v1/organizations/acme/users/"+itoa(users[0].ID), token)
	if recorder.Code != http.StatusConflict {
		t.Fatalf("deleting the last owner = %d, want 409", recorder.Code)
	}
	if _, ok := server.identity.GetUser(users[0].ID); !ok {
		t.Fatalf("the owner was deleted despite the guard")
	}

	// Adding a second owner makes the first deletable.
	second := identity.User{LoginName: "dave", DisplayName: "Dave", Role: identity.RoleOwner}
	if err := server.identity.CreateUser(&second); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	recorder = platformAPIRequest(t, handler, http.MethodDelete,
		"/api/platform/v1/organizations/acme/users/"+itoa(users[0].ID), token)
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("deleting an owner with a peer = %d (%s), want 204", recorder.Code, recorder.Body.String())
	}
	if _, ok := server.identity.GetUser(users[0].ID); ok {
		t.Fatalf("the owner still exists after a successful delete")
	}
}
