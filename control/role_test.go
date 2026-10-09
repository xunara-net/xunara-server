package control

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"tailscale.com/tailcfg"

	"github.com/xunara-net/xunara-server/identity"
	"github.com/xunara-net/xunara-server/state"
)

// seedRoleUser creates a user with the given role and returns its ID.
func seedRoleUser(t *testing.T, s *Server, login string, role identity.Role) tailcfg.UserID {
	t.Helper()

	u := identity.User{LoginName: login, DisplayName: login, Role: role}
	if err := s.Identity().CreateUser(&u); err != nil {
		t.Fatalf("CreateUser(%s): %v", login, err)
	}
	return u.ID
}

// seedUserSession creates a live browser session for a user and returns the
// cookie plus the raw token (for CSRF derivation).
func seedUserSession(t *testing.T, s *Server, userID tailcfg.UserID) (*http.Cookie, string) {
	t.Helper()

	_, token, err := s.Identity().CreateSession(identity.NewSessionOptions{
		UserID:     userID,
		AuthMethod: "test",
		TTL:        time.Hour,
	})
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	return &http.Cookie{Name: sessionCookieName, Value: token}, token
}

// seedAPIKeyForUser creates an API key owned by an arbitrary user.
func seedAPIKeyForUser(t *testing.T, s *Server, userID tailcfg.UserID, scopes ...string) string {
	t.Helper()

	if len(scopes) == 0 {
		scopes = []string{identity.ScopeRead, identity.ScopeWrite}
	}
	_, token, err := s.Identity().CreateAPIKey(identity.NewAPIKeyOptions{
		Name: "role-test", UserID: userID, Scopes: scopes,
	})
	if err != nil {
		t.Fatalf("CreateAPIKey: %v", err)
	}
	return token
}

func TestAPIRoleGatesWrites(t *testing.T) {
	s := newTestServer(t)
	hs := newTestHTTPServer(t, s)
	client := noRedirectClient()

	memberID := seedRoleUser(t, s, "member@example.com", identity.RoleMember)
	adminID := seedRoleUser(t, s, "admin@example.com", identity.RoleAdmin)

	memberCookie, _ := seedUserSession(t, s, memberID)
	adminCookie, _ := seedUserSession(t, s, adminID)

	// Both roles may read.
	for name, cookie := range map[string]*http.Cookie{"member": memberCookie, "admin": adminCookie} {
		req, _ := http.NewRequest(http.MethodGet, hs.URL+"/api/v1/machines", nil)
		req.AddCookie(cookie)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("%s GET: %v", name, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("%s GET status = %d, want 200", name, resp.StatusCode)
		}
	}

	// A member session may not write.
	req, _ := http.NewRequest(http.MethodPost, hs.URL+"/api/v1/auth-keys",
		newJSONBody(map[string]any{"ttl": "1h"}))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(memberCookie)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("member POST: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("member write status = %d, want 403", resp.StatusCode)
	}

	// An admin session may write.
	req, _ = http.NewRequest(http.MethodPost, hs.URL+"/api/v1/auth-keys",
		newJSONBody(map[string]any{"ttl": "1h"}))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(adminCookie)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("admin POST: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Errorf("admin write status = %d, want 201", resp.StatusCode)
	}

	// A service key never widens its owner's role.
	memberToken := seedAPIKeyForUser(t, s, memberID)
	adminToken := seedAPIKeyForUser(t, s, adminID)
	if resp := apiRequest(t, client, http.MethodPost, hs.URL+"/api/v1/auth-keys", memberToken,
		map[string]any{"ttl": "1h"}); resp.StatusCode != http.StatusForbidden {
		t.Errorf("member key write status = %d, want 403", resp.StatusCode)
	}
	if resp := apiRequest(t, client, http.MethodPost, hs.URL+"/api/v1/auth-keys", adminToken,
		map[string]any{"ttl": "1h"}); resp.StatusCode != http.StatusCreated {
		t.Errorf("admin key write status = %d, want 201", resp.StatusCode)
	}
}

func TestAPIRoleChangeRequiresOwner(t *testing.T) {
	s := newTestServer(t)
	hs := newTestHTTPServer(t, s)
	client := noRedirectClient()

	ownerCookie := loginLocal(t, client, hs.URL, "/") // local user is the owner
	adminID := seedRoleUser(t, s, "admin@example.com", identity.RoleAdmin)
	adminCookie, _ := seedUserSession(t, s, adminID)

	// An admin cannot change roles, not even its own.
	req, _ := http.NewRequest(http.MethodPatch, hs.URL+"/api/v1/users/"+itoa(adminID),
		newJSONBody(map[string]any{"role": "owner"}))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(adminCookie)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("admin PATCH: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("admin role change status = %d, want 403", resp.StatusCode)
	}

	// The owner can promote the admin to owner.
	req, _ = http.NewRequest(http.MethodPatch, hs.URL+"/api/v1/users/"+itoa(adminID),
		newJSONBody(map[string]any{"role": "owner"}))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(ownerCookie)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("owner PATCH: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("owner role change status = %d, want 200", resp.StatusCode)
	}
	var view map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&view); err != nil {
		t.Fatalf("decoding user: %v", err)
	}
	if view["role"] != "owner" {
		t.Errorf("role = %v, want owner", view["role"])
	}

	// Audit records the change.
	actions := auditActionSet(t, s)
	if !actions[identity.AuditUserRoleChanged] {
		t.Error("role change was not audited")
	}

	// Now the local user is no longer the last owner; demoting it works.
	req, _ = http.NewRequest(http.MethodPatch, hs.URL+"/api/v1/users/"+itoa(state.DefaultUserID),
		newJSONBody(map[string]any{"role": "member"}))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(ownerCookie)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("demote last-non-owner PATCH: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("demote after another owner exists status = %d, want 200", resp.StatusCode)
	}
}

func TestAPICannotDemoteLastOwner(t *testing.T) {
	s := newTestServer(t)
	hs := newTestHTTPServer(t, s)
	client := noRedirectClient()
	ownerCookie := loginLocal(t, client, hs.URL, "/")

	resp := apiRequestWithCookie(t, client, http.MethodPatch, hs.URL+"/api/v1/users/"+itoa(state.DefaultUserID),
		ownerCookie, map[string]any{"role": "admin"})
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("demoting the only owner status = %d, want 409", resp.StatusCode)
	}
}

func TestDeletedUserCannotAuthenticate(t *testing.T) {
	s := newTestServer(t)
	hs := newTestHTTPServer(t, s)
	client := noRedirectClient()

	userID := seedRoleUser(t, s, "gone@example.com", identity.RoleAdmin)
	cookie, _ := seedUserSession(t, s, userID)
	keyToken := seedAPIKeyForUser(t, s, userID)

	req, _ := http.NewRequest(http.MethodGet, hs.URL+"/api/v1/machines", nil)
	req.AddCookie(cookie)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("session GET: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("session before deletion status = %d, want 200", resp.StatusCode)
	}

	if err := s.Identity().DeleteUser(userID); err != nil {
		t.Fatalf("DeleteUser: %v", err)
	}

	req, _ = http.NewRequest(http.MethodGet, hs.URL+"/api/v1/machines", nil)
	req.AddCookie(cookie)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("session GET after deletion: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("deleted user's session status = %d, want 401", resp.StatusCode)
	}

	if resp := apiRequest(t, client, http.MethodGet, hs.URL+"/api/v1/machines", keyToken, nil); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("deleted user's API key status = %d, want 401", resp.StatusCode)
	}
}

func TestConsoleRoleGating(t *testing.T) {
	s := newTestServer(t)
	hs := newTestHTTPServer(t, s)
	client := noRedirectClient()

	memberID := seedRoleUser(t, s, "viewer@example.com", identity.RoleMember)
	memberCookie, memberToken := seedUserSession(t, s, memberID)
	adminID := seedRoleUser(t, s, "operator@example.com", identity.RoleAdmin)
	adminCookie, adminToken := seedUserSession(t, s, adminID)

	// The member can read pages and is told the access is read-only.
	resp := getRequest(t, client, hs.URL+"/console/machines", memberCookie)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("member GET /console/machines status = %d, want 200", resp.StatusCode)
	}
	body := bodyString(t, resp)
	if want := "read-only"; !strings.Contains(body, want) {
		t.Errorf("member console page does not mention read-only access")
	}
	if strings.Contains(body, "Delete") {
		t.Error("member console page renders a Delete control")
	}

	// A write POST is rejected before CSRF even matters.
	resp = postForm(t, client, hs.URL+"/console/machines/1/delete",
		map[string][]string{"csrf": {csrfTokenFor(memberToken)}}, memberCookie)
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("member console write status = %d, want 403", resp.StatusCode)
	}

	// The admin can perform the same write (the node does not have to exist for
	// the guard to pass; a missing node renders an error page).
	resp = postForm(t, client, hs.URL+"/console/machines/1/delete",
		map[string][]string{"csrf": {csrfTokenFor(adminToken)}}, adminCookie)
	if resp.StatusCode == http.StatusForbidden {
		t.Errorf("admin console write status = %d, want anything but 403", resp.StatusCode)
	}
}

// helpers local to this file

// newJSONBody marshals v for a JSON request body.
func newJSONBody(v any) *bytes.Reader {
	raw, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return bytes.NewReader(raw)
}

// itoa renders a user ID for a URL path.
func itoa(id tailcfg.UserID) string { return strconv.FormatUint(uint64(id), 10) }

// apiRequestWithCookie performs a JSON request authenticated by a session
// cookie.
func apiRequestWithCookie(t *testing.T, client *http.Client, method, rawURL string, cookie *http.Cookie, body any) *http.Response {
	t.Helper()

	req, err := http.NewRequest(method, rawURL, newJSONBody(body))
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(cookie)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, rawURL, err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func TestDeviceApprovalRequiresWriteRole(t *testing.T) {
	s := newTestServer(t)
	hs := newTestHTTPServer(t, s)
	client := noRedirectClient()

	conn, _, _, authID := startRegistration(t, hs, "role-device")
	defer conn.Close()

	memberID := seedRoleUser(t, s, "approver@example.com", identity.RoleMember)
	memberCookie, memberToken := seedUserSession(t, s, memberID)
	adminID := seedRoleUser(t, s, "device-admin@example.com", identity.RoleAdmin)
	adminCookie, adminToken := seedUserSession(t, s, adminID)

	// The member sees the request but no approval controls.
	page := getRequest(t, client, hs.URL+"/register/"+authID, memberCookie)
	body := bodyString(t, page)
	if !strings.Contains(body, "read-only") {
		t.Error("member approval page does not mention read-only access")
	}
	if strings.Contains(body, "Approve device") {
		t.Error("member approval page renders the approve button")
	}

	// A member's approval POST is rejected.
	resp := postForm(t, client, hs.URL+"/register/"+authID+"/approve",
		map[string][]string{"csrf": {csrfTokenFor(memberToken)}}, memberCookie)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("member approval status = %d, want 403", resp.StatusCode)
	}
	if da, ok := s.Identity().GetDeviceAuthorization(authID); !ok || da.State != identity.DevicePending {
		t.Fatalf("device authorization state = %+v, want pending", da)
	}

	// An admin's approval goes through.
	resp = postForm(t, client, hs.URL+"/register/"+authID+"/approve",
		map[string][]string{"csrf": {csrfTokenFor(adminToken)}}, adminCookie)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("admin approval status = %d, want 200", resp.StatusCode)
	}
	if da, ok := s.Identity().GetDeviceAuthorization(authID); !ok || da.State != identity.DeviceApproved {
		t.Fatalf("device authorization state = %+v, want approved", da)
	}
}

func TestSSHCheckApprovalRequiresWriteRole(t *testing.T) {
	s := newServerWithConfig(t, Config{
		ServerURL:  "https://control.test",
		PolicyPath: policyFile(t, sshCheckPolicy),
	})
	hs := newTestHTTPServer(t, s)
	client := noRedirectClient()

	connA, _, nodeKeyA := registerNode(t, s, hs, "role-check-a")
	defer connA.Close()
	connB, clientB, nodeKeyB := registerNode(t, s, hs, "role-check-b")
	defer connB.Close()

	nodeA, ok := s.Store().GetNodeByNodeKey(nodeKeyA.Public())
	if !ok {
		t.Fatal("node A not found")
	}
	nodeB, ok := s.Store().GetNodeByNodeKey(nodeKeyB.Public())
	if !ok {
		t.Fatal("node B not found")
	}

	hold := fetchSSHAction(clientB, testContext(t), sshActionPath(nodeA.ID, nodeB.ID, "root", ""))
	if hold.err != nil || hold.action.HoldAndDelegate == "" {
		t.Fatalf("initial verdict request = %+v", hold)
	}
	authID := authIDFromHold(t, hold.action.HoldAndDelegate)

	memberID := seedRoleUser(t, s, "ssh-member@example.com", identity.RoleMember)
	memberCookie, memberToken := seedUserSession(t, s, memberID)

	page := getRequest(t, client, hs.URL+"/ssh/check/"+authID, memberCookie)
	if body := bodyString(t, page); !strings.Contains(body, "read-only") {
		t.Error("member SSH check page does not mention read-only access")
	}

	resp := postForm(t, client, hs.URL+"/ssh/check/"+authID+"/approve",
		map[string][]string{"csrf": {csrfTokenFor(memberToken)}}, memberCookie)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("member SSH check decision status = %d, want 403", resp.StatusCode)
	}
	if sess, ok := s.Identity().GetSSHCheckSession(authID); !ok || !sess.Pending() {
		t.Fatalf("SSH check session = %+v, want still pending", sess)
	}
}

func TestSelfServiceRevocation(t *testing.T) {
	s := newTestServer(t)
	hs := newTestHTTPServer(t, s)
	client := noRedirectClient()

	aliceID := seedRoleUser(t, s, "alice@example.com", identity.RoleMember)
	bobID := seedRoleUser(t, s, "bob@example.com", identity.RoleMember)
	adminID := seedRoleUser(t, s, "root@example.com", identity.RoleAdmin)

	aliceCookie, _ := seedUserSession(t, s, aliceID)
	bobCookie, _ := seedUserSession(t, s, bobID)
	adminCookie, _ := seedUserSession(t, s, adminID)

	aliceKey := seedAPIKeyForUser(t, s, aliceID)
	bobKey := seedAPIKeyForUser(t, s, bobID)

	// Alice revokes her own API key even though she is read-only.
	if resp := apiRequest(t, client, http.MethodDelete, hs.URL+"/api/v1/api-keys/"+keyIDOf(t, s, aliceKey), aliceKey, nil); resp.StatusCode != http.StatusOK {
		t.Errorf("member revoking own key status = %d, want 200", resp.StatusCode)
	}

	// Alice cannot revoke Bob's key.
	req, _ := http.NewRequest(http.MethodDelete, hs.URL+"/api/v1/api-keys/"+keyIDOf(t, s, bobKey), nil)
	req.AddCookie(aliceCookie)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("cross-user revoke: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("member revoking another user's key status = %d, want 403", resp.StatusCode)
	}

	// An admin may revoke someone else's key.
	req, _ = http.NewRequest(http.MethodDelete, hs.URL+"/api/v1/api-keys/"+keyIDOf(t, s, bobKey), nil)
	req.AddCookie(adminCookie)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("admin cross-user revoke: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("admin revoking another user's key status = %d, want 200", resp.StatusCode)
	}

	// Alice may revoke her own session.
	aliceSession, ok := sessionByCookie(t, s, aliceCookie)
	if !ok {
		t.Fatal("alice session not found")
	}
	req, _ = http.NewRequest(http.MethodDelete, hs.URL+"/api/v1/sessions/"+aliceSession.ID, nil)
	req.AddCookie(aliceCookie)
	req.Header.Set("X-CSRF-Token", csrfTokenFor(aliceCookie.Value))
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("self session revoke: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("member revoking own session status = %d, want 200", resp.StatusCode)
	}

	// Bob's session is untouched.
	if _, err := s.Identity().GetSessionByToken(bobCookie.Value); err != nil {
		t.Errorf("bob's session was affected: %v", err)
	}
}

// keyIDOf finds the public ID of a key by its token.
func keyIDOf(t *testing.T, s *Server, token string) string {
	t.Helper()

	key, err := s.Identity().GetAPIKeyByToken(token)
	if err != nil {
		t.Fatalf("GetAPIKeyByToken: %v", err)
	}
	return key.ID
}

// sessionByCookie resolves the session behind a test cookie.
func sessionByCookie(t *testing.T, s *Server, cookie *http.Cookie) (identity.Session, bool) {
	t.Helper()

	session, err := s.Identity().GetSessionByToken(cookie.Value)
	if err != nil {
		return identity.Session{}, false
	}
	return session, true
}
