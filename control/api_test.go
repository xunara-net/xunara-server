package control

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"tailscale.com/tailcfg"
	"tailscale.com/types/key"

	"github.com/xunara-net/xunara-server/identity"
	"github.com/xunara-net/xunara-server/state"
)

// seedAPIKey creates an API key owned by the built-in local user.
func seedAPIKey(t *testing.T, s *Server, scopes ...string) (identity.APIKey, string) {
	t.Helper()

	if len(scopes) == 0 {
		scopes = []string{identity.ScopeRead, identity.ScopeWrite}
	}
	key, token, err := s.Identity().CreateAPIKey(identity.NewAPIKeyOptions{
		Name: "test", UserID: state.DefaultUserID, Scopes: scopes,
	})
	if err != nil {
		t.Fatalf("CreateAPIKey: %v", err)
	}
	return key, token
}

// apiRequest performs a JSON API request with an optional bearer token.
func apiRequest(t *testing.T, client *http.Client, method, rawURL, token string, body any) *http.Response {
	t.Helper()

	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshalling body: %v", err)
		}
		reader = bytes.NewReader(raw)
	}

	req, err := http.NewRequest(method, rawURL, reader)
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, rawURL, err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

// decodeAPI decodes a JSON API response.
func decodeAPI(t *testing.T, resp *http.Response) map[string]any {
	t.Helper()

	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decoding API response: %v", err)
	}
	return out
}

func TestAPIAuthenticationAndScopes(t *testing.T) {
	s := newTestServer(t)
	hs := newTestHTTPServer(t, s)
	client := noRedirectClient()

	// No credentials: 401 with a challenge.
	resp := apiRequest(t, client, http.MethodGet, hs.URL+"/api/v1/machines", "", nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("anonymous status = %d, want 401", resp.StatusCode)
	}
	if !strings.HasPrefix(resp.Header.Get("WWW-Authenticate"), "Bearer") {
		t.Error("401 response lacks a Bearer challenge")
	}

	// A bogus token is refused.
	if resp := apiRequest(t, client, http.MethodGet, hs.URL+"/api/v1/machines", "nope", nil); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("bogus token status = %d, want 401", resp.StatusCode)
	}

	// A read-only key can read but not write.
	_, readToken := seedAPIKey(t, s, identity.ScopeRead)
	if resp := apiRequest(t, client, http.MethodGet, hs.URL+"/api/v1/machines", readToken, nil); resp.StatusCode != http.StatusOK {
		t.Errorf("read key status = %d, want 200", resp.StatusCode)
	}
	if resp := apiRequest(t, client, http.MethodPost, hs.URL+"/api/v1/auth-keys", readToken, map[string]any{"ttl": "1h"}); resp.StatusCode != http.StatusForbidden {
		t.Errorf("read key write status = %d, want 403", resp.StatusCode)
	}

	// A browser session authenticates the API too.
	sessionCookie := loginLocal(t, client, hs.URL, "/")
	req, _ := http.NewRequest(http.MethodGet, hs.URL+"/api/v1/overview", nil)
	req.AddCookie(sessionCookie)
	sessionResp, err := client.Do(req)
	if err != nil {
		t.Fatalf("session request: %v", err)
	}
	defer sessionResp.Body.Close()
	if sessionResp.StatusCode != http.StatusOK {
		t.Errorf("session status = %d, want 200", sessionResp.StatusCode)
	}
}

func TestAPIMachinesRoutesAndDeletion(t *testing.T) {
	s := newTestServer(t)
	hs := newTestHTTPServer(t, s)
	client := noRedirectClient()
	_, token := seedAPIKey(t, s)

	conn, _, nodeKey := registerNode(t, s, hs, "api-device")
	defer conn.Close()

	machines := decodeAPI(t, apiRequest(t, client, http.MethodGet, hs.URL+"/api/v1/machines", token, nil))["machines"].([]any)
	if len(machines) != 1 {
		t.Fatalf("machines = %v", machines)
	}
	first := machines[0].(map[string]any)
	nodeID := uint64(first["id"].(float64))
	if first["hostname"] != "api-device" || first["online"] != false {
		t.Errorf("machine = %v", first)
	}
	// No key material may leak through the API.
	for _, forbidden := range []string{"machineKey", "nodeKey", "discoKey"} {
		if _, ok := first[forbidden]; ok {
			t.Errorf("machine JSON exposes %s", forbidden)
		}
	}

	// Approve a subnet route.
	resp := apiRequest(t, client, http.MethodPost,
		hs.URL+"/api/v1/machines/"+itoa64(nodeID)+"/routes", token,
		map[string]any{"approve": []string{"10.10.0.0/16"}})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("route approve status = %d (%s)", resp.StatusCode, bodyString(t, resp))
	}
	updated := decodeAPI(t, resp)
	if routes, ok := updated["approvedRoutes"].([]any); !ok || len(routes) != 1 || routes[0] != "10.10.0.0/16" {
		t.Errorf("approvedRoutes = %v", updated["approvedRoutes"])
	}
	node, _ := s.Store().GetNodeByNodeKey(nodeKey.Public())
	if len(node.ApprovedRoutes) != 1 {
		t.Errorf("stored routes = %v", node.ApprovedRoutes)
	}
	if !auditActionSet(t, s)[identity.AuditRouteApproved] {
		t.Error("route approval was not audited")
	}

	// Unapprove it again.
	resp = apiRequest(t, client, http.MethodPost,
		hs.URL+"/api/v1/machines/"+itoa64(nodeID)+"/routes", token,
		map[string]any{"unapprove": []string{"10.10.0.0/16"}})
	updated = decodeAPI(t, resp)
	if routes := updated["approvedRoutes"].([]any); len(routes) != 0 {
		t.Errorf("approvedRoutes after unapprove = %v", routes)
	}

	// Delete (log out).
	if resp := apiRequest(t, client, http.MethodDelete, hs.URL+"/api/v1/machines/"+itoa64(nodeID), token, nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("delete status = %d", resp.StatusCode)
	}
	if _, ok := s.Store().GetNodeByID(state.NodeID(nodeID)); ok {
		t.Error("machine still registered after delete")
	}
	if !auditActionSet(t, s)[identity.AuditNodeDeleted] {
		t.Error("machine deletion was not audited")
	}
}

// itoa64 formats a numeric identifier for URLs.
func itoa64(v uint64) string { return strconv.FormatUint(v, 10) }

func TestAPIUsers(t *testing.T) {
	s := newTestServer(t)
	hs := newTestHTTPServer(t, s)
	client := noRedirectClient()
	_, token := seedAPIKey(t, s)

	users := decodeAPI(t, apiRequest(t, client, http.MethodGet, hs.URL+"/api/v1/users", token, nil))["users"].([]any)
	if len(users) != 1 {
		t.Fatalf("users = %v", users)
	}
	first := users[0].(map[string]any)
	if first["loginName"] != "local" {
		t.Errorf("user = %v", first)
	}
	identities := first["identities"].([]any)
	if len(identities) != 1 || identities[0].(map[string]any)["providerId"] != "local" {
		t.Errorf("identities = %v", identities)
	}

	// Rename: the change is visible in the netmap profile too.
	resp := apiRequest(t, client, http.MethodPatch, hs.URL+"/api/v1/users/1", token,
		map[string]any{"displayName": "Operator", "loginName": "operator@example.com"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("patch status = %d (%s)", resp.StatusCode, bodyString(t, resp))
	}
	profile := s.UserProfile(state.DefaultUserID)
	if profile.DisplayName != "Operator" || profile.LoginName != "operator@example.com" {
		t.Errorf("profile = %+v", profile)
	}
	if !auditActionSet(t, s)[identity.AuditUserUpdated] {
		t.Error("user update was not audited")
	}

	// A duplicate login name is a conflict.
	other := identity.User{LoginName: "taken@example.com"}
	if err := s.Identity().CreateUser(&other); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	resp = apiRequest(t, client, http.MethodPatch, hs.URL+"/api/v1/users/1", token,
		map[string]any{"loginName": "taken@example.com"})
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("duplicate login status = %d, want 409", resp.StatusCode)
	}
}

func TestAPIAuthKeysAndDevices(t *testing.T) {
	s := newTestServer(t)
	hs := newTestHTTPServer(t, s)
	client := noRedirectClient()
	_, token := seedAPIKey(t, s)

	// Create a pre-auth key; the secret is returned exactly once.
	resp := apiRequest(t, client, http.MethodPost, hs.URL+"/api/v1/auth-keys", token,
		map[string]any{"reusable": true, "ttl": "1h"})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create key status = %d (%s)", resp.StatusCode, bodyString(t, resp))
	}
	created := decodeAPI(t, resp)
	secret, _ := created["key"].(string)
	if !state.IsPreAuthKeySecret(secret) {
		t.Fatalf("created key = %v", created)
	}

	// Listing never includes secrets.
	listBody, err := json.Marshal(decodeAPI(t, apiRequest(t, client, http.MethodGet, hs.URL+"/api/v1/auth-keys", token, nil)))
	if err != nil {
		t.Fatalf("marshalling list: %v", err)
	}
	if bytes.Contains(listBody, []byte(secret)) {
		t.Error("auth key listing leaked the secret")
	}

	// The key works for registration.
	if _, err := s.handleRegister(t.Context(), tailcfg.RegisterRequest{
		Version: tailcfg.CurrentCapabilityVersion,
		NodeKey: key.NewNode().Public(),
		Auth:    &tailcfg.RegisterResponseAuth{AuthKey: secret},
		Hostinfo: &tailcfg.Hostinfo{
			Hostname: "api-key-node",
		},
	}, key.NewMachine().Public()); err != nil {
		t.Fatalf("registering with API-created key: %v", err)
	}

	// Delete the key.
	keyID := uint64(created["id"].(float64))
	if resp := apiRequest(t, client, http.MethodDelete, hs.URL+"/api/v1/auth-keys/"+itoa64(keyID), token, nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("delete key status = %d", resp.StatusCode)
	}

	// A pending device shows up and can be approved through the API.
	conn, _, _, authID := startRegistration(t, hs, "api-approval")
	defer conn.Close()

	devices := decodeAPI(t, apiRequest(t, client, http.MethodGet, hs.URL+"/api/v1/devices", token, nil))["devices"].([]any)
	if len(devices) != 1 || devices[0].(map[string]any)["hostname"] != "api-approval" {
		t.Fatalf("devices = %v", devices)
	}

	resp = apiRequest(t, client, http.MethodPost, hs.URL+"/api/v1/devices/"+authID+"/approve", token, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("approve device status = %d (%s)", resp.StatusCode, bodyString(t, resp))
	}
	da, ok := s.Identity().GetDeviceAuthorization(authID)
	if !ok || da.State != identity.DeviceApproved || da.UserID != state.DefaultUserID {
		t.Fatalf("device authorization = %+v, %v", da, ok)
	}

	// The audit actor names the API key.
	found := false
	for _, e := range s.Identity().ListAudit(0) {
		if e.Action == identity.AuditNodeApproved && strings.Contains(e.Actor, "/apikey:key-") {
			found = true
		}
	}
	if !found {
		t.Error("device approval was not attributed to the API key")
	}
}

func TestAPIKeysAreSelfDescribingAndRevocable(t *testing.T) {
	s := newTestServer(t)
	hs := newTestHTTPServer(t, s)
	client := noRedirectClient()
	_, token := seedAPIKey(t, s)

	resp := apiRequest(t, client, http.MethodPost, hs.URL+"/api/v1/api-keys", token,
		map[string]any{"name": "ci", "scopes": []string{"read"}, "ttl": "1h"})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create api key status = %d", resp.StatusCode)
	}
	created := decodeAPI(t, resp)
	newToken, _ := created["token"].(string)
	if !strings.HasPrefix(newToken, identity.APIKeyPrefix) {
		t.Fatalf("token = %q", newToken)
	}
	keyID := created["id"].(string)

	// The new key authenticates.
	if resp := apiRequest(t, client, http.MethodGet, hs.URL+"/api/v1/overview", newToken, nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("new key status = %d", resp.StatusCode)
	}

	// Listing must not contain the token.
	listBody, _ := json.Marshal(decodeAPI(t, apiRequest(t, client, http.MethodGet, hs.URL+"/api/v1/api-keys", token, nil)))
	if bytes.Contains(listBody, []byte(newToken)) {
		t.Error("api key listing leaked the token")
	}

	// Revocation takes effect immediately.
	if resp := apiRequest(t, client, http.MethodDelete, hs.URL+"/api/v1/api-keys/"+keyID, token, nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("revoke status = %d", resp.StatusCode)
	}
	if resp := apiRequest(t, client, http.MethodGet, hs.URL+"/api/v1/overview", newToken, nil); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("revoked key status = %d, want 401", resp.StatusCode)
	}
}

func TestAPIMiscEndpoints(t *testing.T) {
	s := newTestServer(t)
	hs := newTestHTTPServer(t, s)
	client := noRedirectClient()
	_, token := seedAPIKey(t, s)

	for _, path := range []string{"/api/v1/overview", "/api/v1/machines", "/api/v1/routes", "/api/v1/users", "/api/v1/dns", "/api/v1/policy", "/api/v1/devices", "/api/v1/audit", "/api/v1/auth-keys", "/api/v1/api-keys"} {
		resp := apiRequest(t, client, http.MethodGet, hs.URL+path, token, nil)
		if resp.StatusCode != http.StatusOK {
			t.Errorf("GET %s status = %d, want 200", path, resp.StatusCode)
		}
	}
	if resp := apiRequest(t, client, http.MethodGet, hs.URL+"/api/v1/sessions", token, nil); resp.StatusCode != http.StatusForbidden {
		t.Error("service key was allowed to read human sessions through a legacy path")
	}

	// Unknown paths and invalid bodies are handled, not panicked on.
	if resp := apiRequest(t, client, http.MethodPost, hs.URL+"/api/v1/auth-keys", token, map[string]any{"bogus": 1}); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("unknown field status = %d, want 400", resp.StatusCode)
	}
}
