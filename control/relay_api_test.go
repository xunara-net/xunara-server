package control

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/xunara-net/xunara-server/identity"
	"github.com/xunara-net/xunara-server/plan"
	"github.com/xunara-net/xunara-server/state"
)

// decodeBody decodes a JSON response body into v, failing the test on error.
func decodeTestBody(t *testing.T, resp *http.Response, v any) {
	t.Helper()
	if err := json.NewDecoder(resp.Body).Decode(v); err != nil {
		t.Fatalf("decoding %s: %v", resp.Request.URL.Path, err)
	}
}

// issueRelayEnrollToken creates an enrollment token through the console API.
func issueRelayEnrollToken(t *testing.T, hs *httptest.Server, apiKey, visibility string) (string, string) {
	t.Helper()
	resp := apiRequest(t, hs.Client(), http.MethodPost, hs.URL+"/api/v2/relays/enroll-tokens", apiKey,
		map[string]any{"name": "test", "visibility": visibility, "ttl_seconds": 3600})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("POST enroll-tokens status = %d, want 201", resp.StatusCode)
	}
	var created struct {
		Token string `json:"token"`
		Item  struct {
			ID         string `json:"id"`
			Visibility string `json:"visibility"`
			Used       bool   `json:"used"`
		} `json:"item"`
	}
	decodeTestBody(t, resp, &created)
	if created.Token == "" || created.Item.ID == "" {
		t.Fatalf("enrollment token response = %+v", created)
	}
	if created.Item.Used {
		t.Fatalf("a fresh enrollment token is already marked used")
	}
	return created.Token, created.Item.ID
}

// enrollRelay runs the relay-side enrollment call.
func enrollRelay(t *testing.T, hs *httptest.Server, token string, body map[string]any) *http.Response {
	t.Helper()
	if body == nil {
		body = map[string]any{
			"name": "hk-1", "region_code": "hk", "region_name": "Hong Kong",
			"hostname": "hk1.example.com", "node_key": "nodekey:abc",
			"version": "0.1.0", "derp_port": 443, "stun_port": 3478,
		}
	}
	return apiRequest(t, hs.Client(), http.MethodPost, hs.URL+relayEnrollPath, token, body)
}

func TestRelayEnrollHeartbeatAndSteering(t *testing.T) {
	s := newTestServer(t)
	_, apiKey := seedAPIKey(t, s, identity.ScopeRead, identity.ScopeWrite)
	hs := newTestHTTPServer(t, s)

	enrollToken, tokenID := issueRelayEnrollToken(t, hs, apiKey, string(state.RelayVisibilityOrganization))

	// The operator can list the outstanding token, but never its secret.
	resp := apiRequest(t, hs.Client(), http.MethodGet, hs.URL+"/api/v2/relays/enroll-tokens", apiKey, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET enroll-tokens status = %d", resp.StatusCode)
	}
	var listed struct {
		Items []map[string]any `json:"items"`
	}
	decodeTestBody(t, resp, &listed)
	if len(listed.Items) != 1 {
		t.Fatalf("enroll-tokens = %+v, want one", listed.Items)
	}
	if _, leaked := listed.Items[0]["token"]; leaked {
		t.Fatalf("enrollment token list leaked the secret")
	}

	// Enrollment exchanges the one-time token for an identity.
	resp = enrollRelay(t, hs, enrollToken, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("enroll status = %d, want 200", resp.StatusCode)
	}
	var identity struct {
		RelayID    string `json:"relay_id"`
		RelayToken string `json:"relay_token"`
		ControlURL string `json:"control_url"`
		Name       string `json:"name"`
	}
	decodeTestBody(t, resp, &identity)
	if identity.RelayID == "" || identity.RelayToken == "" {
		t.Fatalf("enrollment answer = %+v", identity)
	}
	if !state.ValidRelayToken(identity.RelayToken) {
		t.Fatalf("relay token %q does not validate", identity.RelayToken)
	}
	if identity.ControlURL != s.cfg.ServerURL {
		t.Fatalf("control_url = %q, want %q", identity.ControlURL, s.cfg.ServerURL)
	}

	// A consumed token cannot be replayed.
	if resp := enrollRelay(t, hs, enrollToken, nil); resp.StatusCode != http.StatusConflict {
		t.Fatalf("replayed enrollment status = %d, want 409", resp.StatusCode)
	}
	if resp := enrollRelay(t, hs, enrollToken, nil); resp.StatusCode == http.StatusOK {
		t.Fatalf("a consumed enrollment token enrolled a second relay")
	}

	// The relay appears in the operator list.
	resp = apiRequest(t, hs.Client(), http.MethodGet, hs.URL+"/api/v2/relays/enrolled", apiKey, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET relays/enrolled status = %d", resp.StatusCode)
	}
	var enrolledList struct {
		Items []relayView `json:"items"`
		Used  int         `json:"used"`
		Limit int         `json:"limit"`
	}
	decodeTestBody(t, resp, &enrolledList)
	if len(enrolledList.Items) != 1 || enrolledList.Used != 1 {
		t.Fatalf("enrolled relays = %+v", enrolledList)
	}
	if got := enrolledList.Items[0]; got.Visibility != string(state.RelayVisibilityOrganization) ||
		got.DesiredState != state.RelayStateOnline {
		t.Fatalf("relay view = %+v", got)
	}
	if enrolledList.Items[0].Online {
		t.Fatalf("a relay that never heartbeated is reported online")
	}

	// Heartbeats record telemetry and return the desired configuration.
	resp = apiRequest(t, hs.Client(), http.MethodPost, hs.URL+relayHeartbeatPath, identity.RelayToken,
		map[string]any{"version": "0.1.1", "healthy": true, "uptime_seconds": 3600,
			"connected_clients": 12, "bytes_in": 1000, "bytes_out": 2000})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("heartbeat status = %d, want 200", resp.StatusCode)
	}
	var cfg struct {
		DesiredState   string `json:"desired_state"`
		ConfigVersion  string `json:"config_version"`
		BandwidthLimit int64  `json:"bandwidth_limit"`
		RegionName     string `json:"region_name"`
	}
	decodeTestBody(t, resp, &cfg)
	if cfg.DesiredState != state.RelayStateOnline || cfg.ConfigVersion != "1" {
		t.Fatalf("first heartbeat answer = %+v", cfg)
	}

	// The heartbeat marks the relay online in the operator view.
	resp = apiRequest(t, hs.Client(), http.MethodGet, hs.URL+"/api/v2/relays/enrolled", apiKey, nil)
	decodeTestBody(t, resp, &enrolledList)
	if !enrolledList.Items[0].Online || enrolledList.Items[0].LastSeen == "" {
		t.Fatalf("relay after a heartbeat = %+v", enrolledList.Items[0])
	}

	// An operator steers the relay: state, bandwidth and region name.
	limit := int64(10485760)
	resp = apiRequest(t, hs.Client(), http.MethodPatch, hs.URL+"/api/v2/relays/"+identity.RelayID, apiKey,
		map[string]any{"desired_state": state.RelayStateMaintenance, "bandwidth_limit": limit, "region_name": "Hong Kong 2"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("PATCH relay status = %d, want 200", resp.StatusCode)
	}
	var updated relayView
	decodeTestBody(t, resp, &updated)
	if updated.DesiredState != state.RelayStateMaintenance || updated.ConfigVersion != 2 || updated.BandwidthLimit != limit {
		t.Fatalf("updated relay = %+v", updated)
	}

	// The next heartbeat carries the new configuration.
	resp = apiRequest(t, hs.Client(), http.MethodPost, hs.URL+relayHeartbeatPath, identity.RelayToken,
		map[string]any{"version": "0.1.1", "healthy": true})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("second heartbeat status = %d", resp.StatusCode)
	}
	decodeTestBody(t, resp, &cfg)
	if cfg.DesiredState != state.RelayStateMaintenance || cfg.ConfigVersion != "2" ||
		cfg.BandwidthLimit != limit || cfg.RegionName != "Hong Kong 2" {
		t.Fatalf("steered heartbeat answer = %+v", cfg)
	}

	// Revocation is terminal for the relay's credential.
	apiRequest(t, hs.Client(), http.MethodPatch, hs.URL+"/api/v2/relays/"+identity.RelayID, apiKey,
		map[string]any{"desired_state": state.RelayStateRevoked})
	resp = apiRequest(t, hs.Client(), http.MethodPost, hs.URL+relayHeartbeatPath, identity.RelayToken,
		map[string]any{"healthy": true})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("heartbeat of a revoked relay = %d, want 403", resp.StatusCode)
	}

	// Deleting the relay removes the credential entirely.
	resp = apiRequest(t, hs.Client(), http.MethodDelete, hs.URL+"/api/v2/relays/"+identity.RelayID, apiKey, nil)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("DELETE relay status = %d, want 204", resp.StatusCode)
	}
	if resp := apiRequest(t, hs.Client(), http.MethodPost, hs.URL+relayHeartbeatPath, identity.RelayToken,
		map[string]any{"healthy": true}); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("heartbeat after deletion = %d, want 401", resp.StatusCode)
	}

	// The consumed token is still listed, marked used.
	resp = apiRequest(t, hs.Client(), http.MethodGet, hs.URL+"/api/v2/relays/enroll-tokens", apiKey, nil)
	decodeTestBody(t, resp, &listed)
	if len(listed.Items) != 1 || listed.Items[0]["id"] != tokenID || listed.Items[0]["used"] != true {
		t.Fatalf("enrollment tokens after use = %+v", listed.Items)
	}
}

func TestRelayEnrollValidation(t *testing.T) {
	s := newTestServer(t)
	_, apiKey := seedAPIKey(t, s, identity.ScopeRead, identity.ScopeWrite)
	hs := newTestHTTPServer(t, s)

	// Unknown and malformed tokens are indistinguishable to a caller.
	if resp := enrollRelay(t, hs, "xrelay-enroll-unknown", nil); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unknown enrollment token = %d, want 401", resp.StatusCode)
	}
	if resp := enrollRelay(t, hs, "not-a-token", nil); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("malformed enrollment token = %d, want 401", resp.StatusCode)
	}

	// A malformed request does not consume the token: the caller can retry.
	token, _ := issueRelayEnrollToken(t, hs, apiKey, "")
	if resp := enrollRelay(t, hs, token, map[string]any{"hostname": "http://bad host"}); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("invalid hostname = %d, want 400", resp.StatusCode)
	}
	if resp := enrollRelay(t, hs, token, map[string]any{"hostname": "hk1.example.com"}); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("missing node key = %d, want 400", resp.StatusCode)
	}

	// Unknown fields are accepted, so a newer relay can talk to this build.
	resp := enrollRelay(t, hs, token, map[string]any{
		"name": "hk-1", "hostname": "hk1.example.com", "node_key": "nodekey:xyz",
		"region_code": "hk", "future_field": "ignored",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("enrollment with an unknown field = %d, want 200", resp.StatusCode)
	}
	var enrolled struct {
		RelayID string `json:"relay_id"`
	}
	decodeTestBody(t, resp, &enrolled)

	// The same node key cannot enroll twice.
	second, _ := issueRelayEnrollToken(t, hs, apiKey, "")
	if resp := enrollRelay(t, hs, second, map[string]any{
		"hostname": "hk2.example.com", "node_key": "nodekey:xyz",
	}); resp.StatusCode != http.StatusConflict {
		t.Fatalf("duplicate node key = %d, want 409", resp.StatusCode)
	}

	// An expired token is refused with the protocol's own code.
	expiredSecret, err := state.NewRelayEnrollmentTokenSecret()
	if err != nil {
		t.Fatalf("NewRelayEnrollmentTokenSecret: %v", err)
	}
	if err := s.store.CreateRelayEnrollmentToken(state.RelayEnrollmentToken{
		ID: "renr-expired", Expiry: time.Now().UTC().Add(-time.Minute),
	}, expiredSecret); err != nil {
		t.Fatalf("CreateRelayEnrollmentToken: %v", err)
	}
	resp = enrollRelay(t, hs, expiredSecret, nil)
	if resp.StatusCode != http.StatusGone {
		t.Fatalf("expired enrollment token = %d, want 410", resp.StatusCode)
	}
	var apiErr struct {
		Code string `json:"code"`
	}
	decodeTestBody(t, resp, &apiErr)
	if apiErr.Code != "RELAY_ENROLLMENT_EXPIRED" {
		t.Fatalf("expired token code = %q", apiErr.Code)
	}
}

func TestRelayPlanLimit(t *testing.T) {
	s := newTestServer(t)
	s.planSource = func(string) plan.Plan {
		return plan.Plan{ID: "limited-relay", Name: "Limited relay", MaxRelays: 1, AllowAPI: true}
	}
	_, apiKey := seedAPIKey(t, s, identity.ScopeRead, identity.ScopeWrite)
	hs := newTestHTTPServer(t, s)

	first, _ := issueRelayEnrollToken(t, hs, apiKey, "")
	if resp := enrollRelay(t, hs, first, nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("first relay enrollment = %d, want 200", resp.StatusCode)
	}

	// The plan allows one relay, so a second token cannot even be issued.
	resp := apiRequest(t, hs.Client(), http.MethodPost, hs.URL+"/api/v2/relays/enroll-tokens", apiKey,
		map[string]any{"name": "second"})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("token past the relay quota = %d, want 403", resp.StatusCode)
	}

	// A token issued before the quota filled is refused at enrollment time
	// with the protocol's own error code.
	direct, err := state.NewRelayEnrollmentTokenSecret()
	if err != nil {
		t.Fatalf("NewRelayEnrollmentTokenSecret: %v", err)
	}
	if err := s.store.CreateRelayEnrollmentToken(state.RelayEnrollmentToken{ID: "renr-direct"}, direct); err != nil {
		t.Fatalf("CreateRelayEnrollmentToken: %v", err)
	}
	resp = enrollRelay(t, hs, direct, map[string]any{
		"hostname": "hk2.example.com", "node_key": "nodekey:second",
	})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("enrollment past the relay quota = %d, want 403", resp.StatusCode)
	}
	var apiErr struct {
		Code string `json:"code"`
	}
	decodeTestBody(t, resp, &apiErr)
	if apiErr.Code != "RELAY_LIMIT_REACHED" {
		t.Fatalf("quota error code = %q, want RELAY_LIMIT_REACHED", apiErr.Code)
	}
	// 配额拒绝不消耗凭据，释放资源后仍能使用同一令牌完成注册。
	if record, exists := s.store.RelayEnrollmentTokenByID("renr-direct"); !exists || record.Used() {
		t.Fatal("quota rejection consumed the enrollment token")
	}
	if err := s.store.DeleteRelay(s.store.ListRelays()[0].ID); err != nil {
		t.Fatalf("DeleteRelay: %v", err)
	}
	resp = enrollRelay(t, hs, direct, map[string]any{
		"hostname": "hk2.example.com", "node_key": "nodekey:second",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("retry after releasing quota = %d, want 200", resp.StatusCode)
	}
}

func TestRelayPlatformAPI(t *testing.T) {
	site, err := New(Config{StateDir: t.TempDir(), ServerURL: "http://login.test"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	site.Start(ctx)
	t.Cleanup(cancel)
	site.setOrganization(OrgIdentity{ID: "acme", Name: "Acme"})

	router := newTestRouter(t, RouterConfig{
		Orgs:               []OrgSite{{ID: "acme", Name: "Acme", Server: site}},
		PlatformAdminToken: "platform-token",
	})
	hs := httptest.NewServer(router.Handler())
	t.Cleanup(hs.Close)

	// The operator issues a relay enrollment token for the tenant.
	resp := apiRequest(t, hs.Client(), http.MethodPost,
		hs.URL+"/api/platform/v1/organizations/acme/relays/enroll-tokens", "platform-token",
		map[string]any{"name": "hk-1", "visibility": state.RelayVisibilityPublic})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("platform enroll-token status = %d, want 201", resp.StatusCode)
	}
	var created struct {
		Token string `json:"token"`
	}
	decodeTestBody(t, resp, &created)

	// Enroll through the tenant's own handler (the router routes by host; with
	// one domain-less site every host reaches it), then steer through the
	// platform API.
	enrollResp := apiRequest(t, hs.Client(), http.MethodPost, hs.URL+relayEnrollPath, created.Token,
		map[string]any{"name": "hk-1", "hostname": "hk1.example.com", "node_key": "nodekey:plat",
			"region_code": "hk", "derp_port": 443})
	if enrollResp.StatusCode != http.StatusOK {
		t.Fatalf("enrollment through the router = %d, want 200", enrollResp.StatusCode)
	}
	var identity struct {
		RelayID string `json:"relay_id"`
	}
	decodeTestBody(t, enrollResp, &identity)

	resp = apiRequest(t, hs.Client(), http.MethodGet, hs.URL+"/api/platform/v1/relays", "platform-token", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("platform relay list = %d, want 200", resp.StatusCode)
	}
	var listResp struct {
		Relays []platformRelayView `json:"relays"`
		Count  int                 `json:"count"`
	}
	decodeTestBody(t, resp, &listResp)
	if listResp.Count != 1 || listResp.Relays[0].OrganizationID != "acme" ||
		listResp.Relays[0].Visibility != state.RelayVisibilityPublic {
		t.Fatalf("platform relay list = %+v", listResp)
	}

	resp = apiRequest(t, hs.Client(), http.MethodPatch,
		hs.URL+"/api/platform/v1/organizations/acme/relays/"+identity.RelayID, "platform-token",
		map[string]any{"desired_state": state.RelayStateDisabled})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("platform relay patch = %d, want 200", resp.StatusCode)
	}
	var patched platformRelayView
	decodeTestBody(t, resp, &patched)
	if patched.DesiredState != state.RelayStateDisabled || patched.ConfigVersion != 2 {
		t.Fatalf("platform relay patch = %+v", patched)
	}

	resp = apiRequest(t, hs.Client(), http.MethodDelete,
		hs.URL+"/api/platform/v1/organizations/acme/relays/"+identity.RelayID, "platform-token", nil)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("platform relay delete = %d, want 204", resp.StatusCode)
	}

	// The platform API stays fail closed without its token.
	resp = apiRequest(t, hs.Client(), http.MethodGet, hs.URL+"/api/platform/v1/relays", "", nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("platform relay list without a token = %d, want 401", resp.StatusCode)
	}
}

func TestSingleTenantRouterServesPlatformAPIAndAdmin(t *testing.T) {
	// A single-tenant deployment configures a platform token to get /admin and
	// the platform API; this is the shape cmd/xunarad builds for it (one
	// domain-less site, which becomes the fallback for every host).
	plans, _ := newTestPlanRegistry(t, t.TempDir())
	site, err := New(Config{StateDir: t.TempDir(), ServerURL: "http://login.test"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	site.Start(ctx)
	t.Cleanup(cancel)

	router := newTestRouter(t, RouterConfig{
		Orgs:               []OrgSite{{ID: "default", Name: "Default", Server: site}},
		PlatformAdminToken: "platform-token",
		Plans:              plans,
	})
	hs := httptest.NewServer(router.Handler())
	t.Cleanup(hs.Close)

	// The administrator entry point answers on the single host.
	resp, err := hs.Client().Get(hs.URL + "/admin/login")
	if err != nil {
		t.Fatalf("GET /admin/login: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /admin/login status = %d, want 200", resp.StatusCode)
	}

	// The platform API lists exactly the one tenant.
	resp2 := apiRequest(t, hs.Client(), http.MethodGet, hs.URL+"/api/platform/v1/organizations", "platform-token", nil)
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("GET platform organizations status = %d, want 200", resp2.StatusCode)
	}
	var orgs struct {
		Organizations []PlatformOrg `json:"organizations"`
	}
	decodeTestBody(t, resp2, &orgs)
	if len(orgs.Organizations) != 1 || orgs.Organizations[0].ID != "default" {
		t.Fatalf("platform organizations = %+v", orgs.Organizations)
	}
}
