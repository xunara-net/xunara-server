package control

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"tailscale.com/types/key"

	"github.com/xunara-net/xunara-server/identity"
	"github.com/xunara-net/xunara-server/idtoken"
	"github.com/xunara-net/xunara-server/state"
	"github.com/xunara-net/xunara-server/webhook"
)

// seedAPIMachine creates a node directly in the store.
func seedAPIMachine(t *testing.T, s *Server, hostname string, tags []string) state.Node {
	t.Helper()
	node := state.Node{
		MachineKey: key.NewMachine().Public(),
		NodeKey:    key.NewNode().Public(),
		UserID:     state.DefaultUserID,
		Hostname:   hostname,
		Tags:       tags,
		Method:     state.RegisterMethodAuthKey,
	}
	if err := s.store.CreateNode(&node); err != nil {
		t.Fatalf("CreateNode: %v", err)
	}
	return node
}

func TestAPIV2Meta(t *testing.T) {
	s := newTestServer(t)
	hs := newTestHTTPServer(t, s)
	client := noRedirectClient()

	if resp := apiRequest(t, client, http.MethodGet, hs.URL+"/api/v2/meta", "", nil); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("anonymous meta status = %d, want 401", resp.StatusCode)
	}

	_, token := seedAPIKey(t, s, identity.ScopeRead)
	resp := apiRequest(t, client, http.MethodGet, hs.URL+"/api/v2/meta", token, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("meta status = %d", resp.StatusCode)
	}
	meta := decodeAPI(t, resp)
	if meta["version"] != Version {
		t.Errorf("version = %v, want %s", meta["version"], Version)
	}
	if meta["maxPageSize"] != float64(apiV2MaxPageSize) {
		t.Errorf("maxPageSize = %v", meta["maxPageSize"])
	}
	if _, ok := meta["agentProtocolVersion"]; !ok {
		t.Error("meta lacks the agent protocol version")
	}
	// Feature discovery defaults: nothing optional is enabled on a bare
	// server, and a false must be reported, not omitted.
	for _, field := range []string{"reachEnabled", "fluxEnabled", "passkeysEnabled", "webhooksEnabled", "sharingEnabled"} {
		if meta[field] != false {
			t.Errorf("meta %s = %v, want false on a bare server", field, meta[field])
		}
	}
	// No key material or secrets in the discovery document.
	for _, forbidden := range []string{"noiseKey", "machineKey", "secret", "token"} {
		if _, ok := meta[forbidden]; ok {
			t.Errorf("meta leaks %q", forbidden)
		}
	}
}

// TestAPIV2MetaFeatureFlags checks that the discovery document reflects the
// optional features and, for webhooks, the endpoints created at runtime.
func TestAPIV2MetaFeatureFlags(t *testing.T) {
	s := newServerWithConfig(t, Config{
		ReachEnabled: true,
		Flux:         &FluxConfig{},
		Passkeys:     testPasskeyConfig(),
	})
	hs := newTestHTTPServer(t, s)
	client := noRedirectClient()
	_, readToken := seedAPIKey(t, s, identity.ScopeRead)
	_, writeToken := seedAPIKey(t, s)

	// A local receiver: the dispatcher delivers real audit events to enabled
	// endpoints, and a test must not talk to the outside world.
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(receiver.Close)

	meta := decodeAPI(t, apiRequest(t, client, http.MethodGet, hs.URL+"/api/v2/meta", readToken, nil))
	if meta["reachEnabled"] != true || meta["fluxEnabled"] != true || meta["passkeysEnabled"] != true {
		t.Errorf("enabled features = %v", meta)
	}
	if meta["webhooksEnabled"] != false {
		t.Errorf("webhooksEnabled without a receiver = %v, want false", meta["webhooksEnabled"])
	}

	// A paused managed endpoint is configured but does not deliver, so it
	// must not advertise webhook delivery.
	if _, err := s.storeManagedWebhook(webhook.Endpoint{ID: "paused", URL: "https://hooks.example.com/p", Secret: "s3cret"}, false); err != nil {
		t.Fatalf("storeManagedWebhook: %v", err)
	}
	meta = decodeAPI(t, apiRequest(t, client, http.MethodGet, hs.URL+"/api/v2/meta", readToken, nil))
	if meta["webhooksEnabled"] != false {
		t.Errorf("webhooksEnabled with only a paused endpoint = %v, want false", meta["webhooksEnabled"])
	}

	// Creating one through the API flips the flag without a restart.
	resp := apiRequest(t, client, http.MethodPost, hs.URL+"/api/v2/webhooks", writeToken, apiWebhookCreateRequest{
		ID:     "ops",
		URL:    receiver.URL,
		Secret: "s3cret",
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create status = %d", resp.StatusCode)
	}
	meta = decodeAPI(t, apiRequest(t, client, http.MethodGet, hs.URL+"/api/v2/meta", readToken, nil))
	if meta["webhooksEnabled"] != true {
		t.Errorf("webhooksEnabled after creating an endpoint = %v, want true", meta["webhooksEnabled"])
	}
}

func TestAPIV2MachinesPaginationAndFilters(t *testing.T) {
	s := newTestServer(t)
	hs := newTestHTTPServer(t, s)
	client := noRedirectClient()

	seeded := []state.Node{
		seedAPIMachine(t, s, "one", nil),
		seedAPIMachine(t, s, "two", []string{"tag:server"}),
		seedAPIMachine(t, s, "three", nil),
	}
	_, token := seedAPIKey(t, s, identity.ScopeRead)

	// First page: bounded and followed by a cursor.
	resp := apiRequest(t, client, http.MethodGet, hs.URL+"/api/v2/machines?limit=2", token, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("page 1 status = %d", resp.StatusCode)
	}
	page := decodeAPI(t, resp)
	items, _ := page["items"].([]any)
	if len(items) != 2 {
		t.Fatalf("page 1 items = %d, want 2", len(items))
	}
	cursor, _ := page["nextCursor"].(string)
	if cursor == "" {
		t.Fatal("page 1 lacks a next cursor")
	}

	// Second page: the rest, no cursor.
	resp = apiRequest(t, client, http.MethodGet, hs.URL+"/api/v2/machines?limit=2&cursor="+url.QueryEscape(cursor), token, nil)
	page = decodeAPI(t, resp)
	items, _ = page["items"].([]any)
	if len(items) != 1 {
		t.Fatalf("page 2 items = %d, want 1", len(items))
	}
	if next, _ := page["nextCursor"].(string); next != "" {
		t.Errorf("last page has cursor %q", next)
	}
	last := items[0].(map[string]any)
	if last["stableId"] != seeded[2].StableID {
		t.Errorf("page 2 item = %v, want the third machine", last["stableId"])
	}

	// Tag filter.
	resp = apiRequest(t, client, http.MethodGet, hs.URL+"/api/v2/machines?tag=tag:server", token, nil)
	page = decodeAPI(t, resp)
	if items, _ = page["items"].([]any); len(items) != 1 {
		t.Fatalf("tag filter items = %d, want 1", len(items))
	}
	if got := items[0].(map[string]any)["stableId"]; got != seeded[1].StableID {
		t.Errorf("tag filter item = %v", got)
	}

	// User filter accepts the login name, and an unknown name matches nothing
	// instead of silently unfiltering.
	resp = apiRequest(t, client, http.MethodGet, hs.URL+"/api/v2/machines?user=local", token, nil)
	page = decodeAPI(t, resp)
	if items, _ = page["items"].([]any); len(items) != 3 {
		t.Fatalf("user filter items = %d, want 3", len(items))
	}
	resp = apiRequest(t, client, http.MethodGet, hs.URL+"/api/v2/machines?user=nobody", token, nil)
	page = decodeAPI(t, resp)
	if items, _ = page["items"].([]any); len(items) != 0 {
		t.Fatalf("unknown user filter items = %d, want 0", len(items))
	}
	// "0" is not a user ID: it must match nothing, never mean "no filter".
	resp = apiRequest(t, client, http.MethodGet, hs.URL+"/api/v2/machines?user=0", token, nil)
	page = decodeAPI(t, resp)
	if items, _ = page["items"].([]any); len(items) != 0 {
		t.Fatalf("user=0 filter items = %d, want 0", len(items))
	}

	// Offline filter: no map session is open in this test.
	resp = apiRequest(t, client, http.MethodGet, hs.URL+"/api/v2/machines?state=offline", token, nil)
	page = decodeAPI(t, resp)
	if items, _ = page["items"].([]any); len(items) != 3 {
		t.Fatalf("offline filter items = %d, want 3", len(items))
	}

	// Malformed input is rejected, not ignored.
	for _, target := range []string{
		"/api/v2/machines?cursor=not-a-cursor",
		"/api/v2/machines?state=broken",
		"/api/v2/machines?limit=0",
		"/api/v2/machines?limit=nope",
	} {
		if resp := apiRequest(t, client, http.MethodGet, hs.URL+target, token, nil); resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%s status = %d, want 400", target, resp.StatusCode)
		}
	}
}

func TestAPIV2AuditPaginationAndFilters(t *testing.T) {
	s := newTestServer(t)
	hs := newTestHTTPServer(t, s)
	client := noRedirectClient()

	for i := 0; i < 5; i++ {
		s.audit("tester", "test.something", "test:target", "detail")
	}
	s.audit("tester", "test.special", "test:special", "detail")

	_, token := seedAPIKey(t, s, identity.ScopeRead)

	resp := apiRequest(t, client, http.MethodGet, hs.URL+"/api/v2/audit?limit=2", token, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("audit page status = %d", resp.StatusCode)
	}
	page := decodeAPI(t, resp)
	items, _ := page["items"].([]any)
	if len(items) != 2 {
		t.Fatalf("audit page items = %d, want 2", len(items))
	}
	cursor, _ := page["nextCursor"].(string)
	if cursor == "" {
		t.Fatal("audit page lacks a next cursor")
	}

	// The cursor continues without repeating or skipping events.
	seen := map[float64]bool{}
	for _, it := range items {
		seen[it.(map[string]any)["id"].(float64)] = true
	}
	for cursor != "" {
		resp = apiRequest(t, client, http.MethodGet, hs.URL+"/api/v2/audit?limit=2&cursor="+url.QueryEscape(cursor), token, nil)
		page = decodeAPI(t, resp)
		items, _ = page["items"].([]any)
		for _, it := range items {
			id := it.(map[string]any)["id"].(float64)
			if seen[id] {
				t.Fatalf("audit event %v delivered twice", id)
			}
			seen[id] = true
		}
		cursor, _ = page["nextCursor"].(string)
	}
	// The server seeds its local user at startup, so compare against the
	// store's own count rather than the number of events this test appended.
	if want := len(s.identity.ListAudit(0)); len(seen) != want {
		t.Fatalf("paged audit events = %d, want %d", len(seen), want)
	}

	// Action filter.
	resp = apiRequest(t, client, http.MethodGet, hs.URL+"/api/v2/audit?action=test.special", token, nil)
	page = decodeAPI(t, resp)
	if items, _ = page["items"].([]any); len(items) != 1 {
		t.Fatalf("action filter items = %d, want 1", len(items))
	}
	if got := items[0].(map[string]any)["target"]; got != "test:special" {
		t.Errorf("action filter item = %v", got)
	}

	if resp := apiRequest(t, client, http.MethodGet, hs.URL+"/api/v2/audit?cursor=%%%", token, nil); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("bad cursor status = %d, want 400", resp.StatusCode)
	}
}

func TestAPIV2AgentTokensListAndRevoke(t *testing.T) {
	s := newServerWithConfig(t, Config{Domain: "example.com"})
	hs := newTestHTTPServer(t, s)
	client := hs.Client()

	secret := seedPreAuthKey(t, s, state.PreAuthKey{})
	machineKey := key.NewMachine()
	nodeKey := key.NewNode()
	enrolled := enrollAgent(t, client, hs.URL, machineKey, nodeKey, secret)
	if enrolled.Token == "" {
		t.Fatalf("enrollment = %+v", enrolled)
	}

	_, readToken := seedAPIKey(t, s, identity.ScopeRead)
	resp := apiRequest(t, client, http.MethodGet, hs.URL+"/api/v2/agent-tokens", readToken, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("agent-tokens status = %d", resp.StatusCode)
	}
	page := decodeAPI(t, resp)
	items, _ := page["items"].([]any)
	if len(items) != 1 {
		t.Fatalf("agent tokens = %d, want 1", len(items))
	}
	view := items[0].(map[string]any)
	if view["live"] != true || view["nodeHostname"] != "agent-node" {
		t.Errorf("token view = %v", view)
	}
	if _, ok := view["token"]; ok {
		t.Error("token list leaks the credential")
	}
	tokenID := view["id"].(string)

	// The node filter narrows the list; "0" is not a node ID, so it is
	// refused instead of silently listing every credential.
	byNode := decodeAPI(t, apiRequest(t, client, http.MethodGet,
		hs.URL+"/api/v2/agent-tokens?node="+strconv.FormatInt(int64(view["nodeId"].(float64)), 10), readToken, nil))
	if got, _ := byNode["items"].([]any); len(got) != 1 {
		t.Errorf("node filter = %v, want the enrolled credential", got)
	}
	if resp := apiRequest(t, client, http.MethodGet, hs.URL+"/api/v2/agent-tokens?node=0", readToken, nil); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("node=0 status = %d, want 400", resp.StatusCode)
	}

	// Revoking needs the write scope: a read-only key is refused.
	if resp := apiRequest(t, client, http.MethodDelete, hs.URL+"/api/v2/agent-tokens/"+tokenID, readToken, nil); resp.StatusCode != http.StatusForbidden {
		t.Errorf("read-only revoke status = %d, want 403", resp.StatusCode)
	}

	_, writeToken := seedAPIKey(t, s)
	if resp := apiRequest(t, client, http.MethodDelete, hs.URL+"/api/v2/agent-tokens/"+tokenID, writeToken, nil); resp.StatusCode != http.StatusOK {
		t.Errorf("revoke status = %d, want 200", resp.StatusCode)
	}
	// Idempotent retry.
	if resp := apiRequest(t, client, http.MethodDelete, hs.URL+"/api/v2/agent-tokens/"+tokenID, writeToken, nil); resp.StatusCode != http.StatusOK {
		t.Errorf("repeated revoke status = %d, want 200", resp.StatusCode)
	}
	if resp := apiRequest(t, client, http.MethodDelete, hs.URL+"/api/v2/agent-tokens/xunara_agenttoken_missing", writeToken, nil); resp.StatusCode != http.StatusNotFound {
		t.Errorf("unknown token revoke status = %d, want 404", resp.StatusCode)
	}

	// The revoked credential stops working immediately.
	body, status := agentPost(t, client, hs.URL, "/api/agent/v1/netmap", enrolled.Token, agentRequest{
		MachineKey: machineKey.Public().String(),
		NodeKey:    nodeKey.Public().String(),
	})
	if status != http.StatusUnauthorized {
		t.Fatalf("revoked token netmap status = %d (%s), want 401", status, body)
	}

	if _, ok := findAudit(t, s, identity.AuditAgentTokenRevoked); !ok {
		t.Error("agent.token_revoked audit event missing")
	}
}

// TestAPIV2TailnetLockStatus drives GET /api/v2/tka through the key-authority
// lifecycle: it reports the state the netmap advertises, counts signed nodes,
// and never needs more than the read scope.
func TestAPIV2TailnetLockStatus(t *testing.T) {
	s := newTestServer(t)
	hs := newTestHTTPServer(t, s)
	client := noRedirectClient()

	if resp := apiRequest(t, client, http.MethodGet, hs.URL+"/api/v2/tka", "", nil); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("anonymous status = %d, want 401", resp.StatusCode)
	}

	_, token := seedAPIKey(t, s, identity.ScopeRead)
	signed := seedAPIMachine(t, s, "signed", nil)
	seedAPIMachine(t, s, "unsigned", nil)

	// Before any enablement the tailnet looks untouched.
	raw := bodyString(t, apiRequest(t, client, http.MethodGet, hs.URL+"/api/v2/tka", token, nil))
	var status TKAStatus
	if err := json.Unmarshal([]byte(raw), &status); err != nil {
		t.Fatalf("decoding status: %v\n%s", err, raw)
	}
	for _, field := range []string{"everEnabled", "enabled", "disabled", "nodes", "signed", "unsigned"} {
		if !strings.Contains(raw, `"`+field+`"`) {
			t.Errorf("status JSON lacks %q:\n%s", field, raw)
		}
	}
	if status.EverEnabled || status.Enabled || status.Disabled || status.Head != "" {
		t.Errorf("status before enablement = %+v, want an untouched tailnet", status)
	}
	if status.Nodes != (TKAStatusNodes{Total: 2, Unsigned: 2}) {
		t.Errorf("node counts = %+v, want 2 unsigned nodes", status.Nodes)
	}

	// Enablement: sign one node and turn enforcement on.
	adminKey, genesis := newTestTKAKey(t)
	if err := s.tka.initBegin(genesis); err != nil {
		t.Fatalf("initBegin: %v", err)
	}
	signed = storedNode(t, s, signed.NodeKey)
	signed.KeySignature = signTestNodeKey(t, adminKey, signed.NodeKey)
	if err := s.store.UpdateNode(signed); err != nil {
		t.Fatalf("UpdateNode: %v", err)
	}
	if err := s.tka.enable(nil); err != nil {
		t.Fatalf("enable: %v", err)
	}

	status = decodeTKAStatus(t, apiRequest(t, client, http.MethodGet, hs.URL+"/api/v2/tka", token, nil))
	if !status.Enabled || !status.EverEnabled || status.Disabled {
		t.Errorf("status after enablement = %+v, want enabled", status)
	}
	if status.Head != genesis.Hash().String() {
		t.Errorf("head = %q, want %q", status.Head, genesis.Hash().String())
	}
	if status.Nodes != (TKAStatusNodes{Total: 2, Signed: 1, Unsigned: 1}) {
		t.Errorf("node counts = %+v, want one signed and one unsigned node", status.Nodes)
	}

	// Disablement keeps the chain but stops enforcement; the head is no longer
	// advertised to clients, so it is not reported either.
	if err := s.tka.disable(testDisablementSecret); err != nil {
		t.Fatalf("disable: %v", err)
	}
	status = decodeTKAStatus(t, apiRequest(t, client, http.MethodGet, hs.URL+"/api/v2/tka", token, nil))
	if status.Enabled || !status.Disabled || !status.EverEnabled || status.Head != "" {
		t.Errorf("status after disablement = %+v, want disabled with the chain kept", status)
	}
	if status.Nodes.Signed != 1 {
		t.Errorf("signed nodes after disablement = %d, want the stored signature kept", status.Nodes.Signed)
	}
}

// decodeTKAStatus reads a GET /api/v2/tka response.
func decodeTKAStatus(t *testing.T, resp *http.Response) TKAStatus {
	t.Helper()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("tka status = %d, want 200", resp.StatusCode)
	}
	var out TKAStatus
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decoding tka status: %v", err)
	}
	resp.Body.Close()
	return out
}

// TestAPIV2IDTokenStatus drives GET /api/v2/id-token: read scope only, the
// issuer's public state, and the signing-key bookkeeping a relying party's
// setup needs. Private key material must never appear.
func TestAPIV2IDTokenStatus(t *testing.T) {
	s := newServerWithConfig(t, Config{ServerURL: "https://login.example.com", Domain: "example.com"})
	hs := newTestHTTPServer(t, s)
	client := noRedirectClient()

	if resp := apiRequest(t, client, http.MethodGet, hs.URL+"/api/v2/id-token", "", nil); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("anonymous status = %d, want 401", resp.StatusCode)
	}

	_, readToken := seedAPIKey(t, s, identity.ScopeRead)
	_, writeToken := seedAPIKey(t, s, identity.ScopeWrite)
	if resp := apiRequest(t, client, http.MethodGet, hs.URL+"/api/v2/id-token", writeToken, nil); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("write-only status = %d, want 403", resp.StatusCode)
	}

	raw := bodyString(t, apiRequest(t, client, http.MethodGet, hs.URL+"/api/v2/id-token", readToken, nil))
	var status IDTokenStatus
	if err := json.Unmarshal([]byte(raw), &status); err != nil {
		t.Fatalf("decoding status: %v\n%s", err, raw)
	}
	if !status.Enabled {
		t.Error("status reports the issuer as disabled")
	}
	if status.Issuer != "https://login.example.com" {
		t.Errorf("issuer = %q", status.Issuer)
	}
	if status.JWKSURL != "https://login.example.com/.well-known/jwks.json" {
		t.Errorf("jwksUrl = %q", status.JWKSURL)
	}
	if status.Algorithm != idtoken.Algorithm {
		t.Errorf("algorithm = %q, want %s", status.Algorithm, idtoken.Algorithm)
	}
	if want := int(idtoken.TTL / time.Second); status.TokenTTLSeconds != want {
		t.Errorf("tokenTtlSeconds = %d, want %d", status.TokenTTLSeconds, want)
	}
	if len(status.Keys) != 1 {
		t.Fatalf("keys = %+v, want one active key", status.Keys)
	}
	if !status.Keys[0].Active() || status.ActiveKeyID != status.Keys[0].KID {
		t.Errorf("active key = %q, keys = %+v", status.ActiveKeyID, status.Keys)
	}
	if status.Keys[0].Created.IsZero() {
		t.Errorf("key has no creation time: %+v", status.Keys[0])
	}

	// The response is public metadata plus bookkeeping: no private key
	// material, no PEM, no JWK private parameters.
	for _, forbidden := range []string{"PRIVATE KEY", "privateKey", `"d"`, `"p"`, `"q"`} {
		if strings.Contains(raw, forbidden) {
			t.Errorf("status response contains %q:\n%s", forbidden, raw)
		}
	}

	// Discovery advertises the feature so automation can branch on it.
	meta := decodeAPI(t, apiRequest(t, client, http.MethodGet, hs.URL+"/api/v2/meta", readToken, nil))
	if meta["identityTokensEnabled"] != true {
		t.Errorf("meta identityTokensEnabled = %v, want true", meta["identityTokensEnabled"])
	}
}

// TestAPIV2IDTokenStatusWithoutIssuer checks the disabled shape: no issuer
// URL, no keys, and nothing that could be mistaken for a usable trust anchor.
func TestAPIV2IDTokenStatusWithoutIssuer(t *testing.T) {
	s := newServerWithoutIssuer(t)
	hs := newTestHTTPServer(t, s)
	client := noRedirectClient()

	_, token := seedAPIKey(t, s, identity.ScopeRead)
	raw := bodyString(t, apiRequest(t, client, http.MethodGet, hs.URL+"/api/v2/id-token", token, nil))
	var status IDTokenStatus
	if err := json.Unmarshal([]byte(raw), &status); err != nil {
		t.Fatalf("decoding status: %v\n%s", err, raw)
	}
	if status.Enabled || status.Issuer != "" || status.JWKSURL != "" || status.ActiveKeyID != "" {
		t.Errorf("status without an issuer = %+v, want disabled and empty", status)
	}
	if len(status.Keys) != 0 {
		t.Errorf("keys = %+v, want none", status.Keys)
	}
	if strings.Contains(raw, `"keys":null`) {
		t.Errorf("keys must be an array, not null:\n%s", raw)
	}

	meta := decodeAPI(t, apiRequest(t, client, http.MethodGet, hs.URL+"/api/v2/meta", token, nil))
	if meta["identityTokensEnabled"] != false {
		t.Errorf("meta identityTokensEnabled = %v, want false", meta["identityTokensEnabled"])
	}
}

// TestAPIV2MachineDeviceAttrs checks the read-only posture view: read scope
// only, the values a node reported, an empty object for a machine without any,
// and a count in the machine list so automation can find them.
func TestAPIV2MachineDeviceAttrs(t *testing.T) {
	s := newTestServer(t)
	hs := newTestHTTPServer(t, s)
	client := noRedirectClient()

	reporter := seedAPIMachine(t, s, "reporter", nil)
	quiet := seedAPIMachine(t, s, "quiet", nil)
	if err := s.store.SetNodeDeviceAttrs(reporter.ID, map[string]any{
		"os_version": "15.2",
		"encrypted":  true,
		"score":      float64(7.5),
	}); err != nil {
		t.Fatalf("SetNodeDeviceAttrs: %v", err)
	}

	path := func(id state.NodeID) string {
		return hs.URL + "/api/v2/machines/" + strconv.FormatUint(uint64(id), 10) + "/device-attrs"
	}

	if resp := apiRequest(t, client, http.MethodGet, path(reporter.ID), "", nil); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("anonymous status = %d, want 401", resp.StatusCode)
	}

	_, readToken := seedAPIKey(t, s, identity.ScopeRead)
	_, writeToken := seedAPIKey(t, s, identity.ScopeWrite)
	if resp := apiRequest(t, client, http.MethodGet, path(reporter.ID), writeToken, nil); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("write-only status = %d, want 403", resp.StatusCode)
	}

	if resp := apiRequest(t, client, http.MethodGet, path(state.NodeID(9999)), readToken, nil); resp.StatusCode != http.StatusNotFound {
		t.Errorf("unknown machine status = %d, want 404", resp.StatusCode)
	}
	if resp := apiRequest(t, client, http.MethodGet, hs.URL+"/api/v2/machines/not-a-number/device-attrs", readToken, nil); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("bad machine id status = %d, want 400", resp.StatusCode)
	}

	resp := apiRequest(t, client, http.MethodGet, path(reporter.ID), readToken, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	body := decodeAPI(t, resp)
	if body["machineId"] != float64(reporter.ID) || body["stableId"] != reporter.StableID {
		t.Errorf("identity fields = %v / %v", body["machineId"], body["stableId"])
	}
	attrs, ok := body["attrs"].(map[string]any)
	if !ok {
		t.Fatalf("attrs = %v, want an object", body["attrs"])
	}
	if len(attrs) != 3 || attrs["os_version"] != "15.2" || attrs["encrypted"] != true || attrs["score"] != float64(7.5) {
		t.Errorf("attrs = %#v", attrs)
	}

	// A machine that never reported an attribute answers with an empty object,
	// not null: clients should not have to special-case the state.
	resp = apiRequest(t, client, http.MethodGet, path(quiet.ID), readToken, nil)
	raw := bodyString(t, resp)
	if !strings.Contains(raw, `"attrs":{}`) {
		t.Errorf("empty attrs response = %s", raw)
	}

	// The machine list reports how many attributes each machine has, and omits
	// the field entirely for machines that have none.
	list := decodeAPI(t, apiRequest(t, client, http.MethodGet, hs.URL+"/api/v2/machines", readToken, nil))
	items, ok := list["items"].([]any)
	if !ok || len(items) != 2 {
		t.Fatalf("machine list items = %v, want 2", list["items"])
	}
	seen := 0
	for _, raw := range items {
		item, ok := raw.(map[string]any)
		if !ok {
			t.Fatalf("machine list item = %v, want an object", raw)
		}
		switch item["stableId"] {
		case reporter.StableID:
			seen++
			if item["deviceAttrCount"] != float64(3) {
				t.Errorf("reporter deviceAttrCount = %v, want 3", item["deviceAttrCount"])
			}
		case quiet.StableID:
			seen++
			if _, present := item["deviceAttrCount"]; present {
				t.Errorf("a machine without attributes carries a count: %v", item)
			}
		default:
			t.Errorf("unexpected machine in list: %v", item)
		}
	}
	if seen != 2 {
		t.Errorf("machine list covered %d machines, want 2", seen)
	}
}

// TestAPIV2Services checks the read-only service registry: scopes, filters,
// pagination, the DNS name, and the per-machine count in the machine list.
func TestAPIV2Services(t *testing.T) {
	s := newServerWithConfig(t, Config{Domain: "example.com"})
	hs := newTestHTTPServer(t, s)
	client := noRedirectClient()

	web := seedAPIMachine(t, s, "web", nil)
	quiet := seedAPIMachine(t, s, "quiet", nil)
	if err := s.store.ReplaceNodeServices(web.ID, []state.Service{
		{Name: "api", Protocol: "tcp", Port: 8080, Metadata: map[string]string{"version": "2"}},
		{Name: "metrics", Protocol: "udp", Port: 9090},
	}); err != nil {
		t.Fatalf("ReplaceNodeServices: %v", err)
	}

	url := hs.URL + "/api/v2/services"
	if resp := apiRequest(t, client, http.MethodGet, url, "", nil); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("anonymous status = %d, want 401", resp.StatusCode)
	}
	_, readToken := seedAPIKey(t, s, identity.ScopeRead)
	_, writeToken := seedAPIKey(t, s, identity.ScopeWrite)
	if resp := apiRequest(t, client, http.MethodGet, url, writeToken, nil); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("write-only status = %d, want 403", resp.StatusCode)
	}

	body := decodeAPI(t, apiRequest(t, client, http.MethodGet, url, readToken, nil))
	items, ok := body["items"].([]any)
	if !ok || len(items) != 2 {
		t.Fatalf("items = %v, want two services", body["items"])
	}
	first := items[0].(map[string]any)
	if first["name"] != "api" || first["protocol"] != "tcp" || first["port"] != float64(8080) {
		t.Errorf("first service = %v", first)
	}
	if first["nodeId"] != float64(web.ID) || first["stableId"] != web.StableID || first["hostname"] != "web" {
		t.Errorf("first service identity = %v", first)
	}
	if first["dnsName"] != "api.example.com" {
		t.Errorf("dnsName = %v, want api.example.com", first["dnsName"])
	}
	if metadata, ok := first["metadata"].(map[string]any); !ok || metadata["version"] != "2" {
		t.Errorf("metadata = %v", first["metadata"])
	}
	if second := items[1].(map[string]any); second["name"] != "metrics" || second["protocol"] != "udp" {
		t.Errorf("second service = %v", second)
	}

	// Filters: exact name, node by stable id, and an unknown node that must
	// match nothing instead of widening the result.
	filtered := decodeAPI(t, apiRequest(t, client, http.MethodGet, url+"?name=api", readToken, nil))
	if got := filtered["items"].([]any); len(got) != 1 || got[0].(map[string]any)["name"] != "api" {
		t.Errorf("name filter = %v", got)
	}
	byNode := decodeAPI(t, apiRequest(t, client, http.MethodGet, url+"?node="+web.StableID, readToken, nil))
	if got := byNode["items"].([]any); len(got) != 2 {
		t.Errorf("node filter = %v, want two services", got)
	}
	unknown := decodeAPI(t, apiRequest(t, client, http.MethodGet, url+"?node=9999", readToken, nil))
	if got := unknown["items"].([]any); len(got) != 0 {
		t.Errorf("unknown node filter = %v, want none", got)
	}
	// "0" is not a node ID: it must match nothing, never mean "no filter".
	zero := decodeAPI(t, apiRequest(t, client, http.MethodGet, url+"?node=0", readToken, nil))
	if got := zero["items"].([]any); len(got) != 0 {
		t.Errorf("node=0 filter = %v, want none", got)
	}

	// Pagination: one item per page, names as cursors.
	page := decodeAPI(t, apiRequest(t, client, http.MethodGet, url+"?limit=1", readToken, nil))
	if got := page["items"].([]any); len(got) != 1 || got[0].(map[string]any)["name"] != "api" {
		t.Fatalf("page 1 = %v", got)
	}
	next, _ := page["nextCursor"].(string)
	if next == "" {
		t.Fatal("page 1 has no cursor")
	}
	page2 := decodeAPI(t, apiRequest(t, client, http.MethodGet, url+"?limit=1&cursor="+next, readToken, nil))
	if got := page2["items"].([]any); len(got) != 1 || got[0].(map[string]any)["name"] != "metrics" {
		t.Fatalf("page 2 = %v", got)
	}
	if cursor, _ := page2["nextCursor"].(string); cursor != "" {
		t.Errorf("page 2 cursor = %q, want empty", cursor)
	}

	if resp := apiRequest(t, client, http.MethodGet, url+"?cursor="+apiV2EncodeCursor("machines", "1"), readToken, nil); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("wrong cursor kind status = %d, want 400", resp.StatusCode)
	}
	if resp := apiRequest(t, client, http.MethodGet, url+"?limit=0", readToken, nil); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("bad limit status = %d, want 400", resp.StatusCode)
	}

	// The machine list reports how many services each machine advertises, and
	// omits the field for machines that advertise none.
	list := decodeAPI(t, apiRequest(t, client, http.MethodGet, hs.URL+"/api/v2/machines", readToken, nil))
	seen := 0
	for _, raw := range list["items"].([]any) {
		item := raw.(map[string]any)
		switch item["stableId"] {
		case web.StableID:
			seen++
			if item["serviceCount"] != float64(2) {
				t.Errorf("web serviceCount = %v, want 2", item["serviceCount"])
			}
		case quiet.StableID:
			seen++
			if _, present := item["serviceCount"]; present {
				t.Errorf("a machine without services carries a count: %v", item)
			}
		}
	}
	if seen != 2 {
		t.Errorf("machine list covered %d machines, want 2", seen)
	}
}
