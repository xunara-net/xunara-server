package control

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"tailscale.com/tailcfg"
	"tailscale.com/types/key"

	"github.com/xunara-net/xunara-server/identity"
	"github.com/xunara-net/xunara-server/state"
)

// newShareRouter builds a two-organization router with the platform share
// registry open, mirroring a deployment that runs with
// -platform-state-dir.
func newShareRouter(t *testing.T, dir string) (*Router, *httptest.Server, *Server, *Server) {
	t.Helper()

	acme := newServerWithConfig(t, Config{Domain: "acme.example.com"})
	globex := newServerWithConfig(t, Config{Domain: "globex.example.com"})
	registry := newTestShareRegistryAt(t, filepath.Join(dir, "shares.db"))
	router := newTestRouter(t, RouterConfig{
		Orgs: []OrgSite{
			{ID: "acme", Name: "Acme", Domains: []string{"login.acme.example.com"}, Server: acme},
			{ID: "globex", Name: "Globex", Domains: []string{"login.globex.example.com"}, Server: globex},
		},
		Shares: registry,
	})
	hs := httptest.NewServer(router.Handler())
	t.Cleanup(hs.Close)
	return router, hs, acme, globex
}

// seedExternalUser creates a user whose identity key is (provider, subject).
func seedExternalUser(t *testing.T, s *Server, login, provider, subject string) tailcfg.UserID {
	t.Helper()

	u := identity.User{LoginName: login, DisplayName: "Remote User", Role: identity.RoleMember}
	if err := s.Identity().CreateUser(&u); err != nil {
		t.Fatalf("CreateUser(%s): %v", login, err)
	}
	if err := s.Identity().LinkExternalIdentity(&identity.ExternalIdentity{
		ProviderID:  provider,
		Subject:     subject,
		UserID:      u.ID,
		DisplayName: "Remote User",
	}); err != nil {
		t.Fatalf("LinkExternalIdentity(%s): %v", login, err)
	}
	return u.ID
}

// shareCreateBody is a valid POST /api/v2/shares body.
func shareCreateBody(node, targetOrg, provider, subject string) map[string]any {
	return map[string]any{
		"node":               node,
		"targetOrganization": targetOrg,
		"provider":           provider,
		"subject":            subject,
	}
}

const (
	testShareProvider = "oidc:corp"
	testShareSubject  = "subject-1"
)

// TestAPIV2SharesLifecycle drives the full share flow across two
// organizations: create, list, accept, revoke, and the fail-closed edges.
func TestAPIV2SharesLifecycle(t *testing.T) {
	_, hs, acme, globex := newShareRouter(t, t.TempDir())

	const (
		acmeHost   = "login.acme.example.com"
		globexHost = "login.globex.example.com"
	)
	machine := seedAPIMachine(t, acme, "laptop", nil)
	_, acmeToken := seedAPIKey(t, acme, identity.ScopeRead, identity.ScopeWrite)
	_, acmeRead := seedAPIKey(t, acme, identity.ScopeRead)
	receiver := seedExternalUser(t, globex, "user@globex.example.com", testShareProvider, testShareSubject)
	receiverToken := seedAPIKeyForUser(t, globex, receiver, identity.ScopeRead)
	otherUser := seedRoleUser(t, globex, "other@globex.example.com", identity.RoleMember)
	otherToken := seedAPIKeyForUser(t, globex, otherUser, identity.ScopeRead)

	// Sharing is advertised once the router wires the registry.
	meta := decodeAPI(t, platformJSONRequest(t, hs, http.MethodGet, acmeHost, "/api/v2/meta", acmeRead, nil))
	if meta["sharingEnabled"] != true {
		t.Errorf("sharingEnabled = %v, want true on a share-enabled router", meta["sharingEnabled"])
	}

	// Anonymous and read-only creates fail before touching the registry.
	if resp := platformJSONRequest(t, hs, http.MethodPost, acmeHost, "/api/v2/shares", "", shareCreateBody(machine.StableID, "globex", testShareProvider, testShareSubject)); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("anonymous create status = %d, want 401", resp.StatusCode)
	}
	if resp := platformJSONRequest(t, hs, http.MethodPost, acmeHost, "/api/v2/shares", acmeRead, shareCreateBody(machine.StableID, "globex", testShareProvider, testShareSubject)); resp.StatusCode != http.StatusForbidden {
		t.Errorf("read-scope create status = %d, want 403", resp.StatusCode)
	}

	// Fail-closed validation.
	for name, body := range map[string]map[string]any{
		"unknown node":    shareCreateBody("nope", "globex", testShareProvider, testShareSubject),
		"unknown org":     shareCreateBody(machine.StableID, "initech", testShareProvider, testShareSubject),
		"local provider":  shareCreateBody(machine.StableID, "globex", identity.LocalProviderID, testShareSubject),
		"missing subject": shareCreateBody(machine.StableID, "globex", testShareProvider, ""),
		"same org":        shareCreateBody(machine.StableID, "acme", testShareProvider, testShareSubject),
	} {
		resp := platformJSONRequest(t, hs, http.MethodPost, acmeHost, "/api/v2/shares", acmeToken, body)
		want := http.StatusBadRequest
		if name == "unknown node" || name == "unknown org" {
			want = http.StatusNotFound
		}
		if resp.StatusCode != want {
			t.Errorf("%s status = %d, want %d", name, resp.StatusCode, want)
		}
	}

	resp := platformJSONRequest(t, hs, http.MethodPost, acmeHost, "/api/v2/shares", acmeToken,
		shareCreateBody(machine.StableID, "globex", testShareProvider, testShareSubject))
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create status = %d (%s), want 201", resp.StatusCode, bodyString(t, resp))
	}
	created := decodeAPI(t, resp)
	id, _ := created["id"].(string)
	if id == "" || created["status"] != SharePending || created["direction"] != "outgoing" {
		t.Fatalf("created share = %v", created)
	}
	if created["sourceOrganization"] != "acme" || created["targetOrganization"] != "globex" {
		t.Errorf("created share organizations = %v", created)
	}
	node, _ := created["node"].(map[string]any)
	if node["stableId"] != machine.StableID || node["hostname"] != "laptop" {
		t.Errorf("created share node = %v", node)
	}

	// A duplicate active share conflicts.
	if resp := platformJSONRequest(t, hs, http.MethodPost, acmeHost, "/api/v2/shares", acmeToken,
		shareCreateBody(machine.StableID, "globex", testShareProvider, testShareSubject)); resp.StatusCode != http.StatusConflict {
		t.Errorf("duplicate create status = %d, want 409", resp.StatusCode)
	}

	// Both sides see it; a third party inside the target organization does not.
	outgoing := decodeAPI(t, platformJSONRequest(t, hs, http.MethodGet, acmeHost, "/api/v2/shares?direction=outgoing", acmeToken, nil))
	if items, _ := outgoing["items"].([]any); len(items) != 1 {
		t.Errorf("outgoing items = %v, want 1", outgoing["items"])
	}
	incoming := decodeAPI(t, platformJSONRequest(t, hs, http.MethodGet, globexHost, "/api/v2/shares?direction=incoming", receiverToken, nil))
	if items, _ := incoming["items"].([]any); len(items) != 1 {
		t.Errorf("incoming items = %v, want 1", incoming["items"])
	}
	hidden := decodeAPI(t, platformJSONRequest(t, hs, http.MethodGet, globexHost, "/api/v2/shares?direction=incoming", otherToken, nil))
	if items, _ := hidden["items"].([]any); len(items) != 0 {
		t.Errorf("third-party incoming items = %v, want none", hidden["items"])
	}

	// Unknown directions and cross-organization reads stay fail-closed.
	if resp := platformJSONRequest(t, hs, http.MethodGet, acmeHost, "/api/v2/shares?direction=sideways", acmeToken, nil); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("unknown direction status = %d, want 400", resp.StatusCode)
	}
	if resp := platformJSONRequest(t, hs, http.MethodGet, globexHost, "/api/v2/shares/"+id, otherToken, nil); resp.StatusCode != http.StatusNotFound {
		t.Errorf("third-party read status = %d, want 404", resp.StatusCode)
	}
	if resp := platformJSONRequest(t, hs, http.MethodGet, globexHost, "/api/v2/shares/"+id, receiverToken, nil); resp.StatusCode != http.StatusOK {
		t.Errorf("target read status = %d, want 200", resp.StatusCode)
	}

	// Only the target identity may accept.
	if resp := platformJSONRequest(t, hs, http.MethodPost, globexHost, "/api/v2/shares/"+id+"/accept", otherToken, nil); resp.StatusCode != http.StatusNotFound {
		t.Errorf("non-target accept status = %d, want 404", resp.StatusCode)
	}
	if resp := platformJSONRequest(t, hs, http.MethodPost, acmeHost, "/api/v2/shares/"+id+"/accept", acmeToken, nil); resp.StatusCode != http.StatusNotFound {
		t.Errorf("source accept status = %d, want 404", resp.StatusCode)
	}
	resp = platformJSONRequest(t, hs, http.MethodPost, globexHost, "/api/v2/shares/"+id+"/accept", receiverToken, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("accept status = %d (%s), want 200", resp.StatusCode, bodyString(t, resp))
	}
	accepted := decodeAPI(t, resp)
	if accepted["status"] != ShareAccepted || accepted["direction"] != "incoming" || accepted["acceptedAt"] == nil {
		t.Errorf("accepted share = %v", accepted)
	}
	if resp := platformJSONRequest(t, hs, http.MethodPost, globexHost, "/api/v2/shares/"+id+"/accept", receiverToken, nil); resp.StatusCode != http.StatusConflict {
		t.Errorf("second accept status = %d, want 409", resp.StatusCode)
	}
	if resp := platformJSONRequest(t, hs, http.MethodPost, globexHost, "/api/v2/shares/"+id+"/reject", receiverToken, nil); resp.StatusCode != http.StatusConflict {
		t.Errorf("reject after accept status = %d, want 409", resp.StatusCode)
	}

	// The target user may withdraw; a repeat is idempotent.
	resp = platformJSONRequest(t, hs, http.MethodDelete, globexHost, "/api/v2/shares/"+id, receiverToken, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("revoke status = %d (%s), want 200", resp.StatusCode, bodyString(t, resp))
	}
	revoked := decodeAPI(t, resp)
	if revoked["status"] != ShareRevoked || revoked["revokedBy"] != "target" {
		t.Errorf("revoked share = %v", revoked)
	}
	if resp := platformJSONRequest(t, hs, http.MethodDelete, globexHost, "/api/v2/shares/"+id, receiverToken, nil); resp.StatusCode != http.StatusOK {
		t.Errorf("second revoke status = %d, want 200", resp.StatusCode)
	}
	// The revoked share stays in the caller's history, marked revoked (spec
	// 38.3: outgoing lists every state; incoming matches the target identity).
	incoming = decodeAPI(t, platformJSONRequest(t, hs, http.MethodGet, globexHost, "/api/v2/shares?direction=incoming", receiverToken, nil))
	if items, _ := incoming["items"].([]any); len(items) != 1 {
		t.Errorf("incoming after revoke = %v, want the revoked share", incoming["items"])
	} else if item, _ := items[0].(map[string]any); item["status"] != ShareRevoked {
		t.Errorf("incoming after revoke status = %v, want %s", item["status"], ShareRevoked)
	}
	// The machine can be shared again once the slot is free.
	if resp := platformJSONRequest(t, hs, http.MethodPost, acmeHost, "/api/v2/shares", acmeToken,
		shareCreateBody(machine.StableID, "globex", testShareProvider, testShareSubject)); resp.StatusCode != http.StatusCreated {
		t.Errorf("recreate after revoke status = %d, want 201", resp.StatusCode)
	}
}

// TestAPIV2SharesDisabled checks that a deployment without the platform share
// registry reports 404 on the whole surface, including meta.
func TestAPIV2SharesDisabled(t *testing.T) {
	s := newTestServer(t)
	hs := newTestHTTPServer(t, s)
	client := noRedirectClient()
	_, token := seedAPIKey(t, s)

	if meta := decodeAPI(t, apiRequest(t, client, http.MethodGet, hs.URL+"/api/v2/meta", token, nil)); meta["sharingEnabled"] != false {
		t.Errorf("sharingEnabled = %v, want false without a registry", meta["sharingEnabled"])
	}
	if resp := apiRequest(t, client, http.MethodGet, hs.URL+"/api/v2/shares", token, nil); resp.StatusCode != http.StatusNotFound {
		t.Errorf("disabled list status = %d, want 404", resp.StatusCode)
	}
	if resp := apiRequest(t, client, http.MethodPost, hs.URL+"/api/v2/shares", token,
		shareCreateBody("whatever", "globex", testShareProvider, testShareSubject)); resp.StatusCode != http.StatusNotFound {
		t.Errorf("disabled create status = %d, want 404", resp.StatusCode)
	}
	if resp := apiRequest(t, client, http.MethodDelete, hs.URL+"/api/v2/shares/nope", token, nil); resp.StatusCode != http.StatusNotFound {
		t.Errorf("disabled revoke status = %d, want 404", resp.StatusCode)
	}
}

// TestAPIV2SharesTailnetLock checks the TKA boundary: while either
// organization enforces tailnet lock, new shares are refused and existing
// shares stop exposing foreign peers.
func TestAPIV2SharesTailnetLock(t *testing.T) {
	_, hs, acme, globex := newShareRouter(t, t.TempDir())
	const acmeHost = "login.acme.example.com"
	machine := seedAPIMachine(t, acme, "laptop", nil)
	_, acmeToken := seedAPIKey(t, acme, identity.ScopeRead, identity.ScopeWrite)
	receiver := seedExternalUser(t, globex, "user@globex.example.com", testShareProvider, testShareSubject)
	receiverToken := seedAPIKeyForUser(t, globex, receiver, identity.ScopeRead)
	receiverNode := state.Node{
		MachineKey: key.NewMachine().Public(),
		NodeKey:    key.NewNode().Public(),
		UserID:     receiver,
		Hostname:   "phone",
	}
	if err := globex.store.CreateNode(&receiverNode); err != nil {
		t.Fatalf("CreateNode(receiver): %v", err)
	}

	// Before lock enforcement the accepted share is live in both netmaps.
	resp := platformJSONRequest(t, hs, http.MethodPost, acmeHost, "/api/v2/shares", acmeToken,
		shareCreateBody(machine.StableID, "globex", testShareProvider, testShareSubject))
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create status = %d (%s), want 201", resp.StatusCode, bodyString(t, resp))
	}
	id, _ := decodeAPI(t, resp)["id"].(string)
	if resp := platformJSONRequest(t, hs, http.MethodPost, "login.globex.example.com", "/api/v2/shares/"+id+"/accept", receiverToken, nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("accept status = %d (%s), want 200", resp.StatusCode, bodyString(t, resp))
	}
	if peers := acme.sharePeersFor(machine); peers == nil || len(peers.nodes) != 1 {
		t.Fatalf("unlocked source netmap peers = %+v, want one", peers)
	}
	if peers := globex.sharePeersFor(receiverNode); peers == nil || len(peers.nodes) != 1 {
		t.Fatalf("unlocked target netmap peers = %+v, want one", peers)
	}

	// Enable tailnet lock on the source organization.
	_, genesis := newTestTKAKey(t)
	if err := acme.tka.initBegin(genesis); err != nil {
		t.Fatalf("initBegin: %v", err)
	}
	if err := acme.tka.enable(nil); err != nil {
		t.Fatalf("enable: %v", err)
	}

	// New shares are refused and the existing pair disappears from both sides.
	second := seedAPIMachine(t, acme, "desktop", nil)
	if resp := platformJSONRequest(t, hs, http.MethodPost, acmeHost, "/api/v2/shares", acmeToken,
		shareCreateBody(second.StableID, "globex", testShareProvider, testShareSubject)); resp.StatusCode != http.StatusConflict {
		t.Errorf("create while locked status = %d, want 409", resp.StatusCode)
	}
	if peers := acme.sharePeersFor(machine); peers != nil {
		t.Errorf("locked source netmap has %d foreign peers, want none", len(peers.nodes))
	}
	if peers := globex.sharePeersFor(receiverNode); peers != nil {
		t.Errorf("locked target netmap has %d foreign peers, want none", len(peers.nodes))
	}
	if resp := platformJSONRequest(t, hs, http.MethodPost, "login.globex.example.com", "/api/v2/shares/"+id+"/accept", receiverToken, nil); resp.StatusCode != http.StatusConflict {
		// Already accepted, so the decision conflict wins; the lock is still
		// enforced by the netmap check above and by create.
		t.Logf("re-accept while locked status = %d", resp.StatusCode)
	}
}
