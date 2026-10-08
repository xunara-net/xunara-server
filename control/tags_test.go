package control

import (
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"tailscale.com/tailcfg"
	"tailscale.com/types/key"

	"github.com/xunara-net/xunara-server/control/mapper"
	"github.com/xunara-net/xunara-server/identity"
	"github.com/xunara-net/xunara-server/state"
)

// policyFile writes an ACL document to a temporary file for a test server.
func policyFile(t *testing.T, doc string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "policy.hujson")
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatalf("writing policy: %v", err)
	}
	return path
}

// tagPolicy allows the built-in local user to claim tag:owned and defines an
// unclaimed tag:other so "not owned" and "not defined" are distinguishable.
const tagPolicy = `{
	"tagOwners": {
		"tag:owned": ["local"],
		"tag:other": ["alice@example.com"],
	},
	"acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}],
}`

// startRegistrationWithTags registers a device that advertises ACL tags.
func startRegistrationWithTags(t *testing.T, hs *httptest.Server, hostname string, tags ...string) (net.Conn, key.NodePrivate, string) {
	t.Helper()

	machineKey := key.NewMachine()
	nodeKey := key.NewNode()

	conn := dialNoise(t, hs, machineKey)
	client := h2Client(conn)

	regResp := decodeJSON[tailcfg.RegisterResponse](t, postRaw(t, client, "/machine/register", tailcfg.RegisterRequest{
		Version:  tailcfg.CurrentCapabilityVersion,
		NodeKey:  nodeKey.Public(),
		Hostinfo: &tailcfg.Hostinfo{Hostname: hostname, RequestTags: tags},
	}))
	if regResp.MachineAuthorized {
		t.Fatal("first registration must not be authorized")
	}
	if regResp.AuthURL == "" {
		t.Fatal("expected an AuthURL")
	}

	return conn, nodeKey, path.Base(regResp.AuthURL)
}

// TestAuthKeyTagsReachClients registers a node with a tagged pre-auth key and
// checks the tags reach the netmap and that tagged nodes never expire.
func TestAuthKeyTagsReachClients(t *testing.T) {
	s := newServerWithConfig(t, Config{
		NodeKeyExpiry: time.Hour,
		PolicyPath:    policyFile(t, tagPolicy),
	})
	hs := newTestHTTPServer(t, s)

	secret := seedPreAuthKey(t, s, state.PreAuthKey{Tags: []string{"tag:owned"}})

	machineKey := key.NewMachine()
	nodeKey := key.NewNode()

	conn := dialNoise(t, hs, machineKey)
	defer conn.Close()
	client := h2Client(conn)

	resp := decodeJSON[tailcfg.RegisterResponse](t, postRaw(t, client, "/machine/register", tailcfg.RegisterRequest{
		Version:  tailcfg.CurrentCapabilityVersion,
		NodeKey:  nodeKey.Public(),
		Auth:     &tailcfg.RegisterResponseAuth{AuthKey: secret},
		Hostinfo: &tailcfg.Hostinfo{Hostname: "tagged"},
	}))
	if !resp.MachineAuthorized {
		t.Fatalf("registration was not authorized: %+v", resp)
	}
	if resp.User.ID != mapper.TaggedDevicesUserID || resp.Login.LoginName != "tagged-devices" {
		t.Errorf("registration identity = user %d / %q, want the tagged-devices pseudo identity",
			resp.User.ID, resp.Login.LoginName)
	}

	mapResp := decodeMapResponse(t, postRaw(t, client, "/machine/map", tailcfg.MapRequest{
		Version: tailcfg.CurrentCapabilityVersion,
		NodeKey: nodeKey.Public(),
	}), "")
	if mapResp.Node == nil {
		t.Fatal("no self node in the map response")
	}
	if !slices.Equal(mapResp.Node.Tags, []string{"tag:owned"}) {
		t.Errorf("node tags = %v, want [tag:owned]", mapResp.Node.Tags)
	}
	if mapResp.Node.User != mapper.TaggedDevicesUserID {
		t.Errorf("node user = %d, want the tagged-devices pseudo user", mapResp.Node.User)
	}
	var profile *tailcfg.UserProfile
	for i := range mapResp.UserProfiles {
		if mapResp.UserProfiles[i].ID == mapper.TaggedDevicesUserID {
			profile = &mapResp.UserProfiles[i]
		}
	}
	if profile == nil || profile.LoginName != "tagged-devices" {
		t.Errorf("tagged-devices profile missing from %+v", mapResp.UserProfiles)
	}
	if !mapResp.Node.KeyExpiry.IsZero() {
		t.Errorf("tagged node key expiry = %v, want zero (tagged nodes never expire)", mapResp.Node.KeyExpiry)
	}

	node, ok := s.Store().GetNodeByNodeKey(nodeKey.Public())
	if !ok || !slices.Equal(node.Tags, []string{"tag:owned"}) {
		t.Fatalf("stored node tags = %v (ok=%v), want [tag:owned]", node.Tags, ok)
	}
}

// TestAdvertiseTagsAuthorizedByApprover applies a tag the approving user owns.
func TestAdvertiseTagsAuthorizedByApprover(t *testing.T) {
	s := newServerWithConfig(t, Config{PolicyPath: policyFile(t, tagPolicy)})
	hs := newTestHTTPServer(t, s)

	conn, nodeKey, authID := startRegistrationWithTags(t, hs, "ads", "tag:owned")
	defer conn.Close()

	if err := s.ApproveRegistration(authID); err != nil {
		t.Fatalf("ApproveRegistration: %v", err)
	}

	node, ok := s.Store().GetNodeByNodeKey(nodeKey.Public())
	if !ok {
		t.Fatal("approval did not create the node")
	}
	if !slices.Equal(node.Tags, []string{"tag:owned"}) {
		t.Errorf("node tags = %v, want [tag:owned]", node.Tags)
	}
	if !node.Expiry.IsZero() {
		t.Errorf("tagged node expiry = %v, want zero", node.Expiry)
	}
}

// TestAdvertiseTagsRejectedWithoutOwnership refuses a tag the approver does
// not own, without creating a node or losing the pending registration.
func TestAdvertiseTagsRejectedWithoutOwnership(t *testing.T) {
	s := newServerWithConfig(t, Config{PolicyPath: policyFile(t, tagPolicy)})
	hs := newTestHTTPServer(t, s)

	conn, nodeKey, authID := startRegistrationWithTags(t, hs, "ads", "tag:other")
	defer conn.Close()

	err := s.ApproveRegistration(authID)
	var he HTTPError
	if !errors.As(err, &he) || he.Code != http.StatusForbidden {
		t.Fatalf("ApproveRegistration err = %v, want a 403 HTTPError", err)
	}
	if _, ok := s.Store().GetNodeByNodeKey(nodeKey.Public()); ok {
		t.Error("a rejected tag request must not create a node")
	}
	da, ok := s.Identity().GetDeviceAuthorization(authID)
	if !ok || !da.Pending() {
		t.Errorf("device authorization = %+v (ok=%v), want still pending", da, ok)
	}
	if !auditActionSet(t, s)[identity.AuditTagRejected] {
		t.Error("tag rejection was not audited")
	}
}

// TestAdvertiseTagsWithoutPolicyRejected: with no policy document no tag can
// be owned, so a tag request fails closed.
func TestAdvertiseTagsWithoutPolicyRejected(t *testing.T) {
	s := newTestServer(t)
	hs := newTestHTTPServer(t, s)

	conn, _, authID := startRegistrationWithTags(t, hs, "ads", "tag:anything")
	defer conn.Close()

	if err := s.ApproveRegistration(authID); err == nil {
		t.Fatal("tag request without a policy must be rejected")
	}
}

// TestAdvertiseMalformedTagRejected refuses tags the upstream validator
// rejects, before any ownership look-up.
func TestAdvertiseMalformedTagRejected(t *testing.T) {
	s := newServerWithConfig(t, Config{PolicyPath: policyFile(t, tagPolicy)})
	hs := newTestHTTPServer(t, s)

	conn, _, authID := startRegistrationWithTags(t, hs, "ads", "not-a-tag")
	defer conn.Close()

	err := s.ApproveRegistration(authID)
	var he HTTPError
	if !errors.As(err, &he) || he.Code != http.StatusBadRequest {
		t.Fatalf("ApproveRegistration err = %v, want a 400 HTTPError", err)
	}
}

// TestAPIKeyCreationWithTags checks tag validation on the platform API.
func TestAPIKeyCreationWithTags(t *testing.T) {
	s := newServerWithConfig(t, Config{PolicyPath: policyFile(t, tagPolicy)})
	hs := newTestHTTPServer(t, s)
	client := noRedirectClient()
	_, token := seedAPIKey(t, s)

	ok := apiRequest(t, client, http.MethodPost, hs.URL+"/api/v1/auth-keys", token,
		map[string]any{"tags": []string{"tag:owned"}, "reusable": true})
	if ok.StatusCode != http.StatusCreated {
		t.Fatalf("create status = %d (%s), want 201", ok.StatusCode, bodyString(t, ok))
	}
	body := decodeAPI(t, ok)
	if tags, _ := body["tags"].([]any); len(tags) != 1 || tags[0] != "tag:owned" {
		t.Errorf("created key tags = %v, want [tag:owned]", body["tags"])
	}

	keys := s.Store().ListPreAuthKeys()
	if len(keys) != 1 || !slices.Equal(keys[0].Tags, []string{"tag:owned"}) {
		t.Fatalf("stored keys = %+v, want one key tagged tag:owned", keys)
	}

	// A tag the policy does not define is refused.
	bad := apiRequest(t, client, http.MethodPost, hs.URL+"/api/v1/auth-keys", token,
		map[string]any{"tags": []string{"tag:undefined"}})
	if bad.StatusCode != http.StatusBadRequest {
		t.Errorf("undefined tag status = %d, want 400", bad.StatusCode)
	}

	// The list view exposes tags without secrets.
	list := decodeAPI(t, apiRequest(t, client, http.MethodGet, hs.URL+"/api/v1/auth-keys", token, nil))
	authKeys := list["authKeys"].([]any)
	if len(authKeys) != 1 {
		t.Fatalf("authKeys = %v, want one", authKeys)
	}
	if _, hasSecret := authKeys[0].(map[string]any)["key"]; hasSecret {
		t.Error("the auth-key list must not reveal secrets")
	}
}

// TestConsoleAuthKeyTags checks tag validation on the console form.
func TestConsoleAuthKeyTags(t *testing.T) {
	s := newServerWithConfig(t, Config{PolicyPath: policyFile(t, tagPolicy)})
	hs := newTestHTTPServer(t, s)
	client := noRedirectClient()
	cookie := loginLocal(t, client, hs.URL, "/console/auth-keys")

	page := bodyString(t, getRequest(t, client, hs.URL+"/console/auth-keys", cookie))
	csrf := extractCSRF(t, page)

	// An undefined tag is rejected, not silently stored.
	bad := postForm(t, client, hs.URL+"/console/auth-keys",
		url.Values{"csrf": {csrf}, "tags": {"tag:undefined"}}, cookie)
	if bad.StatusCode != http.StatusBadRequest {
		t.Fatalf("undefined tag status = %d, want 400", bad.StatusCode)
	}
	if keys := s.Store().ListPreAuthKeys(); len(keys) != 0 {
		t.Fatalf("rejected form created a key: %+v", keys)
	}

	good := postForm(t, client, hs.URL+"/console/auth-keys",
		url.Values{"csrf": {csrf}, "tags": {"tag:owned, tag:owned"}}, cookie)
	if good.StatusCode != http.StatusOK {
		t.Fatalf("create status = %d (%s), want 200", good.StatusCode, bodyString(t, good))
	}
	keys := s.Store().ListPreAuthKeys()
	if len(keys) != 1 || !slices.Equal(keys[0].Tags, []string{"tag:owned"}) {
		t.Fatalf("stored keys = %+v, want one key tagged tag:owned", keys)
	}
	if body := bodyString(t, good); !strings.Contains(body, "<code>tag:owned</code>") {
		t.Errorf("key list does not show the tag:\n%s", body)
	}
}
