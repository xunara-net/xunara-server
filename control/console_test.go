package control

import (
	"bytes"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"tailscale.com/tailcfg"
	"tailscale.com/types/key"

	"github.com/xunara-net/xunara-server/identity"
	"github.com/xunara-net/xunara-server/idtoken"
	"github.com/xunara-net/xunara-server/state"
	"github.com/xunara-net/xunara-server/webhook"
)

// TestConsoleRequiresSession checks that every console page sends anonymous
// browsers to the sign-in page with a return path.
func TestConsoleRequiresSession(t *testing.T) {
	s := newTestServer(t)
	hs := newTestHTTPServer(t, s)
	client := noRedirectClient()

	for _, path := range []string{"/console/", "/console/machines", "/console/devices", "/console/audit", "/console/reach", "/console/reach/deadbeef", "/console/flux", "/console/flux/fx_deadbeef"} {
		resp := getRequest(t, client, hs.URL+path, nil)
		if resp.StatusCode != http.StatusFound {
			t.Fatalf("GET %s status = %d, want 302", path, resp.StatusCode)
		}
		loc := resp.Header.Get("Location")
		if !strings.HasPrefix(loc, "/login?return_to=") || !strings.Contains(loc, url.QueryEscape(path)) {
			t.Fatalf("GET %s redirect = %q, want a login redirect for the same path", path, loc)
		}
	}
}

// TestConsolePagesRender walks every console page as a signed-in operator.
func TestConsolePagesRender(t *testing.T) {
	s := newTestServer(t)
	hs := newTestHTTPServer(t, s)
	client := noRedirectClient()
	cookie := loginLocal(t, client, hs.URL, "/console/")

	conn, _, _ := registerNode(t, s, hs, "console-node")
	defer conn.Close()

	pages := []struct {
		path string
		want string
	}{
		{"/console/", "machines online"},
		{"/console/machines", "console-node"},
		{"/console/devices", "No devices are waiting for approval."},
		{"/console/users", "Xunara User"},
		{"/console/dns", "No extra DNS records."},
		{"/console/auth-keys", "Create key"},
		{"/console/agents", "No agent credentials."},
		{"/console/reach", "Reach is not enabled"},
		{"/console/derp", "No DERP map is configured"},
		{"/console/flux", "Flux is not enabled"},
		{"/console/webhooks", "No webhook receivers are configured."},
		{"/console/policy", "No policy document is configured"},
		{"/console/audit", identity.AuditNodeApproved},
	}

	for _, page := range pages {
		resp := getRequest(t, client, hs.URL+page.path, cookie)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET %s status = %d, want 200", page.path, resp.StatusCode)
		}
		if cc := resp.Header.Get("Cache-Control"); cc != "no-store" {
			t.Errorf("GET %s Cache-Control = %q, want no-store", page.path, cc)
		}
		if body := bodyString(t, resp); !strings.Contains(body, page.want) {
			t.Errorf("GET %s does not contain %q:\n%s", page.path, page.want, body)
		}
	}
}

// TestConsoleRevokeAgentToken covers the console half of agent credential
// administration: the list never shows the credential, and revoking it takes
// effect immediately.
func TestConsoleRevokeAgentToken(t *testing.T) {
	s := newServerWithConfig(t, Config{Domain: "example.com"})
	hs := newTestHTTPServer(t, s)
	client := noRedirectClient()
	cookie := loginLocal(t, client, hs.URL, "/console/")

	secret := seedPreAuthKey(t, s, state.PreAuthKey{})
	machineKey := key.NewMachine()
	nodeKey := key.NewNode()
	enrolled := enrollAgent(t, client, hs.URL, machineKey, nodeKey, secret)
	if enrolled.Token == "" {
		t.Fatalf("enrollment = %+v", enrolled)
	}

	resp := getRequest(t, client, hs.URL+"/console/agents", cookie)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("agents page status = %d", resp.StatusCode)
	}
	page := bodyString(t, resp)
	if strings.Contains(page, enrolled.Token) {
		t.Fatal("console page leaks the agent credential")
	}
	if !strings.Contains(page, "agent-node") {
		t.Fatalf("agents page does not list the enrolled node:\n%s", page)
	}

	tokens := s.identity.ListAgentTokens(0)
	if len(tokens) == 0 {
		t.Fatal("no agent token was recorded")
	}
	tokenID := tokens[0].ID

	csrf := extractCSRF(t, page)
	if resp := postForm(t, client, hs.URL+"/console/agents/"+tokenID+"/revoke", url.Values{"csrf": {csrf}}, cookie); resp.StatusCode != http.StatusOK {
		t.Fatalf("revoke status = %d", resp.StatusCode)
	}

	body, status := agentPost(t, client, hs.URL, "/api/agent/v1/netmap", enrolled.Token, agentRequest{
		MachineKey: machineKey.Public().String(),
		NodeKey:    nodeKey.Public().String(),
	})
	if status != http.StatusUnauthorized {
		t.Fatalf("revoked credential netmap status = %d (%s), want 401", status, body)
	}
	if _, ok := findAudit(t, s, identity.AuditAgentTokenRevoked); !ok {
		t.Error("agent.token_revoked audit event missing")
	}
}

// TestConsoleRejectsMissingCSRF checks that state-changing console POSTs
// require the session-bound form token.
func TestConsoleRejectsMissingCSRF(t *testing.T) {
	s := newTestServer(t)
	hs := newTestHTTPServer(t, s)
	client := noRedirectClient()
	cookie := loginLocal(t, client, hs.URL, "/console/")

	posts := []struct {
		path string
		form url.Values
	}{
		{"/console/auth-keys", url.Values{"ttl": {"1h"}}},
		{"/console/machines/1/delete", url.Values{}},
		{"/console/dns/1/delete", url.Values{}},
		{"/console/users/1", url.Values{"displayName": {"nope"}}},
	}
	for _, post := range posts {
		resp := postForm(t, client, hs.URL+post.path, post.form, cookie)
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("POST %s without CSRF status = %d, want 403", post.path, resp.StatusCode)
		}
	}
	if keys := s.Store().ListPreAuthKeys(); len(keys) != 0 {
		t.Errorf("a CSRF-less POST created an auth key: %v", keys)
	}
}

// TestConsoleRouteApproval drives route approval through the console form.
func TestConsoleRouteApproval(t *testing.T) {
	s := newTestServer(t)
	hs := newTestHTTPServer(t, s)
	client := noRedirectClient()
	cookie := loginLocal(t, client, hs.URL, "/console/machines")

	conn, h2, nodeKey := registerNode(t, s, hs, "router")
	defer conn.Close()

	subnet := netip.MustParsePrefix("192.168.7.0/24")
	postRaw(t, h2, "/machine/map", tailcfg.MapRequest{
		Version:  tailcfg.CurrentCapabilityVersion,
		NodeKey:  nodeKey.Public(),
		Hostinfo: advertisedHostinfo("router", subnet),
	})

	node, ok := s.Store().GetNodeByNodeKey(nodeKey.Public())
	if !ok {
		t.Fatal("node not found after map request")
	}
	if got := node.AnnouncedRoutes(); len(got) != 1 || got[0] != subnet {
		t.Fatalf("announced routes = %v, want [%s]", got, subnet)
	}

	page := bodyString(t, getRequest(t, client, hs.URL+"/console/machines", cookie))
	csrf := extractCSRF(t, page)
	if !strings.Contains(page, subnet.String()) {
		t.Fatalf("machines page does not show the announced route %s", subnet)
	}

	action := fmt.Sprintf("/console/machines/%d/routes", node.ID)
	resp := postForm(t, client, hs.URL+action, url.Values{"csrf": {csrf}, "action": {"approve-all"}}, cookie)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("approve-all status = %d, want 200", resp.StatusCode)
	}
	if body := bodyString(t, resp); !strings.Contains(body, "All announced routes approved.") {
		t.Errorf("approve-all page lacks the notice:\n%s", body)
	}

	node, ok = s.Store().GetNodeByID(node.ID)
	if !ok || !containsPrefix(node.ApprovedRoutes, subnet) {
		t.Fatalf("approved routes = %v, want [%s]", node.ApprovedRoutes, subnet)
	}
	if !auditActionSet(t, s)[identity.AuditRouteApproved] {
		t.Error("route approval was not audited")
	}

	// Withdrawing clears the approval again.
	resp = postForm(t, client, hs.URL+action, url.Values{"csrf": {csrf}, "action": {"unapprove-all"}}, cookie)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unapprove-all status = %d, want 200", resp.StatusCode)
	}
	node, _ = s.Store().GetNodeByID(node.ID)
	if len(node.ApprovedRoutes) != 0 {
		t.Fatalf("approved routes after withdraw = %v, want none", node.ApprovedRoutes)
	}
	if !auditActionSet(t, s)[identity.AuditRouteUnapproved] {
		t.Error("route withdrawal was not audited")
	}

	// An unknown action is refused, not treated as a no-op.
	resp = postForm(t, client, hs.URL+action, url.Values{"csrf": {csrf}, "action": {"nope"}}, cookie)
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("unknown action status = %d, want 400", resp.StatusCode)
	}
}

// TestConsoleMachineDelete removes a machine through the console.
func TestConsoleMachineDelete(t *testing.T) {
	s := newTestServer(t)
	hs := newTestHTTPServer(t, s)
	client := noRedirectClient()
	cookie := loginLocal(t, client, hs.URL, "/console/machines")

	conn, _, nodeKey := registerNode(t, s, hs, "doomed")
	defer conn.Close()

	node, ok := s.Store().GetNodeByNodeKey(nodeKey.Public())
	if !ok {
		t.Fatal("node not found")
	}

	page := bodyString(t, getRequest(t, client, hs.URL+"/console/machines", cookie))
	csrf := extractCSRF(t, page)
	action := fmt.Sprintf("/console/machines/%d/delete", node.ID)
	resp := postForm(t, client, hs.URL+action, url.Values{"csrf": {csrf}}, cookie)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("delete status = %d, want 200", resp.StatusCode)
	}
	if body := bodyString(t, resp); !strings.Contains(body, "Machine doomed deleted.") {
		t.Errorf("delete page lacks the notice:\n%s", body)
	}
	if _, ok := s.Store().GetNodeByID(node.ID); ok {
		t.Error("machine still exists after console delete")
	}
	if !auditActionSet(t, s)[identity.AuditNodeDeleted] {
		t.Error("console delete was not audited")
	}
}

// TestConsoleAuthKeyLifecycle creates a key, checks the secret is only shown
// once, then revokes it.
func TestConsoleAuthKeyLifecycle(t *testing.T) {
	s := newTestServer(t)
	hs := newTestHTTPServer(t, s)
	client := noRedirectClient()
	cookie := loginLocal(t, client, hs.URL, "/console/auth-keys")

	page := bodyString(t, getRequest(t, client, hs.URL+"/console/auth-keys", cookie))
	csrf := extractCSRF(t, page)

	resp := postForm(t, client, hs.URL+"/console/auth-keys",
		url.Values{"csrf": {csrf}, "ttl": {"1h"}, "reusable": {"on"}}, cookie)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("create status = %d, want 200", resp.StatusCode)
	}

	keys := s.Store().ListPreAuthKeys()
	if len(keys) != 1 {
		t.Fatalf("keys = %v, want one", keys)
	}
	key := keys[0]
	if !key.Reusable || key.UserID != state.DefaultUserID || key.Expiry.IsZero() {
		t.Errorf("key = %+v", key)
	}

	// The creation page shows the secret exactly once.
	if body := bodyString(t, resp); !strings.Contains(body, key.Key) {
		t.Errorf("creation page does not show the new secret:\n%s", body)
	}

	// Later reads must not.
	again := bodyString(t, getRequest(t, client, hs.URL+"/console/auth-keys", cookie))
	if strings.Contains(again, key.Key) {
		t.Error("the auth key secret is rendered after creation")
	}
	if !strings.Contains(again, fmt.Sprintf("<td>%d</td>", key.ID)) {
		t.Errorf("key list does not show key %d:\n%s", key.ID, again)
	}
	if !auditActionSet(t, s)[identity.AuditPreAuthKeyCreated] {
		t.Error("key creation was not audited")
	}

	resp = postForm(t, client, hs.URL+fmt.Sprintf("/console/auth-keys/%d/delete", key.ID),
		url.Values{"csrf": {csrf}}, cookie)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("revoke status = %d, want 200", resp.StatusCode)
	}
	if keys := s.Store().ListPreAuthKeys(); len(keys) != 0 {
		t.Errorf("keys after revoke = %v, want none", keys)
	}
	if !auditActionSet(t, s)[identity.AuditPreAuthKeyDeleted] {
		t.Error("key revocation was not audited")
	}
}

// TestConsoleDeviceApproval approves a pending device through the console.
func TestConsoleDeviceApproval(t *testing.T) {
	s := newTestServer(t)
	hs := newTestHTTPServer(t, s)
	client := noRedirectClient()
	cookie := loginLocal(t, client, hs.URL, "/console/devices")

	conn, _, _, authID := startRegistration(t, hs, "console-device")
	defer conn.Close()

	page := bodyString(t, getRequest(t, client, hs.URL+"/console/devices", cookie))
	if !strings.Contains(page, "console-device") {
		t.Fatalf("pending device list lacks the hostname:\n%s", page)
	}
	csrf := extractCSRF(t, page)

	resp := postForm(t, client, hs.URL+"/console/devices/"+authID+"/approve", url.Values{"csrf": {csrf}}, cookie)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("approve status = %d, want 200", resp.StatusCode)
	}
	if body := bodyString(t, resp); !strings.Contains(body, "Device approved.") {
		t.Errorf("approve page lacks the notice:\n%s", body)
	}

	da, ok := s.Identity().GetDeviceAuthorization(authID)
	if !ok || da.State != identity.DeviceApproved {
		t.Fatalf("device authorization = %+v (ok=%v), want approved", da, ok)
	}
	if _, ok := s.Store().GetNodeByNodeKey(nodeKeyOfRegistration(t, s, authID)); !ok {
		t.Error("approving through the console did not create the node")
	}
	if da.UserID != state.DefaultUserID {
		t.Errorf("approved user = %d, want the signed-in user %d", da.UserID, state.DefaultUserID)
	}
}

// TestConsoleUserUpdate edits a user profile through the console.
func TestConsoleUserUpdate(t *testing.T) {
	s := newTestServer(t)
	hs := newTestHTTPServer(t, s)
	client := noRedirectClient()
	cookie := loginLocal(t, client, hs.URL, "/console/users")

	page := bodyString(t, getRequest(t, client, hs.URL+"/console/users", cookie))
	csrf := extractCSRF(t, page)

	resp := postForm(t, client, hs.URL+fmt.Sprintf("/console/users/%d", state.DefaultUserID),
		url.Values{"csrf": {csrf}, "displayName": {"Ops Team"}, "email": {"ops@example.com"}}, cookie)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("update status = %d, want 200", resp.StatusCode)
	}
	if body := bodyString(t, resp); !strings.Contains(body, "User updated.") {
		t.Errorf("update page lacks the notice:\n%s", body)
	}

	user, ok := s.Identity().GetUser(state.DefaultUserID)
	if !ok || user.DisplayName != "Ops Team" || user.Email != "ops@example.com" {
		t.Fatalf("user = %+v (ok=%v)", user, ok)
	}
	if !auditActionSet(t, s)[identity.AuditUserUpdated] {
		t.Error("user update was not audited")
	}
}

// TestConsoleWebhookManagement drives the console half of webhook
// administration: the page lists receivers without their secret, creating one
// stores the secret sealed, and deleting it removes the endpoint.
func TestConsoleWebhookManagement(t *testing.T) {
	s := newTestServer(t)
	hs := newTestHTTPServer(t, s)
	client := noRedirectClient()
	cookie := loginLocal(t, client, hs.URL, "/console/webhooks")

	page := bodyString(t, getRequest(t, client, hs.URL+"/console/webhooks", cookie))
	if !strings.Contains(page, "Create webhook") {
		t.Fatalf("webhooks page lacks the create form:\n%s", page)
	}

	const secret = "console-webhook-secret"
	resp := postForm(t, client, hs.URL+"/console/webhooks", url.Values{
		"csrf":   {extractCSRF(t, page)},
		"id":     {"ops"},
		"url":    {"https://example.com/hook"},
		"secret": {secret},
		"events": {"node.*, audit.*"},
	}, cookie)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("create status = %d, want 200", resp.StatusCode)
	}
	body := bodyString(t, resp)
	if !strings.Contains(body, "Webhook created.") || !strings.Contains(body, "<code>ops</code>") {
		t.Fatalf("created webhook is not listed:\n%s", body)
	}
	if strings.Contains(body, secret) {
		t.Fatal("console page leaks the webhook secret")
	}

	stored, ok := s.Identity().GetWebhookEndpoint("ops")
	if !ok {
		t.Fatal("webhook endpoint was not stored")
	}
	if stored.Secret == secret || !strings.HasPrefix(stored.Secret, "v1:") {
		t.Errorf("stored secret = %q, want sealed ciphertext", stored.Secret)
	}
	if got := stored.Events; len(got) != 2 || got[0] != "audit.*" || got[1] != "node.*" {
		t.Errorf("stored events = %v, want sorted [audit.* node.*]", got)
	}
	if !stored.Enabled {
		t.Error("a console-created webhook is not enabled")
	}
	if _, ok := findAudit(t, s, identity.AuditWebhookCreated); !ok {
		t.Error("webhook.created audit event missing")
	}

	resp = postForm(t, client, hs.URL+"/console/webhooks/ops/delete",
		url.Values{"csrf": {extractCSRF(t, body)}}, cookie)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("delete status = %d, want 200", resp.StatusCode)
	}
	if body := bodyString(t, resp); !strings.Contains(body, "Webhook deleted.") {
		t.Errorf("delete page lacks the notice:\n%s", body)
	}
	if _, ok := s.Identity().GetWebhookEndpoint("ops"); ok {
		t.Error("webhook endpoint still exists after deletion")
	}
	if _, ok := findAudit(t, s, identity.AuditWebhookDeleted); !ok {
		t.Error("webhook.deleted audit event missing")
	}

	page = bodyString(t, getRequest(t, client, hs.URL+"/console/webhooks", cookie))
	resp = postForm(t, client, hs.URL+"/console/webhooks/ops/delete",
		url.Values{"csrf": {extractCSRF(t, page)}}, cookie)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("second delete status = %d, want 404", resp.StatusCode)
	}
}

// TestConsoleWebhookConfiguredProtected checks that a deployment-configured
// receiver is listed but can neither be deleted nor shadowed from the console,
// and that read-only roles cannot add receivers.
func TestConsoleWebhookConfiguredProtected(t *testing.T) {
	s := newServerWithConfig(t, Config{
		Webhooks: []webhook.Endpoint{{
			ID: "configured", URL: "https://example.com/hook", Secret: "cfg-secret",
		}},
	})
	hs := newTestHTTPServer(t, s)
	client := noRedirectClient()
	cookie := loginLocal(t, client, hs.URL, "/console/webhooks")

	page := bodyString(t, getRequest(t, client, hs.URL+"/console/webhooks", cookie))
	if !strings.Contains(page, "from startup config") {
		t.Fatalf("configured receiver is not marked as such:\n%s", page)
	}
	if strings.Contains(page, "cfg-secret") {
		t.Fatal("console page leaks a configured webhook secret")
	}
	if strings.Contains(page, "/console/webhooks/configured/delete") {
		t.Error("console offers a delete button for a configured receiver")
	}

	csrf := extractCSRF(t, page)
	resp := postForm(t, client, hs.URL+"/console/webhooks/configured/delete",
		url.Values{"csrf": {csrf}}, cookie)
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("delete configured status = %d, want 409", resp.StatusCode)
	}
	resp = postForm(t, client, hs.URL+"/console/webhooks", url.Values{
		"csrf":   {csrf},
		"id":     {"configured"},
		"url":    {"https://example.com/hook"},
		"secret": {"s"},
	}, cookie)
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("create with a configured id status = %d, want 409", resp.StatusCode)
	}

	memberID := seedRoleUser(t, s, "viewer@example.com", identity.RoleMember)
	memberCookie, _ := seedUserSession(t, s, memberID)
	memberPage := bodyString(t, getRequest(t, client, hs.URL+"/console/webhooks", memberCookie))
	if strings.Contains(memberPage, "Create webhook") {
		t.Error("read-only console page shows the create form")
	}
	resp = postForm(t, client, hs.URL+"/console/webhooks", url.Values{
		"csrf":   {csrf},
		"id":     {"ops"},
		"url":    {"https://example.com/hook"},
		"secret": {"s"},
	}, memberCookie)
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("member create status = %d, want 403", resp.StatusCode)
	}
}

// TestConsolePolicyPage shows the loaded policy document.
func TestConsolePolicyPage(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.hujson")
	doc := `{
  // A policy with one rule and one unsupported field.
  "acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}],
  "autoApprovers": {"routes": {"10.0.0.0/8": ["tag:router"]}},
}`
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatalf("writing policy: %v", err)
	}

	s := newServerWithConfig(t, Config{PolicyPath: path})
	hs := newTestHTTPServer(t, s)
	client := noRedirectClient()
	cookie := loginLocal(t, client, hs.URL, "/console/policy")

	resp := getRequest(t, client, hs.URL+"/console/policy", cookie)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("policy page status = %d, want 200", resp.StatusCode)
	}
	body := bodyString(t, resp)
	for _, want := range []string{"policy.hujson", "<dd>1</dd>", "Unsupported fields", "autoApprovers"} {
		if !strings.Contains(body, want) {
			t.Errorf("policy page lacks %q:\n%s", want, body)
		}
	}
}

// TestConsolePolicyWardenSections covers the read-only Warden tables on the
// policy page: traffic rules, grants, groups, hosts, tag owners, SSH rules,
// node attributes and the document's test results.
func TestConsolePolicyWardenSections(t *testing.T) {
	s := newServerWithConfig(t, Config{PolicyPath: policyFile(t, wardenPolicy)})
	seedAPIMachine(t, s, "warden-node", []string{"tag:server"})
	hs := newTestHTTPServer(t, s)
	client := noRedirectClient()
	cookie := loginLocal(t, client, hs.URL, "/console/policy")

	page := bodyString(t, getRequest(t, client, hs.URL+"/console/policy", cookie))
	for _, want := range []string{
		"Traffic rules", "tag:server:22", "Grants", "example.com/cap/x",
		"group:ops", "Hosts", "Tag owners", "SSH rules", "12h0m0s",
		"Node attributes", "https", "Policy tests", "pass", "autoApprovers",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("policy page lacks %q:\n%s", want, page)
		}
	}
	if strings.Contains(page, `action="/console/policy`) {
		t.Errorf("the policy page offers a write control:\n%s", page)
	}
}

// TestConsoleSSHCheckPage covers the read-only SSH check page: the lifecycle
// states, the fail-closed filter, and the absence of decision controls (the
// ID links to the existing approval page, which guards itself).
func TestConsoleSSHCheckPage(t *testing.T) {
	_, hs, _, _ := sshCheckTestServer(t)
	client := noRedirectClient()
	cookie := loginLocal(t, client, hs.URL, "/console/ssh-check")

	page := bodyString(t, getRequest(t, client, hs.URL+"/console/ssh-check", cookie))
	for _, want := range []string{
		"SSH checks", "pending", "consumed", "accepted", "expired",
		"ssh-src", "ssh-dst", "root", "deploy",
		`href="/ssh/check/check-pending"`,
	} {
		if !strings.Contains(page, want) {
			t.Errorf("ssh check page lacks %q:\n%s", want, page)
		}
	}
	if strings.Contains(page, `action="/ssh/check`) {
		t.Errorf("the ssh check page embeds a decision form:\n%s", page)
	}

	filtered := bodyString(t, getRequest(t, client, hs.URL+"/console/ssh-check?state=pending", cookie))
	if !strings.Contains(filtered, "check-pending") {
		t.Errorf("filtered page lacks the pending check:\n%s", filtered)
	}
	if strings.Contains(filtered, "check-accepted") {
		t.Errorf("state=pending still shows a decided check:\n%s", filtered)
	}

	if resp := getRequest(t, client, hs.URL+"/console/ssh-check?state=nope", cookie); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("unknown state status = %d, want 400", resp.StatusCode)
	}
}

// extractPre reads the first <pre>…</pre> block, which is how the console
// shows a one-time secret.
func extractPre(t *testing.T, html string) string {
	t.Helper()
	start := strings.Index(html, "<pre>")
	if start < 0 {
		t.Fatalf("no <pre> block in page:\n%s", html)
	}
	rest := html[start+len("<pre>"):]
	end := strings.Index(rest, "</pre>")
	if end < 0 {
		t.Fatalf("unterminated <pre> block in page:\n%s", html)
	}
	return rest[:end]
}

// TestConsoleAPIKeysPage covers the API key console: create shows the token
// once, the list never leaks it, the key authenticates, revoke takes it away,
// and a read-only member may look but not create or revoke.
func TestConsoleAPIKeysPage(t *testing.T) {
	s := newTestServer(t)
	hs := newTestHTTPServer(t, s)
	client := noRedirectClient()
	cookie := loginLocal(t, client, hs.URL, "/console/api-keys")

	page := bodyString(t, getRequest(t, client, hs.URL+"/console/api-keys", cookie))
	if !strings.Contains(page, "No API keys yet") {
		t.Fatalf("empty api keys page:\n%s", page)
	}

	csrf := extractCSRF(t, page)
	resp := postForm(t, client, hs.URL+"/console/api-keys", url.Values{
		"csrf": {csrf}, "name": {"ci-deploy"}, "scope_read": {"1"}, "ttl": {"1h"},
	}, cookie)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("create status = %d", resp.StatusCode)
	}
	created := bodyString(t, resp)
	token := extractPre(t, created)
	if !strings.HasPrefix(token, identity.APIKeyPrefix) {
		t.Fatalf("created token = %q, want the xunara_ prefix", token)
	}

	// The token authenticates as a service identity.
	if resp := apiRequest(t, client, http.MethodGet, hs.URL+"/api/v2/meta", token, nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("api status with the new key = %d, want 200", resp.StatusCode)
	}

	// The list shows the key's metadata, never the token.
	page = bodyString(t, getRequest(t, client, hs.URL+"/console/api-keys", cookie))
	for _, want := range []string{"ci-deploy", "read", "live"} {
		if !strings.Contains(page, want) {
			t.Errorf("api keys page lacks %q:\n%s", want, page)
		}
	}
	if strings.Contains(page, token) {
		t.Error("the api keys page leaks the token")
	}

	// Revoke: the key stops working, and a second revoke is a no-op.
	keys := s.Identity().ListAPIKeys()
	if len(keys) != 1 {
		t.Fatalf("api keys = %d, want 1", len(keys))
	}
	csrf = extractCSRF(t, page)
	if resp := postForm(t, client, hs.URL+"/console/api-keys/"+keys[0].ID+"/revoke",
		url.Values{"csrf": {csrf}}, cookie); resp.StatusCode != http.StatusOK {
		t.Fatalf("revoke status = %d", resp.StatusCode)
	}
	if resp := apiRequest(t, client, http.MethodGet, hs.URL+"/api/v2/meta", token, nil); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("revoked key status = %d, want 401", resp.StatusCode)
	}
	if resp := postForm(t, client, hs.URL+"/console/api-keys/"+keys[0].ID+"/revoke",
		url.Values{"csrf": {csrf}}, cookie); resp.StatusCode != http.StatusOK {
		t.Errorf("second revoke status = %d, want 200", resp.StatusCode)
	}

	// Validation: a missing name or scope is refused.
	resp = postForm(t, client, hs.URL+"/console/api-keys", url.Values{
		"csrf": {csrf}, "scope_read": {"1"}}, cookie)
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("nameless create status = %d, want 400", resp.StatusCode)
	}
	resp = postForm(t, client, hs.URL+"/console/api-keys", url.Values{
		"csrf": {csrf}, "name": {"no-scope"}}, cookie)
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("scopeless create status = %d, want 400", resp.StatusCode)
	}

	// A read-only member sees the list but no controls, and a direct POST is
	// refused.
	memberID := seedRoleUser(t, s, "api-member@example.com", identity.RoleMember)
	memberCookie, memberToken := seedUserSession(t, s, memberID)
	memberPage := bodyString(t, getRequest(t, client, hs.URL+"/console/api-keys", memberCookie))
	for _, form := range []string{`action="/console/api-keys"`, `action="/console/api-keys/`} {
		if strings.Contains(memberPage, form) {
			t.Errorf("read-only member sees a write control %s:\n%s", form, memberPage)
		}
	}
	resp = postForm(t, client, hs.URL+"/console/api-keys", url.Values{
		"csrf": {csrfTokenFor(memberToken)}, "name": {"escalate"}, "scope_write": {"1"},
	}, memberCookie)
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("member create status = %d, want 403", resp.StatusCode)
	}
}

// TestConsoleAuditNewestFirst checks the audit page shows recent events first.
func TestConsoleAuditNewestFirst(t *testing.T) {
	s := newTestServer(t)
	hs := newTestHTTPServer(t, s)
	client := noRedirectClient()
	cookie := loginLocal(t, client, hs.URL, "/console/audit")

	if err := s.Store().CreatePreAuthKey(&state.PreAuthKey{Key: "tskey-auth-test", UserID: state.DefaultUserID}); err != nil {
		t.Fatalf("seeding key: %v", err)
	}
	s.audit("test", identity.AuditPreAuthKeyCreated, "preauthkey:1", "seeded")

	body := bodyString(t, getRequest(t, client, hs.URL+"/console/audit", cookie))
	if !strings.Contains(body, identity.AuditPreAuthKeyCreated) {
		t.Fatalf("audit page lacks the seeded event:\n%s", body)
	}
	if i, j := strings.Index(body, identity.AuditPreAuthKeyCreated), strings.Index(body, identity.AuditLoginSucceeded); i > j {
		t.Error("audit page is not newest-first")
	}
}

// TestConsoleOverviewTailnetLock checks that the overview reflects the key
// authority: untouched by default, enabled with the chain head and signed-node
// count, and disabled after disablement.
func TestConsoleOverviewTailnetLock(t *testing.T) {
	s := newTestServer(t)
	hs := newTestHTTPServer(t, s)
	client := noRedirectClient()
	cookie := loginLocal(t, client, hs.URL, "/console/")

	overview := func() string {
		t.Helper()
		return bodyString(t, getRequest(t, client, hs.URL+"/console/", cookie))
	}

	if body := overview(); !strings.Contains(body, "Not enabled. Node keys are not verified by peers") {
		t.Errorf("overview does not describe an unlocked tailnet:\n%s", body)
	}

	adminKey, genesis := newTestTKAKey(t)
	conn, _, nodeKey := registerNode(t, s, hs, "lock-console")
	defer conn.Close()

	if err := s.tka.initBegin(genesis); err != nil {
		t.Fatalf("initBegin: %v", err)
	}
	node := storedNode(t, s, nodeKey.Public())
	node.KeySignature = signTestNodeKey(t, adminKey, node.NodeKey)
	if err := s.store.UpdateNode(node); err != nil {
		t.Fatalf("UpdateNode: %v", err)
	}
	if err := s.tka.enable(nil); err != nil {
		t.Fatalf("enable: %v", err)
	}

	body := overview()
	if !strings.Contains(body, "chain head <code>"+genesis.Hash().String()+"</code>") {
		t.Errorf("overview does not show the chain head:\n%s", body)
	}
	if !strings.Contains(body, "1 of 1 nodes carry a node-key") {
		t.Errorf("overview does not show the signed-node count:\n%s", body)
	}

	if err := s.tka.disable(testDisablementSecret); err != nil {
		t.Fatalf("disable: %v", err)
	}
	if body := overview(); !strings.Contains(body, "disabled</span>") {
		t.Errorf("overview does not report disablement:\n%s", body)
	}
}

// TestConsoleOverviewWorkloadIdentity checks the overview's issuer section:
// an enabled issuer with its public keys, a deployment without one, and the
// warning an operator gets when the keyring needs attention.
func TestConsoleOverviewWorkloadIdentity(t *testing.T) {
	s := newServerWithConfig(t, Config{ServerURL: "https://login.example.com", Domain: "example.com"})
	hs := newTestHTTPServer(t, s)
	client := noRedirectClient()
	cookie := loginLocal(t, client, hs.URL, "/console/")

	overview := func() string {
		t.Helper()
		return bodyString(t, getRequest(t, client, hs.URL+"/console/", cookie))
	}

	body := overview()
	if !strings.Contains(body, "issuer enabled") {
		t.Fatalf("overview does not report the issuer:\n%s", body)
	}
	if !strings.Contains(body, "https://login.example.com") ||
		!strings.Contains(body, "https://login.example.com/.well-known/jwks.json") {
		t.Errorf("overview does not show the issuer and JWKS URL:\n%s", body)
	}
	active := ""
	for _, key := range mustIDTokenStatus(t, s).Keys {
		if key.Active() {
			active = key.KID
		}
	}
	if active == "" || !strings.Contains(body, active) {
		t.Errorf("overview does not show the active key %q:\n%s", active, body)
	}

	// A keyring an operator must fix is reported instead of blanking the page.
	if err := os.Chmod(filepath.Join(s.cfg.StateDir, idtoken.KeyFileName), 0o640); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	if body := overview(); !strings.Contains(body, "unavailable") {
		t.Errorf("overview does not report a broken keyring:\n%s", body)
	}
}

// TestConsoleOverviewWorkloadIdentityWithoutIssuer checks the disabled state.
func TestConsoleOverviewWorkloadIdentityWithoutIssuer(t *testing.T) {
	s := newServerWithoutIssuer(t)
	hs := newTestHTTPServer(t, s)
	client := noRedirectClient()
	cookie := loginLocal(t, client, hs.URL, "/console/")

	body := bodyString(t, getRequest(t, client, hs.URL+"/console/", cookie))
	if !strings.Contains(body, "no externally reachable") {
		t.Errorf("overview does not explain the missing issuer:\n%s", body)
	}
}

// mustIDTokenStatus reads the issuer status outside the HTTP surface, for
// tests that need to know what the console rendered.
func mustIDTokenStatus(t *testing.T, s *Server) IDTokenStatus {
	t.Helper()

	status, err := s.IDTokenStatus()
	if err != nil {
		t.Fatalf("IDTokenStatus: %v", err)
	}
	return status
}

// TestConsoleMachinePostureColumn checks the read-only posture column on the
// machines page: a count with correct pluralisation, and a dash for machines
// that never reported anything.
func TestConsoleMachinePostureColumn(t *testing.T) {
	s := newTestServer(t)
	hs := newTestHTTPServer(t, s)
	client := noRedirectClient()
	cookie := loginLocal(t, client, hs.URL, "/console/machines")

	one := seedAPIMachine(t, s, "postured-one", nil)
	three := seedAPIMachine(t, s, "postured-three", nil)
	seedAPIMachine(t, s, "postured-quiet", nil)
	if err := s.store.SetNodeDeviceAttrs(one.ID, map[string]any{"os_version": "15.2"}); err != nil {
		t.Fatalf("SetNodeDeviceAttrs: %v", err)
	}
	if err := s.store.SetNodeDeviceAttrs(three.ID, map[string]any{"os_version": "15.2", "encrypted": true, "score": float64(1)}); err != nil {
		t.Fatalf("SetNodeDeviceAttrs: %v", err)
	}

	page := bodyString(t, getRequest(t, client, hs.URL+"/console/machines", cookie))
	rows := strings.Split(page, "<tr>")
	find := func(hostname string) string {
		t.Helper()
		for _, row := range rows {
			if strings.Contains(row, hostname) {
				return row
			}
		}
		t.Fatalf("machines page has no row for %s", hostname)
		return ""
	}

	if row := find("postured-one"); !strings.Contains(row, ">1 attr<") {
		t.Errorf("single attribute row lacks a singular count:\n%s", row)
	}
	if row := find("postured-three"); !strings.Contains(row, ">3 attrs<") {
		t.Errorf("three attribute row lacks a plural count:\n%s", row)
	}
	if row := find("postured-quiet"); !strings.Contains(row, ">—<") {
		t.Errorf("machine without attributes lacks a dash:\n%s", row)
	}
}

// TestConsoleServicesPage checks the read-only Services page and the services
// column on the machines page: what a node advertised, with no way to change
// it from the console.
func TestConsoleServicesPage(t *testing.T) {
	s := newServerWithConfig(t, Config{Domain: "example.com"})
	hs := newTestHTTPServer(t, s)
	client := noRedirectClient()
	cookie := loginLocal(t, client, hs.URL, "/console/services")

	web := seedAPIMachine(t, s, "web", nil)
	seedAPIMachine(t, s, "quiet", nil)
	if err := s.store.ReplaceNodeServices(web.ID, []state.Service{
		{Name: "api", Protocol: "tcp", Port: 8080, Metadata: map[string]string{"version": "2"}},
		{Name: "db", Protocol: "tcp", Port: 5432, Health: true, Visibility: []string{"tag:app", "group:eng"}, Shared: true},
		{Name: "acl-only", Protocol: "tcp", Port: 7000, VisibilityFromACL: true},
	}); err != nil {
		t.Fatalf("ReplaceNodeServices: %v", err)
	}
	if _, err := s.store.ReportServiceHealth(web.ID, []state.ServiceHealthReport{{Name: "db", Ready: true}}, time.Minute); err != nil {
		t.Fatalf("ReportServiceHealth: %v", err)
	}

	page := bodyString(t, getRequest(t, client, hs.URL+"/console/services", cookie))
	for _, want := range []string{"api", "tcp", "8080", "web", web.StableID, "api.example.com", "version", "2", "db.example.com", "Health", "healthy", "tag:app, group:eng"} {
		if !strings.Contains(page, want) {
			t.Errorf("services page lacks %q:\n%s", want, page)
		}
	}
	if strings.Contains(page, "/console/services/") {
		t.Errorf("the services page offers a write control:\n%s", page)
	}
	// The shared column reports the cross-organization projection.
	var sharedRow string
	for _, row := range strings.Split(page, "<tr>") {
		if strings.Contains(row, "db.example.com") {
			sharedRow = row
			break
		}
	}
	if !strings.Contains(sharedRow, ">yes<") {
		t.Errorf("db row lacks the shared marker:\n%s", sharedRow)
	}
	// An ACL-derived service renders its discovery scope as "acl".
	var aclRow string
	for _, row := range strings.Split(page, "<tr>") {
		if strings.Contains(row, "acl-only") {
			aclRow = row
			break
		}
	}
	if !strings.Contains(aclRow, ">acl<") {
		t.Errorf("acl-only row lacks the ACL marker:\n%s", aclRow)
	}

	// The machines page counts services per machine, with a dash when there
	// are none.
	machines := bodyString(t, getRequest(t, client, hs.URL+"/console/machines", cookie))
	rows := strings.Split(machines, "<tr>")
	find := func(hostname string) string {
		t.Helper()
		for _, row := range rows {
			// The chunk before the first <tr> is the page head (nav and
			// styles); only table rows are considered.
			if !strings.Contains(row, "<td>") {
				continue
			}
			if strings.Contains(row, ">"+hostname) {
				return row
			}
		}
		t.Fatalf("machines page has no row for %s", hostname)
		return ""
	}
	if row := find("web"); !strings.Contains(row, "<td>3</td>") {
		t.Errorf("web row lacks the service count:\n%s", row)
	}
	if row := find("quiet"); !strings.Contains(row, ">—<") {
		t.Errorf("quiet row lacks a dash:\n%s", row)
	}
}

// TestConsoleServicesPageEmpty checks the empty-state copy.
func TestConsoleServicesPageEmpty(t *testing.T) {
	s := newTestServer(t)
	hs := newTestHTTPServer(t, s)
	client := noRedirectClient()
	cookie := loginLocal(t, client, hs.URL, "/console/services")

	page := bodyString(t, getRequest(t, client, hs.URL+"/console/services", cookie))
	if !strings.Contains(page, "No services have been advertised") {
		t.Errorf("empty services page = %s", page)
	}
}

// TestConsoleReachPage covers the read-only Reach management page: the list
// links to a detail page that shows argv, state and the output, and neither
// page offers a write control.
func TestConsoleReachPage(t *testing.T) {
	_, hs, sender, target, _ := startReach(t)
	client := noRedirectClient()
	cookie := loginLocal(t, client, hs.URL, "/console/reach")

	session := offerReach(t, hs, sender, target, []string{"df", "-h", "<script>alert(1)</script>"})
	target.doReach(t, hs.Client(), http.MethodPost, reachURL(hs, session.ID, "accept"), nil)
	target.doReach(t, hs.Client(), http.MethodPost, reachURL(hs, session.ID, "start"), nil)
	if _, status := target.doReach(t, hs.Client(), http.MethodPost, reachURL(hs, session.ID, "chunks"),
		map[string]any{"stream": "stdout", "seq": 0, "data": []byte("Filesystem  Size\n")}); status != http.StatusNoContent {
		t.Fatalf("storing reach output = %d", status)
	}
	target.doReach(t, hs.Client(), http.MethodPost, reachURL(hs, session.ID, "finish"), map[string]any{"exitCode": 0})

	// The refusing session proves the state filter narrows the list.
	denied := offerReach(t, hs, sender, target, []string{"rm", "-rf", "/"})
	target.doReach(t, hs.Client(), http.MethodPost, reachURL(hs, denied.ID, "deny"), nil)

	list := bodyString(t, getRequest(t, client, hs.URL+"/console/reach", cookie))
	for _, want := range []string{
		"Reach", session.ID, denied.ID, "df -h", sender.node.StableID, target.node.StableID,
		"succeeded", "denied", "&lt;script&gt;alert(1)&lt;/script&gt;",
	} {
		if !strings.Contains(list, want) {
			t.Errorf("reach list lacks %q:\n%s", want, list)
		}
	}
	if strings.Contains(list, "<script>alert(1)</script>") {
		t.Errorf("the reach list does not escape argv:\n%s", list)
	}
	if strings.Contains(list, "Filesystem") {
		t.Errorf("the reach list renders output text:\n%s", list)
	}
	// The only form on the page is the state filter; there is no write path.
	if strings.Contains(list, `action="/console/reach/`) {
		t.Errorf("the reach list offers a write control:\n%s", list)
	}

	filtered := bodyString(t, getRequest(t, client, hs.URL+"/console/reach?state=denied", cookie))
	if strings.Contains(filtered, session.ID) || !strings.Contains(filtered, denied.ID) {
		t.Errorf("state filter = %s", filtered)
	}
	if resp := getRequest(t, client, hs.URL+"/console/reach?state=bogus", cookie); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("unknown state filter = %d, want 400", resp.StatusCode)
	}

	detail := bodyString(t, getRequest(t, client, hs.URL+"/console/reach/"+session.ID, cookie))
	for _, want := range []string{
		session.ID, "succeeded", "<code>df</code>", "<code>-h</code>",
		"&lt;script&gt;alert(1)&lt;/script&gt;", "Filesystem  Size", "Exit code",
		fmt.Sprintf("%d bytes on stdout", len("Filesystem  Size\n")),
	} {
		if !strings.Contains(detail, want) {
			t.Errorf("reach detail lacks %q:\n%s", want, detail)
		}
	}
	if strings.Contains(detail, `action="/console/reach/`) {
		t.Errorf("the reach detail offers a write control:\n%s", detail)
	}
	if resp := getRequest(t, client, hs.URL+"/console/reach/nosuchsession", cookie); resp.StatusCode != http.StatusNotFound {
		t.Errorf("unknown session = %d, want 404", resp.StatusCode)
	}
}

// TestConsoleReachOutputTruncation checks that a long session is cut to the
// page's budget and says so, instead of rendering the whole record.
func TestConsoleReachOutputTruncation(t *testing.T) {
	_, hs, sender, target, _ := startReach(t)
	client := noRedirectClient()
	cookie := loginLocal(t, client, hs.URL, "/console/reach")

	session := offerReach(t, hs, sender, target, []string{"yes"})
	target.doReach(t, hs.Client(), http.MethodPost, reachURL(hs, session.ID, "accept"), nil)
	target.doReach(t, hs.Client(), http.MethodPost, reachURL(hs, session.ID, "start"), nil)
	// Three chunks of 24 KiB: more than the 64 KiB the page renders.
	chunk := bytes.Repeat([]byte("x"), state.ReachMaxChunkBytes)
	for seq := range 3 {
		if _, status := target.doReach(t, hs.Client(), http.MethodPost, reachURL(hs, session.ID, "chunks"),
			map[string]any{"stream": "stdout", "seq": seq, "data": chunk}); status != http.StatusNoContent {
			t.Fatalf("storing chunk %d = %d", seq, status)
		}
	}
	target.doReach(t, hs.Client(), http.MethodPost, reachURL(hs, session.ID, "finish"), map[string]any{"exitCode": 0})

	detail := bodyString(t, getRequest(t, client, hs.URL+"/console/reach/"+session.ID, cookie))
	if !strings.Contains(detail, "more output was written") {
		t.Errorf("truncated detail does not say so:\n%.400s", detail)
	}
	if !strings.Contains(detail, fmt.Sprintf("%d bytes on stdout", 3*len(chunk))) {
		t.Errorf("detail does not report the full output size:\n%.400s", detail)
	}
	// The rendered body must stay bounded: the page never carries all 72 KiB.
	// The check counts the rendered output bytes, not the page size, because
	// the surrounding chrome differs between languages.
	if got := strings.Count(detail, "x"); got > consoleReachOutputLimit+4<<10 {
		t.Errorf("truncated page carries %d bytes of output, want about %d", got, consoleReachOutputLimit)
	}
}

// TestConsoleReachPageDisabled checks that a deployment without Reach explains
// itself on both pages instead of rendering 404s or empty tables.
func TestConsoleReachPageDisabled(t *testing.T) {
	s := newTestServer(t)
	hs := newTestHTTPServer(t, s)
	client := noRedirectClient()
	cookie := loginLocal(t, client, hs.URL, "/console/reach")

	for _, path := range []string{"/console/reach", "/console/reach/deadbeef"} {
		resp := getRequest(t, client, hs.URL+path, cookie)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET %s status = %d, want 200", path, resp.StatusCode)
		}
		page := bodyString(t, resp)
		if !strings.Contains(page, "Reach is not enabled") {
			t.Errorf("GET %s does not explain the disabled feature:\n%s", path, page)
		}
	}
}

// TestConsoleDERPPage checks the read-only DERP page: the policy summary, the
// served regions with their public relays, and where machines are homed.
func TestConsoleDERPPage(t *testing.T) {
	s := newServerWithConfig(t, Config{DERPMap: derpTestMap()})
	hs := newTestHTTPServer(t, s)
	client := noRedirectClient()
	cookie := loginLocal(t, client, hs.URL, "/console/derp")

	seedDERPNode(t, s, "derp-fra", 1)
	seedDERPNode(t, s, "derp-nohome", 0)

	page := bodyString(t, getRequest(t, client, hs.URL+"/console/derp", cookie))
	for _, want := range []string{
		"inherit", "fra", "Frankfurt", "veil1.example.com:443", "veil2a.example.com:443",
		"derp-fra", "derp-nohome", "none chosen yet", "Regions served",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("derp page lacks %q:\n%s", want, page)
		}
	}
	if strings.Contains(page, `action="/console/derp/`) {
		t.Errorf("the derp page offers a write control:\n%s", page)
	}
}

// TestConsoleDERPPageNoMap checks the copy when no DERP map is configured:
// clients keep their built-in defaults, which is not the same as an empty map.
func TestConsoleDERPPageNoMap(t *testing.T) {
	s := newTestServer(t)
	hs := newTestHTTPServer(t, s)
	client := noRedirectClient()
	cookie := loginLocal(t, client, hs.URL, "/console/derp")

	page := bodyString(t, getRequest(t, client, hs.URL+"/console/derp", cookie))
	if !strings.Contains(page, "No DERP map is configured") {
		t.Errorf("no-map derp page = %s", page)
	}
}

// TestConsoleFluxPage covers the read-only Flux page: transfer metadata,
// state filtering, and the guarantee that file content never appears.
func TestConsoleFluxPage(t *testing.T) {
	s := newServerWithConfig(t, Config{Flux: &FluxConfig{}})
	hs := newTestHTTPServer(t, s)
	client := noRedirectClient()
	cookie := loginLocal(t, client, hs.URL, "/console/flux")

	sender := enrollServiceAgent(t, s, hs, "flux-sender")
	recipient := enrollServiceAgent(t, s, hs, "flux-recipient")
	deniedID, _ := offerFlux(t, hs, sender, recipient, "private.bin", []byte("secret bytes"))
	if _, status := recipient.doFlux(t, hs.Client(), http.MethodPost,
		hs.URL+"/api/agent/v1/flux/transfers/"+deniedID+"/deny",
		mustJSON(t, map[string]any{"reason": "not expected"}), "application/json"); status != http.StatusOK {
		t.Fatalf("deny = %d", status)
	}
	pendingID, _ := offerFlux(t, hs, sender, recipient, "later.txt", []byte("pending payload"))

	list := bodyString(t, getRequest(t, client, hs.URL+"/console/flux", cookie))
	for _, want := range []string{
		"private.bin", "later.txt", "denied", "pending", "not expected",
		sender.node.StableID, recipient.node.StableID,
	} {
		if !strings.Contains(list, want) {
			t.Errorf("flux list lacks %q:\n%s", want, list)
		}
	}
	if strings.Contains(list, "secret bytes") || strings.Contains(list, "pending payload") {
		t.Errorf("the flux list renders file content:\n%s", list)
	}
	if strings.Contains(list, `action="/console/flux/`) {
		t.Errorf("the flux list offers a write control:\n%s", list)
	}

	filtered := bodyString(t, getRequest(t, client, hs.URL+"/console/flux?state=denied", cookie))
	if strings.Contains(filtered, pendingID) || !strings.Contains(filtered, deniedID) {
		t.Errorf("state filter = %s", filtered)
	}
	if resp := getRequest(t, client, hs.URL+"/console/flux?state=bogus", cookie); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("unknown state filter = %d, want 400", resp.StatusCode)
	}

	detail := bodyString(t, getRequest(t, client, hs.URL+"/console/flux/"+deniedID, cookie))
	for _, want := range []string{deniedID, "private.bin", "12 bytes", "end-to-end encrypted", "not expected"} {
		if !strings.Contains(detail, want) {
			t.Errorf("flux detail lacks %q:\n%s", want, detail)
		}
	}
	if strings.Contains(detail, "secret bytes") {
		t.Errorf("the flux detail renders file content:\n%s", detail)
	}
	if resp := getRequest(t, client, hs.URL+"/console/flux/nosuchtransfer", cookie); resp.StatusCode != http.StatusNotFound {
		t.Errorf("unknown transfer = %d, want 404", resp.StatusCode)
	}
}

// TestConsoleFluxPageDisabled checks that a deployment without Flux explains
// itself on both pages instead of rendering 404s or empty tables.
func TestConsoleFluxPageDisabled(t *testing.T) {
	s := newTestServer(t)
	hs := newTestHTTPServer(t, s)
	client := noRedirectClient()
	cookie := loginLocal(t, client, hs.URL, "/console/flux")

	for _, path := range []string{"/console/flux", "/console/flux/fx_deadbeef"} {
		resp := getRequest(t, client, hs.URL+path, cookie)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET %s status = %d, want 200", path, resp.StatusCode)
		}
		if page := bodyString(t, resp); !strings.Contains(page, "Flux is not enabled") {
			t.Errorf("GET %s does not explain the disabled feature:\n%s", path, page)
		}
	}
}
