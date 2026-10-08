package control

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"reflect"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	xunarav2 "github.com/xunara-net/xunara-server/api/gen/xunara/v2"
	"github.com/xunara-net/xunara-server/identity"
)

// wardenPolicy exercises every section the Warden surface renders: both ACL
// generations, every map, ssh with a check period, nodeAttrs, a self-test that
// the seeded machine satisfies, and one unsupported field.
const wardenPolicy = `{
  "acls": [{"action": "accept", "src": ["tag:server"], "dst": ["tag:server:22"], "proto": "tcp"}],
  "grants": [{"src": ["group:ops"], "dst": ["tag:server"], "ip": ["tcp:443"],
              "app": {"example.com/cap/x": [{"mode": "read"}]}}],
  "groups": {"group:ops": ["ops@example.com", "tag:server"]},
  "hosts": {"db": "100.64.0.1"},
  "tagOwners": {"tag:server": ["group:ops"]},
  "ssh": [{"action": "check", "src": ["autogroup:member"], "dst": ["tag:server"],
           "users": ["root"], "acceptEnv": ["LC_*"], "checkPeriod": "12h"}],
  "nodeAttrs": [{"target": ["tag:server"], "attr": ["https"]}],
  "tests": [{"src": "tag:server", "accept": ["tag:server:22"], "deny": ["tag:server:80"]}],
  "autoApprovers": {"routes": {"10.0.0.0/8": ["tag:server"]}}
}`

// decodePolicyView reads one GET /api/v2/policy response.
func decodePolicyView(t *testing.T, raw []byte) policyView {
	t.Helper()
	var view policyView
	if err := json.Unmarshal(raw, &view); err != nil {
		t.Fatalf("decoding the policy view: %v (%s)", err, raw)
	}
	return view
}

// TestAPIV2PolicyUnconfigured drives GET /api/v2/policy without a document:
// the deployment allows all traffic, and the sections are present and empty
// so an automation client never has to branch on missing keys.
func TestAPIV2PolicyUnconfigured(t *testing.T) {
	s := newServerWithConfig(t, Config{})
	hs := newTestHTTPServer(t, s)
	client := noRedirectClient()
	_, readToken := seedAPIKey(t, s, identity.ScopeRead)
	_, writeToken := seedAPIKey(t, s, identity.ScopeWrite)

	base := hs.URL + "/api/v2/policy"
	if resp := apiRequest(t, client, http.MethodGet, base, "", nil); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("anonymous status = %d, want 401", resp.StatusCode)
	}
	if resp := apiRequest(t, client, http.MethodGet, base, writeToken, nil); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("write-only status = %d, want 403", resp.StatusCode)
	}

	resp := apiRequest(t, client, http.MethodGet, base, readToken, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if cc := resp.Header.Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", cc)
	}
	raw := readBody(t, resp)
	view := decodePolicyView(t, raw)
	if view.Configured {
		t.Error("configured = true without a document")
	}
	if view.RuleCount != 0 || view.Path != "" || view.LoadError != "" {
		t.Errorf("unconfigured view = %+v", view)
	}
	if len(view.ACLs) != 0 || len(view.Grants) != 0 || len(view.Groups) != 0 ||
		len(view.Hosts) != 0 || len(view.TagOwners) != 0 || len(view.SSH) != 0 ||
		len(view.NodeAttrs) != 0 {
		t.Errorf("unconfigured view has non-empty sections: %+v", view)
	}
	if view.Tests.Ran || view.Tests.Total != 0 || view.Tests.Reason != "" {
		t.Errorf("unconfigured tests = %+v, want an empty summary", view.Tests)
	}
	// Arrays are [] in JSON, never null.
	for _, want := range []string{`"acls":[]`, `"grants":[]`, `"groups":{}`, `"hosts":{}`} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("unconfigured view lacks %s: %s", want, raw)
		}
	}
}

// TestAPIV2PolicyStatus drives GET /api/v2/policy with a document: every
// section renders as written, the document's own test runs against the seeded
// machine, and unsupported fields are reported.
func TestAPIV2PolicyStatus(t *testing.T) {
	s := newServerWithConfig(t, Config{PolicyPath: policyFile(t, wardenPolicy)})
	hs := newTestHTTPServer(t, s)
	client := noRedirectClient()
	_, readToken := seedAPIKey(t, s, identity.ScopeRead)
	seedAPIMachine(t, s, "warden-node", []string{"tag:server"})

	resp := apiRequest(t, client, http.MethodGet, hs.URL+"/api/v2/policy", readToken, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	view := decodePolicyView(t, readBody(t, resp))

	if !view.Configured || view.Path == "" || view.LoadError != "" {
		t.Fatalf("configured/path/loadError = %v/%q/%q", view.Configured, view.Path, view.LoadError)
	}
	// One ACL plus one grant, counted after compilation.
	if view.RuleCount != 2 {
		t.Errorf("ruleCount = %d, want 2", view.RuleCount)
	}
	if want := []string{"autoApprovers"}; !reflect.DeepEqual(view.Unsupported, want) {
		t.Errorf("unsupported = %v, want %v", view.Unsupported, want)
	}

	if len(view.ACLs) != 1 {
		t.Fatalf("acls = %+v, want one row", view.ACLs)
	}
	acl := view.ACLs[0]
	if acl.Action != "accept" || acl.Proto != "tcp" ||
		!reflect.DeepEqual(acl.Src, []string{"tag:server"}) ||
		!reflect.DeepEqual(acl.Dst, []string{"tag:server:22"}) {
		t.Errorf("acl row = %+v", acl)
	}
	if len(view.Grants) != 1 {
		t.Fatalf("grants = %+v, want one row", view.Grants)
	}
	grant := view.Grants[0]
	if !reflect.DeepEqual(grant.Src, []string{"group:ops"}) ||
		!reflect.DeepEqual(grant.Dst, []string{"tag:server"}) ||
		!reflect.DeepEqual(grant.IP, []string{"tcp:443"}) {
		t.Errorf("grant row = %+v", grant)
	}
	if got := string(grant.App["example.com/cap/x"][0]); !strings.Contains(got, `"mode"`) {
		t.Errorf("grant capability value = %q", got)
	}
	if want := []string{"ops@example.com", "tag:server"}; !reflect.DeepEqual(view.Groups["group:ops"], want) {
		t.Errorf("group:ops = %v, want %v", view.Groups["group:ops"], want)
	}
	if view.Hosts["db"] != "100.64.0.1" {
		t.Errorf("hosts = %v", view.Hosts)
	}
	if want := []string{"group:ops"}; !reflect.DeepEqual(view.TagOwners["tag:server"], want) {
		t.Errorf("tagOwners = %v", view.TagOwners)
	}
	if len(view.SSH) != 1 {
		t.Fatalf("ssh = %+v, want one row", view.SSH)
	}
	ssh := view.SSH[0]
	if ssh.Action != "check" || ssh.CheckPeriod != "12h0m0s" ||
		!reflect.DeepEqual(ssh.Users, []string{"root"}) ||
		!reflect.DeepEqual(ssh.AcceptEnv, []string{"LC_*"}) {
		t.Errorf("ssh row = %+v", ssh)
	}
	if len(view.NodeAttrs) != 1 || !reflect.DeepEqual(view.NodeAttrs[0].Attr, []string{"https"}) {
		t.Errorf("nodeAttrs = %+v", view.NodeAttrs)
	}

	if view.Tests.Total != 1 || !view.Tests.Ran || view.Tests.Reason != "" {
		t.Fatalf("tests = %+v, want the one test to run", view.Tests)
	}
	if len(view.Tests.Results) != 1 {
		t.Fatalf("test results = %+v", view.Tests.Results)
	}
	if result := view.Tests.Results[0]; !result.Pass || result.Src != "tag:server" || len(result.Failures) != 0 {
		t.Errorf("test result = %+v, want a pass", result)
	}
}

// TestAPIV2PolicyLoadError checks the view when the file on disk stops
// parsing: the previous policy is still in force and the error is reported
// instead of a 5xx.
func TestAPIV2PolicyLoadError(t *testing.T) {
	path := policyFile(t, wardenPolicy)
	s := newServerWithConfig(t, Config{PolicyPath: path})
	hs := newTestHTTPServer(t, s)
	client := noRedirectClient()
	_, readToken := seedAPIKey(t, s, identity.ScopeRead)

	if err := os.WriteFile(path, []byte("{ not json"), 0o600); err != nil {
		t.Fatalf("overwriting the policy: %v", err)
	}

	resp := apiRequest(t, client, http.MethodGet, hs.URL+"/api/v2/policy", readToken, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 even with a broken file", resp.StatusCode)
	}
	view := decodePolicyView(t, readBody(t, resp))
	if !view.Configured || len(view.ACLs) != 1 {
		t.Errorf("the in-force document is not rendered: %+v", view)
	}
	if view.LoadError == "" {
		t.Error("loadError = empty, want the parse failure")
	}
}

// TestAPIV2PolicyNoMachines checks the tests summary before any machine
// registers: tests assert against real devices, so they are reported as not
// run rather than as failures.
func TestAPIV2PolicyNoMachines(t *testing.T) {
	s := newServerWithConfig(t, Config{PolicyPath: policyFile(t, wardenPolicy)})
	hs := newTestHTTPServer(t, s)
	client := noRedirectClient()
	_, readToken := seedAPIKey(t, s, identity.ScopeRead)

	view := decodePolicyView(t, readBody(t, apiRequest(t, client,
		http.MethodGet, hs.URL+"/api/v2/policy", readToken, nil)))
	if view.Tests.Total != 1 || view.Tests.Ran || view.Tests.Reason != "no machines are registered yet" {
		t.Errorf("tests = %+v, want not-run with the no-machines reason", view.Tests)
	}
}

// TestGetPolicyStatusGRPC checks the gRPC mirror: the same view, the same
// credentials and scope rules.
func TestGetPolicyStatusGRPC(t *testing.T) {
	s := newServerWithConfig(t, Config{PolicyPath: policyFile(t, wardenPolicy)})
	seedAPIMachine(t, s, "warden-node", []string{"tag:server"})
	client := startGRPCTestServer(t, s.RegisterPlatformGRPC)

	if _, err := client.GetPolicyStatus(context.Background(), &xunarav2.GetPolicyStatusRequest{}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("anonymous error = %v, want UNAUTHENTICATED", err)
	}
	_, writeToken := seedAPIKey(t, s, identity.ScopeWrite)
	if _, err := client.GetPolicyStatus(grpcCtx(writeToken), &xunarav2.GetPolicyStatusRequest{}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("write-only error = %v, want PERMISSION_DENIED", err)
	}

	_, readToken := seedAPIKey(t, s, identity.ScopeRead)
	out, err := client.GetPolicyStatus(grpcCtx(readToken), &xunarav2.GetPolicyStatusRequest{})
	if err != nil {
		t.Fatalf("GetPolicyStatus: %v", err)
	}
	if !out.GetConfigured() || out.GetRuleCount() != 2 || out.GetPath() == "" || out.GetLoadError() != "" {
		t.Errorf("status = %+v", out)
	}
	if len(out.GetAcls()) != 1 || out.GetAcls()[0].GetDst()[0] != "tag:server:22" {
		t.Errorf("acls = %+v", out.GetAcls())
	}
	if len(out.GetGrants()) != 1 || len(out.GetGrants()[0].GetApp()["example.com/cap/x"].GetValues()) != 1 {
		t.Errorf("grants = %+v", out.GetGrants())
	}
	if got := out.GetGroups()["group:ops"].GetValues(); !reflect.DeepEqual(got, []string{"ops@example.com", "tag:server"}) {
		t.Errorf("group:ops = %v", got)
	}
	if out.GetHosts()["db"] != "100.64.0.1" {
		t.Errorf("hosts = %v", out.GetHosts())
	}
	if got := out.GetTagOwners()["tag:server"].GetValues(); !reflect.DeepEqual(got, []string{"group:ops"}) {
		t.Errorf("tagOwners = %v", got)
	}
	if len(out.GetSsh()) != 1 || out.GetSsh()[0].GetCheckPeriod() != "12h0m0s" {
		t.Errorf("ssh = %+v", out.GetSsh())
	}
	if len(out.GetNodeAttrs()) != 1 || out.GetNodeAttrs()[0].GetAttr()[0] != "https" {
		t.Errorf("nodeAttrs = %+v", out.GetNodeAttrs())
	}
	if !out.GetTests().GetRan() || out.GetTests().GetTotal() != 1 ||
		len(out.GetTests().GetResults()) != 1 || !out.GetTests().GetResults()[0].GetPass() {
		t.Errorf("tests = %+v", out.GetTests())
	}
	if !reflect.DeepEqual(out.GetUnsupported(), []string{"autoApprovers"}) {
		t.Errorf("unsupported = %v", out.GetUnsupported())
	}
}

// TestAPIV2PolicyBrokenDocumentDoesNot404 guards the "never a 5xx" rule: a
// document that compiles but whose tests cannot run (an ambiguous selector at
// evaluation time) is still data, not an error.
func TestAPIV2PolicyBrokenDocumentDoesNot404(t *testing.T) {
	// Two machines both carry the tag, so the test's source selector is
	// ambiguous at run time; the compile succeeds.
	const ambiguous = `{
  "tagOwners": {"tag:dup": ["autogroup:member"]},
  "acls": [{"action": "accept", "src": ["tag:dup"], "dst": ["tag:dup:22"]}],
  "tests": [{"src": "tag:dup", "accept": ["tag:dup:22"]}]
}`
	s := newServerWithConfig(t, Config{PolicyPath: policyFile(t, ambiguous)})
	hs := newTestHTTPServer(t, s)
	client := noRedirectClient()
	_, readToken := seedAPIKey(t, s, identity.ScopeRead)
	seedAPIMachine(t, s, "dup-a", []string{"tag:dup"})
	seedAPIMachine(t, s, "dup-b", []string{"tag:dup"})

	resp := apiRequest(t, client, http.MethodGet, hs.URL+"/api/v2/policy", readToken, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	view := decodePolicyView(t, readBody(t, resp))
	if !view.Tests.Ran || len(view.Tests.Results) != 1 {
		t.Fatalf("tests = %+v", view.Tests)
	}
	result := view.Tests.Results[0]
	if result.Pass || len(result.Failures) == 0 || !strings.Contains(result.Failures[0], "expected exactly one") {
		t.Errorf("ambiguous test result = %+v, want a recorded failure", result)
	}
}
