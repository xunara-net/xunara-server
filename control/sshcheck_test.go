package control

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"tailscale.com/tailcfg"

	"github.com/xunara-net/xunara-server/state"
)

// sshCheckPolicy holds every SSH connection between a user's own devices until
// a human approves it; approvals are remembered for an hour.
const sshCheckPolicy = `{
	"ssh": [{
		"action": "check",
		"src": ["autogroup:member"],
		"dst": ["autogroup:self"],
		"users": ["root"],
		"checkPeriod": "1h"
	}],
	"acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}]
}`

// sshActionResult is one GET of the verdict endpoint.
type sshActionResult struct {
	action tailcfg.SSHAction
	status int
	err    error
}

// fetchSSHAction performs GET path over a node's Noise HTTP/2 client.
func fetchSSHAction(client *http.Client, ctx context.Context, path string) sshActionResult {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://xunara.test"+path, nil)
	if err != nil {
		return sshActionResult{err: err}
	}
	resp, err := client.Do(req)
	if err != nil {
		return sshActionResult{err: err}
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return sshActionResult{status: resp.StatusCode, err: err}
	}
	if resp.StatusCode != http.StatusOK {
		return sshActionResult{status: resp.StatusCode}
	}
	var action tailcfg.SSHAction
	if err := json.Unmarshal(body, &action); err != nil {
		return sshActionResult{status: resp.StatusCode, err: err}
	}
	return sshActionResult{action: action, status: resp.StatusCode}
}

// sshActionPath builds the verdict-endpoint path tailscaled calls, with the
// auth_id added for follow-up requests.
func sshActionPath(src, dst state.NodeID, localUser, authID string) string {
	path := fmt.Sprintf("/machine/ssh/action/%d/to/%d?local_user=%s",
		int64(src), int64(dst), url.QueryEscape(localUser))
	if authID != "" {
		path += "&auth_id=" + url.QueryEscape(authID)
	}
	return path
}

// authIDFromHold extracts the auth_id tailscaled would expand into its
// follow-up request.
func authIDFromHold(t *testing.T, holdURL string) string {
	t.Helper()

	u, err := url.Parse(holdURL)
	if err != nil {
		t.Fatalf("parsing HoldAndDelegate %q: %v", holdURL, err)
	}
	id := u.Query().Get("auth_id")
	if id == "" {
		t.Fatalf("HoldAndDelegate %q has no auth_id", holdURL)
	}
	return id
}

// TestSSHCheckPolicyReachesDestination checks the destination's netmap carries
// a hold action instead of an immediate accept.
func TestSSHCheckPolicyReachesDestination(t *testing.T) {
	s := newServerWithConfig(t, Config{
		ServerURL:  "https://control.test",
		PolicyPath: policyFile(t, sshCheckPolicy),
	})
	hs := newTestHTTPServer(t, s)

	connB, clientB, nodeKeyB := registerNode(t, s, hs, "check-b")
	defer connB.Close()

	resp := decodeMapResponse(t, postRaw(t, clientB, "/machine/map", tailcfg.MapRequest{
		Version: tailcfg.CurrentCapabilityVersion,
		NodeKey: nodeKeyB.Public(),
	}), "")
	if resp.SSHPolicy == nil || len(resp.SSHPolicy.Rules) != 1 {
		t.Fatalf("SSHPolicy = %+v, want one rule", resp.SSHPolicy)
	}
	action := resp.SSHPolicy.Rules[0].Action
	if action == nil || action.Accept || action.Reject || action.HoldAndDelegate == "" {
		t.Fatalf("action = %+v, want a hold", action)
	}
	if !strings.HasPrefix(action.HoldAndDelegate, "https://control.test/machine/ssh/action/") {
		t.Errorf("HoldAndDelegate = %q, want the control server's action URL", action.HoldAndDelegate)
	}
	if _, ok := resp.Node.CapMap[tailcfg.CapabilitySSH]; !ok {
		t.Errorf("CapMap = %v, want %s on a check destination", resp.Node.CapMap, tailcfg.CapabilitySSH)
	}
}

// TestSSHCheckApproveFlow drives the whole hold-and-delegate round trip: the
// destination holds, the browser approves, the long poll returns accept, the
// pair is remembered, and a policy reload forgets it.
func TestSSHCheckApproveFlow(t *testing.T) {
	s := newServerWithConfig(t, Config{
		ServerURL:  "https://control.test",
		PolicyPath: policyFile(t, sshCheckPolicy),
	})
	hs := newTestHTTPServer(t, s)

	connA, _, nodeKeyA := registerNode(t, s, hs, "check-a")
	defer connA.Close()
	connB, clientB, nodeKeyB := registerNode(t, s, hs, "check-b")
	defer connB.Close()

	nodeA, ok := s.Store().GetNodeByNodeKey(nodeKeyA.Public())
	if !ok {
		t.Fatal("node A not found")
	}
	nodeB, ok := s.Store().GetNodeByNodeKey(nodeKeyB.Public())
	if !ok {
		t.Fatal("node B not found")
	}

	// Initial request: no verdict yet, so the connection is held with a new
	// auth_id and a banner telling the user where to approve.
	path := sshActionPath(nodeA.ID, nodeB.ID, "root", "")
	hold := fetchSSHAction(clientB, testContext(t), path)
	if hold.err != nil || hold.status != http.StatusOK {
		t.Fatalf("initial verdict request = %+v", hold)
	}
	if hold.action.HoldAndDelegate == "" || !strings.Contains(hold.action.Message, "/ssh/check/") {
		t.Fatalf("initial action = %+v, want a hold with an approval link", hold.action)
	}

	authID := authIDFromHold(t, hold.action.HoldAndDelegate)
	sess, ok := s.Identity().GetSSHCheckSession(authID)
	if !ok || sess.SrcNodeID != int64(nodeA.ID) || sess.DstNodeID != int64(nodeB.ID) {
		t.Fatalf("session = %+v (ok=%v), want the (A, B) binding", sess, ok)
	}

	// The follow-up request parks until a human decides.
	results := make(chan sshActionResult, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		results <- fetchSSHAction(clientB, ctx, sshActionPath(nodeA.ID, nodeB.ID, "root", authID))
	}()

	// Approve in a browser.
	browser := noRedirectClient()
	cookie := loginLocal(t, browser, hs.URL, "/ssh/check/"+authID)
	page := getRequest(t, browser, hs.URL+"/ssh/check/"+authID, cookie)
	if page.StatusCode != http.StatusOK {
		t.Fatalf("approval page = %d, want 200", page.StatusCode)
	}
	csrf := extractCSRF(t, bodyString(t, page))
	if resp := postForm(t, browser, hs.URL+"/ssh/check/"+authID+"/approve",
		url.Values{"csrf": {csrf}}, cookie); resp.StatusCode != http.StatusOK {
		t.Fatalf("approve = %d, want 200", resp.StatusCode)
	}

	select {
	case res := <-results:
		if res.err != nil || res.status != http.StatusOK {
			t.Fatalf("follow-up = %+v", res)
		}
		if !res.action.Accept || res.action.Reject {
			t.Fatalf("follow-up action = %+v, want accept", res.action)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("follow-up never returned after approval")
	}

	// The approval is remembered: a fresh connection skips the prompt.
	again := fetchSSHAction(clientB, testContext(t), path)
	if again.err != nil || !again.action.Accept {
		t.Fatalf("second connection = %+v, want auto-approval within the check period", again)
	}

	// A policy reload clears the remembered approvals.
	if err := s.loadPolicy(); err != nil {
		t.Fatalf("loadPolicy: %v", err)
	}
	held := fetchSSHAction(clientB, testContext(t), path)
	if held.err != nil || held.action.HoldAndDelegate == "" || held.action.Accept {
		t.Fatalf("after policy reload = %+v, want a new hold", held)
	}
}

// TestSSHCheckDenyFlow checks a denial reaches the waiting client as a reject.
func TestSSHCheckDenyFlow(t *testing.T) {
	s := newServerWithConfig(t, Config{
		ServerURL:  "https://control.test",
		PolicyPath: policyFile(t, sshCheckPolicy),
	})
	hs := newTestHTTPServer(t, s)

	connA, _, nodeKeyA := registerNode(t, s, hs, "deny-a")
	defer connA.Close()
	connB, clientB, nodeKeyB := registerNode(t, s, hs, "deny-b")
	defer connB.Close()

	nodeA, _ := s.Store().GetNodeByNodeKey(nodeKeyA.Public())
	nodeB, _ := s.Store().GetNodeByNodeKey(nodeKeyB.Public())

	hold := fetchSSHAction(clientB, testContext(t), sshActionPath(nodeA.ID, nodeB.ID, "root", ""))
	if hold.err != nil || hold.action.HoldAndDelegate == "" {
		t.Fatalf("initial request = %+v", hold)
	}
	authID := authIDFromHold(t, hold.action.HoldAndDelegate)

	results := make(chan sshActionResult, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		results <- fetchSSHAction(clientB, ctx, sshActionPath(nodeA.ID, nodeB.ID, "root", authID))
	}()

	browser := noRedirectClient()
	cookie := loginLocal(t, browser, hs.URL, "/ssh/check/"+authID)
	page := getRequest(t, browser, hs.URL+"/ssh/check/"+authID, cookie)
	csrf := extractCSRF(t, bodyString(t, page))
	if resp := postForm(t, browser, hs.URL+"/ssh/check/"+authID+"/deny",
		url.Values{"csrf": {csrf}}, cookie); resp.StatusCode != http.StatusOK {
		t.Fatalf("deny = %d, want 200", resp.StatusCode)
	}

	select {
	case res := <-results:
		if res.err != nil || !res.action.Reject || res.action.Accept {
			t.Fatalf("follow-up action = %+v, want reject", res.action)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("follow-up never returned after denial")
	}

	// A rejected connection is not remembered: the next one is held again.
	held := fetchSSHAction(clientB, testContext(t), sshActionPath(nodeA.ID, nodeB.ID, "root", ""))
	if held.err != nil || held.action.HoldAndDelegate == "" {
		t.Fatalf("connection after denial = %+v, want a new hold", held)
	}
}

// TestSSHCheckAlwaysRechecks keeps checkPeriod "always" honest: even an
// approved pair must ask again for the next connection.
func TestSSHCheckAlwaysRechecks(t *testing.T) {
	s := newServerWithConfig(t, Config{
		ServerURL: "https://control.test",
		PolicyPath: policyFile(t, `{
			"ssh": [{
				"action": "check",
				"src": ["autogroup:member"],
				"dst": ["autogroup:self"],
				"users": ["root"],
				"checkPeriod": "always"
			}],
			"acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}]
		}`),
	})
	hs := newTestHTTPServer(t, s)

	connA, _, nodeKeyA := registerNode(t, s, hs, "always-a")
	defer connA.Close()
	connB, clientB, nodeKeyB := registerNode(t, s, hs, "always-b")
	defer connB.Close()

	nodeA, _ := s.Store().GetNodeByNodeKey(nodeKeyA.Public())
	nodeB, _ := s.Store().GetNodeByNodeKey(nodeKeyB.Public())
	path := sshActionPath(nodeA.ID, nodeB.ID, "root", "")

	hold := fetchSSHAction(clientB, testContext(t), path)
	authID := authIDFromHold(t, hold.action.HoldAndDelegate)

	results := make(chan sshActionResult, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		results <- fetchSSHAction(clientB, ctx, sshActionPath(nodeA.ID, nodeB.ID, "root", authID))
	}()

	browser := noRedirectClient()
	cookie := loginLocal(t, browser, hs.URL, "/ssh/check/"+authID)
	page := getRequest(t, browser, hs.URL+"/ssh/check/"+authID, cookie)
	csrf := extractCSRF(t, bodyString(t, page))
	postForm(t, browser, hs.URL+"/ssh/check/"+authID+"/approve", url.Values{"csrf": {csrf}}, cookie)

	select {
	case res := <-results:
		if res.err != nil || !res.action.Accept {
			t.Fatalf("follow-up = %+v, want accept", res)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("follow-up never returned")
	}

	if _, ok := s.Identity().SSHCheckAuth(int64(nodeA.ID), int64(nodeB.ID)); ok {
		t.Error(`checkPeriod "always" must not record a remembered approval`)
	}
	next := fetchSSHAction(clientB, testContext(t), path)
	if next.err != nil || next.action.HoldAndDelegate == "" {
		t.Fatalf("next connection = %+v, want a hold", next)
	}
}

// TestSSHCheckMachineKeyBinding rejects a verdict request whose Noise session
// does not belong to the destination node.
func TestSSHCheckMachineKeyBinding(t *testing.T) {
	s := newServerWithConfig(t, Config{
		ServerURL:  "https://control.test",
		PolicyPath: policyFile(t, sshCheckPolicy),
	})
	hs := newTestHTTPServer(t, s)

	connA, clientA, nodeKeyA := registerNode(t, s, hs, "key-a")
	defer connA.Close()
	connB, _, nodeKeyB := registerNode(t, s, hs, "key-b")
	defer connB.Close()

	nodeA, _ := s.Store().GetNodeByNodeKey(nodeKeyA.Public())
	nodeB, _ := s.Store().GetNodeByNodeKey(nodeKeyB.Public())

	// A's Noise session must not act as destination B.
	res := fetchSSHAction(clientA, testContext(t), sshActionPath(nodeA.ID, nodeB.ID, "root", ""))
	if res.status != http.StatusUnauthorized {
		t.Fatalf("verdict request from the wrong machine key = %+v, want 401", res)
	}
}

// TestSSHCheckAuthIDBinding refuses to reuse an auth_id for another pair.
func TestSSHCheckAuthIDBinding(t *testing.T) {
	s := newServerWithConfig(t, Config{
		ServerURL:  "https://control.test",
		PolicyPath: policyFile(t, sshCheckPolicy),
	})
	hs := newTestHTTPServer(t, s)

	connA, _, nodeKeyA := registerNode(t, s, hs, "bind-a")
	defer connA.Close()
	connB, clientB, nodeKeyB := registerNode(t, s, hs, "bind-b")
	defer connB.Close()
	connC, clientC, nodeKeyC := registerNode(t, s, hs, "bind-c")
	defer connC.Close()

	nodeA, _ := s.Store().GetNodeByNodeKey(nodeKeyA.Public())
	nodeB, _ := s.Store().GetNodeByNodeKey(nodeKeyB.Public())
	nodeC, _ := s.Store().GetNodeByNodeKey(nodeKeyC.Public())

	hold := fetchSSHAction(clientB, testContext(t), sshActionPath(nodeA.ID, nodeB.ID, "root", ""))
	authID := authIDFromHold(t, hold.action.HoldAndDelegate)

	// Same auth_id, different destination: the binding must reject it even
	// though C's Noise session is authentic.
	res := fetchSSHAction(clientC, testContext(t), sshActionPath(nodeA.ID, nodeC.ID, "root", authID))
	if res.status != http.StatusUnauthorized {
		t.Fatalf("auth_id reused for another pair = %+v, want 401", res)
	}
}

// TestSSHCheckPageRequiresLogin keeps the approval page behind the trust
// plane's browser session.
func TestSSHCheckPageRequiresLogin(t *testing.T) {
	s := newServerWithConfig(t, Config{
		ServerURL:  "https://control.test",
		PolicyPath: policyFile(t, sshCheckPolicy),
	})
	hs := newTestHTTPServer(t, s)

	connA, _, nodeKeyA := registerNode(t, s, hs, "page-a")
	defer connA.Close()
	connB, clientB, nodeKeyB := registerNode(t, s, hs, "page-b")
	defer connB.Close()

	nodeA, _ := s.Store().GetNodeByNodeKey(nodeKeyA.Public())
	nodeB, _ := s.Store().GetNodeByNodeKey(nodeKeyB.Public())

	hold := fetchSSHAction(clientB, testContext(t), sshActionPath(nodeA.ID, nodeB.ID, "root", ""))
	authID := authIDFromHold(t, hold.action.HoldAndDelegate)

	browser := noRedirectClient()
	resp := getRequest(t, browser, hs.URL+"/ssh/check/"+authID, nil)
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("unauthenticated page = %d, want 302", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "/login?return_to=%2Fssh%2Fcheck%2F"+authID {
		t.Errorf("redirect = %q, want the login page with return_to", loc)
	}
}

// testContext bounds one verdict request.
func testContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	t.Cleanup(cancel)
	return ctx
}
