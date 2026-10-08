package control

import (
	"bytes"
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"tailscale.com/tailcfg"
	"tailscale.com/types/key"

	"github.com/xunara-net/xunara-server/state"
)

// queryFeature drives POST /machine/feature/query inside an existing
// (machine-key bound) Noise session.
func queryFeature(t *testing.T, client *http.Client, nodeKey key.NodePublic, feature string) tailcfg.QueryFeatureResponse {
	t.Helper()
	return decodeJSON[tailcfg.QueryFeatureResponse](t, postRaw(t, client, "/machine/feature/query", tailcfg.QueryFeatureRequest{
		Feature: feature,
		NodeKey: nodeKey,
	}))
}

// TestFeatureQueryCompleteWhenCapGranted checks that a node whose policy
// grants the "https" node attribute is told server-side enablement is already
// complete.
func TestFeatureQueryCompleteWhenCapGranted(t *testing.T) {
	s := newServerWithConfig(t, Config{
		PolicyPath: policyFile(t, `{
			"tagOwners": {"tag:server": ["local"]},
			"nodeAttrs": [{"target": ["tag:server"], "attr": ["https"]}],
			"acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}]
		}`),
	})
	hs := newTestHTTPServer(t, s)

	secret := seedPreAuthKey(t, s, state.PreAuthKey{Tags: []string{"tag:server"}})
	conn, client, nodeKey := registerPreAuthedNode(t, hs, "feature-granted", secret)
	defer conn.Close()

	resp := queryFeature(t, client, nodeKey.Public(), "serve")
	if !resp.Complete {
		t.Fatalf("serve query = %+v, want Complete", resp)
	}
	if resp.Text != "" || resp.URL != "" || resp.ShouldWait {
		t.Errorf("complete response carries instructions: %+v", resp)
	}
}

// TestFeatureQueryExplainsMissingCap checks the help path for an unprivileged
// node: the response must be actionable text, must not claim success, and must
// not ask the CLI to block (ShouldWait=false) since Xunara has no server-side
// enablement flow.
func TestFeatureQueryExplainsMissingCap(t *testing.T) {
	s := newServerWithConfig(t, Config{})
	hs := newTestHTTPServer(t, s)

	conn, client, nodeKey := registerNode(t, s, hs, "feature-plain")
	defer conn.Close()

	resp := queryFeature(t, client, nodeKey.Public(), "serve")
	if resp.Complete {
		t.Fatalf("serve query = %+v, want incomplete", resp)
	}
	if !strings.Contains(resp.Text, "https") {
		t.Errorf("help text does not mention the capability to grant: %q", resp.Text)
	}
	if resp.ShouldWait {
		t.Error("ShouldWait = true, but Xunara has no enablement flow to wait for")
	}
	if resp.URL != "" {
		t.Errorf("URL = %q, want empty (grants come from the policy file)", resp.URL)
	}
}

// TestFeatureQueryFunnelUnsupported checks that Funnel is refused with an
// explanation even when the node holds the https capability.
func TestFeatureQueryFunnelUnsupported(t *testing.T) {
	s := newServerWithConfig(t, Config{
		PolicyPath: policyFile(t, `{
			"tagOwners": {"tag:server": ["local"]},
			"nodeAttrs": [{"target": ["tag:server"], "attr": ["https"]}],
			"acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}]
		}`),
	})
	hs := newTestHTTPServer(t, s)

	secret := seedPreAuthKey(t, s, state.PreAuthKey{Tags: []string{"tag:server"}})
	conn, client, nodeKey := registerPreAuthedNode(t, hs, "feature-funnel", secret)
	defer conn.Close()

	resp := queryFeature(t, client, nodeKey.Public(), "funnel")
	if resp.Complete {
		t.Fatalf("funnel query = %+v, want incomplete", resp)
	}
	if !strings.Contains(resp.Text, "not supported") {
		t.Errorf("funnel text = %q, want a not-supported explanation", resp.Text)
	}
	if resp.ShouldWait {
		t.Error("ShouldWait = true for an unsupported feature")
	}
}

// TestFeatureQueryRejectsForeignNodeKey checks the machine-key binding: a node
// cannot query another registered node's capabilities through its own Noise
// session, and unknown node keys are refused.
func TestFeatureQueryRejectsForeignNodeKey(t *testing.T) {
	s := newServerWithConfig(t, Config{})
	hs := newTestHTTPServer(t, s)

	otherConn, _, otherKey := registerNode(t, s, hs, "feature-other")
	defer otherConn.Close()

	conn, client, _ := registerNode(t, s, hs, "feature-self")
	defer conn.Close()

	body, status := postRawStatus(t, client, "/machine/feature/query", tailcfg.QueryFeatureRequest{
		Feature: "serve",
		NodeKey: otherKey.Public(),
	})
	if status != 404 {
		t.Fatalf("cross-node query status = %d, want 404 (body %s)", status, body)
	}

	unknown := key.NewNode().Public()
	body, status = postRawStatus(t, client, "/machine/feature/query", tailcfg.QueryFeatureRequest{
		Feature: "serve",
		NodeKey: unknown,
	})
	if status != 404 {
		t.Fatalf("unknown-node query status = %d, want 404 (body %s)", status, body)
	}
}

// TestFeatureQueryUnknownFeatureIsBounded checks that an unknown feature name
// is answered (not an error) and echoed back in bounded, printable form only.
func TestFeatureQueryUnknownFeatureIsBounded(t *testing.T) {
	s := newServerWithConfig(t, Config{})
	hs := newTestHTTPServer(t, s)

	conn, client, nodeKey := registerNode(t, s, hs, "feature-unknown")
	defer conn.Close()

	resp := queryFeature(t, client, nodeKey.Public(), strings.Repeat("A", maxFeatureNameLen*4)+"\x07")
	if resp.Complete {
		t.Fatalf("unknown feature = %+v, want incomplete", resp)
	}
	if got := len([]rune(resp.Text)); got > 2*maxFeatureNameLen {
		t.Errorf("unknown-feature text is %d runes, want bounded", got)
	}
	if strings.ContainsRune(resp.Text, '\x07') {
		t.Errorf("unknown-feature text keeps control characters: %q", resp.Text)
	}
}

// TestFeatureQueryBadJSONIsRejected checks a truncated body does not leak
// internals or silently succeed.
func TestFeatureQueryBadJSONIsRejected(t *testing.T) {
	s := newServerWithConfig(t, Config{})
	hs := newTestHTTPServer(t, s)

	conn, client, _ := registerNode(t, s, hs, "feature-badjson")
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"http://xunara.test/machine/feature/query", bytes.NewReader([]byte(`{"feature":`)))
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST /machine/feature/query: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("bad JSON status = %d, want 500", resp.StatusCode)
	}
}
