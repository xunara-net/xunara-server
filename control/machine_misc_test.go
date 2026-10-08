package control

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"tailscale.com/tailcfg"
	"tailscale.com/types/key"

	"github.com/xunara-net/xunara-server/identity"
)

// doRaw performs an arbitrary-method request inside a Noise session and
// returns the body and status.
func doRaw(t *testing.T, client *http.Client, method, path string, req any) ([]byte, int) {
	t.Helper()

	var body io.Reader
	if req != nil {
		raw, err := json.Marshal(req)
		if err != nil {
			t.Fatalf("marshalling %s %s: %v", method, path, err)
		}
		body = bytes.NewReader(raw)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	httpReq, err := http.NewRequestWithContext(ctx, method, "http://xunara.test"+path, body)
	if err != nil {
		t.Fatalf("building %s %s: %v", method, path, err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(httpReq)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()

	out, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading %s %s: %v", method, path, err)
	}
	return out, resp.StatusCode
}

// TestAuditLogEndpointPersistsClientReport checks that a client-reported
// disconnect lands in the durable audit log, sanitised and attributed.
func TestAuditLogEndpointPersistsClientReport(t *testing.T) {
	s := newServerWithConfig(t, Config{})
	hs := newTestHTTPServer(t, s)

	conn, client, nodeKey := registerNode(t, s, hs, "audit-reporter")
	defer conn.Close()

	body, status := doRaw(t, client, http.MethodPost, "/machine/audit-log", tailcfg.AuditLogRequest{
		Version: tailcfg.CurrentCapabilityVersion,
		NodeKey: nodeKey.Public(),
		Action:  tailcfg.AuditNodeDisconnect,
		Details: "user ran tailscale down\x07\nsecond line",
	})
	if status != http.StatusOK {
		t.Fatalf("audit-log status = %d (%s)", status, body)
	}

	events := s.Identity().ListAudit(0)
	var found *identity.AuditEvent
	for i := range events {
		if events[i].Action == identity.AuditNodeDisconnectReported {
			found = &events[i]
		}
	}
	if found == nil {
		t.Fatalf("audit log has no %s event: %+v", identity.AuditNodeDisconnectReported, events)
	}
	if !strings.HasPrefix(found.Actor, "node:") || !strings.HasPrefix(found.Target, "node:") {
		t.Errorf("attribution = %q -> %q, want node prefixes", found.Actor, found.Target)
	}
	if strings.ContainsRune(found.Detail, '\x07') || strings.ContainsRune(found.Detail, '\n') {
		t.Errorf("detail = %q, want control characters removed", found.Detail)
	}

	// Unknown actions are refused rather than written to the durable log.
	_, status = doRaw(t, client, http.MethodPost, "/machine/audit-log", tailcfg.AuditLogRequest{
		Version: tailcfg.CurrentCapabilityVersion,
		NodeKey: nodeKey.Public(),
		Action:  "MADE_UP_ACTION",
	})
	if status != http.StatusBadRequest {
		t.Errorf("unknown action status = %d, want 400", status)
	}

	// A foreign node key is refused (machine-key binding).
	otherNode := key.NewNode().Public()
	_, status = doRaw(t, client, http.MethodPost, "/machine/audit-log", tailcfg.AuditLogRequest{
		Version: tailcfg.CurrentCapabilityVersion,
		NodeKey: otherNode,
		Action:  tailcfg.AuditNodeDisconnect,
	})
	if status != http.StatusNotFound {
		t.Errorf("foreign node key status = %d, want 404", status)
	}
}

// TestUpdateHealthEndpoint checks the advisory health endpoint: 204 for
// reports bound to the session's node, with or without a node key.
func TestUpdateHealthEndpoint(t *testing.T) {
	s := newServerWithConfig(t, Config{})
	hs := newTestHTTPServer(t, s)

	conn, client, nodeKey := registerNode(t, s, hs, "healthy-node")
	defer conn.Close()

	if _, status := doRaw(t, client, http.MethodPost, "/machine/update-health", tailcfg.HealthChangeRequest{
		Subsys:  "dns",
		Error:   "resolv.conf changed",
		NodeKey: nodeKey.Public(),
	}); status != http.StatusNoContent {
		t.Errorf("health report status = %d, want 204", status)
	}

	if _, status := doRaw(t, client, http.MethodPost, "/machine/update-health", tailcfg.HealthChangeRequest{
		Subsys: "wg",
	}); status != http.StatusNoContent {
		t.Errorf("node-key-less health report status = %d, want 204", status)
	}

	other := key.NewNode().Public()
	if _, status := doRaw(t, client, http.MethodPost, "/machine/update-health", tailcfg.HealthChangeRequest{
		Subsys:  "wg",
		NodeKey: other,
	}); status != http.StatusNotFound {
		t.Errorf("foreign node health report status = %d, want 404", status)
	}
}

// TestWhoamiEndpoint checks the debug probe: a registered machine gets its
// node identity, an unregistered Noise session gets 404.
func TestWhoamiEndpoint(t *testing.T) {
	s := newServerWithConfig(t, Config{Domain: "example.com"})
	hs := newTestHTTPServer(t, s)

	conn, client, _ := registerNode(t, s, hs, "whoami-node")
	defer conn.Close()

	body, status := doRaw(t, client, http.MethodGet, "/machine/whoami", nil)
	if status != http.StatusOK {
		t.Fatalf("whoami status = %d (%s)", status, body)
	}
	var whoami map[string]any
	if err := json.Unmarshal(body, &whoami); err != nil {
		t.Fatalf("decoding whoami: %v", err)
	}
	if whoami["name"] != "whoami-node.example.com." {
		t.Errorf("whoami name = %v, want whoami-node.example.com.", whoami["name"])
	}
	if _, ok := whoami["machine_key"]; !ok {
		t.Errorf("whoami response lacks machine_key: %v", whoami)
	}

	// A Noise session that never registered must not learn anything.
	strangerConn := dialNoise(t, hs, key.NewMachine())
	defer strangerConn.Close()
	stranger := h2Client(strangerConn)

	if _, status := doRaw(t, stranger, http.MethodGet, "/machine/whoami", nil); status != http.StatusNotFound {
		t.Errorf("unregistered whoami status = %d, want 404", status)
	}
}
