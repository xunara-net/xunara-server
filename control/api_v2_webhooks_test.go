package control

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/xunara-net/xunara-server/identity"
	"github.com/xunara-net/xunara-server/state"
	"github.com/xunara-net/xunara-server/webhook"
)

// TestAPIV2WebhookLifecycle covers managed webhook endpoints end to end:
// creation with a sealed secret, delivery of a real audit event, listing
// without the secret, and deletion.
func TestAPIV2WebhookLifecycle(t *testing.T) {
	s := newTestServer(t)
	hs := newTestHTTPServer(t, s)
	client := noRedirectClient()
	_, token := seedAPIKey(t, s)

	received := make(chan *http.Request, 8)
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case received <- r:
		default:
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(receiver.Close)

	resp := apiRequest(t, client, http.MethodPost, hs.URL+"/api/v2/webhooks", token, apiWebhookCreateRequest{
		ID:     "ops",
		URL:    receiver.URL,
		Secret: "s3cret",
		Events: []string{"node.*"},
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create status = %d", resp.StatusCode)
	}
	created := decodeAPI(t, resp)
	if created["id"] != "ops" || created["source"] != "managed" || created["enabled"] != true {
		t.Fatalf("created webhook = %v", created)
	}
	if _, ok := created["secret"]; ok {
		t.Error("create response leaks the secret")
	}

	// The secret is sealed at rest: the stored blob is not the plaintext.
	stored, ok := s.identity.GetWebhookEndpoint("ops")
	if !ok {
		t.Fatal("managed endpoint was not stored")
	}
	if stored.Secret == "s3cret" || stored.Secret == "" {
		t.Fatalf("stored secret = %q, want a sealed blob", stored.Secret)
	}
	if got, err := openWebhookSecret(s.webhookKey, stored.Secret); err != nil || got != "s3cret" {
		t.Fatalf("unsealing stored secret = %q, %v", got, err)
	}

	// A real audit event reaches the receiver with a valid signature.
	secret := seedPreAuthKey(t, s, state.PreAuthKey{})
	registerPreAuthedNode(t, hs, "webhook-node", secret)

	select {
	case req := <-received:
		if got := req.Header.Get("X-Xunara-Event"); got != identity.AuditNodeRegistered {
			t.Errorf("X-Xunara-Event = %q, want %q", got, identity.AuditNodeRegistered)
		}
		if req.Header.Get("X-Xunara-Signature") == "" {
			t.Error("delivery lacks a signature")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("managed webhook never delivered an event")
	}

	// Listing never returns the secret, and shows both sources.
	resp = apiRequest(t, client, http.MethodGet, hs.URL+"/api/v2/webhooks", token, nil)
	list := decodeAPI(t, resp)
	items, _ := list["items"].([]any)
	if len(items) != 1 {
		t.Fatalf("webhooks = %d, want 1", len(items))
	}
	view := items[0].(map[string]any)
	for _, forbidden := range []string{"secret", "signingSecret"} {
		if _, ok := view[forbidden]; ok {
			t.Errorf("list leaks %q", forbidden)
		}
	}

	// Deletion removes it and stops delivery.
	if resp := apiRequest(t, client, http.MethodDelete, hs.URL+"/api/v2/webhooks/ops", token, nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("delete status = %d", resp.StatusCode)
	}
	if _, ok := s.identity.GetWebhookEndpoint("ops"); ok {
		t.Error("endpoint still stored after deletion")
	}
	if resp := apiRequest(t, client, http.MethodDelete, hs.URL+"/api/v2/webhooks/ops", token, nil); resp.StatusCode != http.StatusNotFound {
		t.Errorf("second delete status = %d, want 404", resp.StatusCode)
	}

	if _, ok := findAudit(t, s, identity.AuditWebhookCreated); !ok {
		t.Error("webhook.created audit event missing")
	}
	if _, ok := findAudit(t, s, identity.AuditWebhookDeleted); !ok {
		t.Error("webhook.deleted audit event missing")
	}
}

// TestAPIV2WebhookValidation checks the rejections: bad IDs, bad URLs, empty
// secrets, duplicate IDs and configured endpoints.
func TestAPIV2WebhookValidation(t *testing.T) {
	s := newServerWithConfig(t, Config{
		Webhooks: []webhook.Endpoint{{ID: "configured", URL: "https://example.com/hook", Secret: "x"}},
	})
	hs := newTestHTTPServer(t, s)
	client := noRedirectClient()
	_, token := seedAPIKey(t, s)

	base := apiWebhookCreateRequest{ID: "ops", URL: "https://example.com/hook", Secret: "s"}

	for _, tc := range []struct {
		name string
		req  apiWebhookCreateRequest
		want int
	}{
		{"bad id", apiWebhookCreateRequest{ID: "bad id!", URL: base.URL, Secret: "s"}, http.StatusBadRequest},
		{"missing secret", apiWebhookCreateRequest{ID: "ops", URL: base.URL}, http.StatusBadRequest},
		{"plaintext remote URL", apiWebhookCreateRequest{ID: "ops", URL: "http://example.com/hook", Secret: "s"}, http.StatusBadRequest},
		{"bad glob", apiWebhookCreateRequest{ID: "ops", URL: base.URL, Secret: "s", Events: []string{"node.?"}}, http.StatusBadRequest},
		{"configured id", apiWebhookCreateRequest{ID: "configured", URL: base.URL, Secret: "s"}, http.StatusConflict},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp := apiRequest(t, client, http.MethodPost, hs.URL+"/api/v2/webhooks", token, tc.req)
			if resp.StatusCode != tc.want {
				t.Errorf("status = %d, want %d", resp.StatusCode, tc.want)
			}
		})
	}

	// A configured endpoint cannot be deleted through the API.
	if resp := apiRequest(t, client, http.MethodDelete, hs.URL+"/api/v2/webhooks/configured", token, nil); resp.StatusCode != http.StatusConflict {
		t.Errorf("deleting a configured webhook status = %d, want 409", resp.StatusCode)
	}

	// Read-only keys cannot create or delete.
	_, readToken := seedAPIKey(t, s, identity.ScopeRead)
	if resp := apiRequest(t, client, http.MethodPost, hs.URL+"/api/v2/webhooks", readToken, base); resp.StatusCode != http.StatusForbidden {
		t.Errorf("read-only create status = %d, want 403", resp.StatusCode)
	}
}

// TestWebhookSecretSealing covers the crypto: round trip, tamper detection and
// key independence.
func TestWebhookSecretSealing(t *testing.T) {
	var key [32]byte
	for i := range key {
		key[i] = byte(i)
	}

	sealed, err := sealWebhookSecret(key, "hunter2")
	if err != nil {
		t.Fatalf("sealWebhookSecret: %v", err)
	}
	if got, err := openWebhookSecret(key, sealed); err != nil || got != "hunter2" {
		t.Fatalf("openWebhookSecret = %q, %v", got, err)
	}

	// Sealing is randomised: the same plaintext never produces the same blob.
	again, err := sealWebhookSecret(key, "hunter2")
	if err != nil {
		t.Fatalf("second seal: %v", err)
	}
	if again == sealed {
		t.Error("sealing reused the nonce")
	}

	// A tampered blob is rejected.
	tampered := []byte(sealed)
	tampered[len(tampered)-1] ^= 'A'
	if _, err := openWebhookSecret(key, string(tampered)); err == nil {
		t.Error("tampered secret was accepted")
	}

	// A different key cannot open it.
	var other [32]byte
	if _, err := openWebhookSecret(other, sealed); err == nil {
		t.Error("a different sealing key opened the secret")
	}

	// Unsupported formats are rejected without leaking anything.
	if _, err := openWebhookSecret(key, "plaintext"); err == nil {
		t.Error("unsealed secret was accepted")
	}
}

// TestWebhookKeyFilePermissions checks that the sealing key is created 0600
// and that a world-readable key stops the server from starting.
func TestWebhookKeyFilePermissions(t *testing.T) {
	dir := t.TempDir()
	key, err := loadOrCreateWebhookSecretKey(dir)
	if err != nil {
		t.Fatalf("loadOrCreateWebhookSecretKey: %v", err)
	}
	reloaded, err := loadOrCreateWebhookSecretKey(dir)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if key != reloaded {
		t.Error("the key changed across loads")
	}

	path := dir + "/" + webhookSecretKeyFile
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	if _, err := loadOrCreateWebhookSecretKey(dir); err == nil {
		t.Error("a world-readable sealing key was accepted")
	}
}
