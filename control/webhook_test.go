package control

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/xunara-net/xunara-server/state"
	"github.com/xunara-net/xunara-server/webhook"
)

// webhookReceiver records deliveries and signals a channel.
type webhookReceiver struct {
	mu         sync.Mutex
	deliveries []webhook.Delivery
	signatures []string
	raw        [][]byte
	ch         chan struct{}
}

func newWebhookReceiver() *webhookReceiver {
	return &webhookReceiver{ch: make(chan struct{}, 16)}
}

func (r *webhookReceiver) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	body, _ := io.ReadAll(req.Body)

	var d webhook.Delivery
	if err := json.Unmarshal(body, &d); err != nil {
		http.Error(w, "bad payload", http.StatusBadRequest)
		return
	}

	r.mu.Lock()
	r.deliveries = append(r.deliveries, d)
	r.signatures = append(r.signatures, req.Header.Get("X-Xunara-Signature"))
	r.raw = append(r.raw, body)
	r.mu.Unlock()

	w.WriteHeader(http.StatusOK)
	select {
	case r.ch <- struct{}{}:
	default:
	}
}

// waitForEvent waits until a delivery with the given action arrives.
func (r *webhookReceiver) waitForEvent(t *testing.T, action string, timeout time.Duration) bool {
	t.Helper()

	deadline := time.After(timeout)
	for {
		r.mu.Lock()
		for _, d := range r.deliveries {
			if d.Event.Action == action {
				r.mu.Unlock()
				return true
			}
		}
		r.mu.Unlock()

		select {
		case <-r.ch:
		case <-deadline:
			return false
		}
	}
}

// TestAuditEventsReachConfiguredWebhook wires a webhook endpoint into a real
// server and checks that an audited action (node registration) is delivered
// with a valid signature.
func TestAuditEventsReachConfiguredWebhook(t *testing.T) {
	receiver := newWebhookReceiver()
	hs := httptest.NewServer(receiver)
	defer hs.Close()

	s := newServerWithConfig(t, Config{
		Webhooks: []webhook.Endpoint{{
			ID:     "test",
			URL:    hs.URL,
			Secret: "s3cret",
			Events: []string{"node.*"},
		}},
	})
	controlHS := newTestHTTPServer(t, s)

	secret := seedPreAuthKey(t, s, state.PreAuthKey{})
	conn, _, _ := registerPreAuthedNode(t, controlHS, "hooked-node", secret)
	defer conn.Close()

	if !receiver.waitForEvent(t, "node.registered", 10*time.Second) {
		t.Fatal("node.registered was not delivered")
	}

	receiver.mu.Lock()
	defer receiver.mu.Unlock()

	idx := -1
	for i, d := range receiver.deliveries {
		if d.Event.Action == "node.registered" {
			idx = i
			break
		}
	}
	event := receiver.deliveries[idx]

	// The signature header must match the payload under the endpoint secret.
	// The dispatcher reads the clock once per delivery, so SentAt is exactly
	// the timestamp it signed.
	want := "sha256=" + webhook.Sign("s3cret", event.SentAt.Unix(), receiver.raw[idx])
	if got := receiver.signatures[idx]; got != want {
		t.Errorf("signature = %q, want %q", got, want)
	}

	if event.Event.Target == "" {
		t.Errorf("event target is empty, want the node")
	}
}
