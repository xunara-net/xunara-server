package webhook

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xunara-net/xunara-server/identity"
)

// fakeStore is the narrow store the dispatcher consumes.
type fakeStore struct {
	mu      sync.Mutex
	events  []identity.AuditEvent
	cursors map[string]uint64
	claims  map[string]claimState
	retries map[string]retryState

	listErr chan struct{} // optional: closed to fail ListAuditAfter
}

// claimState mirrors the durable delivery lease.
type claimState struct {
	owner   string
	expires time.Time
}

// retryState mirrors the persisted backoff.
type retryState struct {
	attempts int
	retryAt  time.Time
}

func newFakeStore() *fakeStore {
	return &fakeStore{
		cursors: make(map[string]uint64),
		claims:  make(map[string]claimState),
		retries: make(map[string]retryState),
	}
}

func (s *fakeStore) append(action string) uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	id := uint64(len(s.events) + 1)
	s.events = append(s.events, identity.AuditEvent{
		ID:     id,
		Time:   time.Unix(0, int64(id)*int64(time.Second)).UTC(),
		Actor:  "user:1",
		Action: action,
		Target: fmt.Sprintf("node:%d", id),
	})
	return id
}

func (s *fakeStore) ListAuditAfter(afterID uint64, limit int) []identity.AuditEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []identity.AuditEvent
	for _, e := range s.events {
		if e.ID <= afterID {
			continue
		}
		out = append(out, e)
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out
}

func (s *fakeStore) GetWebhookCursor(endpoint string) uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cursors[endpoint]
}

func (s *fakeStore) SetWebhookCursor(endpoint string, eventID uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cursors[endpoint] = eventID
	return nil
}

func (s *fakeStore) ClaimWebhookEndpoint(endpoint, owner string, now, expiresAt time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	claim := s.claims[endpoint]
	if claim.owner != "" && claim.owner != owner && claim.expires.After(now) {
		return false, nil
	}
	s.claims[endpoint] = claimState{owner: owner, expires: expiresAt}
	return true, nil
}

func (s *fakeStore) RenewWebhookClaim(endpoint, owner string, expiresAt time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	claim := s.claims[endpoint]
	if claim.owner != owner {
		return false, nil
	}
	claim.expires = expiresAt
	s.claims[endpoint] = claim
	return true, nil
}

func (s *fakeStore) ReleaseWebhookClaim(endpoint, owner string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if claim := s.claims[endpoint]; claim.owner == owner {
		delete(s.claims, endpoint)
	}
	return nil
}

func (s *fakeStore) WebhookRetryState(endpoint string) (int, time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	retry := s.retries[endpoint]
	return retry.attempts, retry.retryAt
}

func (s *fakeStore) SetWebhookRetryState(endpoint string, attempts int, retryAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.retries[endpoint] = retryState{attempts: attempts, retryAt: retryAt}
	return nil
}

// recorded is one delivery a test receiver observed.
type recorded struct {
	event     string
	body      []byte
	delivery  string
	timestamp string
	signature string
	at        time.Time
}

// recordingReceiver collects deliveries, optionally failing the first
// failures attempts with a status.
type recordingReceiver struct {
	mu       sync.Mutex
	got      []recorded
	status   int // when non-zero, returned until failures exhausted
	failures int
	notify   chan struct{}
}

func (r *recordingReceiver) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	body, _ := io.ReadAll(req.Body)
	r.mu.Lock()
	if r.failures > 0 {
		r.failures--
		status := r.status
		r.mu.Unlock()
		w.WriteHeader(status)
		return
	}
	r.got = append(r.got, recorded{
		event:     req.Header.Get("X-Xunara-Event"),
		body:      body,
		delivery:  req.Header.Get("X-Xunara-Delivery"),
		timestamp: req.Header.Get("X-Xunara-Timestamp"),
		signature: req.Header.Get("X-Xunara-Signature"),
		at:        time.Now(),
	})
	notify := r.notify
	r.mu.Unlock()

	w.WriteHeader(http.StatusOK)
	if notify != nil {
		select {
		case notify <- struct{}{}:
		default:
		}
	}
}

func (r *recordingReceiver) delivered() []recorded {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]recorded(nil), r.got...)
}

// waitFor polls until cond is true or the deadline passes.
func waitFor(t *testing.T, cond func() bool, what string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// startDispatcher runs a dispatcher until the test ends.
func startDispatcher(t *testing.T, cfg Config) *Dispatcher {
	t.Helper()
	if cfg.PollInterval == 0 {
		cfg.PollInterval = 5 * time.Millisecond
	}
	d, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go d.Run(ctx)
	return d
}

// TestDeliversSignedEventsInOrder checks payload contents, headers, ordering
// and HMAC signing.
func TestDeliversSignedEventsInOrder(t *testing.T) {
	store := newFakeStore()
	store.append("node.registered")
	store.append("user.created")

	receiver := &recordingReceiver{}
	hs := httptest.NewServer(receiver)
	t.Cleanup(hs.Close)

	startDispatcher(t, Config{
		Endpoints: []Endpoint{{ID: "ops", URL: hs.URL, Secret: "s3cret"}},
		Store:     store,
	})

	waitFor(t, func() bool { return len(receiver.delivered()) == 2 }, "two deliveries")
	got := receiver.delivered()

	if got[0].event != "node.registered" || got[1].event != "user.created" {
		t.Fatalf("delivery order = %q, %q", got[0].event, got[1].event)
	}

	var payload Delivery
	if err := json.Unmarshal(got[0].body, &payload); err != nil {
		t.Fatalf("decoding payload: %v", err)
	}
	if payload.Endpoint != "ops" || payload.Event.Action != "node.registered" || payload.Event.Actor != "user:1" {
		t.Errorf("payload = %+v", payload)
	}
	if payload.ID != "ops-1" || got[0].delivery != "ops-1" {
		t.Errorf("delivery id = %q / %q, want ops-1", payload.ID, got[0].delivery)
	}

	ts, err := strconv.ParseInt(got[0].timestamp, 10, 64)
	if err != nil {
		t.Fatalf("timestamp header %q: %v", got[0].timestamp, err)
	}
	want := "sha256=" + Sign("s3cret", ts, got[0].body)
	if got[0].signature != want {
		t.Errorf("signature = %q, want %q", got[0].signature, want)
	}

	waitFor(t, func() bool { return store.GetWebhookCursor("ops") == 2 }, "cursor at 2")
}

// TestEventFilterSkipsUnsubscribedEvents checks the glob filter and that the
// cursor advances past filtered events.
func TestEventFilterSkipsUnsubscribedEvents(t *testing.T) {
	store := newFakeStore()
	store.append("session.created")
	store.append("node.approved")

	receiver := &recordingReceiver{}
	hs := httptest.NewServer(receiver)
	t.Cleanup(hs.Close)

	startDispatcher(t, Config{
		Endpoints: []Endpoint{{ID: "nodes", URL: hs.URL, Secret: "k", Events: []string{"node.*"}}},
		Store:     store,
	})

	waitFor(t, func() bool { return store.GetWebhookCursor("nodes") == 2 }, "cursor past filtered event")
	got := receiver.delivered()
	if len(got) != 1 || got[0].event != "node.approved" {
		t.Fatalf("delivered %d events (%v), want only node.approved", len(got), got)
	}
}

// TestRetriesTransientFailures checks that a 500 is retried and the cursor
// only advances after acknowledgement.
func TestRetriesTransientFailures(t *testing.T) {
	store := newFakeStore()
	store.append("node.registered")

	receiver := &recordingReceiver{status: http.StatusInternalServerError, failures: 1}
	hs := httptest.NewServer(receiver)
	t.Cleanup(hs.Close)

	startDispatcher(t, Config{
		Endpoints: []Endpoint{{ID: "retry", URL: hs.URL, Secret: "k"}},
		Store:     store,
	})

	waitFor(t, func() bool { return len(receiver.delivered()) == 1 }, "retried delivery")
	waitFor(t, func() bool { return store.GetWebhookCursor("retry") == 1 }, "cursor after ack")
}

// TestDropsPermanentlyRejectedEvents checks that a 400 does not stall the
// endpoint: the event is dropped with the cursor advanced and later events
// still flow.
func TestDropsPermanentlyRejectedEvents(t *testing.T) {
	store := newFakeStore()
	store.append("node.registered") // rejected with 400
	store.append("node.approved")   // delivered

	receiver := &recordingReceiver{status: http.StatusBadRequest, failures: 1}
	hs := httptest.NewServer(receiver)
	t.Cleanup(hs.Close)

	startDispatcher(t, Config{
		Endpoints: []Endpoint{{ID: "drop", URL: hs.URL, Secret: "k"}},
		Store:     store,
	})

	waitFor(t, func() bool { return store.GetWebhookCursor("drop") == 2 }, "cursor past the dropped event")
	got := receiver.delivered()
	if len(got) != 1 || got[0].event != "node.approved" {
		t.Fatalf("delivered %v, want only node.approved", got)
	}
}

// TestNewValidation pins the fail-closed configuration checks.
func TestNewValidation(t *testing.T) {
	store := newFakeStore()

	cases := []struct {
		name string
		ep   Endpoint
	}{
		{"missing id", Endpoint{URL: "https://example.com/hook", Secret: "k"}},
		{"plaintext remote", Endpoint{ID: "a", URL: "http://example.com/hook", Secret: "k"}},
		{"missing secret", Endpoint{ID: "a", URL: "https://example.com/hook"}},
		{"bad glob", Endpoint{ID: "a", URL: "https://example.com/hook", Secret: "k", Events: []string{"node.?"}}},
		{"empty glob", Endpoint{ID: "a", URL: "https://example.com/hook", Secret: "k", Events: []string{""}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := New(Config{Endpoints: []Endpoint{tc.ep}, Store: store}); err == nil {
				t.Fatal("New accepted an invalid endpoint")
			}
		})
	}

	if _, err := New(Config{
		Endpoints: []Endpoint{
			{ID: "a", URL: "https://example.com/hook", Secret: "k"},
			{ID: "a", URL: "http://127.0.0.1:9/hook", Secret: "k"},
		},
		Store: store,
	}); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("duplicate endpoint IDs accepted: %v", err)
	}
}

// TestGlobMatch pins the pattern semantics.
func TestGlobMatch(t *testing.T) {
	cases := []struct {
		pattern string
		s       string
		want    bool
	}{
		{"*", "anything", true},
		{"node.*", "node.approved", true},
		{"node.*", "session.created", false},
		{"*.created", "user.created", true},
		{"a*c", "abc", true},
		{"a*c", "ac", true},
		{"a*c", "ab", false},
		{"node.approved", "node.approved", true},
	}
	for _, tc := range cases {
		got, err := globMatch(tc.pattern, tc.s)
		if err != nil {
			t.Fatalf("globMatch(%q, %q): %v", tc.pattern, tc.s, err)
		}
		if got != tc.want {
			t.Errorf("globMatch(%q, %q) = %v, want %v", tc.pattern, tc.s, got, tc.want)
		}
	}
}

// mustDispatcher builds a dispatcher or fails the test.
func mustDispatcher(t *testing.T, cfg Config) *Dispatcher {
	t.Helper()
	d, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return d
}

// TestDeliveryLeaseSingleWriter checks that two instances sharing a store
// deliver each event once between them, and that a stopped holder's lease is
// taken over.
func TestDeliveryLeaseSingleWriter(t *testing.T) {
	store := newFakeStore()
	store.append("node.registered")
	store.append("node.approved")

	receiver := &recordingReceiver{}
	hs := httptest.NewServer(receiver)
	t.Cleanup(hs.Close)

	endpoint := Endpoint{ID: "ops", URL: hs.URL, Secret: "s3cret"}
	base := Config{
		Endpoints:          []Endpoint{endpoint},
		Store:              store,
		PollInterval:       5 * time.Millisecond,
		LeaseDuration:      time.Minute,
		LeaseRenewInterval: time.Second,
	}

	ctxA, cancelA := context.WithCancel(context.Background())
	ctxB, cancelB := context.WithCancel(context.Background())
	t.Cleanup(func() { cancelA(); cancelB() })

	cfgA := base
	cfgA.InstanceID = "a"
	cfgB := base
	cfgB.InstanceID = "b"
	dA := mustDispatcher(t, cfgA)
	dB := mustDispatcher(t, cfgB)

	go dA.Run(ctxA)
	go dB.Run(ctxB)

	waitFor(t, func() bool { return len(receiver.delivered()) == 2 }, "two deliveries")

	// The second instance must not duplicate them while the first holds the
	// lease.
	time.Sleep(100 * time.Millisecond)
	if got := len(receiver.delivered()); got != 2 {
		t.Fatalf("deliveries = %d, want 2 (one writer per endpoint)", got)
	}

	// The holder stops; the other instance takes over and delivers the event
	// that arrived afterwards.
	cancelA()
	waitFor(t, func() bool { return store.GetWebhookCursor("ops") == 2 }, "cursor at 2")
	store.append("node.deleted")
	waitFor(t, func() bool { return store.GetWebhookCursor("ops") == 3 }, "takeover delivery")
	if got := len(receiver.delivered()); got != 3 {
		t.Fatalf("deliveries = %d, want 3", got)
	}
}

// TestRetryBackoffIsPersisted checks that a failed delivery's backoff is
// durable: a fresh instance waits for the recorded retry time instead of
// hammering the receiver immediately.
func TestRetryBackoffIsPersisted(t *testing.T) {
	store := newFakeStore()
	store.append("node.registered")

	receiver := &recordingReceiver{status: http.StatusInternalServerError, failures: 1}
	hs := httptest.NewServer(receiver)
	t.Cleanup(hs.Close)

	endpoint := Endpoint{ID: "ops", URL: hs.URL, Secret: "s3cret"}
	base := Config{
		Endpoints:          []Endpoint{endpoint},
		Store:              store,
		PollInterval:       5 * time.Millisecond,
		MaxBackoff:         500 * time.Millisecond,
		LeaseDuration:      time.Second,
		LeaseRenewInterval: time.Second,
	}

	ctxA, cancelA := context.WithCancel(context.Background())
	t.Cleanup(cancelA)
	cfgA := base
	cfgA.InstanceID = "a"
	dA := mustDispatcher(t, cfgA)
	go dA.Run(ctxA)

	waitFor(t, func() bool {
		attempts, _ := store.WebhookRetryState("ops")
		return attempts == 1
	}, "persisted retry state")

	_, retryAt := store.WebhookRetryState("ops")
	if retryAt.IsZero() || !retryAt.After(time.Now()) {
		t.Fatalf("retryAt = %v, want a future time", retryAt)
	}
	cancelA()

	// A fresh instance must honour the persisted delay.
	ctxB, cancelB := context.WithCancel(context.Background())
	t.Cleanup(cancelB)
	cfgB := base
	cfgB.InstanceID = "b"
	dB := mustDispatcher(t, cfgB)
	go dB.Run(ctxB)

	waitFor(t, func() bool { return len(receiver.delivered()) == 1 }, "delivery after backoff")
	if got := receiver.delivered()[0]; got.at.Before(retryAt.Add(-2 * time.Millisecond)) {
		t.Errorf("delivered at %v, before the persisted retry time %v", got.at, retryAt)
	}
	if attempts, _ := store.WebhookRetryState("ops"); attempts != 0 {
		t.Errorf("attempts = %d after a successful delivery, want 0", attempts)
	}
}
