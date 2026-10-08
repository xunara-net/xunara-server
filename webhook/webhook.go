// Package webhook delivers audit events to operator-configured HTTPS
// endpoints, signed with an HMAC so receivers can authenticate the control
// plane.
//
// Delivery is driven by the durable audit log: each endpoint has a cursor, and
// the dispatcher only ever moves it forward after a delivery is acknowledged.
// That makes delivery at-least-once and restart-safe without a server-local
// queue (AGENTS.md section 9); receivers deduplicate by the delivery ID.
package webhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xunara-net/xunara-server/identity"
)

const (
	// defaultPollInterval is how often an idle endpoint looks for new events.
	defaultPollInterval = time.Second
	// defaultMaxBackoff caps the retry delay after delivery failures.
	defaultMaxBackoff = time.Minute
	// deliveryBatch bounds how many audit events one endpoint pulls per round.
	deliveryBatch = 100
	// maxResponseBytes is how much of a receiver's response body is read (to
	// reuse the connection) before it is discarded.
	maxResponseBytes = 4 << 10
	// requestTimeout bounds one delivery attempt.
	requestTimeout = 10 * time.Second
)

// Endpoint is one webhook receiver.
type Endpoint struct {
	// ID is a stable, operator-chosen identifier. It is the cursor key, so
	// renaming it replays the whole audit log.
	ID string
	// URL is the receiver. HTTPS, or loopback HTTP for tests.
	URL string
	// Secret signs deliveries. Required: unsigned webhooks are not allowed.
	Secret string
	// Events filters on the audit action: glob patterns such as "node.*" or
	// "*". Empty means every event.
	Events []string
}

// Config configures a [Dispatcher].
type Config struct {
	Endpoints []Endpoint
	// Store is the audit log the dispatcher consumes.
	Store Store
	// Logger receives delivery logs. Defaults to slog.Default.
	Logger *slog.Logger
	// HTTPClient performs the deliveries. Defaults to a client with a
	// per-request timeout and no redirects (a redirect to another host would
	// leak the signature to that host).
	HTTPClient *http.Client
	// PollInterval is how often an idle endpoint checks for new events.
	PollInterval time.Duration
	// MaxBackoff caps the exponential retry delay.
	MaxBackoff time.Duration
	// Now, if set, overrides the clock (tests).
	Now func() time.Time
	// InstanceID identifies this process in webhook delivery leases. Defaults
	// to a random identifier; tests may pin it.
	InstanceID string
	// LeaseDuration is how long a delivery lease is valid without renewal.
	// Zero uses DefaultLeaseDuration. Only short-lived for tests.
	LeaseDuration time.Duration
	// LeaseRenewInterval is how often the lease holder renews it. Zero uses
	// LeaseDuration/3.
	LeaseRenewInterval time.Duration
}

const (
	// DefaultLeaseDuration bounds how long a crashed instance can block
	// delivery for an endpoint.
	DefaultLeaseDuration = time.Minute
)

// Store is the part of the trust plane the dispatcher consumes. It is
// satisfied by [identity.Store]; keeping it narrow lets tests use a tiny fake
// and keeps the dispatcher independent of the rest of the identity model.
type Store interface {
	// ListAuditAfter returns events with ID greater than afterID, oldest
	// first, at most limit of them (0 means no limit).
	ListAuditAfter(afterID uint64, limit int) []identity.AuditEvent
	// GetWebhookCursor returns the last delivered event ID for an endpoint,
	// or 0 when it has never delivered.
	GetWebhookCursor(endpoint string) uint64
	// SetWebhookCursor records the last delivered event ID.
	SetWebhookCursor(endpoint string, eventID uint64) error

	// ClaimWebhookEndpoint claims exclusive delivery for an endpoint until
	// expiresAt. See [identity.WebhookCursorStore] for the semantics.
	ClaimWebhookEndpoint(endpoint, owner string, now, expiresAt time.Time) (bool, error)
	// RenewWebhookClaim extends a claim; false means it was taken over.
	RenewWebhookClaim(endpoint, owner string, expiresAt time.Time) (bool, error)
	// ReleaseWebhookClaim drops a claim the owner still holds.
	ReleaseWebhookClaim(endpoint, owner string) error
	// WebhookRetryState returns the persisted backoff state.
	WebhookRetryState(endpoint string) (attempts int, retryAt time.Time)
	// SetWebhookRetryState persists the backoff state.
	SetWebhookRetryState(endpoint string, attempts int, retryAt time.Time) error
}

// Dispatcher delivers audit events to the configured endpoints.
type Dispatcher struct {
	cfg    Config
	log    *slog.Logger
	client *http.Client
	// owner is this process's identity in delivery leases.
	owner string

	// mu guards the runtime endpoint set. runCtx is non-nil once Run has
	// started; running holds each endpoint's cancel function; endpoints added
	// before Run are queued in cfg.Endpoints.
	mu      sync.Mutex
	runCtx  context.Context
	running map[string]context.CancelFunc
	wg      sync.WaitGroup
	seq     atomic.Uint64
}

// Delivery is the JSON document POSTed to an endpoint.
type Delivery struct {
	// ID uniquely identifies this delivery attempt chain; receivers
	// deduplicate on it (at-least-once delivery).
	ID string `json:"id"`
	// Endpoint is the destination endpoint ID.
	Endpoint string `json:"endpoint"`
	// Event is the audit event being delivered.
	Event Event `json:"event"`
	// SentAt is the sender's wall clock.
	SentAt time.Time `json:"sent_at"`
}

// Event is the wire form of an [identity.AuditEvent].
type Event struct {
	ID     uint64    `json:"id"`
	Time   time.Time `json:"time"`
	Actor  string    `json:"actor,omitempty"`
	Action string    `json:"action"`
	Target string    `json:"target,omitempty"`
	Detail string    `json:"detail,omitempty"`
}

// New validates the configuration and returns a dispatcher.
func New(cfg Config) (*Dispatcher, error) {
	if cfg.Store == nil {
		return nil, errors.New("webhook: store is required")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = defaultPollInterval
	}
	if cfg.MaxBackoff <= 0 {
		cfg.MaxBackoff = defaultMaxBackoff
	}
	if cfg.Now == nil {
		cfg.Now = func() time.Time { return time.Now().UTC() }
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{
			Timeout: requestTimeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				// Following a redirect would hand the HMAC signature to the
				// redirect target.
				return errors.New("webhook: redirects are not followed")
			},
		}
	}

	seen := make(map[string]bool, len(cfg.Endpoints))
	for i := range cfg.Endpoints {
		ep := &cfg.Endpoints[i]
		if strings.TrimSpace(ep.ID) == "" {
			return nil, fmt.Errorf("webhook: endpoint %d: id is required", i)
		}
		if seen[ep.ID] {
			return nil, fmt.Errorf("webhook: duplicate endpoint id %q", ep.ID)
		}
		seen[ep.ID] = true
		if err := ValidateEndpoint(*ep); err != nil {
			return nil, err
		}
	}

	if cfg.InstanceID == "" {
		id, err := randomInstanceID()
		if err != nil {
			return nil, err
		}
		cfg.InstanceID = id
	}
	if cfg.LeaseDuration <= 0 {
		cfg.LeaseDuration = DefaultLeaseDuration
	}
	if cfg.LeaseRenewInterval <= 0 {
		cfg.LeaseRenewInterval = cfg.LeaseDuration / 3
		if cfg.LeaseRenewInterval < time.Second {
			cfg.LeaseRenewInterval = time.Second
		}
	}

	return &Dispatcher{cfg: cfg, log: cfg.Logger, client: cfg.HTTPClient, owner: cfg.InstanceID}, nil
}

// randomInstanceID returns a random lease owner identifier.
func randomInstanceID() (string, error) {
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", fmt.Errorf("webhook: generating instance id: %w", err)
	}
	return hex.EncodeToString(buf[:]), nil
}

// ValidateEndpoint checks one endpoint's configuration. It is the validation
// [New] applies, exported so the management API can reject a bad endpoint
// before persisting it.
func ValidateEndpoint(ep Endpoint) error {
	if strings.TrimSpace(ep.ID) == "" {
		return errors.New("webhook: endpoint id is required")
	}
	if err := validateEndpointURL(ep.URL); err != nil {
		return fmt.Errorf("webhook: endpoint %q: %w", ep.ID, err)
	}
	if strings.TrimSpace(ep.Secret) == "" {
		return fmt.Errorf("webhook: endpoint %q: signing secret is required", ep.ID)
	}
	for _, pattern := range ep.Events {
		if _, err := globMatch(pattern, ""); err != nil {
			return fmt.Errorf("webhook: endpoint %q: %w", ep.ID, err)
		}
	}
	return nil
}

// MatchGlob reports whether s matches a glob pattern. It exposes the same
// syntax the endpoint event filters use ("*" is the only wildcard), so an
// operator can copy a receiver's filter into another tool without guessing.
func MatchGlob(pattern, s string) (bool, error) {
	return globMatch(pattern, s)
}

// Run delivers events until ctx is cancelled. One goroutine per endpoint; a
// running dispatcher also accepts [Upsert] and [Remove], so endpoints can be
// managed while it serves.
func (d *Dispatcher) Run(ctx context.Context) {
	d.mu.Lock()
	d.runCtx = ctx
	initial := append([]Endpoint(nil), d.cfg.Endpoints...)
	d.cfg.Endpoints = nil
	d.mu.Unlock()

	for _, ep := range initial {
		d.start(ctx, ep)
	}

	<-ctx.Done()

	d.mu.Lock()
	for _, cancel := range d.running {
		cancel()
	}
	d.mu.Unlock()
	d.wg.Wait()
}

// Upsert adds an endpoint, or replaces the running one with the same ID. The
// durable cursor is untouched, so a reconfiguration does not replay history.
func (d *Dispatcher) Upsert(ep Endpoint) error {
	if err := ValidateEndpoint(ep); err != nil {
		return err
	}

	d.mu.Lock()
	ctx := d.runCtx
	d.mu.Unlock()

	if ctx == nil {
		// Not running yet: queue it for Run.
		d.mu.Lock()
		defer d.mu.Unlock()
		for i := range d.cfg.Endpoints {
			if d.cfg.Endpoints[i].ID == ep.ID {
				d.cfg.Endpoints[i] = ep
				return nil
			}
		}
		d.cfg.Endpoints = append(d.cfg.Endpoints, ep)
		return nil
	}

	d.start(ctx, ep)
	return nil
}

// Remove stops delivering to an endpoint. The next instance to start with the
// same ID resumes from the durable cursor; removing an unknown endpoint is a
// no-op.
func (d *Dispatcher) Remove(id string) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if cancel, ok := d.running[id]; ok {
		cancel()
		delete(d.running, id)
	}
	for i := range d.cfg.Endpoints {
		if d.cfg.Endpoints[i].ID == id {
			d.cfg.Endpoints = append(d.cfg.Endpoints[:i], d.cfg.Endpoints[i+1:]...)
			return
		}
	}
}

// start launches (or restarts) one endpoint's goroutine.
func (d *Dispatcher) start(ctx context.Context, ep Endpoint) {
	// Each goroutine generation gets its own lease owner, so a replaced
	// goroutine's deferred release cannot free its successor's claim.
	owner := fmt.Sprintf("%s/%s/%d", d.owner, ep.ID, d.seq.Add(1))

	epCtx, cancel := context.WithCancel(ctx)

	d.mu.Lock()
	if prev, ok := d.running[ep.ID]; ok {
		prev()
	}
	if d.running == nil {
		d.running = make(map[string]context.CancelFunc)
	}
	d.running[ep.ID] = cancel
	d.wg.Add(1)
	d.mu.Unlock()

	go func() {
		defer d.wg.Done()
		defer cancel()
		d.runEndpoint(epCtx, ep, owner)
	}()
}

// runEndpoint drives one endpoint's cursor until ctx is cancelled.
//
// Delivery is single-writer per endpoint: the instance holding the durable
// lease delivers, and the others wait. That is what keeps several instances
// sharing one database from double delivering; the retry backoff is persisted
// with the same row, so a restart does not reset it.
func (d *Dispatcher) runEndpoint(ctx context.Context, ep Endpoint, owner string) {
	if !d.acquire(ctx, ep, owner) {
		return
	}
	defer func() {
		if err := d.cfg.Store.ReleaseWebhookClaim(ep.ID, owner); err != nil {
			d.log.Warn("releasing webhook claim", "endpoint", ep.ID, "err", err)
		}
	}()

	lost := make(chan struct{})
	renewCtx, stopRenew := context.WithCancel(ctx)
	defer stopRenew()
	go d.renewLoop(renewCtx, ep.ID, owner, lost)

	attempts, retryAt := d.cfg.Store.WebhookRetryState(ep.ID)
	delay := d.backoffFor(attempts)

	// A persisted retry time from a previous instance is honoured before the
	// first attempt, so a restart does not hammer a down receiver.
	if wait := time.Until(retryAt); wait > 0 {
		if wait > d.cfg.MaxBackoff {
			wait = d.cfg.MaxBackoff
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-lost:
			timer.Stop()
			return
		case <-timer.C:
		}
	}

	for {
		if ctx.Err() != nil {
			return
		}
		select {
		case <-lost:
			d.log.Warn("webhook delivery lease was taken over; stopping", "endpoint", ep.ID)
			return
		default:
		}

		progress, failed := d.deliverPending(ctx, ep)
		switch {
		case failed:
			// Back off so a down endpoint does not get hammered, and persist
			// the delay so a restart does not reset it.
			if delay < d.cfg.MaxBackoff {
				delay *= 2
				if delay > d.cfg.MaxBackoff {
					delay = d.cfg.MaxBackoff
				}
			}
			attempts++
			d.storeRetry(ep, attempts, d.cfg.Now().Add(delay))
		case progress:
			delay = d.cfg.PollInterval
			if attempts > 0 {
				attempts = 0
				d.storeRetry(ep, 0, time.Time{})
			}
		}

		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-lost:
			timer.Stop()
			d.log.Warn("webhook delivery lease was taken over; stopping", "endpoint", ep.ID)
			return
		case <-timer.C:
		}
	}
}

// acquire blocks until this instance holds the endpoint's delivery lease, and
// reports false when ctx is cancelled first.
func (d *Dispatcher) acquire(ctx context.Context, ep Endpoint, owner string) bool {
	waiting := false
	for {
		claimed, err := d.cfg.Store.ClaimWebhookEndpoint(ep.ID, owner,
			d.cfg.Now(), d.cfg.Now().Add(d.cfg.LeaseDuration))
		switch {
		case err != nil:
			d.log.Error("claiming webhook endpoint", "endpoint", ep.ID, "err", err)
		case claimed:
			if waiting {
				d.log.Info("acquired webhook delivery lease", "endpoint", ep.ID)
			}
			return true
		case !waiting:
			d.log.Debug("another instance holds the webhook delivery lease", "endpoint", ep.ID)
			waiting = true
		}

		timer := time.NewTimer(d.cfg.PollInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return false
		case <-timer.C:
		}
	}
}

// renewLoop extends the lease until ctx is cancelled or the lease is taken
// over, in which case lost is closed.
func (d *Dispatcher) renewLoop(ctx context.Context, endpoint, owner string, lost chan<- struct{}) {
	ticker := time.NewTicker(d.cfg.LeaseRenewInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			ok, err := d.cfg.Store.RenewWebhookClaim(endpoint, owner, d.cfg.Now().Add(d.cfg.LeaseDuration))
			if err != nil {
				d.log.Error("renewing webhook claim", "endpoint", endpoint, "err", err)
				continue
			}
			if !ok {
				close(lost)
				return
			}
		}
	}
}

// storeRetry persists the endpoint's backoff state, logging failures: a
// delivery that is a little early after a restart is safe, a wrongly skipped
// one is not.
func (d *Dispatcher) storeRetry(ep Endpoint, attempts int, retryAt time.Time) {
	if err := d.cfg.Store.SetWebhookRetryState(ep.ID, attempts, retryAt); err != nil {
		d.log.Error("persisting webhook retry state", "endpoint", ep.ID, "err", err)
	}
}

// backoffFor returns the delay after attempts consecutive failures.
func (d *Dispatcher) backoffFor(attempts int) time.Duration {
	delay := d.cfg.PollInterval
	for i := 0; i < attempts; i++ {
		if delay >= d.cfg.MaxBackoff {
			return d.cfg.MaxBackoff
		}
		delay *= 2
	}
	if delay > d.cfg.MaxBackoff {
		delay = d.cfg.MaxBackoff
	}
	return delay
}

// deliverPending walks the events after the endpoint's cursor.
//
// It reports whether anything was processed (so the caller can reset its
// backoff) and whether a delivery failed (so the caller can back off). A
// permanently rejected event is dropped with an error log: keeping it would
// stall the endpoint forever.
func (d *Dispatcher) deliverPending(ctx context.Context, ep Endpoint) (progress, failed bool) {
	cursor := d.cfg.Store.GetWebhookCursor(ep.ID)

	for {
		if ctx.Err() != nil {
			return progress, failed
		}

		events := d.cfg.Store.ListAuditAfter(cursor, deliveryBatch)
		if len(events) == 0 {
			return progress, failed
		}

		for _, event := range events {
			if ctx.Err() != nil {
				return progress, failed
			}

			if !d.wants(ep, event.Action) {
				// Filtered-out events still advance the cursor; they will
				// never be delivered.
				if err := d.advance(ep, event.ID); err != nil {
					d.log.Error("advancing webhook cursor", "endpoint", ep.ID, "err", err)
					return progress, true
				}
				cursor = event.ID
				progress = true
				continue
			}

			switch d.deliver(ctx, ep, event) {
			case deliveryOK:
				if err := d.advance(ep, event.ID); err != nil {
					d.log.Error("advancing webhook cursor", "endpoint", ep.ID, "err", err)
					return progress, true
				}
				cursor = event.ID
				progress = true
			case deliveryDropped:
				// The receiver rejected the payload; skip it rather than
				// blocking every later event.
				if err := d.advance(ep, event.ID); err != nil {
					d.log.Error("advancing webhook cursor", "endpoint", ep.ID, "err", err)
					return progress, true
				}
				cursor = event.ID
				progress = true
			case deliveryRetry:
				return progress, true
			}
		}

		if len(events) < deliveryBatch {
			return progress, failed
		}
	}
}

// advance moves an endpoint's cursor past one event.
func (d *Dispatcher) advance(ep Endpoint, eventID uint64) error {
	return d.cfg.Store.SetWebhookCursor(ep.ID, eventID)
}

// wants reports whether an endpoint subscribes to an audit action.
func (d *Dispatcher) wants(ep Endpoint, action string) bool {
	if len(ep.Events) == 0 {
		return true
	}
	for _, pattern := range ep.Events {
		if ok, _ := globMatch(pattern, action); ok {
			return true
		}
	}
	return false
}

// deliveryResult classifies one delivery attempt.
type deliveryResult int

const (
	deliveryOK      deliveryResult = iota // acknowledged
	deliveryDropped                       // permanently rejected; do not retry
	deliveryRetry                         // transient; retry later
)

// deliver POSTs one event, retrying transient failures.
func (d *Dispatcher) deliver(ctx context.Context, ep Endpoint, event identity.AuditEvent) deliveryResult {
	deliveryID := fmt.Sprintf("%s-%d", ep.ID, event.ID)
	// Read the clock once: the same instant is both SentAt and the timestamp
	// covered by the signature, so receivers can recompute the MAC from the
	// payload alone.
	now := d.cfg.Now()
	payload := Delivery{
		ID:       deliveryID,
		Endpoint: ep.ID,
		Event: Event{
			ID:     event.ID,
			Time:   event.Time,
			Actor:  event.Actor,
			Action: event.Action,
			Target: event.Target,
			Detail: event.Detail,
		},
		SentAt: now,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		d.log.Error("encoding webhook payload", "endpoint", ep.ID, "event_id", event.ID, "err", err)
		return deliveryDropped
	}

	timestamp := now.Unix()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ep.URL, bytes.NewReader(body))
	if err != nil {
		d.log.Error("building webhook request", "endpoint", ep.ID, "err", err)
		return deliveryDropped
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "xunara-webhook")
	req.Header.Set("X-Xunara-Event", event.Action)
	req.Header.Set("X-Xunara-Delivery", deliveryID)
	req.Header.Set("X-Xunara-Timestamp", fmt.Sprintf("%d", timestamp))
	req.Header.Set("X-Xunara-Signature", "sha256="+sign(ep.Secret, timestamp, body))

	resp, err := d.client.Do(req)
	if err != nil {
		d.log.Warn("webhook delivery failed", "endpoint", ep.ID, "event_id", event.ID, "err", err)
		return deliveryRetry
	}
	defer resp.Body.Close()

	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseBytes))

	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return deliveryOK
	case resp.StatusCode == http.StatusRequestTimeout, resp.StatusCode == http.StatusTooManyRequests:
		d.log.Warn("webhook delivery throttled", "endpoint", ep.ID,
			"event_id", event.ID, "status", resp.StatusCode)
		return deliveryRetry
	case resp.StatusCode >= 400 && resp.StatusCode < 500:
		d.log.Error("webhook receiver rejected an event; dropping it",
			"endpoint", ep.ID, "event_id", event.ID, "status", resp.StatusCode)
		return deliveryDropped
	default:
		d.log.Warn("webhook delivery failed", "endpoint", ep.ID,
			"event_id", event.ID, "status", resp.StatusCode)
		return deliveryRetry
	}
}

// Sign returns the hex HMAC-SHA256 of "<timestamp>.<body>" under secret. It is
// the value of the X-Xunara-Signature header, minus the "sha256=" prefix.
//
// It is exported so receivers (and tests) can verify deliveries without
// reimplementing the scheme.
func Sign(secret string, timestamp int64, body []byte) string {
	return sign(secret, timestamp, body)
}

func sign(secret string, timestamp int64, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	fmt.Fprintf(mac, "%d.", timestamp)
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

// validateEndpointURL enforces HTTPS (or loopback HTTP for tests), so an HMAC
// signature is never sent over a plaintext network.
func validateEndpointURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid URL %q: %w", raw, err)
	}
	if u.Host == "" {
		return fmt.Errorf("invalid URL %q: missing host", raw)
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		host := u.Hostname()
		if host == "localhost" {
			return nil
		}
		if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
			return nil
		}
		return fmt.Errorf("plaintext URL %q is only allowed for loopback receivers", raw)
	default:
		return fmt.Errorf("unsupported URL scheme %q (use https)", u.Scheme)
	}
}

// globMatch matches a glob pattern ("*" wildcard) against a string. Patterns
// only contain literals and "*"; anything else is rejected at startup.
func globMatch(pattern, s string) (bool, error) {
	if pattern == "" {
		return false, errors.New("empty event pattern")
	}
	parts := strings.Split(pattern, "*")
	for _, part := range parts {
		if strings.ContainsAny(part, "?[]\\") {
			return false, fmt.Errorf("event pattern %q uses unsupported wildcards (only * is allowed)", pattern)
		}
	}

	if len(parts) == 1 {
		return pattern == s, nil
	}
	if !strings.HasPrefix(s, parts[0]) {
		return false, nil
	}
	s = s[len(parts[0]):]
	for i := 1; i < len(parts)-1; i++ {
		idx := strings.Index(s, parts[i])
		if idx < 0 {
			return false, nil
		}
		s = s[idx+len(parts[i]):]
	}
	return strings.HasSuffix(s, parts[len(parts)-1]), nil
}
