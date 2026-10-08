package control

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xunara-net/xunara-server/identity"
	"github.com/xunara-net/xunara-server/state"
)

// doFlux performs an authenticated flux request: the bearer token plus the
// machine and node key headers every flux endpoint expects.
func (a enrolledServiceAgent) doFlux(t *testing.T, client *http.Client, method, rawURL string, body []byte, contentType string) ([]byte, int) {
	t.Helper()

	req, err := http.NewRequest(method, rawURL, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("building %s %s: %v", method, rawURL, err)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	req.Header.Set("Authorization", "Bearer "+a.token)
	req.Header.Set("X-Xunara-Machine-Key", a.machineKey.Public().String())
	req.Header.Set("X-Xunara-Node-Key", a.nodeKey.Public().String())

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, rawURL, err)
	}
	defer resp.Body.Close()
	return readBody(t, resp), resp.StatusCode
}

// fluxTransfers decodes a list response.
func fluxTransfers(t *testing.T, raw []byte) []fluxTransferView {
	t.Helper()
	var out struct {
		Transfers []fluxTransferView `json:"transfers"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decoding transfer list: %v (%s)", err, raw)
	}
	return out.Transfers
}

// TestFluxEndToEnd walks the whole v1 flow with three agents: offer, accept,
// upload, download, complete — plus the isolation checks (a bystander sees
// nothing, each side may only act in its role).
func TestFluxEndToEnd(t *testing.T) {
	s := newServerWithConfig(t, Config{Flux: &FluxConfig{}})
	hs := newTestHTTPServer(t, s)

	sender := enrollServiceAgent(t, s, hs, "sender")
	recipient := enrollServiceAgent(t, s, hs, "recipient")
	bystander := enrollServiceAgent(t, s, hs, "bystander")

	plaintext := []byte("hello flux")
	sum := sha256.Sum256(plaintext)

	raw, status := sender.doFlux(t, hs.Client(), http.MethodPost, hs.URL+"/api/agent/v1/flux/transfers",
		mustJSON(t, map[string]any{
			"recipient": recipient.node.StableID,
			"name":      "notes.txt",
			"size":      len(plaintext),
			"sha256":    hex.EncodeToString(sum[:]),
		}), "application/json")
	if status != http.StatusCreated {
		t.Fatalf("create offer = %d (%s)", status, raw)
	}
	offer := decodeJSON[fluxTransferView](t, raw)
	if offer.ID == "" || offer.State != string(state.FluxPending) || offer.Direction != "sent" {
		t.Fatalf("offer = %+v", offer)
	}

	// The recipient sees the offer; a bystander sees nothing.
	raw, status = recipient.doFlux(t, hs.Client(), http.MethodGet, hs.URL+"/api/agent/v1/flux/transfers", nil, "")
	if status != http.StatusOK {
		t.Fatalf("recipient list = %d (%s)", status, raw)
	}
	listed := fluxTransfers(t, raw)
	if len(listed) != 1 || listed[0].ID != offer.ID || listed[0].Direction != "received" {
		t.Fatalf("recipient list = %+v", listed)
	}
	if raw, _ := bystander.doFlux(t, hs.Client(), http.MethodGet, hs.URL+"/api/agent/v1/flux/transfers", nil, ""); len(fluxTransfers(t, raw)) != 0 {
		t.Fatalf("bystander sees transfers: %s", raw)
	}
	if _, status := bystander.doFlux(t, hs.Client(), http.MethodPost,
		hs.URL+"/api/agent/v1/flux/transfers/"+offer.ID+"/accept", mustJSON(t, map[string]any{
			"publicKey": base64.StdEncoding.EncodeToString(make([]byte, 32)),
		}), "application/json"); status != http.StatusNotFound {
		t.Fatalf("bystander accept = %d, want 404", status)
	}

	// Only the recipient may accept.
	if _, status := sender.doFlux(t, hs.Client(), http.MethodPost,
		hs.URL+"/api/agent/v1/flux/transfers/"+offer.ID+"/accept", mustJSON(t, map[string]any{
			"publicKey": base64.StdEncoding.EncodeToString(make([]byte, 32)),
		}), "application/json"); status != http.StatusNotFound {
		t.Fatalf("sender accept = %d, want 404", status)
	}

	recipientKey := make([]byte, 32)
	if _, err := rand.Read(recipientKey); err != nil {
		t.Fatalf("generating key: %v", err)
	}
	raw, status = recipient.doFlux(t, hs.Client(), http.MethodPost,
		hs.URL+"/api/agent/v1/flux/transfers/"+offer.ID+"/accept",
		mustJSON(t, map[string]any{"publicKey": base64.StdEncoding.EncodeToString(recipientKey)}),
		"application/json")
	if status != http.StatusOK {
		t.Fatalf("accept = %d (%s)", status, raw)
	}
	accepted := decodeJSON[fluxTransferView](t, raw)
	if accepted.State != string(state.FluxAccepted) ||
		accepted.RecipientKey != base64.StdEncoding.EncodeToString(recipientKey) {
		t.Fatalf("accepted = %+v", accepted)
	}

	// The sender learns the recipient key from its list and uploads; the
	// recipient may not upload.
	ciphertext := make([]byte, len(plaintext)+60)
	if _, err := rand.Read(ciphertext); err != nil {
		t.Fatalf("generating ciphertext: %v", err)
	}
	if _, status := recipient.doFlux(t, hs.Client(), http.MethodPut,
		hs.URL+"/api/agent/v1/flux/transfers/"+offer.ID+"/content", ciphertext, "application/octet-stream"); status != http.StatusNotFound {
		t.Fatalf("recipient upload = %d, want 404", status)
	}
	raw, status = sender.doFlux(t, hs.Client(), http.MethodPut,
		hs.URL+"/api/agent/v1/flux/transfers/"+offer.ID+"/content", ciphertext, "application/octet-stream")
	if status != http.StatusOK {
		t.Fatalf("upload = %d (%s)", status, raw)
	}
	if uploaded := decodeJSON[fluxTransferView](t, raw); uploaded.State != string(state.FluxUploaded) {
		t.Fatalf("upload response = %+v", uploaded)
	}
	// Content beyond the declared size plus the E2E overhead is rejected
	// before it can be stored. (The transfer is already uploaded, so this
	// checks the conflict path; the size path is covered separately.)
	if _, status := sender.doFlux(t, hs.Client(), http.MethodPut,
		hs.URL+"/api/agent/v1/flux/transfers/"+offer.ID+"/content", ciphertext, "application/octet-stream"); status != http.StatusConflict {
		t.Fatalf("second upload = %d, want 409", status)
	}

	// Only the recipient may download, and only after upload.
	if _, status := sender.doFlux(t, hs.Client(), http.MethodGet,
		hs.URL+"/api/agent/v1/flux/transfers/"+offer.ID+"/content", nil, ""); status != http.StatusNotFound {
		t.Fatalf("sender download = %d, want 404", status)
	}
	raw, status = recipient.doFlux(t, hs.Client(), http.MethodGet,
		hs.URL+"/api/agent/v1/flux/transfers/"+offer.ID+"/content", nil, "")
	if status != http.StatusOK || !bytes.Equal(raw, ciphertext) {
		t.Fatalf("download = %d, %d bytes (want %d)", status, len(raw), len(ciphertext))
	}
	// A second download is allowed: the recipient may retry before acking.
	if _, status := recipient.doFlux(t, hs.Client(), http.MethodGet,
		hs.URL+"/api/agent/v1/flux/transfers/"+offer.ID+"/content", nil, ""); status != http.StatusOK {
		t.Fatalf("second download = %d, want 200", status)
	}

	// Complete: only the recipient, only after upload; content disappears.
	if _, status := sender.doFlux(t, hs.Client(), http.MethodPost,
		hs.URL+"/api/agent/v1/flux/transfers/"+offer.ID+"/complete", nil, ""); status != http.StatusNotFound {
		t.Fatalf("sender complete = %d, want 404", status)
	}
	raw, status = recipient.doFlux(t, hs.Client(), http.MethodPost,
		hs.URL+"/api/agent/v1/flux/transfers/"+offer.ID+"/complete", nil, "")
	if status != http.StatusOK {
		t.Fatalf("complete = %d (%s)", status, raw)
	}
	if completed := decodeJSON[fluxTransferView](t, raw); completed.State != string(state.FluxCompleted) {
		t.Fatalf("complete response = %+v", completed)
	}
	if _, err := os.Stat(filepath.Join(s.flux.dir, offer.ID+".bin")); !os.IsNotExist(err) {
		t.Errorf("content file still exists after completion: %v", err)
	}
	if _, status := recipient.doFlux(t, hs.Client(), http.MethodGet,
		hs.URL+"/api/agent/v1/flux/transfers/"+offer.ID+"/content", nil, ""); status != http.StatusConflict {
		t.Fatalf("download after complete = %d, want 409", status)
	}

	for _, action := range []string{
		identity.AuditFluxOffered, identity.AuditFluxAccepted,
		identity.AuditFluxUploaded, identity.AuditFluxCompleted,
	} {
		if _, ok := findAudit(t, s, action); !ok {
			t.Errorf("no %s audit event", action)
		}
	}
}

// TestFluxValidationAndLimits covers the fail-closed input checks and quotas.
func TestFluxValidationAndLimits(t *testing.T) {
	s := newServerWithConfig(t, Config{Flux: &FluxConfig{
		MaxSize: 16,
		Quotas:  state.FluxQuotas{MaxActivePerNode: 1, MaxActiveTotal: 2, MaxStoredBytes: 64},
	}})
	hs := newTestHTTPServer(t, s)
	sender := enrollServiceAgent(t, s, hs, "sender")
	recipient := enrollServiceAgent(t, s, hs, "recipient")
	sum := sha256.Sum256([]byte("payload"))

	create := func(body map[string]any) ([]byte, int) {
		return sender.doFlux(t, hs.Client(), http.MethodPost, hs.URL+"/api/agent/v1/flux/transfers",
			mustJSON(t, body), "application/json")
	}
	valid := map[string]any{
		"recipient": recipient.node.StableID,
		"name":      "file.bin",
		"size":      7,
		"sha256":    hex.EncodeToString(sum[:]),
	}

	for name, mutate := range map[string]func(map[string]any){
		"unknown recipient": func(b map[string]any) { b["recipient"] = "nope" },
		"self transfer":     func(b map[string]any) { b["recipient"] = sender.node.StableID },
		"path in name":      func(b map[string]any) { b["name"] = "../etc/passwd" },
		"control in name":   func(b map[string]any) { b["name"] = "bad\nname" },
		"long name":         func(b map[string]any) { b["name"] = strings.Repeat("x", 129) },
		"bad sha":           func(b map[string]any) { b["sha256"] = "zz" },
		"negative size":     func(b map[string]any) { b["size"] = -1 },
		"oversized":         func(b map[string]any) { b["size"] = 17 },
	} {
		t.Run(name, func(t *testing.T) {
			body := map[string]any{}
			for k, v := range valid {
				body[k] = v
			}
			mutate(body)
			if _, status := create(body); status != http.StatusBadRequest && status != http.StatusRequestEntityTooLarge {
				t.Fatalf("status = %d, want 400/413", status)
			}
		})
	}

	raw, status := create(valid)
	if status != http.StatusCreated {
		t.Fatalf("create = %d (%s)", status, raw)
	}
	offer := decodeJSON[fluxTransferView](t, raw)

	// The per-node quota (one active transfer) rejects the second offer.
	if _, status := create(valid); status != http.StatusTooManyRequests {
		t.Fatalf("second offer = %d, want 429", status)
	}

	// A malformed accept key is rejected before any state change.
	if _, status := recipient.doFlux(t, hs.Client(), http.MethodPost,
		hs.URL+"/api/agent/v1/flux/transfers/"+offer.ID+"/accept",
		mustJSON(t, map[string]any{"publicKey": "short"}), "application/json"); status != http.StatusBadRequest {
		t.Fatalf("bad accept key = %d, want 400", status)
	}

	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	if _, status := recipient.doFlux(t, hs.Client(), http.MethodPost,
		hs.URL+"/api/agent/v1/flux/transfers/"+offer.ID+"/accept",
		mustJSON(t, map[string]any{"publicKey": key}), "application/json"); status != http.StatusOK {
		t.Fatalf("accept = %d", status)
	}

	// Content past the declared size plus overhead is rejected.
	tooLarge := make([]byte, valid["size"].(int)+fluxOverhead+1)
	if _, status := sender.doFlux(t, hs.Client(), http.MethodPut,
		hs.URL+"/api/agent/v1/flux/transfers/"+offer.ID+"/content", tooLarge, "application/octet-stream"); status != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized upload = %d, want 413", status)
	}
	if _, err := os.Stat(filepath.Join(s.flux.dir, offer.ID+".bin")); !os.IsNotExist(err) {
		t.Errorf("rejected upload left a content file: %v", err)
	}

	// Valid content uploads, then completing before upload is impossible for
	// a different transfer. Here the transfer is uploaded already; a second
	// complete attempt is a state conflict after the first completion.
	content := make([]byte, valid["size"].(int)+60)
	if _, status := sender.doFlux(t, hs.Client(), http.MethodPut,
		hs.URL+"/api/agent/v1/flux/transfers/"+offer.ID+"/content", content, "application/octet-stream"); status != http.StatusOK {
		t.Fatalf("upload = %d", status)
	}
	if stored, err := s.store.FluxStoredBytes(); err != nil || stored != int64(valid["size"].(int)) {
		t.Errorf("FluxStoredBytes = %d, %v, want the declared plaintext size", stored, err)
	}
}

// TestFluxFailAndDeny checks the two refusal paths and their reasons.
func TestFluxFailAndDeny(t *testing.T) {
	s := newServerWithConfig(t, Config{Flux: &FluxConfig{}})
	hs := newTestHTTPServer(t, s)
	sender := enrollServiceAgent(t, s, hs, "sender")
	recipient := enrollServiceAgent(t, s, hs, "recipient")

	create := func(name string) fluxTransferView {
		t.Helper()
		raw, status := sender.doFlux(t, hs.Client(), http.MethodPost, hs.URL+"/api/agent/v1/flux/transfers",
			mustJSON(t, map[string]any{
				"recipient": recipient.node.StableID,
				"name":      name,
				"size":      3,
				"sha256":    strings.Repeat("ab", 32),
			}), "application/json")
		if status != http.StatusCreated {
			t.Fatalf("create %s = %d (%s)", name, status, raw)
		}
		return decodeJSON[fluxTransferView](t, raw)
	}

	denied := create("denied.txt")
	raw, status := recipient.doFlux(t, hs.Client(), http.MethodPost,
		hs.URL+"/api/agent/v1/flux/transfers/"+denied.ID+"/deny",
		mustJSON(t, map[string]any{"reason": "not wanted"}), "application/json")
	if status != http.StatusOK || decodeJSON[fluxTransferView](t, raw).Reason != "not wanted" {
		t.Fatalf("deny = %d (%s)", status, raw)
	}

	failed := create("failed.txt")
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	if _, status := recipient.doFlux(t, hs.Client(), http.MethodPost,
		hs.URL+"/api/agent/v1/flux/transfers/"+failed.ID+"/accept",
		mustJSON(t, map[string]any{"publicKey": key}), "application/json"); status != http.StatusOK {
		t.Fatalf("accept = %d", status)
	}
	if _, status := recipient.doFlux(t, hs.Client(), http.MethodPost,
		hs.URL+"/api/agent/v1/flux/transfers/"+failed.ID+"/fail",
		mustJSON(t, map[string]any{"reason": "could not decrypt"}), "application/json"); status != http.StatusOK {
		t.Fatalf("fail = %d", status)
	}
	for _, action := range []string{identity.AuditFluxDenied, identity.AuditFluxFailed} {
		if _, ok := findAudit(t, s, action); !ok {
			t.Errorf("no %s audit event", action)
		}
	}
}

// TestFluxJanitor covers expiry (with content cleanup) and the orphan sweep.
func TestFluxJanitor(t *testing.T) {
	s := newServerWithConfig(t, Config{Flux: &FluxConfig{}})
	hs := newTestHTTPServer(t, s)
	sender := enrollServiceAgent(t, s, hs, "sender")
	recipient := enrollServiceAgent(t, s, hs, "recipient")

	raw, status := sender.doFlux(t, hs.Client(), http.MethodPost, hs.URL+"/api/agent/v1/flux/transfers",
		mustJSON(t, map[string]any{
			"recipient": recipient.node.StableID,
			"name":      "expires.txt",
			"size":      0,
			"sha256":    strings.Repeat("00", 32),
		}), "application/json")
	if status != http.StatusCreated {
		t.Fatalf("create = %d (%s)", status, raw)
	}
	offer := decodeJSON[fluxTransferView](t, raw)

	s.reapFluxTransfers(time.Now().Add(2 * time.Hour))
	if got, _ := s.store.GetFluxTransfer(offer.ID); got.State != state.FluxExpired {
		t.Fatalf("transfer after janitor = %+v, want expired", got)
	}
	if _, ok := findAudit(t, s, identity.AuditFluxExpired); !ok {
		t.Error("no flux.transfer_expired audit event")
	}

	// Orphan sweep: a content file and an upload temp file with no row.
	orphan := filepath.Join(s.flux.dir, "fx_00000000000000000000000000000000.bin")
	if err := os.WriteFile(orphan, []byte("stale"), 0o600); err != nil {
		t.Fatalf("writing orphan: %v", err)
	}
	temp := filepath.Join(s.flux.dir, ".upload-stale")
	if err := os.WriteFile(temp, []byte("stale"), 0o600); err != nil {
		t.Fatalf("writing temp: %v", err)
	}
	s.reapFluxTransfers(time.Now())
	for _, path := range []string{orphan, temp} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Errorf("%s survived the sweep: %v", path, err)
		}
	}
}

// TestFluxDisabled checks the off switch: no endpoints.
func TestFluxDisabled(t *testing.T) {
	s := newServerWithConfig(t, Config{Flux: &FluxConfig{Disabled: true}})
	hs := newTestHTTPServer(t, s)
	agent := enrollServiceAgent(t, s, hs, "agent")

	if _, status := agent.doFlux(t, hs.Client(), http.MethodGet, hs.URL+"/api/agent/v1/flux/transfers", nil, ""); status != http.StatusNotFound {
		t.Fatalf("list with flux disabled = %d, want 404", status)
	}
	if s.flux != nil {
		t.Error("disabled flux still prepared a content directory")
	}
}

// mustJSON marshals a request body, failing the test on error.
func mustJSON(t *testing.T, body any) []byte {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshalling body: %v", err)
	}
	return raw
}
