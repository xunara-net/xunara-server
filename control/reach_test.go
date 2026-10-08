package control

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/xunara-net/xunara-server/identity"
	"github.com/xunara-net/xunara-server/state"
)

// doReach performs an authenticated agent request against the reach API. GET
// requests carry the keys in headers; POST bodies repeat them, as every JSON
// agent endpoint requires.
func (a enrolledServiceAgent) doReach(t *testing.T, client *http.Client, method, rawURL string, body any) ([]byte, int) {
	t.Helper()

	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshalling %s %s: %v", method, rawURL, err)
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, rawURL, reader)
	if err != nil {
		t.Fatalf("building %s %s: %v", method, rawURL, err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+a.token)
	req.Header.Set("X-Xunara-Machine-Key", a.machineKey.Public().String())
	req.Header.Set("X-Xunara-Node-Key", a.nodeKey.Public().String())

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, rawURL, err)
	}
	defer resp.Body.Close()
	out, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading %s %s: %v", method, rawURL, err)
	}
	return out, resp.StatusCode
}

// reachBody builds a session-creation body with the agent keys included.
func (a enrolledServiceAgent) reachBody(extra map[string]any) map[string]any {
	body := map[string]any{
		"machine_key": a.machineKey.Public().String(),
		"node_key":    a.nodeKey.Public().String(),
	}
	for k, v := range extra {
		body[k] = v
	}
	return body
}

// brief shortens a response body for test failure messages.
func brief(raw []byte) string {
	if len(raw) <= 300 {
		return string(raw)
	}
	return string(raw[:300]) + "..."
}

// decodeReachSession decodes one session view.
func decodeReachSession(t *testing.T, raw []byte) reachSessionView {
	t.Helper()
	var resp reachDecisionResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		t.Fatalf("decoding a reach session: %v (%s)", err, raw)
	}
	return resp.Session
}

// decodeReachChunks decodes a chunk read.
func decodeReachChunks(t *testing.T, raw []byte) reachChunksResponse {
	t.Helper()
	var resp reachChunksResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		t.Fatalf("decoding reach chunks: %v (%s)", err, raw)
	}
	return resp
}

// startReach returns a reach-enabled test server plus three enrolled agents.
func startReach(t *testing.T) (*Server, *httptest.Server, enrolledServiceAgent, enrolledServiceAgent, enrolledServiceAgent) {
	t.Helper()
	s := newServerWithConfig(t, Config{ReachEnabled: true})
	hs := newTestHTTPServer(t, s)
	sender := enrollServiceAgent(t, s, hs, "reach-sender")
	target := enrollServiceAgent(t, s, hs, "reach-target")
	bystander := enrollServiceAgent(t, s, hs, "reach-bystander")
	return s, hs, sender, target, bystander
}

// offerReach creates a session from sender to target and returns its view.
func offerReach(t *testing.T, hs *httptest.Server, sender, target enrolledServiceAgent, argv []string) reachSessionView {
	t.Helper()
	raw, status := sender.doReach(t, hs.Client(), http.MethodPost, hs.URL+"/api/agent/v1/reach/sessions",
		sender.reachBody(map[string]any{"to": target.node.StableID, "argv": argv}))
	if status != http.StatusCreated {
		t.Fatalf("create reach session = %d (%s)", status, brief(raw))
	}
	return decodeReachSession(t, raw)
}

// reachPath builds a session endpoint URL.
func reachURL(hs *httptest.Server, id string, parts ...string) string {
	path := "/api/agent/v1/reach/sessions/" + id
	for _, part := range parts {
		path += "/" + part
	}
	return hs.URL + path
}

// TestReachEndToEnd walks a session through the whole state machine - offer,
// approval, start, output relay, finish - and checks that each participant can
// only do its own part.
func TestReachEndToEnd(t *testing.T) {
	s, hs, sender, target, bystander := startReach(t)

	// The marker argument makes a substring hit in the audit trail
	// unambiguous: a two-letter command like "df" can appear by chance inside
	// a random hex session ID, which would be a false leak report.
	session := offerReach(t, hs, sender, target, []string{"uname", "-a", "xunara-leak-probe"})
	if session.State != string(state.ReachOffered) {
		t.Fatalf("new session state = %q, want offered", session.State)
	}
	if session.Sender.StableID != sender.node.StableID || session.Target.StableID != target.node.StableID {
		t.Fatalf("session participants = %+v / %+v", session.Sender, session.Target)
	}
	if len(session.Argv) != 3 || session.Argv[0] != "uname" {
		t.Errorf("session argv = %q", session.Argv)
	}
	if session.TimeoutSec != 60 {
		t.Errorf("default timeout = %d, want 60", session.TimeoutSec)
	}

	// Only the two participants can see the session; a bystander gets the
	// same 404 as for an unknown ID.
	if _, status := bystander.doReach(t, hs.Client(), http.MethodGet, reachURL(hs, session.ID), nil); status != http.StatusNotFound {
		t.Errorf("bystander get = %d, want 404", status)
	}
	if _, status := sender.doReach(t, hs.Client(), http.MethodGet, reachURL(hs, session.ID), nil); status != http.StatusOK {
		t.Errorf("sender get = %d, want 200", status)
	}

	// The sender may not decide; the target may not start before accepting.
	if _, status := sender.doReach(t, hs.Client(), http.MethodPost, reachURL(hs, session.ID, "accept"), nil); status != http.StatusForbidden {
		t.Errorf("sender accept = %d, want 403", status)
	}
	if _, status := target.doReach(t, hs.Client(), http.MethodPost, reachURL(hs, session.ID, "start"), nil); status != http.StatusConflict {
		t.Errorf("start before accept = %d, want 409", status)
	}
	if _, status := sender.doReach(t, hs.Client(), http.MethodPost, reachURL(hs, session.ID, "chunks"),
		map[string]any{"stream": "stdout", "seq": 0, "data": []byte("x")}); status != http.StatusForbidden {
		t.Errorf("sender chunk = %d, want 403", status)
	}

	raw, status := target.doReach(t, hs.Client(), http.MethodPost, reachURL(hs, session.ID, "accept"), nil)
	if status != http.StatusOK {
		t.Fatalf("target accept = %d (%s)", status, brief(raw))
	}
	if session = decodeReachSession(t, raw); session.State != string(state.ReachAccepted) {
		t.Fatalf("accepted state = %q", session.State)
	}
	// A second decision on the same offer conflicts.
	if _, status := target.doReach(t, hs.Client(), http.MethodPost, reachURL(hs, session.ID, "accept"), nil); status != http.StatusConflict {
		t.Errorf("second accept = %d, want 409", status)
	}

	// Output can only be stored while running.
	if _, status := target.doReach(t, hs.Client(), http.MethodPost, reachURL(hs, session.ID, "chunks"),
		map[string]any{"stream": "stdout", "seq": 0, "data": []byte("early")}); status != http.StatusConflict {
		t.Errorf("chunk before start = %d, want 409", status)
	}

	raw, status = target.doReach(t, hs.Client(), http.MethodPost, reachURL(hs, session.ID, "start"), nil)
	if status != http.StatusOK {
		t.Fatalf("target start = %d (%s)", status, brief(raw))
	}
	if session = decodeReachSession(t, raw); session.State != string(state.ReachRunning) {
		t.Fatalf("running state = %q", session.State)
	}
	if want := time.Now().Add(time.Duration(session.TimeoutSec)*time.Second + state.ReachFinishGrace); session.ExpiresAt.After(want.Add(5 * time.Second)) {
		t.Errorf("expires_at = %s, want about %s", session.ExpiresAt, want)
	}

	// stdout: two chunks, stderr: one; sequences are per stream.
	for _, chunk := range []struct {
		stream string
		seq    int64
		data   string
	}{
		{"stdout", 0, "Filesystem "},
		{"stdout", 1, "/dev/sda1\n"},
		{"stderr", 0, "warning: ignoring\n"},
	} {
		if _, status := target.doReach(t, hs.Client(), http.MethodPost, reachURL(hs, session.ID, "chunks"),
			map[string]any{"stream": chunk.stream, "seq": chunk.seq, "data": []byte(chunk.data)}); status != http.StatusNoContent {
			t.Errorf("chunk %s/%d = %d, want 204", chunk.stream, chunk.seq, status)
		}
	}
	// A retried sequence is refused instead of duplicating output.
	if _, status := target.doReach(t, hs.Client(), http.MethodPost, reachURL(hs, session.ID, "chunks"),
		map[string]any{"stream": "stdout", "seq": 0, "data": []byte("again")}); status != http.StatusConflict {
		t.Errorf("duplicate chunk = %d, want 409", status)
	}

	// Both sides read the output; the cursors advance per stream.
	raw, status = sender.doReach(t, hs.Client(), http.MethodGet, reachURL(hs, session.ID, "chunks"), nil)
	if status != http.StatusOK {
		t.Fatalf("sender read chunks = %d (%s)", status, brief(raw))
	}
	chunks := decodeReachChunks(t, raw)
	if len(chunks.Out) != 2 || len(chunks.Err) != 1 {
		t.Fatalf("chunks = %d stdout, %d stderr", len(chunks.Out), len(chunks.Err))
	}
	if string(chunks.Out[0].Data) != "Filesystem " || string(chunks.Out[1].Data) != "/dev/sda1\n" {
		t.Errorf("stdout = %+v", chunks.Out)
	}
	if chunks.NextOut != 1 || chunks.NextErr != 0 {
		t.Errorf("cursors = %d/%d, want 1/0", chunks.NextOut, chunks.NextErr)
	}
	raw, status = sender.doReach(t, hs.Client(), http.MethodGet,
		reachURL(hs, session.ID, "chunks")+"?out=1&err=0", nil)
	if status != http.StatusOK {
		t.Fatalf("cursor read = %d (%s)", status, brief(raw))
	}
	if rest := decodeReachChunks(t, raw); len(rest.Out) != 0 || len(rest.Err) != 0 {
		t.Errorf("read after cursor = %+v", rest)
	}

	// Only the target finishes; a zero exit is success.
	if _, status := sender.doReach(t, hs.Client(), http.MethodPost, reachURL(hs, session.ID, "finish"),
		map[string]any{"exitCode": 0}); status != http.StatusForbidden {
		t.Errorf("sender finish = %d, want 403", status)
	}
	raw, status = target.doReach(t, hs.Client(), http.MethodPost, reachURL(hs, session.ID, "finish"),
		map[string]any{"exitCode": 0})
	if status != http.StatusOK {
		t.Fatalf("finish = %d (%s)", status, brief(raw))
	}
	if session = decodeReachSession(t, raw); session.State != string(state.ReachSucceeded) {
		t.Fatalf("finished state = %q", session.State)
	}
	if session.ExitCode == nil || *session.ExitCode != 0 {
		t.Errorf("exit code = %v, want 0", session.ExitCode)
	}
	if _, status := target.doReach(t, hs.Client(), http.MethodPost, reachURL(hs, session.ID, "finish"),
		map[string]any{"exitCode": 0}); status != http.StatusConflict {
		t.Errorf("second finish = %d, want 409", status)
	}
	if _, status := sender.doReach(t, hs.Client(), http.MethodPost, reachURL(hs, session.ID, "cancel"), nil); status != http.StatusConflict {
		t.Errorf("cancel after finish = %d, want 409", status)
	}

	// Both participants see the session in their list; the bystander sees
	// nothing.
	raw, _ = sender.doReach(t, hs.Client(), http.MethodGet, hs.URL+"/api/agent/v1/reach/sessions", nil)
	var list struct {
		Sessions []reachSessionView `json:"sessions"`
	}
	if err := json.Unmarshal(raw, &list); err != nil {
		t.Fatalf("decoding the list: %v", err)
	}
	if len(list.Sessions) != 1 || list.Sessions[0].ID != session.ID {
		t.Errorf("sender list = %+v", list.Sessions)
	}
	raw, _ = bystander.doReach(t, hs.Client(), http.MethodGet, hs.URL+"/api/agent/v1/reach/sessions", nil)
	if err := json.Unmarshal(raw, &list); err != nil {
		t.Fatalf("decoding the bystander list: %v", err)
	}
	if len(list.Sessions) != 0 {
		t.Errorf("bystander list = %+v", list.Sessions)
	}

	// The audit trail records the lifecycle, and never the command itself.
	offered, ok := findAudit(t, s, identity.AuditReachOffered)
	if !ok {
		t.Fatal("no reach.offered audit event")
	}
	if offered.Target != nodeTarget(target.node) || offered.Actor != nodeActor(sender.node) {
		t.Errorf("reach.offered actor/target = %s/%s", offered.Actor, offered.Target)
	}
	if !strings.Contains(offered.Detail, session.ID) {
		t.Errorf("reach.offered detail = %q", offered.Detail)
	}
	for _, action := range []string{identity.AuditReachAccepted, identity.AuditReachStarted, identity.AuditReachFinished} {
		if _, ok := findAudit(t, s, action); !ok {
			t.Errorf("no %s audit event", action)
		}
	}
	for _, event := range auditEvents(t, s) {
		haystack := event.Action + " " + event.Actor + " " + event.Target + " " + event.Detail
		if strings.Contains(haystack, "uname") || strings.Contains(haystack, "xunara-leak-probe") {
			t.Errorf("%s audit event leaks the command: %q", event.Action, haystack)
		}
	}
}

// TestReachDenyCancelAndFailure covers the paths that end a session without a
// successful command.
func TestReachDenyCancelAndFailure(t *testing.T) {
	s, hs, sender, target, _ := startReach(t)

	// Deny: the offer never runs.
	denied := offerReach(t, hs, sender, target, []string{"rm", "-rf", "/tmp/x"})
	raw, status := target.doReach(t, hs.Client(), http.MethodPost, reachURL(hs, denied.ID, "deny"), nil)
	if status != http.StatusOK {
		t.Fatalf("deny = %d (%s)", status, brief(raw))
	}
	if session := decodeReachSession(t, raw); session.State != string(state.ReachDenied) {
		t.Fatalf("denied state = %q", session.State)
	}
	if _, status := target.doReach(t, hs.Client(), http.MethodPost, reachURL(hs, denied.ID, "accept"), nil); status != http.StatusConflict {
		t.Errorf("accept after deny = %d, want 409", status)
	}

	// Cancel: either side may end a session that is still active.
	canceled := offerReach(t, hs, sender, target, []string{"uptime"})
	raw, status = sender.doReach(t, hs.Client(), http.MethodPost, reachURL(hs, canceled.ID, "cancel"), nil)
	if status != http.StatusOK {
		t.Fatalf("sender cancel = %d (%s)", status, brief(raw))
	}
	if session := decodeReachSession(t, raw); session.State != string(state.ReachCanceled) {
		t.Fatalf("canceled state = %q", session.State)
	}
	if _, status := target.doReach(t, hs.Client(), http.MethodPost, reachURL(hs, canceled.ID, "chunks"),
		map[string]any{"stream": "stdout", "seq": 0, "data": []byte("late")}); status != http.StatusConflict {
		t.Errorf("chunk after cancel = %d, want 409", status)
	}

	// Failure: a non-zero exit carries the code and the static error.
	failed := offerReach(t, hs, sender, target, []string{"false"})
	target.doReach(t, hs.Client(), http.MethodPost, reachURL(hs, failed.ID, "accept"), nil)
	target.doReach(t, hs.Client(), http.MethodPost, reachURL(hs, failed.ID, "start"), nil)
	raw, status = target.doReach(t, hs.Client(), http.MethodPost, reachURL(hs, failed.ID, "finish"),
		map[string]any{"exitCode": 3, "error": "command failed"})
	if status != http.StatusOK {
		t.Fatalf("finish failure = %d (%s)", status, brief(raw))
	}
	session := decodeReachSession(t, raw)
	if session.State != string(state.ReachFailed) {
		t.Fatalf("failed state = %q", session.State)
	}
	if session.ExitCode == nil || *session.ExitCode != 3 || session.Error != "command failed" {
		t.Errorf("failure = %v %q", session.ExitCode, session.Error)
	}

	event, ok := findAudit(t, s, identity.AuditReachFailed)
	if !ok {
		t.Fatal("no reach.failed audit event")
	}
	if !strings.Contains(event.Detail, "exit=3") || strings.Contains(event.Detail, "command failed") {
		t.Errorf("reach.failed detail = %q", event.Detail)
	}
	for _, action := range []string{identity.AuditReachDenied, identity.AuditReachCanceled} {
		if _, ok := findAudit(t, s, action); !ok {
			t.Errorf("no %s audit event", action)
		}
	}
}

// TestReachValidation checks the fail-closed limits at the API edge.
func TestReachValidation(t *testing.T) {
	_, hs, sender, target, _ := startReach(t)
	create := hs.URL + "/api/agent/v1/reach/sessions"

	tooMany := make([]string, state.ReachMaxArgvEntries+1)
	for i := range tooMany {
		tooMany[i] = "x"
	}
	longArg := strings.Repeat("a", state.ReachMaxArgBytes+1)
	total := make([]string, 5)
	for i := range total {
		total[i] = strings.Repeat("b", state.ReachMaxArgBytes)
	}

	cases := []struct {
		name string
		body map[string]any
		want int
	}{
		{"no argv", sender.reachBody(map[string]any{"to": target.node.StableID}), http.StatusBadRequest},
		{"empty entry", sender.reachBody(map[string]any{"to": target.node.StableID, "argv": []string{"echo", ""}}), http.StatusBadRequest},
		{"too many entries", sender.reachBody(map[string]any{"to": target.node.StableID, "argv": tooMany}), http.StatusBadRequest},
		{"long entry", sender.reachBody(map[string]any{"to": target.node.StableID, "argv": []string{"echo", longArg}}), http.StatusBadRequest},
		{"long total", sender.reachBody(map[string]any{"to": target.node.StableID, "argv": total}), http.StatusBadRequest},
		{"negative timeout", sender.reachBody(map[string]any{"to": target.node.StableID, "argv": []string{"true"}, "timeoutSec": -1}), http.StatusBadRequest},
		{"long timeout", sender.reachBody(map[string]any{"to": target.node.StableID, "argv": []string{"true"}, "timeoutSec": 901}), http.StatusBadRequest},
		{"unknown target", sender.reachBody(map[string]any{"to": "n0000000000000000", "argv": []string{"true"}}), http.StatusNotFound},
		{"self target", sender.reachBody(map[string]any{"to": sender.node.StableID, "argv": []string{"true"}}), http.StatusNotFound},
	}
	for _, tc := range cases {
		raw, status := sender.doReach(t, hs.Client(), http.MethodPost, create, tc.body)
		if status != tc.want {
			t.Errorf("%s = %d (%s), want %d", tc.name, status, brief(raw), tc.want)
		}
	}

	// A request without any credential is refused before anything else.
	req, err := http.NewRequest(http.MethodPost, create, bytes.NewReader([]byte(`{}`)))
	if err != nil {
		t.Fatalf("building an anonymous request: %v", err)
	}
	resp, err := hs.Client().Do(req)
	if err != nil {
		t.Fatalf("anonymous create: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("anonymous create = %d, want 401", resp.StatusCode)
	}
}

// TestReachChunkLimits checks the per-chunk and total output limits.
func TestReachChunkLimits(t *testing.T) {
	_, hs, sender, target, _ := startReach(t)

	session := offerReach(t, hs, sender, target, []string{"yes"})
	target.doReach(t, hs.Client(), http.MethodPost, reachURL(hs, session.ID, "accept"), nil)
	if _, status := target.doReach(t, hs.Client(), http.MethodPost, reachURL(hs, session.ID, "start"), nil); status != http.StatusOK {
		t.Fatal("start failed")
	}
	chunks := reachURL(hs, session.ID, "chunks")

	bad := []struct {
		name string
		body map[string]any
		want int
	}{
		{"unknown stream", map[string]any{"stream": "stdin", "seq": 0, "data": []byte("x")}, http.StatusBadRequest},
		{"negative seq", map[string]any{"stream": "stdout", "seq": -1, "data": []byte("x")}, http.StatusBadRequest},
		{"empty data", map[string]any{"stream": "stdout", "seq": 0, "data": []byte{}}, http.StatusBadRequest},
		{"oversized chunk", map[string]any{"stream": "stdout", "seq": 0, "data": bytes.Repeat([]byte("x"), state.ReachMaxChunkBytes+1)}, http.StatusRequestEntityTooLarge},
	}
	for _, tc := range bad {
		if _, status := target.doReach(t, hs.Client(), http.MethodPost, chunks, tc.body); status != tc.want {
			t.Errorf("%s = %d, want %d", tc.name, status, tc.want)
		}
	}

	// Fill the session until the control plane refuses more: truncation is
	// explicit, and the limit is the documented one.
	payload := bytes.Repeat([]byte("x"), state.ReachMaxChunkBytes)
	var seq int64
	for {
		_, status := target.doReach(t, hs.Client(), http.MethodPost, chunks,
			map[string]any{"stream": "stdout", "seq": seq, "data": payload})
		if status == http.StatusRequestEntityTooLarge {
			break
		}
		if status != http.StatusNoContent {
			t.Fatalf("chunk %d = %d", seq, status)
		}
		seq++
		if seq > state.ReachMaxOutputBytes/state.ReachMaxChunkBytes+2 {
			t.Fatal("the output limit was never reached")
		}
	}
	if stored, next := seq*state.ReachMaxChunkBytes, (seq+1)*state.ReachMaxChunkBytes; next <= state.ReachMaxOutputBytes {
		t.Errorf("refused after %d bytes; %d more would still fit in %d", stored, state.ReachMaxChunkBytes, state.ReachMaxOutputBytes)
	}
}

// TestReachRateLimit checks that session creation is limited per node.
func TestReachRateLimit(t *testing.T) {
	_, hs, sender, target, _ := startReach(t)
	create := hs.URL + "/api/agent/v1/reach/sessions"

	for i := 0; i < 12; i++ {
		raw, status := sender.doReach(t, hs.Client(), http.MethodPost, create,
			sender.reachBody(map[string]any{"to": target.node.StableID, "argv": []string{"true"}}))
		if status == http.StatusCreated {
			continue
		}
		if status != http.StatusTooManyRequests {
			t.Fatalf("create %d = %d (%s)", i+1, status, raw)
		}
		// A rejected attempt is not audited; the loop above can only reach 429
		// after the pair quota (8) as well, so accept either message.
		return
	}
	t.Fatal("the rate limit never triggered")
}

// TestReachExpiryAndRetention covers the janitor: overdue sessions expire and
// terminal ones are deleted after the retention window.
func TestReachExpiryAndRetention(t *testing.T) {
	s, hs, sender, target, _ := startReach(t)

	// An unanswered offer expires after the offer window.
	offer := offerReach(t, hs, sender, target, []string{"sleep", "1"})
	running := offerReach(t, hs, sender, target, []string{"sleep", "1"})
	target.doReach(t, hs.Client(), http.MethodPost, reachURL(hs, running.ID, "accept"), nil)
	target.doReach(t, hs.Client(), http.MethodPost, reachURL(hs, running.ID, "start"), nil)

	s.reapReach(time.Now().Add(state.ReachMaxOfferAge + time.Minute))
	for _, id := range []string{offer.ID, running.ID} {
		session, ok := s.store.GetReachSession(id)
		if !ok {
			t.Fatalf("session %s disappeared", id)
		}
		if session.State != state.ReachExpired {
			t.Errorf("session %s state = %q, want expired", id, session.State)
		}
	}
	event, ok := findAudit(t, s, identity.AuditReachExpired)
	if !ok {
		t.Fatal("no reach.expired audit event")
	}
	if event.Actor != "system" {
		t.Errorf("reach.expired actor = %q, want system", event.Actor)
	}

	// Terminal sessions are deleted once they are old enough.
	s.reapReach(time.Now().Add(2 * time.Hour))
	for _, id := range []string{offer.ID, running.ID} {
		if _, ok := s.store.GetReachSession(id); ok {
			t.Errorf("session %s survived the retention window", id)
		}
	}
}

// TestReachDisabled checks that a deployment without Reach has no endpoints.
func TestReachDisabled(t *testing.T) {
	s := newServerWithConfig(t, Config{})
	hs := newTestHTTPServer(t, s)
	agent := enrollServiceAgent(t, s, hs, "reach-off")

	raw, status := agent.doReach(t, hs.Client(), http.MethodGet, hs.URL+"/api/agent/v1/reach/sessions", nil)
	if status != http.StatusNotFound {
		t.Fatalf("reach list with reach disabled = %d (%s), want 404", status, raw)
	}
}

// TestReachReadCursorValidation checks the cursor parser.
func TestReachReadCursorValidation(t *testing.T) {
	_, hs, sender, target, _ := startReach(t)
	session := offerReach(t, hs, sender, target, []string{"true"})

	for _, query := range []string{"?out=x", "?err=-2"} {
		if _, status := sender.doReach(t, hs.Client(), http.MethodGet, reachURL(hs, session.ID, "chunks")+query, nil); status != http.StatusBadRequest {
			t.Errorf("cursor %q = %d, want 400", query, status)
		}
	}
	// A read of an unknown session is a 404, not a leak.
	if _, status := sender.doReach(t, hs.Client(), http.MethodGet, reachURL(hs, "does-not-exist"), nil); status != http.StatusNotFound {
		t.Errorf("unknown session = %d, want 404", status)
	}
}
