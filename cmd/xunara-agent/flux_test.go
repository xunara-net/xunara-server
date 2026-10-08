package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"tailscale.com/types/key"

	"github.com/xunara-net/xunara-server/client/daemon"
	"github.com/xunara-net/xunara-server/client/protocol"
	"github.com/xunara-net/xunara-server/control"
	"github.com/xunara-net/xunara-server/state"
)

func TestRunFluxDispatch(t *testing.T) {
	if err := runFlux(context.Background(), nil); err == nil {
		t.Error("runFlux with no subcommand succeeded")
	}
	if err := runFlux(context.Background(), []string{"bogus"}); err == nil {
		t.Error("runFlux accepted an unknown subcommand")
	}
}

func TestHumanBytes(t *testing.T) {
	cases := []struct {
		in   int64
		want string
	}{
		{0, "0 B"},
		{999, "999 B"},
		{1024, "1.0 KiB"},
		{8 << 20, "8.0 MiB"},
		{1 << 30, "1.0 GiB"},
	}
	for _, tc := range cases {
		if got := humanBytes(tc.in); got != tc.want {
			t.Errorf("humanBytes(%d) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestSafeFluxFileName(t *testing.T) {
	safe := []string{"notes.txt", "a", "..hidden", "with space.txt"}
	for _, name := range safe {
		if !safeFluxFileName(name) {
			t.Errorf("safeFluxFileName(%q) = false", name)
		}
	}
	unsafe := []string{"", ".", "..", "a/b", `a\b`, "a\x00b", "line\nbreak"}
	for _, name := range unsafe {
		if safeFluxFileName(name) {
			t.Errorf("safeFluxFileName(%q) = true", name)
		}
	}
}

func TestWriteFluxFileDoesNotOverwrite(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "received")

	first, err := writeFluxFile(dir, "notes.txt", []byte("first"))
	if err != nil {
		t.Fatalf("writeFluxFile: %v", err)
	}
	if got := first; got != filepath.Join(dir, "notes.txt") {
		t.Errorf("first path = %q", got)
	}

	second, err := writeFluxFile(dir, "notes.txt", []byte("second"))
	if err != nil {
		t.Fatalf("writeFluxFile again: %v", err)
	}
	if second != filepath.Join(dir, "notes.txt.1") {
		t.Errorf("second path = %q, want notes.txt.1", second)
	}

	info, err := os.Stat(first)
	if err != nil {
		t.Fatalf("stat first: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("received file mode = %04o, want 0600", perm)
	}
	raw, err := os.ReadFile(first)
	if err != nil || string(raw) != "first" {
		t.Fatalf("first file = %q (%v)", raw, err)
	}
	raw, err = os.ReadFile(second)
	if err != nil || string(raw) != "second" {
		t.Fatalf("second file = %q (%v)", raw, err)
	}
}

func TestReadFluxFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "payload.bin")
	payload := bytes.Repeat([]byte{0xab}, 4096)
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatalf("writing payload: %v", err)
	}

	raw, sum, err := readFluxFile(path, int64(len(payload)))
	if err != nil {
		t.Fatalf("readFluxFile: %v", err)
	}
	if !bytes.Equal(raw, payload) {
		t.Error("readFluxFile changed the payload")
	}
	want := sha256.Sum256(payload)
	if sum != hex.EncodeToString(want[:]) {
		t.Errorf("digest = %q", sum)
	}

	// A file that changed since the stat is refused: the declared digest
	// must cover exactly the uploaded bytes.
	if _, _, err := readFluxFile(path, int64(len(payload))+1); err == nil {
		t.Error("readFluxFile accepted a size mismatch")
	}
	if _, _, err := readFluxFile(path, int64(len(payload))-1); err == nil {
		t.Error("readFluxFile accepted a shrunk file")
	}
}

func TestWriteFluxTransfers(t *testing.T) {
	var buf bytes.Buffer
	if err := writeFluxTransfers(&buf, nil); err != nil {
		t.Fatalf("writeFluxTransfers: %v", err)
	}
	if !strings.Contains(buf.String(), "No transfers.") {
		t.Errorf("empty list = %q", buf.String())
	}

	transfers := []protocol.FluxTransfer{
		{
			ID:                "fx_1",
			Direction:         "sent",
			State:             protocol.FluxCompleted,
			Name:              "notes.txt",
			Size:              2048,
			RecipientHostname: "peer",
			UpdatedAt:         time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC),
		},
		{
			ID:             "fx_2",
			Direction:      "received",
			State:          protocol.FluxDenied,
			Name:           "big.iso",
			Size:           3 << 20,
			SenderHostname: "other",
			Reason:         "not wanted",
		},
	}
	buf.Reset()
	if err := writeFluxTransfers(&buf, transfers); err != nil {
		t.Fatalf("writeFluxTransfers: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"ID", "fx_1", "sent", "peer", "notes.txt", "2.0 KiB", "completed", "fx_2", "received", "other", "3.0 MiB", "denied", "not wanted"} {
		if !strings.Contains(out, want) {
			t.Errorf("output is missing %q:\n%s", want, out)
		}
	}
}

func TestConfirmFluxAcceptSkipsPrompt(t *testing.T) {
	transfer := protocol.FluxTransfer{Name: "notes.txt", Size: 10, SenderHostname: "peer"}

	if ok, err := confirmFluxAccept(transfer, true); err != nil || !ok {
		t.Fatalf("confirmFluxAccept(-yes) = %v, %v", ok, err)
	}
}

func TestConfirmFluxAcceptPrompts(t *testing.T) {
	// No answer (stdin at EOF) must be an error, not a silent acceptance:
	// a scripted receive has to pass -yes on purpose.
	stdin := os.Stdin
	t.Cleanup(func() { os.Stdin = stdin })

	path := filepath.Join(t.TempDir(), "answers")
	if err := os.WriteFile(path, []byte("yes\n"), 0o600); err != nil {
		t.Fatalf("writing answers: %v", err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("opening answers: %v", err)
	}
	defer f.Close()
	os.Stdin = f

	out := captureStdout(t, func() error {
		transfer := protocol.FluxTransfer{Name: "notes.txt", Size: 10, SenderHostname: "peer"}
		ok, err := confirmFluxAccept(transfer, false)
		if err != nil || !ok {
			return fmt.Errorf("confirmFluxAccept(yes) = %v, %v", ok, err)
		}
		return nil
	})
	if !strings.Contains(out, "Accept notes.txt") {
		t.Errorf("prompt = %q", out)
	}
	// The file is at EOF now, so the next prompt has no answer.
	captureStdout(t, func() error {
		if _, err := confirmFluxAccept(protocol.FluxTransfer{Name: "notes.txt"}, false); err == nil {
			return errors.New("confirmFluxAccept at EOF succeeded")
		}
		return nil
	})
}

func TestFluxTerminalError(t *testing.T) {
	err := fluxTerminalError(protocol.FluxTransfer{ID: "fx_1", State: protocol.FluxDenied, Reason: "nope"})
	if err == nil || !strings.Contains(err.Error(), "denied") || !strings.Contains(err.Error(), "nope") {
		t.Fatalf("fluxTerminalError = %v", err)
	}
}

func TestLooksLikeFluxStableID(t *testing.T) {
	if !looksLikeStableID("n0123456789abcdef") {
		t.Error("rejected a valid stable ID")
	}
	for _, bad := range []string{"", "n0123", "x0123456789abcdef", "n0123456789abcdeg", "recipient"} {
		if looksLikeStableID(bad) {
			t.Errorf("looksLikeStableID(%q) = true", bad)
		}
	}
}

func TestWaitForFluxTransferNotFound(t *testing.T) {
	hs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"transfers":[]}`))
	}))
	defer hs.Close()

	client := protocol.New(hs.URL)
	keys := newTestKeys(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if _, err := waitForFluxTransfer(ctx, client, "tok", keys, "fx_1", func(protocol.FluxTransfer) bool { return true }); err == nil {
		t.Fatal("waitForFluxTransfer accepted an unknown transfer")
	}
}

func TestWaitForFluxTransferUnauthorized(t *testing.T) {
	hs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		http.Error(w, "gone", http.StatusUnauthorized)
	}))
	defer hs.Close()

	client := protocol.New(hs.URL)
	keys := newTestKeys(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := waitForFluxTransfer(ctx, client, "tok", keys, "fx_1", func(protocol.FluxTransfer) bool { return true })
	if !protocol.IsUnauthorized(err) {
		t.Fatalf("waitForFluxTransfer = %v, want unauthorized", err)
	}
}

func TestFluxSendValidation(t *testing.T) {
	dir := t.TempDir()

	if err := runFluxSend(context.Background(), []string{"-file", "x"}); err == nil {
		t.Error("flux send without -to succeeded")
	}
	if err := runFluxSend(context.Background(), []string{"-to", "peer"}); err == nil {
		t.Error("flux send without -file succeeded")
	}
	if err := runFluxSend(context.Background(), []string{"-to", "peer", "-file", dir}); err == nil {
		t.Error("flux send accepted a directory")
	}
	if err := runFluxSend(context.Background(), []string{"-to", "peer", "-file", filepath.Join(dir, "missing")}); err == nil {
		t.Error("flux send accepted a missing file")
	}

	big := filepath.Join(dir, "big.bin")
	f, err := os.Create(big)
	if err != nil {
		t.Fatalf("creating big file: %v", err)
	}
	if err := f.Truncate(maxFluxFileSize + 1); err != nil {
		t.Fatalf("truncating: %v", err)
	}
	f.Close()
	if err := runFluxSend(context.Background(), []string{"-to", "peer", "-file", big}); err == nil {
		t.Error("flux send accepted a file past the size ceiling")
	}

	small := filepath.Join(dir, "small.txt")
	if err := os.WriteFile(small, []byte("x"), 0o600); err != nil {
		t.Fatalf("writing small file: %v", err)
	}
	if err := runFluxSend(context.Background(), []string{"-to", "peer", "-file", small, "-state-dir", t.TempDir()}); err == nil {
		t.Error("flux send ran with an unenrolled agent")
	}
}

func TestFluxDenyArgumentCheck(t *testing.T) {
	if err := runFluxDeny(context.Background(), nil); err == nil {
		t.Error("flux deny without an ID succeeded")
	}
	if err := runFluxDeny(context.Background(), []string{"fx_1", "fx_2"}); err == nil {
		t.Error("flux deny with two IDs succeeded")
	}
}

func TestFluxReceiveArgumentCheck(t *testing.T) {
	if err := runFluxReceive(context.Background(), nil); err == nil {
		t.Error("flux receive without -dir succeeded")
	}
	if err := runFluxReceive(context.Background(), []string{"-dir", t.TempDir(), "-interval", "1ms"}); err == nil {
		t.Error("flux receive accepted a sub-second interval")
	}
}

// --- End-to-end against a real control plane ---------------------------------

// enrollFluxAgent creates a pre-auth key and enrolls an agent with it.
func enrollFluxAgent(t *testing.T, srv *control.Server, serverURL, hostname string) string {
	t.Helper()

	secret, err := state.NewPreAuthKeySecret()
	if err != nil {
		t.Fatalf("NewPreAuthKeySecret: %v", err)
	}
	if err := srv.Store().CreatePreAuthKey(&state.PreAuthKey{Key: secret, UserID: state.DefaultUserID}); err != nil {
		t.Fatalf("CreatePreAuthKey: %v", err)
	}

	stateDir := t.TempDir()
	if _, err := daemon.Enroll(context.Background(), daemon.EnrollOptions{
		ServerURL: serverURL,
		StateDir:  stateDir,
		AuthKey:   secret,
		Hostname:  hostname,
	}); err != nil {
		t.Fatalf("enrolling %s: %v", hostname, err)
	}
	return stateDir
}

// fluxViewer is one agent's credential for direct API calls in assertions.
func fluxViewer(t *testing.T, serverURL, stateDir string) (*protocol.Client, protocol.Keys, string) {
	t.Helper()
	st, err := daemon.LoadState(stateDir)
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	keys, err := st.Keys()
	if err != nil {
		t.Fatalf("state keys: %v", err)
	}
	return protocol.New(serverURL), keys, st.Token
}

// listFluxTransfers is the agent's current view.
func listFluxTransfers(t *testing.T, client *protocol.Client, token string, keys protocol.Keys) []protocol.FluxTransfer {
	t.Helper()
	transfers, err := client.ListFluxTransfers(context.Background(), token, keys)
	if err != nil {
		t.Fatalf("ListFluxTransfers: %v", err)
	}
	return transfers
}

// waitForPendingTransfer polls until the recipient sees a pending offer.
func waitForPendingTransfer(t *testing.T, client *protocol.Client, token string, keys protocol.Keys) protocol.FluxTransfer {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		for _, transfer := range listFluxTransfers(t, client, token, keys) {
			if transfer.Direction == "received" && transfer.State == protocol.FluxPending {
				return transfer
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("no pending transfer appeared")
	return protocol.FluxTransfer{}
}

// TestFluxSendReceiveEndToEnd drives the CLI against a real control plane:
// send resolves the recipient by hostname, the recipient accepts explicitly
// (-yes), fetches and verifies the content, and both sides end up seeing a
// completed transfer while the control plane only ever held ciphertext.
func TestFluxSendReceiveEndToEnd(t *testing.T) {
	srv, hs := newFluxControlServer(t)
	senderDir := enrollFluxAgent(t, srv, hs.URL, "flux-sender")
	recipientDir := enrollFluxAgent(t, srv, hs.URL, "flux-recipient")

	payload := []byte("xunara flux: end to end\n")
	srcDir := t.TempDir()
	srcPath := filepath.Join(srcDir, "notes.txt")
	if err := os.WriteFile(srcPath, payload, 0o600); err != nil {
		t.Fatalf("writing source file: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	sendDone := make(chan error, 1)
	go func() {
		sendDone <- runFluxSend(ctx, []string{
			"-state-dir", senderDir,
			"-to", "flux-recipient",
			"-file", srcPath,
			"-timeout", "45s",
		})
	}()

	recipientClient, recipientKeys, recipientToken := fluxViewer(t, hs.URL, recipientDir)
	waitForPendingTransfer(t, recipientClient, recipientToken, recipientKeys)

	recvDir := t.TempDir()
	if err := runFluxReceive(ctx, []string{
		"-state-dir", recipientDir,
		"-dir", recvDir,
		"-yes",
	}); err != nil {
		t.Fatalf("runFluxReceive: %v", err)
	}
	if err := <-sendDone; err != nil {
		t.Fatalf("runFluxSend: %v", err)
	}

	received := filepath.Join(recvDir, "notes.txt")
	raw, err := os.ReadFile(received)
	if err != nil {
		t.Fatalf("reading the received file: %v", err)
	}
	if !bytes.Equal(raw, payload) {
		t.Fatalf("received %q, want %q", raw, payload)
	}
	info, err := os.Stat(received)
	if err != nil {
		t.Fatalf("stat received file: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("received file mode = %04o, want 0600", perm)
	}

	// Both sides see a completed transfer; the recipient's record carries the
	// sender's hostname and the digest the sender declared.
	senderClient, senderKeys, senderToken := fluxViewer(t, hs.URL, senderDir)
	sent := listFluxTransfers(t, senderClient, senderToken, senderKeys)
	if len(sent) != 1 || sent[0].State != protocol.FluxCompleted || sent[0].Direction != "sent" {
		t.Fatalf("sender list = %+v", sent)
	}
	wantSum := sha256.Sum256(payload)
	if sent[0].SHA256 != hex.EncodeToString(wantSum[:]) {
		t.Errorf("declared digest = %q", sent[0].SHA256)
	}
	receivedList := listFluxTransfers(t, recipientClient, recipientToken, recipientKeys)
	if len(receivedList) != 1 || receivedList[0].State != protocol.FluxCompleted || receivedList[0].Direction != "received" {
		t.Fatalf("recipient list = %+v", receivedList)
	}
	if receivedList[0].SenderHostname != "flux-sender" {
		t.Errorf("recipient sees sender %q", receivedList[0].SenderHostname)
	}
}

// TestFluxDenyEndToEnd checks the refusal path: the sender sees the denial and
// the reason the recipient attached.
func TestFluxDenyEndToEnd(t *testing.T) {
	srv, hs := newFluxControlServer(t)
	senderDir := enrollFluxAgent(t, srv, hs.URL, "flux-sender")
	recipientDir := enrollFluxAgent(t, srv, hs.URL, "flux-recipient")

	srcPath := filepath.Join(t.TempDir(), "unwanted.txt")
	if err := os.WriteFile(srcPath, []byte("nope"), 0o600); err != nil {
		t.Fatalf("writing source file: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	sendDone := make(chan error, 1)
	go func() {
		sendDone <- runFluxSend(ctx, []string{
			"-state-dir", senderDir,
			"-to", "flux-recipient",
			"-file", srcPath,
			"-timeout", "45s",
		})
	}()

	recipientClient, recipientKeys, recipientToken := fluxViewer(t, hs.URL, recipientDir)
	pending := waitForPendingTransfer(t, recipientClient, recipientToken, recipientKeys)

	if err := runFluxDeny(ctx, []string{
		"-state-dir", recipientDir,
		"-reason", "not wanted today",
		pending.ID,
	}); err != nil {
		t.Fatalf("runFluxDeny: %v", err)
	}

	err := <-sendDone
	if err == nil || !strings.Contains(err.Error(), "denied") || !strings.Contains(err.Error(), "not wanted today") {
		t.Fatalf("runFluxSend = %v, want the denial with its reason", err)
	}
}

// TestFluxReceiveNoAnswer checks that a non-interactive receive refuses to
// accept on its own.
func TestFluxReceiveNoAnswer(t *testing.T) {
	srv, hs := newFluxControlServer(t)
	senderDir := enrollFluxAgent(t, srv, hs.URL, "flux-sender")
	recipientDir := enrollFluxAgent(t, srv, hs.URL, "flux-recipient")

	srcPath := filepath.Join(t.TempDir(), "offer.txt")
	if err := os.WriteFile(srcPath, []byte("hello"), 0o600); err != nil {
		t.Fatalf("writing source file: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	sendDone := make(chan error, 1)
	go func() {
		sendDone <- runFluxSend(ctx, []string{
			"-state-dir", senderDir,
			"-to", "flux-recipient",
			"-file", srcPath,
			"-timeout", "45s",
		})
	}()
	defer cancel()

	recipientClient, recipientKeys, recipientToken := fluxViewer(t, hs.URL, recipientDir)
	waitForPendingTransfer(t, recipientClient, recipientToken, recipientKeys)

	stdin := os.Stdin
	t.Cleanup(func() { os.Stdin = stdin })
	devNull, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatalf("opening %s: %v", os.DevNull, err)
	}
	os.Stdin = devNull
	defer devNull.Close()

	captureStdout(t, func() error {
		if err := runFluxReceive(ctx, []string{"-state-dir", recipientDir, "-dir", t.TempDir()}); err == nil {
			return errors.New("flux receive accepted a transfer without an answer")
		}
		return nil
	})

	// The offer is still pending: no side acted on it.
	for _, transfer := range listFluxTransfers(t, recipientClient, recipientToken, recipientKeys) {
		if transfer.State != protocol.FluxPending {
			t.Fatalf("transfer state = %q, want pending", transfer.State)
		}
	}
	cancel()
	<-sendDone
}

func newFluxControlServer(t *testing.T) (*control.Server, *httptest.Server) {
	t.Helper()

	srv, err := control.New(control.Config{
		StateDir:  t.TempDir(),
		ServerURL: "http://login.test",
		Domain:    "example.com",
		Flux:      &control.FluxConfig{},
	})
	if err != nil {
		t.Fatalf("control.New: %v", err)
	}
	t.Cleanup(func() { srv.Close() })

	hs := httptest.NewServer(srv.Handler())
	t.Cleanup(hs.Close)
	return srv, hs
}

// newTestKeys returns throwaway machine and node keys for protocol calls.
func newTestKeys(t *testing.T) protocol.Keys {
	t.Helper()
	return protocol.Keys{Machine: key.NewMachine(), Node: key.NewNode()}
}
