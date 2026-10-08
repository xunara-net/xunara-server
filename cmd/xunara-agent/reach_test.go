package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/xunara-net/xunara-server/client/daemon"
	"github.com/xunara-net/xunara-server/client/protocol"
	"github.com/xunara-net/xunara-server/control"
)

// newReachControlServer brings up a control plane with Reach enabled.
func newReachControlServer(t *testing.T) (*control.Server, *httptest.Server) {
	t.Helper()

	srv, err := control.New(control.Config{
		StateDir:     t.TempDir(),
		ServerURL:    "http://login.test",
		Domain:       "example.com",
		ReachEnabled: true,
	})
	if err != nil {
		t.Fatalf("control.New: %v", err)
	}
	t.Cleanup(func() { srv.Close() })

	hs := httptest.NewServer(srv.Handler())
	t.Cleanup(hs.Close)
	return srv, hs
}

// startReachTarget runs the target-side execution loop for a state directory.
func startReachTarget(t *testing.T, ctx context.Context, stateDir string) *daemon.Agent {
	t.Helper()

	agentState, err := daemon.LoadState(stateDir)
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	agent, err := daemon.NewAgent(agentState, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("NewAgent: %v", err)
	}
	agent.ReachInterval = 100 * time.Millisecond
	go func() { _ = agent.ServeReach(ctx) }()
	return agent
}

// waitForReachOffer polls the target's session list for a pending offer.
func waitForReachOffer(t *testing.T, client *protocol.Client, token string, keys protocol.Keys) protocol.ReachSession {
	t.Helper()

	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		sessions, err := client.ReachList(context.Background(), token, keys)
		if err != nil {
			t.Fatalf("ReachList: %v", err)
		}
		for _, session := range sessions {
			if session.State == protocol.ReachOffered {
				return session
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("no reach offer appeared")
	return protocol.ReachSession{}
}

// TestReachRunEndToEnd drives `reach run` against a real control plane and a
// real target agent: offer, approval, streamed output, and the remote exit
// status mapped onto the CLI's own.
func TestReachRunEndToEnd(t *testing.T) {
	srv, hs := newReachControlServer(t)
	// enrollFluxAgent is generic: a pre-auth key plus daemon.Enroll.
	senderDir := enrollFluxAgent(t, srv, hs.URL, "reach-sender")
	targetDir := enrollFluxAgent(t, srv, hs.URL, "reach-target")

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	startReachTarget(t, ctx, targetDir)
	targetClient, targetKeys, targetToken := fluxViewer(t, hs.URL, targetDir)

	run := func(argv ...string) error {
		t.Helper()
		done := make(chan error, 1)
		go func() {
			done <- runReachRun(ctx, append([]string{
				"-state-dir", senderDir,
				"-to", "reach-target",
				"-timeout", "30s",
				"--",
			}, argv...))
		}()

		offer := waitForReachOffer(t, targetClient, targetToken, targetKeys)
		if offer.Sender.StableID == "" || offer.Target.StableID != strings.TrimSpace(offer.Target.StableID) {
			t.Fatalf("offer participants = %+v / %+v", offer.Sender, offer.Target)
		}
		if len(offer.Argv) != len(argv) || offer.Argv[0] != argv[0] {
			t.Fatalf("offer argv = %q, want %q", offer.Argv, argv)
		}
		if _, err := targetClient.ReachAccept(ctx, targetToken, targetKeys, offer.ID); err != nil {
			t.Fatalf("ReachAccept: %v", err)
		}
		return <-done
	}

	if err := run("sh", "-c", "printf hello; printf oops 1>&2"); err != nil {
		t.Fatalf("reach run: %v", err)
	}

	// A failing command ends the CLI with the remote status.
	var exitErr *reachExitError
	if err := run("sh", "-c", "exit 7"); !errors.As(err, &exitErr) || exitErr.code != 7 {
		t.Errorf("failing reach run = %v", err)
	}
}

// TestReachRunDenied checks that a refusal on the target ends the waiting
// sender with an error instead of a timeout.
func TestReachRunDenied(t *testing.T) {
	srv, hs := newReachControlServer(t)
	senderDir := enrollFluxAgent(t, srv, hs.URL, "reach-sender")
	targetDir := enrollFluxAgent(t, srv, hs.URL, "reach-target")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	targetClient, targetKeys, targetToken := fluxViewer(t, hs.URL, targetDir)

	done := make(chan error, 1)
	go func() {
		done <- runReachRun(ctx, []string{
			"-state-dir", senderDir,
			"-to", "reach-target",
			"--", "true",
		})
	}()

	offer := waitForReachOffer(t, targetClient, targetToken, targetKeys)
	if _, err := targetClient.ReachDeny(ctx, targetToken, targetKeys, offer.ID); err != nil {
		t.Fatalf("ReachDeny: %v", err)
	}
	err := <-done
	if err == nil || !strings.Contains(err.Error(), "denied") {
		t.Fatalf("reach run after deny = %v", err)
	}
}

func TestRunReachDispatch(t *testing.T) {
	if err := runReach(context.Background(), nil); err == nil {
		t.Error("runReach with no subcommand succeeded")
	}
	if err := runReach(context.Background(), []string{"bogus"}); err == nil {
		t.Error("runReach accepted an unknown subcommand")
	}
}

func TestReachArgvValidation(t *testing.T) {
	valid := [][]string{{"true"}, {"sh", "-c", "echo hi"}}
	for _, argv := range valid {
		if err := validateReachArgv(argv); err != nil {
			t.Errorf("validateReachArgv(%q) = %v", argv, err)
		}
	}

	tooMany := make([]string, protocol.ReachMaxArgvEntries+1)
	for i := range tooMany {
		tooMany[i] = "x"
	}
	long := make([]string, 5)
	for i := range long {
		long[i] = strings.Repeat("a", protocol.ReachMaxArgBytes)
	}
	invalid := [][]string{
		{""},
		{"echo", ""},
		tooMany,
		{"echo", strings.Repeat("a", protocol.ReachMaxArgBytes+1)},
		long,
	}
	for _, argv := range invalid {
		if err := validateReachArgv(argv); err == nil {
			t.Errorf("validateReachArgv(%q) succeeded", argv)
		}
	}
}

func TestReachCommandParsing(t *testing.T) {
	// The remote command is taken verbatim after "--": even a flag-like
	// argument belongs to the remote command.
	cmd, err := parseReachCommand("reach run", []string{"-to", "peer", "-timeout", "30s", "--", "-l", "a"})
	if err != nil {
		t.Fatalf("parseReachCommand: %v", err)
	}
	if cmd.to != "peer" || cmd.timeout != 30*time.Second {
		t.Errorf("flags = %q %s", cmd.to, cmd.timeout)
	}
	if len(cmd.argv) != 2 || cmd.argv[0] != "-l" {
		t.Errorf("argv = %q", cmd.argv)
	}

	bad := [][]string{
		{"-to", "peer"}, // no command
		{"--", "true"},  // no target
		{"-to", "peer", "-timeout", "0s", "--", "true"},
		{"-to", "peer", "-timeout", "16m", "--", "true"},
	}
	for _, args := range bad {
		if _, err := parseReachCommand("reach run", args); err == nil {
			t.Errorf("parseReachCommand(%q) succeeded", args)
		}
	}
	if _, err := parseReachCommand("reach run", []string{"-to", "peer", "--", "true"}); err != nil {
		t.Errorf("plain command = %v", err)
	}
}

func TestReachExitCode(t *testing.T) {
	cases := map[int]int{1: 1, 7: 7, 125: 125, 126: 1, 137: 1, 0: 1, -1: 1}
	for in, want := range cases {
		if got := reachExitCode(in); got != want {
			t.Errorf("reachExitCode(%d) = %d, want %d", in, got, want)
		}
	}
}

func TestWriteReachSessions(t *testing.T) {
	exit := 0
	sessions := []protocol.ReachSession{
		{
			ID:        "aaa",
			State:     protocol.ReachSucceeded,
			Target:    protocol.ReachPeer{StableID: "n2222222222222222", Hostname: "peer"},
			Argv:      []string{"df", "-h"},
			UpdatedAt: time.Unix(1700000000, 0),
			ExitCode:  &exit,
		},
		{
			ID:     "bbb",
			State:  protocol.ReachOffered,
			Sender: protocol.ReachPeer{StableID: "n4444444444444444", Hostname: "other"},
			Target: protocol.ReachPeer{StableID: "n3333333333333333"},
			Argv:   []string{"sh", "-c", strings.Repeat("x", 200)},
		},
	}
	var buf bytes.Buffer
	if err := writeReachSessions(&buf, sessions, "n3333333333333333"); err != nil {
		t.Fatalf("writeReachSessions: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"aaa", "sent", "succeeded", "df -h", "bbb", "received", "offered"} {
		if !strings.Contains(out, want) {
			t.Errorf("table is missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, strings.Repeat("x", 100)) {
		t.Errorf("long command was not truncated:\n%s", out)
	}
	if got := truncateReachCommand("short"); got != "short" {
		t.Errorf("truncateReachCommand(short) = %q", got)
	}
}

// TestReachServeArguments checks the serve flag validation.
func TestReachServeArguments(t *testing.T) {
	if err := runReachServe(context.Background(), []string{"-state-dir", t.TempDir(), "-interval", "100ms"}); err == nil {
		t.Error("reach serve accepted an interval below 1s")
	}
	if err := runReachServe(context.Background(), []string{"-state-dir", t.TempDir()}); err == nil {
		t.Error("reach serve accepted a state directory that is not enrolled")
	}
}

// TestReachDecisionArguments checks that the ID is required before any network
// call happens.
func TestReachDecisionArguments(t *testing.T) {
	for _, action := range []string{"accept", "deny", "cancel"} {
		if err := runReachDecision(context.Background(), []string{"-state-dir", t.TempDir()}, action); err == nil {
			t.Errorf("reach %s without an ID succeeded", action)
		}
	}
	if err := runReachShow(context.Background(), []string{"-state-dir", t.TempDir()}); err == nil {
		t.Error("reach show without an ID succeeded")
	}
}

// TestReachResultError checks the mapping from session states onto errors.
func TestReachResultError(t *testing.T) {
	code := 3
	if err := reachResultError(protocol.ReachSession{ID: "x", State: protocol.ReachSucceeded}); err != nil {
		t.Errorf("succeeded = %v", err)
	}
	err := reachResultError(protocol.ReachSession{ID: "x", State: protocol.ReachFailed, ExitCode: &code})
	var exitErr *reachExitError
	if !errors.As(err, &exitErr) || exitErr.code != 3 {
		t.Errorf("failed = %v", err)
	}
	for _, state := range []string{protocol.ReachDenied, protocol.ReachCanceled, protocol.ReachExpired} {
		err := reachResultError(protocol.ReachSession{ID: "x", State: state})
		if err == nil || !strings.Contains(err.Error(), state) {
			t.Errorf("%s = %v", state, err)
		}
	}
}
