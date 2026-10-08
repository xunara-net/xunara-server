package daemon

import (
	"context"
	"io"
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/xunara-net/xunara-server/client/protocol"
	"github.com/xunara-net/xunara-server/control"
	"github.com/xunara-net/xunara-server/state"
)

// startReachControl brings up a reach-enabled control plane.
func startReachControl(t *testing.T) (*control.Server, *httptest.Server) {
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

// enrollReachAgent enrolls one agent against the control plane.
func enrollReachAgent(t *testing.T, srv *control.Server, serverURL, hostname string) State {
	t.Helper()

	secret, err := state.NewPreAuthKeySecret()
	if err != nil {
		t.Fatalf("NewPreAuthKeySecret: %v", err)
	}
	if err := srv.Store().CreatePreAuthKey(&state.PreAuthKey{Key: secret, UserID: state.DefaultUserID}); err != nil {
		t.Fatalf("CreatePreAuthKey: %v", err)
	}
	agentState, err := Enroll(context.Background(), EnrollOptions{
		ServerURL: serverURL,
		StateDir:  t.TempDir(),
		AuthKey:   secret,
		Hostname:  hostname,
		Logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("enrolling %s: %v", hostname, err)
	}
	return agentState
}

// reachTestAgent builds a target-side agent with a fast poll interval and
// starts its execution loop.
func reachTestAgent(t *testing.T, target State, serverURL string) (*Agent, protocol.Keys) {
	t.Helper()

	keys, err := target.Keys()
	if err != nil {
		t.Fatalf("target keys: %v", err)
	}
	agent, err := NewAgent(target, protocol.New(serverURL), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("NewAgent: %v", err)
	}
	agent.ReachInterval = 100 * time.Millisecond
	return agent, keys
}

// waitReachSession polls until the session satisfies done.
func waitReachSession(t *testing.T, client *protocol.Client, token string, keys protocol.Keys, id string, done func(protocol.ReachSession) bool) protocol.ReachSession {
	t.Helper()

	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		session, err := client.ReachGet(context.Background(), token, keys, id)
		if err != nil {
			t.Fatalf("ReachGet: %v", err)
		}
		if done(session) {
			return session
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("session %s never reached the expected state", id)
	return protocol.ReachSession{}
}

// reachOutput joins the chunks of one stream.
func reachOutput(t *testing.T, client *protocol.Client, token string, keys protocol.Keys, id, stream string) string {
	t.Helper()

	chunks, err := client.ReachChunks(context.Background(), token, keys, id, -1, -1)
	if err != nil {
		t.Fatalf("ReachChunks: %v", err)
	}
	list := chunks.Out
	if stream == protocol.ReachStderr {
		list = chunks.Err
	}
	var out strings.Builder
	for _, chunk := range list {
		out.Write(chunk.Data)
	}
	return out.String()
}

// TestReachAgentRunsApprovedSessions drives the whole target side: an offered
// session waits for local approval, and after `accept` the agent runs the
// command, relays both streams and reports the result.
func TestReachAgentRunsApprovedSessions(t *testing.T) {
	srv, hs := startReachControl(t)
	sender := enrollReachAgent(t, srv, hs.URL, "reach-sender")
	target := enrollReachAgent(t, srv, hs.URL, "reach-target")

	senderClient := protocol.New(hs.URL)
	targetClient := protocol.New(hs.URL)
	senderKeys, err := sender.Keys()
	if err != nil {
		t.Fatalf("sender keys: %v", err)
	}
	targetAgent, targetKeys := reachTestAgent(t, target, hs.URL)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	serveCtx, stopServe := context.WithCancel(ctx)
	defer stopServe()
	serveDone := make(chan error, 1)
	go func() { serveDone <- targetAgent.ServeReach(serveCtx) }()

	session, err := senderClient.ReachOffer(ctx, sender.Token, senderKeys, target.StableID,
		[]string{"sh", "-c", "printf 'out'; printf 'err' 1>&2"}, 30*time.Second)
	if err != nil {
		t.Fatalf("ReachOffer: %v", err)
	}

	// Approval is local: a running loop must leave an offer alone.
	time.Sleep(500 * time.Millisecond)
	if current, err := senderClient.ReachGet(ctx, sender.Token, senderKeys, session.ID); err != nil {
		t.Fatalf("ReachGet: %v", err)
	} else if current.State != protocol.ReachOffered {
		t.Fatalf("an offered session ran before approval (state %s)", current.State)
	}

	if _, err := targetClient.ReachAccept(ctx, target.Token, targetKeys, session.ID); err != nil {
		t.Fatalf("ReachAccept: %v", err)
	}

	final := waitReachSession(t, senderClient, sender.Token, senderKeys, session.ID,
		func(s protocol.ReachSession) bool { return s.Terminal() })
	if final.State != protocol.ReachSucceeded {
		t.Fatalf("session state = %s (%s)", final.State, final.Error)
	}
	if final.ExitCode == nil || *final.ExitCode != 0 {
		t.Errorf("exit code = %v", final.ExitCode)
	}
	if out := reachOutput(t, senderClient, sender.Token, senderKeys, session.ID, protocol.ReachStdout); out != "out" {
		t.Errorf("stdout = %q", out)
	}
	if errOut := reachOutput(t, senderClient, sender.Token, senderKeys, session.ID, protocol.ReachStderr); errOut != "err" {
		t.Errorf("stderr = %q", errOut)
	}

	stopServe()
	if err := <-serveDone; err != nil {
		t.Errorf("ServeReach: %v", err)
	}
}

// TestReachAgentReportsFailures covers the failure paths the target reports:
// a non-zero exit, a timeout, and the output limit.
func TestReachAgentReportsFailures(t *testing.T) {
	srv, hs := startReachControl(t)
	sender := enrollReachAgent(t, srv, hs.URL, "reach-sender")
	target := enrollReachAgent(t, srv, hs.URL, "reach-target")

	senderClient := protocol.New(hs.URL)
	targetClient := protocol.New(hs.URL)
	senderKeys, err := sender.Keys()
	if err != nil {
		t.Fatalf("sender keys: %v", err)
	}
	targetAgent, targetKeys := reachTestAgent(t, target, hs.URL)

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	serveCtx, stopServe := context.WithCancel(ctx)
	defer stopServe()
	go func() { _ = targetAgent.ServeReach(serveCtx) }()

	cases := []struct {
		name    string
		argv    []string
		timeout time.Duration
		state   string
		error   string
		exit    int
	}{
		{"non-zero exit", []string{"sh", "-c", "echo boom 1>&2; exit 7"}, 30 * time.Second, protocol.ReachFailed, "", 7},
		{"timeout", []string{"sleep", "30"}, 2 * time.Second, protocol.ReachFailed, "timed out", 0},
		{"output limit", []string{"sh", "-c", "head -c 3000000 /dev/zero"}, 30 * time.Second, protocol.ReachFailed, "output limit exceeded", 0},
	}
	for _, tc := range cases {
		session, err := senderClient.ReachOffer(ctx, sender.Token, senderKeys, target.StableID, tc.argv, tc.timeout)
		if err != nil {
			t.Fatalf("%s: ReachOffer: %v", tc.name, err)
		}
		if _, err := targetClient.ReachAccept(ctx, target.Token, targetKeys, session.ID); err != nil {
			t.Fatalf("%s: ReachAccept: %v", tc.name, err)
		}

		final := waitReachSession(t, senderClient, sender.Token, senderKeys, session.ID,
			func(s protocol.ReachSession) bool { return s.Terminal() })
		if final.State != tc.state {
			t.Errorf("%s: state = %s (%s), want %s", tc.name, final.State, final.Error, tc.state)
			continue
		}
		if tc.error != "" && final.Error != tc.error {
			t.Errorf("%s: error = %q, want %q", tc.name, final.Error, tc.error)
		}
		if tc.exit > 0 && (final.ExitCode == nil || *final.ExitCode != tc.exit) {
			t.Errorf("%s: exit code = %v, want %d", tc.name, final.ExitCode, tc.exit)
		}
	}

	stopServe()
}

// TestReachAgentStopsOnCancel checks that a cancel kills the command instead
// of letting it run to its timeout, and that the canceled state survives.
func TestReachAgentStopsOnCancel(t *testing.T) {
	srv, hs := startReachControl(t)
	sender := enrollReachAgent(t, srv, hs.URL, "reach-sender")
	target := enrollReachAgent(t, srv, hs.URL, "reach-target")

	senderClient := protocol.New(hs.URL)
	targetClient := protocol.New(hs.URL)
	senderKeys, err := sender.Keys()
	if err != nil {
		t.Fatalf("sender keys: %v", err)
	}
	targetAgent, targetKeys := reachTestAgent(t, target, hs.URL)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	serveCtx, stopServe := context.WithCancel(ctx)
	defer stopServe()
	go func() { _ = targetAgent.ServeReach(serveCtx) }()

	session, err := senderClient.ReachOffer(ctx, sender.Token, senderKeys, target.StableID,
		[]string{"sh", "-c", "sleep 30"}, 60*time.Second)
	if err != nil {
		t.Fatalf("ReachOffer: %v", err)
	}
	if _, err := targetClient.ReachAccept(ctx, target.Token, targetKeys, session.ID); err != nil {
		t.Fatalf("ReachAccept: %v", err)
	}
	waitReachSession(t, senderClient, sender.Token, senderKeys, session.ID,
		func(s protocol.ReachSession) bool { return s.State == protocol.ReachRunning })

	if _, err := senderClient.ReachCancel(ctx, sender.Token, senderKeys, session.ID); err != nil {
		t.Fatalf("ReachCancel: %v", err)
	}

	// The command must be dead well before its 60s timeout.
	stopped := make(chan struct{})
	go func() {
		targetAgent.reachWG.Wait()
		close(stopped)
	}()
	select {
	case <-stopped:
	case <-time.After(15 * time.Second):
		t.Fatal("the command kept running after the session was canceled")
	}

	final, err := senderClient.ReachGet(ctx, sender.Token, senderKeys, session.ID)
	if err != nil {
		t.Fatalf("ReachGet: %v", err)
	}
	if final.State != protocol.ReachCanceled {
		t.Errorf("state after cancel = %s, want canceled", final.State)
	}
	stopServe()
}

// TestReachAgentReportsOrphanedSessions checks the restart path: a session
// left in running by a previous process is reported instead of hanging until
// the janitor expires it.
func TestReachAgentReportsOrphanedSessions(t *testing.T) {
	srv, hs := startReachControl(t)
	sender := enrollReachAgent(t, srv, hs.URL, "reach-sender")
	target := enrollReachAgent(t, srv, hs.URL, "reach-target")

	senderClient := protocol.New(hs.URL)
	targetClient := protocol.New(hs.URL)
	senderKeys, err := sender.Keys()
	if err != nil {
		t.Fatalf("sender keys: %v", err)
	}
	targetAgent, targetKeys := reachTestAgent(t, target, hs.URL)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	session, err := senderClient.ReachOffer(ctx, sender.Token, senderKeys, target.StableID,
		[]string{"true"}, 30*time.Second)
	if err != nil {
		t.Fatalf("ReachOffer: %v", err)
	}
	if _, err := targetClient.ReachAccept(ctx, target.Token, targetKeys, session.ID); err != nil {
		t.Fatalf("ReachAccept: %v", err)
	}
	// A previous agent process started the command and died with it.
	if _, err := targetClient.ReachStart(ctx, target.Token, targetKeys, session.ID); err != nil {
		t.Fatalf("ReachStart: %v", err)
	}

	if err := targetAgent.reachCycle(ctx, targetKeys); err != nil {
		t.Fatalf("reachCycle: %v", err)
	}
	final := waitReachSession(t, senderClient, sender.Token, senderKeys, session.ID,
		func(s protocol.ReachSession) bool { return s.Terminal() })
	if final.State != protocol.ReachFailed || !strings.Contains(final.Error, "restarted") {
		t.Errorf("orphaned session = %s (%q)", final.State, final.Error)
	}
	// The leftover goroutine reports with its own context; let it finish so
	// the test does not leave it behind.
	targetAgent.reachWG.Wait()
}
