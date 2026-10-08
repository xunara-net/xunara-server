package daemon

// This file is the target side of Xunara Reach remote command execution
// (PROJECT_SPEC section 29). The agent runs nothing until the local operator
// approves the offer on the command line (xunara-agent reach accept); the
// loop below only picks up sessions that are already accepted, claims them,
// runs argv directly - no shell, no stdin, no PTY - and relays output chunks
// to the control plane, which never sees the process.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xunara-net/xunara-server/client/protocol"
)

const (
	// defaultReachInterval is how often the agent looks for accepted sessions.
	defaultReachInterval = 2 * time.Second
	// reachDisabledInterval is the poll interval after the control plane
	// answers 404: reach is not enabled there, so polling fast is pointless,
	// and a deployment that enables it later is still noticed.
	reachDisabledInterval = time.Minute
	// reachMaxConcurrent bounds how many commands one agent runs at once.
	reachMaxConcurrent = 8
	// reachWatchInterval is how often a running command re-checks the session
	// so a cancel (or an expiry) stops it.
	reachWatchInterval = 2 * time.Second
	// reachReaderGrace bounds how long the output readers may stay blocked
	// after the command exited. A grandchild that inherited the pipe keeps it
	// open; the readers are closed at this point rather than waiting forever.
	reachReaderGrace = 5 * time.Second
	// reachFinishTimeout bounds the best-effort result report after the agent
	// itself is shutting down.
	reachFinishTimeout = 5 * time.Second
)

// ServeReach runs only the reach execution loop, for `xunara-agent reach
// serve`. [Agent.Run] starts the same loop when [Agent.ExecuteReach] is set.
func (a *Agent) ServeReach(ctx context.Context) error {
	keys, err := a.State.Keys()
	if err != nil {
		return err
	}
	defer a.reachWG.Wait()
	return a.reachServe(ctx, keys)
}

// reachServe polls for accepted sessions until ctx is cancelled. Failures back
// off; a missing endpoint means the feature is off on the control plane.
func (a *Agent) reachServe(ctx context.Context, keys protocol.Keys) error {
	interval := a.reachInterval()
	backoff := interval
	for {
		err := a.reachCycle(ctx, keys)
		switch {
		case ctx.Err() != nil:
			return nil
		case err == nil:
			backoff = interval
		case protocol.IsUnauthorized(err):
			return fmt.Errorf("daemon: reach credential rejected (%w); enroll again", err)
		case protocol.IsNotFound(err):
			if backoff != reachDisabledInterval {
				a.Logger.Info("control plane has no reach endpoint; polling slowly")
			}
			backoff = reachDisabledInterval
		default:
			a.Logger.Warn("reach cycle failed", "err", err)
			backoff = nextBackoff(backoff)
		}
		if !sleep(ctx, backoff) {
			return nil
		}
	}
}

// reachCycle starts every accepted session addressed to this node and reports
// running sessions this process does not own (a restart orphaned them).
func (a *Agent) reachCycle(ctx context.Context, keys protocol.Keys) error {
	sessions, err := a.Client.ReachList(ctx, a.State.Token, keys)
	if err != nil {
		return err
	}
	for _, session := range sessions {
		if session.Target.StableID != a.State.StableID {
			// The sender side is driven by `xunara-agent reach run`.
			continue
		}
		switch session.State {
		case protocol.ReachAccepted:
			if !a.claimReachSlot(session.ID) {
				continue
			}
			a.reachWG.Add(1)
			go func(session protocol.ReachSession) {
				defer a.reachWG.Done()
				defer a.releaseReachSlot(session.ID)
				a.executeReach(ctx, keys, session)
			}(session)
		case protocol.ReachRunning:
			if !a.claimReachSlot(session.ID) {
				continue
			}
			// Nobody here is running this session: the agent restarted while
			// the command was in flight. Report it instead of leaving the
			// sender until the janitor expires the session.
			a.reachWG.Add(1)
			go func(session protocol.ReachSession) {
				defer a.reachWG.Done()
				defer a.releaseReachSlot(session.ID)
				a.finishReachDetached(keys, session.ID, -1, "target agent restarted")
			}(session)
		}
	}
	return nil
}

// claimReachSlot reserves a session for one execution. It also caps how many
// commands this agent runs at once; a session skipped at the cap is claimed on
// a later cycle.
func (a *Agent) claimReachSlot(id string) bool {
	a.reachMu.Lock()
	defer a.reachMu.Unlock()
	if a.reachRunning == nil {
		a.reachRunning = make(map[string]bool)
	}
	if a.reachRunning[id] || len(a.reachRunning) >= reachMaxConcurrent {
		return false
	}
	a.reachRunning[id] = true
	return true
}

// releaseReachSlot frees a session after its execution ended.
func (a *Agent) releaseReachSlot(id string) {
	a.reachMu.Lock()
	defer a.reachMu.Unlock()
	delete(a.reachRunning, id)
}

// executeReach claims an accepted session and runs the command. The result is
// always reported to the control plane unless the session itself left the
// running state (cancelled or expired): then the outcome is already known and
// finishing it would fail with a conflict.
func (a *Agent) executeReach(ctx context.Context, keys protocol.Keys, session protocol.ReachSession) {
	if len(session.Argv) == 0 {
		a.finishReachDetached(keys, session.ID, -1, "empty argv")
		return
	}

	timeout := time.Duration(session.TimeoutSec) * time.Second
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	runCtx, cancelRun := context.WithTimeout(ctx, timeout)
	defer cancelRun()

	if _, err := a.Client.ReachStart(runCtx, a.State.Token, keys, session.ID); err != nil {
		// A conflict means the state moved on (another instance claimed it, or
		// it was cancelled); anything else is worth a line.
		if !protocol.IsUnauthorized(err) && runCtx.Err() == nil {
			a.Logger.Warn("claiming reach session failed", "session", session.ID, "err", err)
		}
		return
	}

	// argv is executed element by element: there is no shell, so nothing in
	// the arguments can be interpreted. The command inherits the agent's
	// environment and working directory (spec section 29).
	cmd := exec.CommandContext(runCtx, session.Argv[0], session.Argv[1:]...)
	cmd.Stdin = nil
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		a.finishReachDetached(keys, session.ID, -1, "could not capture stdout: "+err.Error())
		return
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		a.finishReachDetached(keys, session.ID, -1, "could not capture stderr: "+err.Error())
		return
	}
	if err := cmd.Start(); err != nil {
		a.finishReachDetached(keys, session.ID, -1, "could not start: "+err.Error())
		return
	}

	var (
		readers   sync.WaitGroup
		total     atomic.Int64
		overLimit atomic.Bool
		remoteEnd atomic.Bool
	)

	// The command is killed when either side cancels the session, when the
	// janitor expires it, or when the timeout fires.
	watchCtx, stopWatch := context.WithCancel(runCtx)
	go func() {
		defer stopWatch()
		a.watchReachSession(watchCtx, keys, session.ID, func() {
			remoteEnd.Store(true)
			cancelRun()
		})
	}()

	readers.Add(2)
	relay := func(stream string, pipe io.ReadCloser) {
		defer readers.Done()
		seq := int64(0)
		buf := make([]byte, protocol.ReachMaxChunkBytes)
		for {
			n, readErr := pipe.Read(buf)
			if n > 0 {
				if total.Add(int64(n)) > protocol.ReachMaxOutputBytes {
					// Stop the command and report it: truncation must not be
					// silent (spec section 29.1).
					overLimit.Store(true)
					cancelRun()
					return
				}
				if sendErr := a.Client.ReachAppendChunk(runCtx, a.State.Token, keys, session.ID, stream, seq, buf[:n]); sendErr != nil {
					if !protocol.IsUnauthorized(sendErr) && runCtx.Err() == nil {
						a.Logger.Warn("relaying reach output failed", "session", session.ID, "stream", stream, "err", sendErr)
					}
					return
				}
				seq++
			}
			if readErr != nil {
				return
			}
		}
	}
	go relay(protocol.ReachStdout, stdout)
	go relay(protocol.ReachStderr, stderr)

	// os/exec's Wait closes the pipe ends it handed out, so the readers must
	// drain to EOF first: calling Wait while a reader is still behind discards
	// output the command already wrote (spec section 29: output is complete or
	// explicitly truncated, never silently dropped). Readers normally end when
	// the process closes the pipes; a grandchild holding them open must not
	// stall the result forever, hence the grace period.
	readersDone := make(chan struct{})
	go func() {
		select {
		case <-readersDone:
		case <-time.After(reachReaderGrace):
			stdout.Close()
			stderr.Close()
		}
	}()
	readers.Wait()
	close(readersDone)

	waitErr := cmd.Wait()
	stopWatch() // the command is gone; the watcher has nothing to stop
	if remoteEnd.Load() {
		return
	}

	exitCode := -1
	if state := cmd.ProcessState; state != nil {
		exitCode = state.ExitCode()
	}

	switch {
	case overLimit.Load():
		a.finishReach(ctx, keys, session.ID, exitCode, "output limit exceeded")
	case runCtx.Err() == context.DeadlineExceeded:
		a.finishReach(ctx, keys, session.ID, exitCode, "timed out")
	case ctx.Err() != nil:
		// The agent is stopping; report it so the sender is not left waiting
		// for the janitor.
		a.finishReachDetached(keys, session.ID, exitCode, "target agent stopped")
	case waitErr != nil && exitCode == 0:
		// Defensive: a wait error without a status is still a failure.
		a.finishReach(ctx, keys, session.ID, -1, "command failed: "+waitErr.Error())
	default:
		a.finishReach(ctx, keys, session.ID, exitCode, "")
	}
}

// watchReachSession calls stop when the session leaves running, so a cancel
// from either side kills the command instead of letting it run to the timeout.
func (a *Agent) watchReachSession(ctx context.Context, keys protocol.Keys, id string, stop func()) {
	ticker := time.NewTicker(reachWatchInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		session, err := a.Client.ReachGet(ctx, a.State.Token, keys, id)
		if err != nil {
			if ctx.Err() != nil || protocol.IsUnauthorized(err) {
				return
			}
			continue
		}
		if session.State != protocol.ReachRunning {
			stop()
			return
		}
	}
}

// finishReach reports the result while the agent still has a live context.
func (a *Agent) finishReach(ctx context.Context, keys protocol.Keys, id string, exitCode int, errText string) {
	if err := a.reachFinishRequest(ctx, keys, id, exitCode, errText); err != nil && ctx.Err() == nil {
		a.Logger.Warn("reporting reach result failed", "session", id, "err", err)
	}
}

// finishReachDetached reports the result with a short background context, for
// paths where the caller's context is already gone (shutdown, start failure).
func (a *Agent) finishReachDetached(keys protocol.Keys, id string, exitCode int, errText string) {
	ctx, cancel := context.WithTimeout(context.Background(), reachFinishTimeout)
	defer cancel()
	a.finishReach(ctx, keys, id, exitCode, errText)
}

// reachFinishRequest posts one finish and treats an already-finished session
// as success: a concurrent cancel means there is nothing left to report.
func (a *Agent) reachFinishRequest(ctx context.Context, keys protocol.Keys, id string, exitCode int, errText string) error {
	_, err := a.Client.ReachFinish(ctx, a.State.Token, keys, id, exitCode, errText)
	var he *protocol.HTTPError
	if errors.As(err, &he) && (he.StatusCode == 404 || he.StatusCode == 409) {
		return nil
	}
	return err
}

// reachInterval returns the configured poll interval with the default applied.
func (a *Agent) reachInterval() time.Duration {
	if a.ReachInterval > 0 {
		return a.ReachInterval
	}
	return defaultReachInterval
}
