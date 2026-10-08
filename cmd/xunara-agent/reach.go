package main

// This file implements `xunara-agent reach`: remote command execution through
// the control plane (Xunara Reach, PROJECT_SPEC section 29).
//
// The control plane only orchestrates the session and relays output chunks.
// The target executes the command, but never without its local operator
// approving the offer first; the sender's `reach run` streams the output back
// and maps the remote exit status onto its own.

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/xunara-net/xunara-server/client/daemon"
	"github.com/xunara-net/xunara-server/client/protocol"
)

const (
	// reachPollInterval is how often the CLI re-checks a session it waits on.
	reachPollInterval = time.Second
	// reachOfferWait is how long an unanswered offer lives on the control
	// plane; mirrors state.ReachMaxOfferAge (spec section 29.1).
	reachOfferWait = 5 * time.Minute
	// reachDefaultTimeout is the command timeout when -timeout is not given.
	reachDefaultTimeout = 60 * time.Second
	// reachCommandWidth bounds the command column of `reach list`.
	reachCommandWidth = 60
)

// runReach implements `xunara-agent reach`.
func runReach(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("reach needs a subcommand: offer, run, list, show, accept, deny, cancel or serve")
	}
	switch args[0] {
	case "offer":
		return runReachOffer(ctx, args[1:])
	case "run":
		return runReachRun(ctx, args[1:])
	case "list":
		return runReachList(ctx, args[1:])
	case "show":
		return runReachShow(ctx, args[1:])
	case "accept":
		return runReachDecision(ctx, args[1:], "accept")
	case "deny":
		return runReachDecision(ctx, args[1:], "deny")
	case "cancel":
		return runReachDecision(ctx, args[1:], "cancel")
	case "serve":
		return runReachServe(ctx, args[1:])
	default:
		return fmt.Errorf("unknown reach subcommand %q", args[0])
	}
}

// reachCommand is the parsed argument set of offer and run. The remote command
// comes after "--", so the flag parser never mistakes a remote flag for one of
// its own.
type reachCommand struct {
	stateDir string
	to       string
	timeout  time.Duration
	asJSON   bool
	argv     []string
}

// parseReachCommand parses the shared offer/run command line.
func parseReachCommand(name string, args []string) (reachCommand, error) {
	var cmd reachCommand
	fs := flag.NewFlagSet(name, flag.ExitOnError)
	fs.StringVar(&cmd.stateDir, "state-dir", defaultStateDir(), "directory holding agent.json")
	fs.StringVar(&cmd.to, "to", "", "target node: a hostname or a node stable ID")
	fs.DurationVar(&cmd.timeout, "timeout", reachDefaultTimeout, "how long the command may run on the target")
	fs.BoolVar(&cmd.asJSON, "json", false, "print the session as JSON")
	if err := fs.Parse(args); err != nil {
		return cmd, err
	}
	if cmd.to == "" {
		return cmd, fmt.Errorf("%s needs -to <hostname|stable-id>", name)
	}
	if cmd.timeout <= 0 || cmd.timeout > protocol.ReachMaxTimeout {
		return cmd, fmt.Errorf("-timeout must be positive and at most %s", protocol.ReachMaxTimeout)
	}
	cmd.argv = fs.Args()
	if len(cmd.argv) == 0 {
		return cmd, fmt.Errorf("%s needs a command after --, e.g. -- df -h", name)
	}
	if err := validateReachArgv(cmd.argv); err != nil {
		return cmd, err
	}
	return cmd, nil
}

// validateReachArgv mirrors the control plane's argv limits so an oversized
// command fails here, before a session exists.
func validateReachArgv(argv []string) error {
	if len(argv) > protocol.ReachMaxArgvEntries {
		return fmt.Errorf("a command may have at most %d arguments", protocol.ReachMaxArgvEntries)
	}
	total := 0
	for _, arg := range argv {
		if arg == "" {
			return errors.New("command arguments must not be empty")
		}
		if len(arg) > protocol.ReachMaxArgBytes {
			return fmt.Errorf("a command argument is longer than %d bytes", protocol.ReachMaxArgBytes)
		}
		total += len(arg)
	}
	if total > protocol.ReachMaxArgvBytes {
		return fmt.Errorf("the command is longer than %d bytes", protocol.ReachMaxArgvBytes)
	}
	return nil
}

// runReachOffer implements `xunara-agent reach offer`: ask the target to run a
// command. Nothing runs until the target approves it.
func runReachOffer(ctx context.Context, args []string) error {
	cmd, err := parseReachCommand("reach offer", args)
	if err != nil {
		return err
	}

	state, keys, client, err := enrolledClient(cmd.stateDir)
	if err != nil {
		return err
	}
	to, err := resolvePeer(ctx, client, state.Token, keys, cmd.to, "a node cannot reach itself")
	if err != nil {
		return err
	}

	session, err := client.ReachOffer(ctx, state.Token, keys, to, cmd.argv, cmd.timeout)
	if err != nil {
		return err
	}
	if cmd.asJSON {
		return writeReachJSON(session)
	}
	fmt.Printf("Offered %s to %s (%s).\n", session.ID, cmd.to, session.Target.StableID)
	fmt.Printf("The target must approve it first: xunara-agent reach accept %s\n", session.ID)
	return nil
}

// runReachRun implements `xunara-agent reach run`: offer a command, wait for
// the target to approve and start it, stream the output, and exit with the
// command's status.
func runReachRun(ctx context.Context, args []string) error {
	cmd, err := parseReachCommand("reach run", args)
	if err != nil {
		return err
	}

	state, keys, client, err := enrolledClient(cmd.stateDir)
	if err != nil {
		return err
	}
	to, err := resolvePeer(ctx, client, state.Token, keys, cmd.to, "a node cannot reach itself")
	if err != nil {
		return err
	}

	// The whole operation may take the offer wait plus the command timeout.
	ctx, cancel := context.WithTimeout(ctx, reachOfferWait+cmd.timeout+time.Minute)
	defer cancel()

	session, err := client.ReachOffer(ctx, state.Token, keys, to, cmd.argv, cmd.timeout)
	if err != nil {
		return err
	}
	reachProgress("offered %s to %s; waiting for approval", session.ID, cmd.to)

	// Wait until the target decides. A fast target can pass through accepted
	// and running before the first poll: any state other than offered means
	// the wait is over, and streamReachOutput drains the result either way.
	session, err = waitForReachState(ctx, client, state.Token, keys, session.ID, func(s protocol.ReachSession) bool {
		return s.State != protocol.ReachOffered
	})
	if err != nil {
		return err
	}
	if session.State == protocol.ReachAccepted {
		reachProgress("%s approved by %s; waiting for the command to start", session.ID, session.Target.Hostname)
	}

	session, err = streamReachOutput(ctx, client, state.Token, keys, session)
	if err != nil {
		return err
	}
	return reachResultError(session)
}

// waitForReachState polls until done accepts the session. A session that
// reaches a terminal state without satisfying done is an error.
func waitForReachState(ctx context.Context, client *protocol.Client, token string, keys protocol.Keys, id string, done func(protocol.ReachSession) bool) (protocol.ReachSession, error) {
	ticker := time.NewTicker(reachPollInterval)
	defer ticker.Stop()
	for {
		session, err := client.ReachGet(ctx, token, keys, id)
		switch {
		case err == nil && done(session):
			return session, nil
		case err == nil && session.Terminal():
			return session, reachTerminalError(session)
		case err != nil && ctx.Err() != nil:
			return protocol.ReachSession{}, ctx.Err()
		case err != nil && !protocol.IsUnauthorized(err):
			reachProgress("polling %s: %v", id, err)
		case err != nil:
			return protocol.ReachSession{}, err
		}

		select {
		case <-ctx.Done():
			return protocol.ReachSession{}, ctx.Err()
		case <-ticker.C:
		}
	}
}

// streamReachOutput relays the command's output to this terminal until the
// session reaches a terminal state, then drains the last chunks.
func streamReachOutput(ctx context.Context, client *protocol.Client, token string, keys protocol.Keys, session protocol.ReachSession) (protocol.ReachSession, error) {
	outCursor, errCursor := int64(-1), int64(-1)
	drain := func() error {
		chunks, err := client.ReachChunks(ctx, token, keys, session.ID, outCursor, errCursor)
		if err != nil {
			return err
		}
		for _, chunk := range chunks.Out {
			if _, err := os.Stdout.Write(chunk.Data); err != nil {
				return err
			}
			outCursor = chunk.Seq
		}
		for _, chunk := range chunks.Err {
			if _, err := os.Stderr.Write(chunk.Data); err != nil {
				return err
			}
			errCursor = chunk.Seq
		}
		return nil
	}

	ticker := time.NewTicker(reachPollInterval)
	defer ticker.Stop()
	for {
		if err := drain(); err != nil {
			if ctx.Err() != nil || protocol.IsUnauthorized(err) {
				return session, err
			}
			reachProgress("reading output: %v", err)
		}

		current, err := client.ReachGet(ctx, token, keys, session.ID)
		switch {
		case err != nil && ctx.Err() != nil:
			return session, ctx.Err()
		case err != nil && !protocol.IsUnauthorized(err):
			reachProgress("polling %s: %v", session.ID, err)
		case err != nil:
			return session, err
		case current.Terminal():
			// One last read: a chunk may have been stored between the drain
			// above and this state check.
			if err := drain(); err != nil && ctx.Err() != nil {
				return current, err
			}
			return current, nil
		}

		select {
		case <-ctx.Done():
			return session, ctx.Err()
		case <-ticker.C:
		}
	}
}

// reachResultError maps a finished session onto the CLI's exit path: zero is
// success, a non-zero exit status becomes [reachExitError] so main can exit
// with the remote status.
func reachResultError(session protocol.ReachSession) error {
	switch session.State {
	case protocol.ReachSucceeded:
		reachProgress("%s succeeded", session.ID)
		return nil
	case protocol.ReachFailed:
		if session.ExitCode != nil && *session.ExitCode > 0 {
			code := *session.ExitCode
			return &reachExitError{
				code: reachExitCode(code),
				msg:  fmt.Sprintf("command %s exited with status %d", session.ID, code),
			}
		}
		detail := session.Error
		if detail == "" {
			detail = "no exit status"
		}
		return &reachExitError{code: 1, msg: fmt.Sprintf("command %s failed: %s", session.ID, detail)}
	default:
		return reachTerminalError(session)
	}
}

// reachTerminalError explains a session that ended without running, or without
// finishing, the command.
func reachTerminalError(session protocol.ReachSession) error {
	message := fmt.Sprintf("session %s is %s", session.ID, session.State)
	if session.Error != "" {
		message += ": " + session.Error
	}
	return errors.New(message)
}

// reachExitError carries a remote exit status through main.
type reachExitError struct {
	code int
	msg  string
}

func (e *reachExitError) Error() string { return e.msg }

// reachExitCode maps a remote exit status onto this process's exit status:
// 1..125 pass through, anything else (killed by a signal, a status this shell
// cannot represent) becomes 1.
func reachExitCode(code int) int {
	if code >= 1 && code <= 125 {
		return code
	}
	return 1
}

// runReachList implements `xunara-agent reach list`.
func runReachList(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("reach list", flag.ExitOnError)
	stateDir := fs.String("state-dir", defaultStateDir(), "directory holding agent.json")
	asJSON := fs.Bool("json", false, "print the sessions as JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}

	state, keys, client, err := enrolledClient(*stateDir)
	if err != nil {
		return err
	}
	sessions, err := client.ReachList(ctx, state.Token, keys)
	if err != nil {
		return err
	}
	if *asJSON {
		if sessions == nil {
			sessions = []protocol.ReachSession{}
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(struct {
			Sessions []protocol.ReachSession `json:"sessions"`
		}{Sessions: sessions})
	}
	return writeReachSessions(os.Stdout, sessions, state.StableID)
}

// runReachShow implements `xunara-agent reach show <id>`: the full session,
// including the argv the target is asked to approve.
func runReachShow(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("reach show", flag.ExitOnError)
	stateDir := fs.String("state-dir", defaultStateDir(), "directory holding agent.json")
	asJSON := fs.Bool("json", false, "print the session as JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("reach show needs exactly one session ID")
	}

	state, keys, client, err := enrolledClient(*stateDir)
	if err != nil {
		return err
	}
	session, err := client.ReachGet(ctx, state.Token, keys, fs.Arg(0))
	if err != nil {
		return err
	}
	if *asJSON {
		return writeReachJSON(session)
	}
	writeReachSession(os.Stdout, session)
	return nil
}

// runReachDecision implements accept, deny and cancel: one ID, one transition.
func runReachDecision(ctx context.Context, args []string, action string) error {
	fs := flag.NewFlagSet("reach "+action, flag.ExitOnError)
	stateDir := fs.String("state-dir", defaultStateDir(), "directory holding agent.json")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("reach %s needs exactly one session ID", action)
	}
	id := fs.Arg(0)

	state, keys, client, err := enrolledClient(*stateDir)
	if err != nil {
		return err
	}
	var session protocol.ReachSession
	switch action {
	case "accept":
		session, err = client.ReachAccept(ctx, state.Token, keys, id)
	case "deny":
		session, err = client.ReachDeny(ctx, state.Token, keys, id)
	default:
		session, err = client.ReachCancel(ctx, state.Token, keys, id)
	}
	if err != nil {
		return err
	}

	switch action {
	case "accept":
		// Approval is informed consent: show exactly what will run.
		fmt.Printf("Accepted %s; it will run:\n  %s\n", session.ID, strings.Join(session.Argv, " "))
	case "deny":
		fmt.Printf("Denied %s.\n", session.ID)
	default:
		fmt.Printf("Canceled %s.\n", session.ID)
	}
	return nil
}

// runReachServe implements `xunara-agent reach serve`: the target-side
// execution loop on its own. `xunara-agent run` starts the same loop.
func runReachServe(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("reach serve", flag.ExitOnError)
	stateDir := fs.String("state-dir", defaultStateDir(), "directory holding agent.json")
	interval := fs.Duration("interval", 2*time.Second, "how often to look for accepted sessions")
	logLevel := fs.String("log-level", "info", "log level: debug|info|warn|error")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *interval < time.Second {
		return errors.New("reach serve -interval must be at least 1s")
	}

	state, err := daemon.LoadState(*stateDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return errors.New("this agent is not enrolled; run `xunara-agent enroll -server <url>` first")
		}
		return err
	}
	if !state.Enrolled() {
		return errors.New("this agent has not been approved yet; run `xunara-agent enroll` again after approving the device")
	}

	agent, err := daemon.NewAgent(state, nil, newLogger(*logLevel))
	if err != nil {
		return err
	}
	agent.ReachInterval = *interval
	agent.Logger.Info("reach execution loop running", "server", state.ServerURL, "node_id", state.NodeID)
	return agent.ServeReach(ctx)
}

// writeReachJSON prints one session as JSON.
func writeReachJSON(session protocol.ReachSession) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(session)
}

// writeReachSessions renders the session table.
func writeReachSessions(w io.Writer, sessions []protocol.ReachSession, selfStableID string) error {
	if len(sessions) == 0 {
		fmt.Fprintln(w, "No sessions.")
		return nil
	}

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tDIR\tSTATE\tPEER\tCOMMAND\tUPDATED")
	for _, session := range sessions {
		direction, peer := "sent", session.Target
		if session.Target.StableID == selfStableID {
			direction, peer = "received", session.Sender
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n",
			session.ID, direction, session.State, dashIfEmpty(peer.Hostname),
			truncateReachCommand(strings.Join(session.Argv, " ")), dashIfZeroTime(session.UpdatedAt))
	}
	return tw.Flush()
}

// writeReachSession renders one session in full.
func writeReachSession(w io.Writer, session protocol.ReachSession) {
	fmt.Fprintf(w, "id:       %s\n", session.ID)
	fmt.Fprintf(w, "state:    %s\n", session.State)
	fmt.Fprintf(w, "from:     %s (%s)\n", dashIfEmpty(session.Sender.Hostname), session.Sender.StableID)
	fmt.Fprintf(w, "to:       %s (%s)\n", dashIfEmpty(session.Target.Hostname), session.Target.StableID)
	fmt.Fprintf(w, "command:  %s\n", strings.Join(session.Argv, " "))
	fmt.Fprintf(w, "timeout:  %ds\n", session.TimeoutSec)
	fmt.Fprintf(w, "created:  %s\n", session.CreatedAt.Format(time.RFC3339))
	fmt.Fprintf(w, "expires:  %s\n", session.ExpiresAt.Format(time.RFC3339))
	if session.ExitCode != nil {
		fmt.Fprintf(w, "exit:     %d\n", *session.ExitCode)
	}
	if session.Error != "" {
		fmt.Fprintf(w, "error:    %s\n", session.Error)
	}
}

// truncateReachCommand shortens the command column of `reach list`.
func truncateReachCommand(command string) string {
	if len(command) <= reachCommandWidth {
		return command
	}
	return command[:reachCommandWidth-1] + "…"
}

// reachProgress reports progress on stderr, so the remote command's stdout
// stays exactly what it is.
func reachProgress(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "xunara-agent: reach: "+format+"\n", args...)
}
