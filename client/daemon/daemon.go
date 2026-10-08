// Package daemon runs a Xunara Agent: enrollment, credential storage, and the
// heartbeat/netmap loop that keeps the node present in the control plane.
package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"tailscale.com/tailcfg"
	"tailscale.com/types/key"

	"github.com/xunara-net/xunara-server/client/protocol"
)

// Version is the agent's own version, reported to the control plane.
const Version = "0.1.0"

// stateFile is the durable agent state inside the state directory.
const stateFile = "agent.json"

// defaultInterval is how often the agent heartbeats and refreshes its netmap.
const defaultInterval = 30 * time.Second

// maxInterval bounds the exponential backoff after server errors.
const maxInterval = 5 * time.Minute

// defaultServicesInterval is how often a running agent re-publishes its
// service declaration. The publish is declarative and the control plane
// leaves an unchanged set alone, so a refresh only costs one request.
const defaultServicesInterval = 5 * time.Minute

// defaultHealthInterval is how often a running agent reports the readiness of
// health-tracked services. The control plane's default TTL (90s) tolerates
// two missed reports at this cadence.
const defaultHealthInterval = 30 * time.Second

// State is the agent's durable identity and credential.
//
// The machine and node keys are private key material: the file is written
// 0600 and never logged.
type State struct {
	ServerURL    string    `json:"server_url"`
	MachineKey   string    `json:"machine_key"`
	NodeKey      string    `json:"node_key"`
	Token        string    `json:"token"`
	NodeID       int64     `json:"node_id"`
	StableID     string    `json:"stable_id"`
	AgentVersion string    `json:"agent_version,omitempty"`
	EnrolledAt   time.Time `json:"enrolled_at"`
}

// Keys parses the state's private keys.
func (s State) Keys() (protocol.Keys, error) {
	var machine key.MachinePrivate
	if err := machine.UnmarshalText([]byte(s.MachineKey)); err != nil {
		return protocol.Keys{}, fmt.Errorf("daemon: invalid machine key in state: %w", err)
	}
	var node key.NodePrivate
	if err := node.UnmarshalText([]byte(s.NodeKey)); err != nil {
		return protocol.Keys{}, fmt.Errorf("daemon: invalid node key in state: %w", err)
	}
	return protocol.Keys{Machine: machine, Node: node}, nil
}

// LoadState reads the agent state, returning [os.ErrNotExist] wrapped when the
// agent has not enrolled yet.
func LoadState(stateDir string) (State, error) {
	raw, err := os.ReadFile(filepath.Join(stateDir, stateFile))
	if err != nil {
		return State{}, err
	}

	var s State
	if err := json.Unmarshal(raw, &s); err != nil {
		return State{}, fmt.Errorf("daemon: parsing %s: %w", stateFile, err)
	}
	if s.ServerURL == "" || s.MachineKey == "" || s.NodeKey == "" {
		return State{}, errors.New("daemon: agent state is incomplete; enroll again")
	}
	return s, nil
}

// SaveState writes the agent state atomically with 0600 permissions.
func SaveState(stateDir string, s State) error {
	raw, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("daemon: encoding state: %w", err)
	}
	return writeFileAtomic(stateDir, stateFile, raw)
}

// writeFileAtomic writes raw to <stateDir>/<name> atomically, creating the
// directory 0700 and the file 0600: both hold private key material.
func writeFileAtomic(stateDir, name string, raw []byte) error {
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return fmt.Errorf("daemon: creating state directory: %w", err)
	}

	final := filepath.Join(stateDir, name)
	tmp, err := os.CreateTemp(stateDir, name+".tmp*")
	if err != nil {
		return fmt.Errorf("daemon: creating %s: %w", name, err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("daemon: setting %s permissions: %w", name, err)
	}
	if _, err := tmp.Write(raw); err != nil {
		tmp.Close()
		return fmt.Errorf("daemon: writing %s: %w", name, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("daemon: closing %s: %w", name, err)
	}
	if err := os.Rename(tmpName, final); err != nil {
		return fmt.Errorf("daemon: replacing %s: %w", name, err)
	}
	return nil
}

// EnrollOptions are the inputs to [Enroll].
type EnrollOptions struct {
	ServerURL string
	StateDir  string
	// AuthKey authorizes the machine without a browser. Empty starts the
	// interactive flow, which [Enroll] completes only if a human approves
	// within the timeout.
	AuthKey   string
	Hostname  string
	Ephemeral bool
	// Timeout bounds the interactive approval wait. Zero uses five minutes.
	Timeout time.Duration
	Logger  *slog.Logger
	// Client overrides the protocol client (tests).
	Client *protocol.Client
}

// Enroll registers this agent and persists the resulting state. With an auth
// key it returns immediately; otherwise it polls until the device is approved
// or timeout elapses.
func Enroll(ctx context.Context, opts EnrollOptions) (State, error) {
	if opts.ServerURL == "" {
		return State{}, errors.New("daemon: no server URL")
	}
	if opts.StateDir == "" {
		return State{}, errors.New("daemon: no state directory")
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 5 * time.Minute
	}

	client := opts.Client
	if client == nil {
		client = protocol.New(opts.ServerURL)
	}

	state, err := LoadState(opts.StateDir)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return State{}, err
	}
	if state.MachineKey == "" {
		machine := key.NewMachine()
		node := key.NewNode()
		machineText, err := machine.MarshalText()
		if err != nil {
			return State{}, fmt.Errorf("daemon: encoding machine key: %w", err)
		}
		nodeText, err := node.MarshalText()
		if err != nil {
			return State{}, fmt.Errorf("daemon: encoding node key: %w", err)
		}
		state = State{
			ServerURL:  opts.ServerURL,
			MachineKey: string(machineText),
			NodeKey:    string(nodeText),
		}
	}
	if state.ServerURL != opts.ServerURL {
		return State{}, fmt.Errorf("daemon: state belongs to %s, not %s", state.ServerURL, opts.ServerURL)
	}

	// Persist the generated keys before talking to the server: a pending
	// interactive enrollment must be retried with the same keys, or every
	// retry would create another device authorization.
	if err := SaveState(opts.StateDir, state); err != nil {
		return State{}, err
	}

	keys, err := state.Keys()
	if err != nil {
		return State{}, err
	}

	ctx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()

	for {
		resp, err := client.Enroll(ctx, protocol.EnrollRequest{
			AuthKey:      opts.AuthKey,
			MachineKey:   keys.Machine.Public().String(),
			NodeKey:      keys.Node.Public().String(),
			Hostname:     opts.Hostname,
			OS:           runtime.GOOS,
			AgentVersion: Version,
			Ephemeral:    opts.Ephemeral,
		})
		if err != nil {
			return State{}, err
		}

		switch resp.Status {
		case "authorized":
			if resp.Token == "" {
				return State{}, errors.New("daemon: server authorized the agent without a token")
			}
			state.Token = resp.Token
			state.NodeID = resp.NodeID
			state.StableID = resp.StableID
			state.AgentVersion = Version
			state.EnrolledAt = time.Now().UTC()
			if err := SaveState(opts.StateDir, state); err != nil {
				return State{}, err
			}
			return state, nil
		case "pending":
			opts.Logger.Info("waiting for device approval", "url", resp.AuthURL)
			// Interactive enrollment: no auth key was supplied, so the agent
			// exits and the operator approves and reruns it.
			return state, &PendingApprovalError{AuthURL: resp.AuthURL}
		case "rejected":
			return State{}, fmt.Errorf("daemon: enrollment rejected: %s", resp.Error)
		default:
			return State{}, fmt.Errorf("daemon: unknown enrollment status %q", resp.Status)
		}
	}
}

// PendingApprovalError means the device needs a human to approve it in the
// browser; running enroll again afterwards authorizes the agent.
type PendingApprovalError struct {
	AuthURL string
}

func (e *PendingApprovalError) Error() string {
	return "daemon: device approval pending; approve it at " + e.AuthURL + " and run enroll again"
}

// Agent runs the steady-state loop on top of a persisted [State].
type Agent struct {
	State    State
	Interval time.Duration
	Logger   *slog.Logger
	Client   *protocol.Client

	// Services is the service declaration to keep published when StateDir is
	// empty (embedded use). With a StateDir the declaration file is the
	// source of truth.
	Services []protocol.Service
	// StateDir is the agent's state directory. When set, the declaration file
	// is re-read on every refresh, so a `services publish` run next to a
	// running agent takes effect without a restart; a missing file publishes
	// nothing.
	StateDir string
	// ServicesInterval is how often the declaration is re-published. Zero
	// uses the default.
	ServicesInterval time.Duration
	// HealthInterval is how often the readiness of health-tracked services is
	// reported. Zero uses the default; the control plane's TTL must be at
	// least a few times this to tolerate a missed report.
	HealthInterval time.Duration

	// ExecuteReach starts the Reach execution loop with Run (PROJECT_SPEC
	// section 29). The loop only executes sessions the local operator
	// approved; a deployment still has to opt in.
	ExecuteReach bool
	// ReachInterval is how often the loop looks for accepted sessions. Zero
	// uses the default.
	ReachInterval time.Duration

	// netmapMu guards the netmap the agent last applied and how many it has
	// applied in total.
	netmapMu   sync.Mutex
	netmaps    int
	lastNetmap *tailcfg.MapResponse

	// reachMu guards reachRunning, the session IDs this agent is executing.
	reachMu      sync.Mutex
	reachRunning map[string]bool
	// reachWG tracks the executions started by the reach loop so a stopping
	// agent can wait for them to report their outcome.
	reachWG sync.WaitGroup
}

// NewAgent builds the steady-state loop for an enrolled state.
func NewAgent(state State, client *protocol.Client, logger *slog.Logger) (*Agent, error) {
	if _, err := state.Keys(); err != nil {
		return nil, err
	}
	if client == nil {
		client = protocol.New(state.ServerURL)
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Agent{State: state, Interval: defaultInterval, Logger: logger, Client: client}, nil
}

// Run keeps this node present in the control plane until ctx is cancelled.
//
// Bring-up is one heartbeat plus one netmap fetch: it proves the credential
// still works, so a revoked agent stops instead of reconnecting forever, and a
// credential from a wrong state file fails before anything else happens.
//
// The steady state prefers the server's Server-Sent Events stream (M9 SSE):
// netmaps arrive when the tailnet changes instead of on a poll timer, with a
// heartbeat loop keeping liveness fresh next to it. A server that has no
// stream endpoint, or a stream that keeps failing, falls back to the polling
// cycle.
func (a *Agent) Run(ctx context.Context) error {
	keys, err := a.State.Keys()
	if err != nil {
		return err
	}

	interval := a.interval()

	if err := a.runWithBackoff(ctx, interval, func() error {
		return a.tick(ctx, keys)
	}); err != nil {
		if ctx.Err() != nil {
			return nil
		}
		return err
	}

	if len(a.Services) > 0 || a.StateDir != "" {
		go a.servicesLoop(ctx, keys)
	}
	if a.StateDir != "" {
		// Readiness is only meaningful while a declaration exists; the loop
		// re-reads both files each cycle, so enabling health on a service
		// takes effect without a restart.
		go a.healthLoop(ctx, keys)
	}
	if a.ExecuteReach {
		go func() {
			// Give in-flight commands a chance to report their result before
			// the process exits.
			defer a.reachWG.Wait()
			if err := a.reachServe(ctx, keys); err != nil && ctx.Err() == nil {
				a.Logger.Warn("reach loop stopped", "err", err)
			}
		}()
	}

	backoff := interval
	for {
		streamCtx, cancel := context.WithCancel(ctx)
		go a.heartbeatLoop(streamCtx, keys, interval)

		started := time.Now()
		streamErr := a.Client.StreamNetmap(streamCtx, a.State.Token, keys, func(netmap *tailcfg.MapResponse) error {
			a.setNetmap(netmap)
			if netmap.Node != nil {
				a.Logger.Debug("netmap pushed", "node", netmap.Node.Name, "peers", len(netmap.Peers))
			}
			return nil
		})
		cancel()

		switch {
		case ctx.Err() != nil:
			return nil
		case protocol.IsUnauthorized(streamErr):
			return fmt.Errorf("daemon: credential rejected (%w); enroll again", streamErr)
		case protocol.IsStreamUnsupported(streamErr):
			a.Logger.Info("server has no event stream; polling instead")
			return a.pollLoop(ctx, keys, interval)
		}

		// A stream that stayed up for a while was healthy; a fresh backoff
		// would punish a server that restarts once.
		if time.Since(started) > interval {
			backoff = interval
		}
		a.Logger.Warn("event stream ended; reconnecting", "err", streamErr, "backoff", backoff)
		if !sleep(ctx, backoff) {
			return nil
		}
		backoff = nextBackoff(backoff)
	}
}

// pollLoop is the pre-stream steady state: heartbeat plus netmap fetch on a
// timer, with exponential backoff. It is used against servers without the
// event stream.
func (a *Agent) pollLoop(ctx context.Context, keys protocol.Keys, interval time.Duration) error {
	backoff := interval
	for {
		err := a.tick(ctx, keys)
		switch {
		case err == nil:
			backoff = interval
		case protocol.IsUnauthorized(err):
			return fmt.Errorf("daemon: credential rejected (%w); enroll again", err)
		case ctx.Err() != nil:
			return nil
		default:
			a.Logger.Warn("agent cycle failed", "err", err)
			backoff = nextBackoff(backoff)
		}

		if !sleep(ctx, backoff) {
			return nil
		}
	}
}

// heartbeatLoop reports liveness until ctx is cancelled.
func (a *Agent) heartbeatLoop(ctx context.Context, keys protocol.Keys, interval time.Duration) {
	hostname, _ := os.Hostname()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			err := a.Client.Heartbeat(ctx, a.State.Token, protocol.HeartbeatRequest{
				MachineKey:   keys.Machine.Public().String(),
				NodeKey:      keys.Node.Public().String(),
				Hostname:     hostname,
				AgentVersion: Version,
			})
			if err != nil && ctx.Err() == nil {
				// A rejected heartbeat surfaces on the stream as a 401, which
				// stops the agent; here it is only worth a log line.
				a.Logger.Warn("heartbeat failed", "err", err)
			}
		}
	}
}

// servicesLoop keeps the agent's service declaration published until ctx is
// cancelled. It is a reconciliation: re-publishing repairs a control plane
// that lost the record (after a restore, for example) and is a no-op there
// when the set is unchanged, so a failed or skipped refresh is simply retried
// on the next tick.
func (a *Agent) servicesLoop(ctx context.Context, keys protocol.Keys) {
	interval := a.servicesInterval()
	timer := time.NewTimer(0)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}

		if services := a.declaredServices(); len(services) > 0 {
			_, err := a.Client.Services(ctx, a.State.Token, keys, services)
			switch {
			case err == nil:
				a.Logger.Debug("services published", "count", len(services))
			case ctx.Err() != nil:
				return
			case protocol.IsUnauthorized(err):
				// The main loop turns this into a stopped agent; publishing
				// is not the place to report the rejection twice.
				return
			default:
				a.Logger.Warn("publishing services failed", "err", err)
			}
		}

		timer.Reset(interval)
	}
}

// healthLoop reports the readiness of health-tracked services on a timer. It
// sends a complete report every cycle: services missing from the readiness
// file - or the whole file being absent - are reported not ready, which
// withdraws them from discovery until they are reported ready again.
func (a *Agent) healthLoop(ctx context.Context, keys protocol.Keys) {
	interval := a.healthInterval()
	timer := time.NewTimer(0)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}

		if reports, ok := a.healthReports(); ok && len(reports) > 0 {
			_, err := a.Client.ReportServiceHealth(ctx, a.State.Token, keys, reports)
			switch {
			case err == nil:
				a.Logger.Debug("service health reported", "count", len(reports))
			case ctx.Err() != nil:
				return
			case protocol.IsUnauthorized(err):
				// The main loop turns this into a stopped agent.
				return
			default:
				a.Logger.Warn("reporting service health failed", "err", err)
			}
		}

		timer.Reset(interval)
	}
}

// healthReports builds the complete readiness report for this cycle. It
// returns ok=false when the agent has nothing to report (no health-tracked
// service in the declaration) or cannot read the input files; in the latter
// case the services stay unreported, which withdraws them once the TTL passes.
func (a *Agent) healthReports() ([]protocol.ServiceHealth, bool) {
	tracked := make(map[string]bool)
	for _, svc := range a.declaredServices() {
		if svc.Health {
			tracked[svc.Name] = true
		}
	}
	if len(tracked) == 0 {
		return nil, false
	}

	// Every tracked service starts as not ready and only the readiness file
	// can flip it: a missing file is an explicit "not ready", not silence.
	ready := make(map[string]bool, len(tracked))
	file, err := LoadServiceHealth(a.StateDir)
	switch {
	case err == nil:
		for _, entry := range file {
			if !tracked[entry.Name] {
				// A stale line for a service that was removed or no longer
				// opts in must not fail the whole report.
				a.Logger.Warn("ignoring readiness for an untracked service", "service", entry.Name)
				continue
			}
			ready[entry.Name] = entry.Ready
		}
	case errors.Is(err, os.ErrNotExist):
		// No readiness file: everything is not ready.
	default:
		a.Logger.Warn("reading service readiness failed", "err", err)
		return nil, false
	}

	names := make([]string, 0, len(tracked))
	for name := range tracked {
		names = append(names, name)
	}
	sort.Strings(names)
	reports := make([]protocol.ServiceHealth, 0, len(names))
	for _, name := range names {
		reports = append(reports, protocol.ServiceHealth{Name: name, Ready: ready[name]})
	}
	return reports, true
}

// healthInterval returns the configured reporting interval with the default
// applied.
func (a *Agent) healthInterval() time.Duration {
	if a.HealthInterval > 0 {
		return a.HealthInterval
	}
	return defaultHealthInterval
}

// declaredServices returns the set to publish. A state directory is
// authoritative: its declaration file is re-read so edits take effect without
// a restart, and a missing file means nothing is published.
func (a *Agent) declaredServices() []protocol.Service {
	if a.StateDir == "" {
		return a.Services
	}
	services, err := LoadServices(a.StateDir)
	switch {
	case err == nil:
		return services
	case errors.Is(err, os.ErrNotExist):
		return nil
	default:
		a.Logger.Warn("reading service declaration failed", "err", err)
		return nil
	}
}

// servicesInterval returns the configured refresh interval with the default
// applied.
func (a *Agent) servicesInterval() time.Duration {
	if a.ServicesInterval > 0 {
		return a.ServicesInterval
	}
	return defaultServicesInterval
}

// runWithBackoff calls fn until it succeeds, ctx is cancelled or the
// credential is rejected. Rejections are returned; other failures back off.
func (a *Agent) runWithBackoff(ctx context.Context, interval time.Duration, fn func() error) error {
	for {
		err := fn()
		switch {
		case err == nil:
			return nil
		case protocol.IsUnauthorized(err):
			return fmt.Errorf("daemon: credential rejected (%w); enroll again", err)
		case ctx.Err() != nil:
			return ctx.Err()
		default:
			a.Logger.Warn("agent cycle failed", "err", err)
		}

		if !sleep(ctx, interval) {
			return ctx.Err()
		}
		interval = nextBackoff(interval)
	}
}

// interval returns the configured cycle interval with the default applied.
func (a *Agent) interval() time.Duration {
	if a.Interval > 0 {
		return a.Interval
	}
	return defaultInterval
}

// nextBackoff doubles an interval up to maxInterval.
func nextBackoff(interval time.Duration) time.Duration {
	if interval <= 0 {
		interval = defaultInterval
	}
	interval *= 2
	if interval > maxInterval {
		interval = maxInterval
	}
	return interval
}

// sleep waits for d, returning false when ctx is cancelled first.
func sleep(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

// setNetmap publishes the most recent netmap for status reporting.
func (a *Agent) setNetmap(netmap *tailcfg.MapResponse) {
	a.netmapMu.Lock()
	defer a.netmapMu.Unlock()
	a.lastNetmap = netmap
	a.netmaps++
}

// netmapStats returns how many netmaps this agent has applied and the most
// recent one (nil before the first).
func (a *Agent) netmapStats() (int, *tailcfg.MapResponse) {
	a.netmapMu.Lock()
	defer a.netmapMu.Unlock()
	return a.netmaps, a.lastNetmap
}

// tick performs one heartbeat + netmap refresh.
func (a *Agent) tick(ctx context.Context, keys protocol.Keys) error {
	hostname, _ := os.Hostname()
	if err := a.Client.Heartbeat(ctx, a.State.Token, protocol.HeartbeatRequest{
		MachineKey:   keys.Machine.Public().String(),
		NodeKey:      keys.Node.Public().String(),
		Hostname:     hostname,
		AgentVersion: Version,
	}); err != nil {
		return err
	}

	netmap, err := a.Client.Netmap(ctx, a.State.Token, keys)
	if err != nil {
		return err
	}
	a.setNetmap(netmap)

	if netmap.Node != nil {
		a.Logger.Debug("netmap refreshed",
			"node", netmap.Node.Name, "peers", len(netmap.Peers))
	}
	return nil
}

// Status summarizes the agent for `xunara-agent status`.
type Status struct {
	NodeID    int64  `json:"node_id"`
	StableID  string `json:"stable_id"`
	ServerURL string `json:"server_url"`
	Version   string `json:"agent_version"`
	// Name is the node's MagicDNS name, empty when the agent has not fetched a
	// netmap yet.
	Name  string `json:"name,omitempty"`
	Peers int    `json:"peers,omitempty"`
}

// Status reports what the agent knows after at least one cycle. Run it after
// [Agent.tick]-equivalent work: it fetches a fresh netmap.
func (a *Agent) Status(ctx context.Context) (Status, error) {
	keys, err := a.State.Keys()
	if err != nil {
		return Status{}, err
	}
	netmap, err := a.Client.Netmap(ctx, a.State.Token, keys)
	if err != nil {
		return Status{}, err
	}

	status := Status{
		NodeID:    a.State.NodeID,
		StableID:  a.State.StableID,
		ServerURL: a.State.ServerURL,
		Version:   Version,
		Peers:     len(netmap.Peers),
	}
	if netmap.Node != nil {
		status.Name = netmap.Node.Name
	}
	return status, nil
}

// Enrolled reports whether the state carries a usable credential.
func (s State) Enrolled() bool { return s.Token != "" }

// CleanState removes the local agent state (used by `enroll --force` and
// tests). It does not touch the control plane.
func CleanState(stateDir string) error {
	err := os.Remove(filepath.Join(stateDir, stateFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

// NormalizeServerURL trims a trailing slash.
func NormalizeServerURL(raw string) string { return strings.TrimRight(raw, "/") }
