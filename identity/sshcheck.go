package identity

import (
	"context"
	"errors"
	"time"

	"tailscale.com/tailcfg"
)

// Errors returned by the SSH check-mode store.
var (
	// ErrSSHCheckNotFound is returned for an unknown (or reaped) session.
	ErrSSHCheckNotFound = errors.New("identity: ssh check session not found")
	// ErrSSHCheckDecided is returned when deciding a session that is no
	// longer pending.
	ErrSSHCheckDecided = errors.New("identity: ssh check session already decided")
	// ErrSSHCheckExpired is returned once a session's TTL has passed.
	ErrSSHCheckExpired = errors.New("identity: ssh check session expired")
	// ErrSSHCheckPending is returned when consuming a verdict that has not
	// been made yet.
	ErrSSHCheckPending = errors.New("identity: ssh check session still pending")
	// ErrSSHCheckConsumed is returned when a verdict was already handed to a
	// follow-up request.
	ErrSSHCheckConsumed = errors.New("identity: ssh check verdict already consumed")
	// ErrSSHCheckVerdict is returned for a verdict value that is not accept
	// or reject.
	ErrSSHCheckVerdict = errors.New("identity: ssh check verdict must be accept or reject")
)

// SSHCheckVerdict is the lifecycle state of one SSH check-mode authorization.
type SSHCheckVerdict string

// The states an SSH check session can be in.
const (
	SSHCheckPending  SSHCheckVerdict = "pending"
	SSHCheckAccepted SSHCheckVerdict = "accept"
	SSHCheckRejected SSHCheckVerdict = "reject"
)

// SSHCheckSession is one held SSH connection waiting for a human verdict.
//
// It is bound to the exact (source node, destination node) pair and the local
// user the session asked to run as. A verdict is consumed by exactly one
// follow-up request; a replay is re-delegated rather than accepted again
// (AGENTS.md sections 9 and 10: the store is durable, not a server-local map).
type SSHCheckSession struct {
	// ID is the opaque identifier carried in the HoldAndDelegate URL and in
	// the approval page's URL.
	ID string

	// SrcNodeID and DstNodeID are the node IDs the session is bound to.
	SrcNodeID int64
	DstNodeID int64

	// LocalUser is the local account the SSH session asked to run as.
	LocalUser string

	// Verdict is pending until a user decides; only then are DecidedBy and
	// DecidedAt set.
	Verdict   SSHCheckVerdict
	DecidedBy tailcfg.UserID
	DecidedAt time.Time

	// ConsumedAt is set when a follow-up request has taken the verdict.
	ConsumedAt time.Time

	CreatedAt time.Time
	ExpiresAt time.Time
}

// Pending reports whether the session is still awaiting a decision.
func (s SSHCheckSession) Pending() bool { return s.Verdict == SSHCheckPending }

// Expired reports whether the session's TTL has passed at now.
func (s SSHCheckSession) Expired(now time.Time) bool {
	return !s.ExpiresAt.IsZero() && now.After(s.ExpiresAt)
}

// NewSSHCheckOptions are the inputs to
// [SSHCheckStore.CreateSSHCheckSession].
type NewSSHCheckOptions struct {
	// ID is the client-facing identifier. Empty means "generate one".
	ID string

	// SrcNodeID and DstNodeID are required: the verdict is bound to them.
	SrcNodeID int64
	DstNodeID int64

	LocalUser string

	// TTL bounds how long the human has to decide. Zero means
	// [DefaultSSHCheckTTL].
	TTL time.Duration
}

// DefaultSSHCheckTTL bounds how long an SSH connection may stay held.
const DefaultSSHCheckTTL = 15 * time.Minute

// SSHCheckStore is the durable SSH check-mode state: pending sessions plus the
// per-pair "last approved" timestamps auto-approval reads.
type SSHCheckStore interface {
	// CreateSSHCheckSession records a held SSH session awaiting a decision.
	CreateSSHCheckSession(opts NewSSHCheckOptions) (SSHCheckSession, error)

	// LookupSSHCheckSession distinguishes a missing record from a storage failure.
	LookupSSHCheckSession(ctx context.Context, id string) (SSHCheckSession, error)

	// GetSSHCheckSession returns a session by ID.
	GetSSHCheckSession(id string) (SSHCheckSession, bool)

	// ListSSHCheckSessions returns up to limit sessions, newest first
	// (createdAt descending, ID ascending). limit <= 0 returns no rows: the
	// management surface always asks for a bounded page, and the janitor's
	// TTL keeps the table small.
	ListSSHCheckSessions(limit int) ([]SSHCheckSession, error)

	// GetPendingSSHCheckSession returns the newest pending, unexpired session
	// bound to the exact (source, destination, local user) triple. Repeated
	// hold requests for one connection reuse a single approval instead of
	// piling up rows.
	GetPendingSSHCheckSession(srcNodeID, dstNodeID int64, localUser string, now time.Time) (SSHCheckSession, bool)

	// DecideSSHCheckSession records the human accept/reject verdict on a
	// pending, unexpired session. Deciding twice fails with
	// ErrSSHCheckDecided.
	DecideSSHCheckSession(id string, verdict SSHCheckVerdict, by tailcfg.UserID, now time.Time) (SSHCheckSession, error)

	// ConsumeSSHCheckVerdict atomically hands the session's verdict to one
	// caller. It fails with ErrSSHCheckPending, ErrSSHCheckExpired,
	// ErrSSHCheckConsumed or ErrSSHCheckNotFound when there is no verdict to
	// hand out.
	ConsumeSSHCheckVerdict(id string, now time.Time) (SSHCheckSession, error)

	// RecordSSHCheckAuth remembers that a (source, destination) pair was
	// approved at the given time, so later sessions skip the prompt.
	RecordSSHCheckAuth(srcNodeID, dstNodeID int64, at time.Time) error

	// SSHCheckAuth returns when the pair was last approved.
	SSHCheckAuth(srcNodeID, dstNodeID int64) (time.Time, bool)

	// ClearSSHCheckAuth forgets every approval. It is called when the policy
	// changes, because the remembered approvals belong to the old rules.
	ClearSSHCheckAuth() error

	// DeleteExpiredSSHCheckSessions reaps sessions past their TTL and reports
	// how many were deleted.
	DeleteExpiredSSHCheckSessions(now time.Time) (int64, error)
}
