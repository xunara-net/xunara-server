package identity

import (
	"context"
	"errors"
	"time"

	"tailscale.com/tailcfg"
)

// Errors returned by the device authorization store.
var (
	// ErrDeviceNotFound is returned for an unknown device authorization.
	ErrDeviceNotFound = errors.New("identity: device authorization not found")
	// ErrDeviceExpired is returned once an authorization's TTL has passed.
	ErrDeviceExpired = errors.New("identity: device authorization expired")
	// ErrDeviceDecided is returned when approving or denying an authorization
	// that is no longer pending (duplicate or replayed approval).
	ErrDeviceDecided = errors.New("identity: device authorization already decided")
)

// DeviceAuthorization is one machine waiting for a human to approve it.
//
// It binds the exact (machine key, node key) pair the device presented; the
// approver confirms the human, never the keys, and the two halves stay
// separate objects (AGENTS.md sections 5 and 10).
type DeviceAuthorization struct {
	// ID is the opaque identifier; the client's register AuthURL carries it.
	ID string

	// MachineKey and NodeKey are the exact keys the device presented. Approval
	// authorizes this pair and nothing else.
	MachineKey string
	NodeKey    string

	// UserID and ApprovedBy are set when the device is approved. UserID is 0
	// while pending.
	UserID     tailcfg.UserID
	ApprovedBy tailcfg.UserID

	// State is pending, approved or denied.
	State DeviceAuthorizationState

	RequestedAction string
	ClientMetadata  string

	CreatedAt  time.Time
	ExpiresAt  time.Time
	ApprovedAt time.Time
	DeniedAt   time.Time
}

// DeviceAuthorizationState is the lifecycle state of a device authorization.
type DeviceAuthorizationState string

// The states a device authorization can be in.
const (
	DevicePending  DeviceAuthorizationState = "pending"
	DeviceApproved DeviceAuthorizationState = "approved"
	DeviceDenied   DeviceAuthorizationState = "denied"
)

// Pending reports whether the authorization is still awaiting a decision.
func (d DeviceAuthorization) Pending() bool { return d.State == DevicePending }

// Expired reports whether the authorization's TTL has passed at now.
func (d DeviceAuthorization) Expired(now time.Time) bool {
	return !d.ExpiresAt.IsZero() && now.After(d.ExpiresAt)
}

// NewDeviceAuthorizationOptions are the inputs to
// [DeviceAuthorizationStore.CreateDeviceAuthorization].
type NewDeviceAuthorizationOptions struct {
	// ID is the client-facing identifier (the register AuthURL's ID). Empty
	// means "generate one".
	ID string

	// MachineKey and NodeKey are required: approval is bound to them.
	MachineKey string
	NodeKey    string

	RequestedAction string
	ClientMetadata  string

	// TTL bounds how long the device may wait. Zero means
	// [DefaultDeviceAuthorizationTTL].
	TTL time.Duration
}

// DefaultDeviceAuthorizationTTL bounds how long a device may wait for approval.
const DefaultDeviceAuthorizationTTL = 15 * time.Minute

// DeviceAuthorizationStore is the durable device-approval table.
type DeviceAuthorizationStore interface {
	// CreateDeviceAuthorization records a device awaiting approval.
	CreateDeviceAuthorization(opts NewDeviceAuthorizationOptions) (DeviceAuthorization, error)
	CreatePendingDeviceAuthorization(ctx context.Context, opts NewDeviceAuthorizationOptions) (DeviceAuthorization, error)

	// GetDeviceAuthorization returns an authorization by ID.
	GetDeviceAuthorization(id string) (DeviceAuthorization, bool)
	LookupDeviceAuthorization(ctx context.Context, id string) (DeviceAuthorization, error)
	LookupDeviceAuthorizationByKeys(ctx context.Context, machineKey, nodeKey string) (DeviceAuthorization, error)

	// GetDeviceAuthorizationByNodeKey returns the most recent authorization
	// for a node key, so an instance that did not create the registration can
	// follow it up.
	GetDeviceAuthorizationByNodeKey(nodeKey string) (DeviceAuthorization, bool)

	// ListPendingDeviceAuthorizations returns pending, unexpired
	// authorizations, newest first.
	ListPendingDeviceAuthorizations(now time.Time) []DeviceAuthorization

	// ApproveDeviceAuthorization approves a pending, unexpired authorization
	// for the given user. The machine and node keys are taken from the stored
	// row, never from the caller.
	ApproveDeviceAuthorization(id string, userID tailcfg.UserID) (DeviceAuthorization, error)

	// DenyDeviceAuthorization refuses a pending, unexpired authorization.
	DenyDeviceAuthorization(id string, userID tailcfg.UserID) (DeviceAuthorization, error)

	// DeleteExpiredDeviceAuthorizations removes authorizations past their
	// expiry and reports how many were deleted.
	DeleteExpiredDeviceAuthorizations(now time.Time) (int64, error)
}
