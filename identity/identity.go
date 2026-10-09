// Package identity holds Xunara's trust plane: who a human, a machine and a
// service are, and how that came to be known.
//
// The package is built around three deliberately separate objects
// (AGENTS.md section 10):
//
//	AuthTransaction     one login attempt, with its OAuth state and PKCE
//	Session             a logged-in browser, revocable and expiring
//	DeviceAuthorization one machine waiting for a human to authorize it
//
// They share nothing but identifiers. A design that folds them into one cache
// entry is exactly what this package exists to avoid.
package identity

import (
	"time"

	"tailscale.com/tailcfg"
)

// User is a human (or service) identity in Xunara.
type User struct {
	ID          tailcfg.UserID
	LoginName   string
	DisplayName string
	// Email is an attribute, never an identity key (AGENTS.md section 6).
	Email string
	// Role gates the platform layer (console, API, CLI). The zero value is
	// treated as [RoleMember] on write and reported as-is on read.
	Role      Role
	CreatedAt time.Time
	UpdatedAt time.Time
}

// ExternalIdentity binds a user to an account at an external provider.
//
// The identity key is exactly (ProviderID, Subject). Email is stored for
// display and for matching heuristics an administrator may confirm, but it
// never identifies an account on its own.
type ExternalIdentity struct {
	ProviderID  string
	Subject     string
	UserID      tailcfg.UserID
	Email       string
	DisplayName string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// IdentityResult is what a provider returns after a successful authentication.
//
// It is deliberately not a session: the caller decides which user to attach the
// result to, and creating a session is a separate, audited step.
type IdentityResult struct {
	// ProviderID identifies the provider that authenticated the subject.
	ProviderID string

	// Subject is the provider's stable, unique identifier for the account. It
	// is the only part of the result that is an identity key.
	Subject string

	// Email is an attribute the provider reports. It is never used to link
	// accounts automatically.
	Email string

	// DisplayName is a human-readable name, for display only.
	DisplayName string

	// Claims are the raw claims, for claims mapping and debugging. They must
	// not be logged verbatim: they can contain tokens.
	Claims map[string]any
}

// LocalProviderID is the provider ID used for locally created users.
const LocalProviderID = "local"

// LocalLoginName is the login name of the single-user tailnet's user.
const LocalLoginName = "local"

// LocalDisplayName is the display name of that user.
const LocalDisplayName = "Xunara User"

// EnsureLocalUser creates the built-in local user when the store is empty.
//
// It returns the user and whether it was created. The first user gets ID 1,
// which is the ID nodes and pre-auth keys default to.
func EnsureLocalUser(store Store) (User, bool, error) {
	if users := store.ListUsers(); len(users) > 0 {
		return users[0], false, nil
	}

	u := User{
		LoginName:   LocalLoginName,
		DisplayName: LocalDisplayName,
		// The built-in user bootstraps the tailnet and owns it: someone must
		// be able to grant the first OIDC user a role.
		Role: RoleOwner,
	}
	if err := store.CreateUser(&u); err != nil {
		return User{}, false, err
	}

	// The local user is also reachable as an external identity, so a
	// deployment that later adds an OIDC provider keeps a stable key for it.
	ei := ExternalIdentity{
		ProviderID:  LocalProviderID,
		Subject:     LocalLoginName,
		UserID:      u.ID,
		DisplayName: u.DisplayName,
	}
	if err := store.LinkExternalIdentity(&ei); err != nil {
		return User{}, false, err
	}
	return u, true, nil
}

// AuditEvent is one entry in the control plane's audit log.
//
// The actor is recorded as a free-form string ("user:1", "system", "cli") so
// that machine, human and service actors stay distinguishable in the log.
type AuditEvent struct {
	ID     uint64
	Time   time.Time
	Actor  string
	Action string
	Target string
	Detail string
}

// AuditActions are the actions this build records. They are constants so that
// the log stays greppable and so that action names cannot drift.
const (
	AuditUserCreated          = "user.created"
	AuditUserUpdated          = "user.updated"
	AuditUserRoleChanged      = "user.role_changed"
	AuditPasswordChanged      = "user.password_changed"
	AuditPasswordChangeFailed = "user.password_change_failed"
	AuditNodeRegistered       = "node.registered"
	AuditNodeApproved         = "node.approved"
	AuditNodeReaped           = "node.reaped"
	AuditNodeDeleted          = "node.deleted"
	// AuditNodeKeyRotated records a node key rotation: the same machine key
	// re-authorized with a new node key, so the node kept its identity
	// (ID/StableID/ownership) instead of registering a duplicate.
	AuditNodeKeyRotated = "node.key_rotated"
	// AuditNodeDisconnectReported is a client-reported disconnect (the user
	// ran `tailscale down` or the node shut down), delivered through
	// /machine/audit-log.
	AuditNodeDisconnectReported = "node.disconnect_reported"
	// AuditAgentEnrolled records a native client (Xunara Agent) enrolling or
	// rotating its machine-bound credential.
	AuditAgentEnrolled = "agent.enrolled"
	// AuditAgentTokenRevoked records an administrator revoking a native
	// client's machine-bound credential.
	AuditAgentTokenRevoked = "agent.token_revoked"
	// AuditWebhookCreated and AuditWebhookDeleted record managed webhook
	// receivers being added to or removed from the control plane.
	AuditWebhookCreated    = "webhook.created"
	AuditWebhookDeleted    = "webhook.deleted"
	AuditRouteApproved     = "route.approved"
	AuditRouteUnapproved   = "route.unapproved"
	AuditDNSRecordSet      = "dns.record_set"
	AuditDNSRecordDeleted  = "dns.record_deleted"
	AuditPolicyReloaded    = "policy.reloaded"
	AuditPreAuthKeyCreated = "preauthkey.created"
	AuditPreAuthKeyDeleted = "preauthkey.deleted"
	AuditLoginSucceeded    = "login.succeeded"
	AuditLoginFailed       = "login.failed"
	AuditSessionCreated    = "session.created"
	AuditSessionRevoked    = "session.revoked"
	AuditDeviceApproved    = "device.approved"
	AuditDeviceDenied      = "device.denied"
	AuditTagRejected       = "device.tag_rejected"
	AuditAPIKeyCreated     = "apikey.created"
	AuditAPIKeyRevoked     = "apikey.revoked"
	AuditSSHCheckApproved  = "ssh.check_approved"
	AuditSSHCheckDenied    = "ssh.check_denied"
	// AuditTailnetLockEnabled, AuditTailnetLockDisabled and
	// AuditTailnetLockNodeSigned record tailnet-lock (TKA) lifecycle events:
	// a genesis chain being installed, the authority being disabled, and a
	// node key being signed.
	AuditTailnetLockEnabled    = "tailnet_lock.enabled"
	AuditTailnetLockDisabled   = "tailnet_lock.disabled"
	AuditTailnetLockNodeSigned = "tailnet_lock.node_signed"
	// AuditIDTokenIssued records a node minting an OIDC identity token for a
	// third-party audience through /machine/id-token. The token itself is a
	// bearer credential and is never written: the record names the node and
	// the audience, which is what an incident review needs to correlate.
	AuditIDTokenIssued = "identity_token.issued"
	// AuditDeviceAttrsUpdated records a node reporting device posture
	// attributes about itself through /machine/set-device-attr. The detail
	// names the attributes that were set or deleted, never their values.
	AuditDeviceAttrsUpdated = "node.device_attrs_updated"
	AuditShareCreated       = "share.created"
	AuditShareAccepted      = "share.accepted"
	AuditShareRejected      = "share.rejected"
	AuditShareRevoked       = "share.revoked"
	// AuditRelayEnrolled records a relay exchanging its one-time enrollment
	// token for a long-lived identity. The record names the relay and its
	// region; neither credential is ever written.
	AuditRelayEnrolled           = "relay.enrolled"
	AuditRelayEnrollTokenCreated = "relay.enrollment_token_created"
	AuditRelayEnrollTokenRevoked = "relay.enrollment_token_revoked"
	AuditRelayUpdated            = "relay.updated"
	AuditRelayDeleted            = "relay.deleted"
	// AuditAdminBootstrap records the first-run setup that gave the built-in
	// administrator its password. The detail names the login, never the
	// password or its hash.
	AuditAdminBootstrap = "admin.bootstrap"
	// AuditInviteCreated and AuditInviteRevoked track registration invites by
	// ID; the token itself is never stored or logged.
	AuditInviteCreated = "invite.created"
	AuditInviteRevoked = "invite.revoked"
	// AuditInviteRedeemed records an invite being spent, by invite ID and
	// the account it created.
	AuditInviteRedeemed = "invite.redeemed"
	// AuditUserRegistered records an account created by redeeming an invite.
	AuditUserRegistered = "user.registered"
	// AuditNodeExpiryShortened records a node shortening its own key expiry
	// (upstream LocalBackend.SetExpirySooner). Extensions are rejected, so the
	// expiry in this record is always sooner than the previous one.
	AuditNodeExpiryShortened = "node.expiry_shortened"
	// AuditServicesUpdated records a node publishing the set of services it
	// advertises (Xunara Atlas). The detail lists names, protocols and ports,
	// never metadata values.
	AuditServicesUpdated = "node.services_updated"
	// AuditServiceHealthy and AuditServiceUnhealthy record a health-tracked
	// service becoming discoverable or being withdrawn from discovery
	// (section 26). They are written on transitions only, so a node repeating
	// "ready" does not spam the log; the detail names the service and the
	// static reason (reported / report expired), never metadata.
	AuditServiceHealthy   = "service.healthy"
	AuditServiceUnhealthy = "service.unhealthy"
	// AuditPasskeyRegistered and AuditPasskeyDeleted record a user adding or
	// removing a WebAuthn credential. The detail names the user-chosen label,
	// never the credential ID, public key or challenge.
	AuditPasskeyRegistered = "passkey.registered"
	AuditPasskeyDeleted    = "passkey.deleted"
	// Xunara Flux (file transfer) lifecycle. Details name the transfer ID,
	// file name and size; content and keys are never written.
	AuditFluxOffered   = "flux.transfer_offered"
	AuditFluxAccepted  = "flux.transfer_accepted"
	AuditFluxDenied    = "flux.transfer_denied"
	AuditFluxUploaded  = "flux.transfer_uploaded"
	AuditFluxCompleted = "flux.transfer_completed"
	AuditFluxFailed    = "flux.transfer_failed"
	AuditFluxCancelled = "flux.transfer_cancelled"
	AuditFluxExpired   = "flux.transfer_expired"

	// Xunara Reach remote command sessions (PROJECT_SPEC section 29). argv and
	// output never appear in audit details.
	AuditReachOffered  = "reach.offered"
	AuditReachAccepted = "reach.accepted"
	AuditReachDenied   = "reach.denied"
	AuditReachStarted  = "reach.started"
	AuditReachFinished = "reach.finished"
	AuditReachFailed   = "reach.failed"
	AuditReachCanceled = "reach.canceled"
	AuditReachExpired  = "reach.expired"

	// Commercial plan changes (PROJECT_SPEC section 54). They are written to
	// the affected tenant's audit log, so a member can see that the platform
	// moved the tailnet to another plan or network range.
	AuditPlanChanged  = "plan.changed"
	AuditNetworkSet   = "plan.network_set"
	AuditQuotaReached = "plan.quota_reached"
)
