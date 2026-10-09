package control

import (
	"fmt"
	"strings"
)

// RegistrationMode is a deployment's account-creation policy. It is a policy
// rather than a per-request option because every entry point (the JSON auth
// API, the HTML sign-up page, the console) must answer the same thing: a
// deployment that says "invite" in one place and "open" in another is a bug
// waiting to happen.
type RegistrationMode string

const (
	// RegistrationClosed accepts no self-service sign-up at all. Accounts
	// come from an identity provider or from an administrator.
	RegistrationClosed RegistrationMode = "closed"
	// RegistrationInvite requires a single-use invitation token. It is the
	// default because an invitation is the only self-service path that
	// carries the role it grants, which keeps the default least-privilege.
	RegistrationInvite RegistrationMode = "invite"
	// RegistrationOpen lets anyone create an account. Who they become
	// depends on the deployment: a single-tenant installation adds them to
	// that tenant as a member (subject to the plan's member quota), while a
	// hosted deployment with tenant provisioning gives them a tailnet of
	// their own (see selfservice.go).
	RegistrationOpen RegistrationMode = "open"
)

// DefaultRegistrationMode is what an unset configuration means. It is the
// invitation flow: no deployment becomes open by accident.
const DefaultRegistrationMode = RegistrationInvite

// ParseRegistrationMode normalizes a configured mode. The empty string means
// the default, so deployments that never set it keep their behavior.
func ParseRegistrationMode(raw string) (RegistrationMode, error) {
	mode := RegistrationMode(strings.ToLower(strings.TrimSpace(raw)))
	switch mode {
	case "":
		return DefaultRegistrationMode, nil
	case RegistrationClosed, RegistrationInvite, RegistrationOpen:
		return mode, nil
	default:
		return "", fmt.Errorf("control: unknown registration mode %q (want closed, invite or open)", raw)
	}
}

// AllowsSignup reports whether the mode accepts self-service sign-ups.
func (m RegistrationMode) AllowsSignup() bool {
	return m == RegistrationOpen || m == RegistrationInvite
}

// RequiresInvite reports whether an invitation token is mandatory.
func (m RegistrationMode) RequiresInvite() bool { return m == RegistrationInvite }

func (m RegistrationMode) String() string {
	if m == "" {
		return string(DefaultRegistrationMode)
	}
	return string(m)
}
