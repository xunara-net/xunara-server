package control

import (
	"errors"
	"fmt"

	"github.com/xunara-net/xunara-server/identity"
	"github.com/xunara-net/xunara-server/state"
)

// The built-in local account.
//
// Every control plane starts with one user: the built-in local owner
// (identity.EnsureLocalUser). It exists so that a brand-new installation has
// somebody who can grant the first role, and so that nodes and pre-auth keys
// have a user to belong to.
//
// Two flows turn that placeholder into a real account by claiming it: the
// first-run setup page, and the platform's tenant provisioner, which creates a
// tenant per sign-up. Claiming rather than creating a second user matters for
// more than tidiness: the new tenant is on a plan from the moment it exists,
// and the shipped free plan allows exactly one member. Creating another user
// would either burn that allowance on an account nobody can sign in as, or
// fail the sign-up outright on the customer's first day.

// Errors [Server.claimLocalAccount] returns. They are deliberately coarse:
// callers render their own copy, and an account that does not exist is an
// internal failure, not something the person in front of the form can fix.
var (
	errLocalAccountMissing = errors.New("control: the built-in local account is missing")
	errLoginNameTaken      = errors.New("control: that login name is already taken")
)

// claimLocalAccount binds the built-in user to a real account: the login name,
// display name, email and role given, plus the password. It is idempotent in
// the sense that matters — claiming an already claimed account replaces its
// password and names, which is what a password reset is.
func (s *Server) claimLocalAccount(login, display, email string, role identity.Role, password string) (identity.User, error) {
	user, ok := s.identity.GetUser(state.DefaultUserID)
	if !ok {
		return identity.User{}, errLocalAccountMissing
	}
	if other, taken := s.identity.GetUserByLoginName(login); taken && other.ID != user.ID {
		return identity.User{}, errLoginNameTaken
	}

	hash, err := identity.HashPassword(password)
	if err != nil {
		return identity.User{}, fmt.Errorf("hashing password: %w", err)
	}

	user.LoginName = login
	if display != "" {
		user.DisplayName = display
	} else if user.DisplayName == "" {
		user.DisplayName = login
	}
	if email != "" {
		user.Email = email
	}
	// The role is enforced here rather than inherited from whatever the row
	// happened to hold: both callers are creating the account that owns the
	// organization.
	user.Role = role
	if err := s.identity.UpdateUser(user); err != nil {
		return identity.User{}, fmt.Errorf("updating the local account: %w", err)
	}
	if err := s.identity.SetLocalCredential(&identity.LocalCredential{
		UserID:       user.ID,
		PasswordHash: hash,
	}); err != nil {
		return identity.User{}, fmt.Errorf("storing the local password: %w", err)
	}
	return user, nil
}
