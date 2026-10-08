package control

import (
	"context"
	"fmt"

	"github.com/xunara-net/xunara-server/identity"
	"github.com/xunara-net/xunara-server/state"
)

// newIdentityStore opens the trust plane on the control plane's database and
// makes sure the local user exists.
func newIdentityStore(store *state.SQLiteStore) (identity.Store, error) {
	ctx := context.Background()

	s, err := identity.NewSQLiteStore(ctx, store.DB())
	if err != nil {
		return nil, err
	}

	user, created, err := identity.EnsureLocalUser(s)
	if err != nil {
		return nil, fmt.Errorf("control: seeding the local user: %w", err)
	}
	if created {
		event := identity.AuditEvent{
			Actor:  "system",
			Action: identity.AuditUserCreated,
			Target: fmt.Sprintf("user:%d", user.ID),
			Detail: "created the built-in local user",
		}
		if err := s.AppendAudit(&event); err != nil {
			return nil, err
		}
	}
	return s, nil
}
