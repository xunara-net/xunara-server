package control

import (
	"errors"
	"os"
	"testing"
)

func TestArchivedSignupNameReleaseRollsBackOnFault(test *testing.T) {
	registry := newTestRegistry(test, test.TempDir())
	test.Cleanup(func() { registry.Close() })
	ctx := test.Context()
	if _, err := registry.create(ctx, signupTestOrg("alice"), "alice"); err != nil {
		test.Fatal(err)
	}
	if err := registry.completeSignupLogin(ctx, "alice", "alice"); err != nil {
		test.Fatal(err)
	}
	if _, err := registry.db.ExecContext(ctx, `CREATE TRIGGER deny_release BEFORE DELETE ON signup_login_claims BEGIN SELECT RAISE(ABORT, 'fixture'); END`); err != nil {
		test.Fatal(err)
	}
	if err := registry.deleteArchived(ctx, "alice"); err == nil {
		test.Fatal("fault released a completed username")
	}
	if _, found, err := registry.Get(ctx, "alice"); err != nil || !found {
		test.Fatal("failed release partially deleted the organization")
	}
	if _, err := registry.create(ctx, signupTestOrg("another"), "ALICE"); !errors.Is(err, errSignupLoginTaken) {
		test.Fatal("failed release allowed duplicate signup")
	}
	if _, err := registry.db.ExecContext(ctx, "DROP TRIGGER deny_release"); err != nil {
		test.Fatal(err)
	}
	if err := registry.deleteArchived(ctx, "alice"); err != nil {
		test.Fatal(err)
	}
	if _, err := registry.create(ctx, signupTestOrg("fresh"), "ALICE"); err != nil {
		test.Fatalf("confirmed release did not allow signup: %v", err)
	}
}

func TestUpgradeOnlyReleasesFullyDeletedSignupNames(test *testing.T) {
	router := nativeTestRouter(test)
	registry := router.cfg.Registry
	for _, orgID := range []string{"gone", "leftover"} {
		if _, err := registry.db.ExecContext(test.Context(), "INSERT INTO signup_login_claims (login_name, org_id, completed, created_at) VALUES (?, ?, 1, 1)", orgID, orgID); err != nil {
			test.Fatal(err)
		}
	}
	if err := os.MkdirAll(registry.StateDir("leftover"), 0o700); err != nil {
		test.Fatal(err)
	}
	router.mu.Lock()
	err := router.releaseDeletedSignupLoginsLocked(test.Context())
	router.mu.Unlock()
	if err != nil {
		test.Fatal(err)
	}
	for login, expected := range map[string]bool{"gone": false, "leftover": true, "alice": true} {
		reserved, err := registry.signupLoginReserved(test.Context(), login)
		if err != nil || reserved != expected {
			test.Fatalf("reservation %s = %v, %v", login, reserved, err)
		}
	}
}
