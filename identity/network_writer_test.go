package identity

import (
	"errors"
	"testing"
	"time"
)

func TestNetworkWriterUsesPersistedAPIKeyScopesAndOwnerRole(test *testing.T) {
	for _, scenario := range []struct {
		name    string
		scopes  []string
		stored  string
		role    Role
		allowed bool
	}{
		{"write", []string{ScopeWrite}, "", RoleOwner, true},
		{"read and write", []string{ScopeRead, ScopeWrite}, "", RoleAdmin, true},
		{"read only", []string{ScopeRead}, "", RoleOwner, false},
		{"owner demoted", []string{ScopeWrite}, "", RoleMember, false},
		{"unknown persisted scope", []string{ScopeWrite}, "write,unknown", RoleOwner, false},
		{"incorrect JSON format", []string{ScopeWrite}, `["write"]`, RoleOwner, false},
	} {
		test.Run(scenario.name, func(test *testing.T) {
			store := openTestStore(test)
			user := User{LoginName: "network-writer", Role: scenario.role}
			if err := store.CreateUser(&user); err != nil {
				test.Fatal(err)
			}
			credential, _, err := store.CreateAPIKey(NewAPIKeyOptions{Name: "configuration", UserID: user.ID, Scopes: scenario.scopes})
			if err != nil {
				test.Fatal(err)
			}
			if scenario.stored != "" {
				if _, err := store.db.ExecContext(test.Context(), "UPDATE api_keys SET scopes = ? WHERE id = ?", scenario.stored, credential.ID); err != nil {
					test.Fatal(err)
				}
			}
			transaction, err := store.db.BeginTx(test.Context(), nil)
			if err != nil {
				test.Fatal(err)
			}
			defer transaction.Rollback()
			err = CheckNetworkWriter(test.Context(), transaction, user.ID, "", credential.ID, time.Now())
			if scenario.allowed && err != nil {
				test.Fatal(err)
			}
			if !scenario.allowed && !errors.Is(err, ErrNetworkWriterForbidden) {
				test.Fatalf("unexpected authorization result: %v", err)
			}
		})
	}
}
