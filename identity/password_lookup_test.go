package identity

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
)

func TestPasswordLookupsPreserveIdentityAndMissingRecords(t *testing.T) {
	store := openTestStore(t)
	user := User{LoginName: "Password-Lookup", DisplayName: "读取测试", Role: RoleMember}
	if err := store.CreateUser(&user); err != nil {
		t.Fatal(err)
	}
	read, err := store.LookupUserByLoginName(t.Context(), strings.ToLower(user.LoginName))
	if err != nil || read.ID != user.ID || read.Role != RoleMember {
		t.Fatal("case-insensitive login lookup changed identity")
	}
	if _, err := store.LookupUserByLoginName(t.Context(), "unknown"); !errors.Is(err, ErrUserNotFound) {
		t.Fatal("unknown login did not return the missing-user result")
	}
	if _, err := store.LookupLocalCredential(t.Context(), user.ID); !errors.Is(err, ErrCredentialNotFound) {
		t.Fatal("account without a password did not return the missing-credential result")
	}
	if count, err := store.LocalCredentialCount(t.Context()); err != nil || count != 0 {
		t.Fatal("empty credential store was not counted")
	}
	hash, err := HashPassword("real password lookup fixture")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetLocalCredential(&LocalCredential{UserID: user.ID, PasswordHash: hash}); err != nil {
		t.Fatal(err)
	}
	credential, err := store.LookupLocalCredential(t.Context(), user.ID)
	if err != nil || credential.UserID != user.ID || !bytes.Equal(credential.PasswordHash, hash) || credential.CreatedAt.IsZero() || credential.UpdatedAt.IsZero() {
		t.Fatal("password lookup lost stored attributes")
	}
	if count, err := store.LocalCredentialCount(t.Context()); err != nil || count != 1 {
		t.Fatal("credential count lost an existing password")
	}
	legacyUser, exists := store.GetUserByLoginName(strings.ToUpper(user.LoginName))
	if !exists || legacyUser.ID != user.ID {
		t.Fatal("legacy user adapter no longer shares lookup semantics")
	}
	legacyCredential, exists := store.GetLocalCredential(user.ID)
	if !exists || !bytes.Equal(legacyCredential.PasswordHash, credential.PasswordHash) || store.CountLocalCredentials() != 1 {
		t.Fatal("legacy credential adapters no longer share lookup semantics")
	}
}

func TestPasswordLookupsPreserveStorageErrorsAndCancellation(t *testing.T) {
	for _, fault := range []string{"cancellation", "closed database"} {
		t.Run(fault, func(t *testing.T) {
			store := openTestStore(t)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if fault == "cancellation" {
				cancel()
			} else if err := store.db.Close(); err != nil {
				t.Fatal(err)
			}
			for _, lookup := range []struct {
				name string
				read func() error
			}{
				{"login name", func() error { _, err := store.LookupUserByLoginName(ctx, "unknown"); return err }},
				{"password", func() error { _, err := store.LookupLocalCredential(ctx, 1); return err }},
				{"setup count", func() error { _, err := store.LocalCredentialCount(ctx); return err }},
			} {
				t.Run(lookup.name, func(t *testing.T) {
					err := lookup.read()
					if err == nil || errors.Is(err, ErrUserNotFound) || errors.Is(err, ErrCredentialNotFound) {
						t.Fatal("failed lookup was disguised as a missing account or password")
					}
					if fault == "cancellation" && !errors.Is(err, context.Canceled) {
						t.Fatal("lookup did not preserve cancellation")
					}
				})
			}
		})
	}
}

func TestPasswordLookupsDoNotHideScanErrors(t *testing.T) {
	store := openTestStore(t)
	user := User{LoginName: "scan-failure", Role: RoleMember}
	if err := store.CreateUser(&user); err != nil {
		t.Fatal(err)
	}
	if err := store.SetLocalCredential(&LocalCredential{UserID: user.ID, PasswordHash: []byte("lookup-only fixture")}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec("UPDATE users SET created_at = 'unreadable timestamp' WHERE id = ?", user.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.LookupUserByLoginName(t.Context(), user.LoginName); err == nil || errors.Is(err, ErrUserNotFound) {
		t.Fatal("invalid user row was disguised as unknown")
	}
	if _, err := store.db.Exec("UPDATE local_credentials SET created_at = 'unreadable timestamp' WHERE user_id = ?", user.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.LookupLocalCredential(t.Context(), user.ID); err == nil || errors.Is(err, ErrCredentialNotFound) {
		t.Fatal("invalid credential row was disguised as absent")
	}
}
