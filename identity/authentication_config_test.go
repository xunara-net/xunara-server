package identity

import (
	"bytes"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestAuthenticationConfigurationAtomicOwnerAuditAndInvalidation(test *testing.T) {
	store := openTestStore(test)
	user, _, session, token := seedAccount(test, store, "owner")
	write := AuthenticationConfigWrite{UserID: user.ID, SessionID: session.ID, Detail: "registration policy updated"}
	config := AuthenticationConfig{Payload: []byte(`{"registration":"invite"}`)}
	if _, err := store.SaveAuthenticationConfig(test.Context(), config, write); !errors.Is(err, ErrInviteOwnerRequired) {
		test.Fatalf("member wrote configuration: %v", err)
	}
	user.Role = RoleOwner
	if err := store.UpdateUser(user); err != nil {
		test.Fatal(err)
	}
	authorization, _, err := store.CreateAuthTransaction(NewAuthTransactionOptions{ProviderID: "external"})
	if err != nil {
		test.Fatal(err)
	}
	if _, err := store.db.Exec(`CREATE TRIGGER fail_auth_configuration_audit BEFORE INSERT ON audit_events WHEN NEW.action = 'authentication.configured' BEGIN SELECT RAISE(ABORT, 'audit failure'); END;`); err != nil {
		test.Fatal(err)
	}
	if _, err := store.SaveAuthenticationConfig(test.Context(), config, write); err == nil {
		test.Fatal("configuration committed without its required audit")
	}
	if saved, err := store.ReadAuthenticationConfig(test.Context()); err != nil || saved.Revision != 0 {
		test.Fatal("audit failure changed the configuration")
	}
	if _, exists := store.GetAuthTransaction(authorization.ID); !exists {
		test.Fatal("audit rollback lost a pending transaction")
	}
	if _, err := store.db.Exec("DROP TRIGGER fail_auth_configuration_audit"); err != nil {
		test.Fatal(err)
	}
	saved, err := store.SaveAuthenticationConfig(test.Context(), config, write)
	if err != nil || saved.Revision != 1 || !bytes.Equal(saved.Payload, config.Payload) {
		test.Fatalf("configuration write: %v", err)
	}
	if _, exists := store.GetAuthTransaction(authorization.ID); exists {
		test.Fatal("old external transaction was not invalidated")
	}
	if _, err := store.GetSessionByToken(token); err != nil {
		test.Fatal("configuration change revoked an existing session")
	}
	if _, _, err := store.CreateAuthTransaction(NewAuthTransactionOptions{ProviderID: "external"}); !errors.Is(err, ErrAuthenticationConfigChanged) {
		test.Fatal("stale authorization started after configuration changed")
	}
	if _, _, _, err := store.RegisterLocalAccount(test.Context(), LocalRegistration{LoginName: "stale", PasswordHash: []byte("hash"), MaxUsers: -1}); !errors.Is(err, ErrAuthenticationConfigChanged) {
		test.Fatal("stale local signup bypassed the new policy")
	}
	if _, _, err := store.CreateAuthTransaction(NewAuthTransactionOptions{ProviderID: "external", AuthenticationRevision: 1}); err != nil {
		test.Fatal(err)
	}
}

func TestAuthenticationConfigurationCrossInstanceCAS(test *testing.T) {
	first, second := openAccountStores(test)
	var wait sync.WaitGroup
	results := make(chan error, 2)
	for _, store := range []*SQLiteStore{first, second} {
		wait.Add(1)
		go func(store *SQLiteStore) {
			defer wait.Done()
			_, err := store.SaveAuthenticationConfig(test.Context(), AuthenticationConfig{Payload: []byte(`{}`)}, AuthenticationConfigWrite{Platform: true, Detail: "configuration updated"})
			results <- err
		}(store)
	}
	wait.Wait()
	close(results)
	successes := 0
	for err := range results {
		if err == nil {
			successes++
		} else if !errors.Is(err, ErrAuthenticationConfigChanged) {
			test.Fatal(err)
		}
	}
	if successes != 1 || len(first.ListAudit(0)) != 1 {
		test.Fatal("concurrent configuration writes did not have exactly one winner")
	}
	if saved, err := second.ReadAuthenticationConfig(test.Context()); err != nil || saved.Revision != 1 {
		test.Fatal("second instance did not see the committed configuration")
	}
}

func TestAuthenticationConfigurationProtectsOnlyProviderLogin(test *testing.T) {
	store := openTestStore(test)
	user := User{LoginName: "external-only", Role: RoleMember}
	if err := store.CreateUser(&user); err != nil {
		test.Fatal(err)
	}
	if err := store.LinkExternalIdentity(&ExternalIdentity{ProviderID: "external", Subject: "subject", UserID: user.ID}); err != nil {
		test.Fatal(err)
	}
	write := AuthenticationConfigWrite{Platform: true, Removed: []string{"external"}, Methods: LoginMethods{Local: true}, Detail: "provider disabled"}
	config := AuthenticationConfig{Payload: []byte(`{}`)}
	if _, err := store.SaveAuthenticationConfig(test.Context(), config, write); !errors.Is(err, ErrLastLoginMethod) {
		test.Fatalf("external-only account locked out: %v", err)
	}
	if saved, _ := store.ReadAuthenticationConfig(test.Context()); saved.Revision != 0 {
		test.Fatal("last-login guard did not roll back")
	}
	if err := store.SetLocalCredential(&LocalCredential{UserID: user.ID, PasswordHash: accountHash(test, "recovery password")}); err != nil {
		test.Fatal(err)
	}
	if _, err := store.SaveAuthenticationConfig(test.Context(), config, write); err != nil {
		test.Fatal(err)
	}
	if _, exists := store.GetExternalIdentity("external", "subject"); !exists {
		test.Fatal("disabling provider deleted a binding")
	}
	_, token, err := store.CreateSession(NewSessionOptions{UserID: user.ID, TTL: time.Hour})
	if err != nil {
		test.Fatal(err)
	}
	if _, err := store.GetSessionByToken(token); err != nil {
		test.Fatal(err)
	}
}
