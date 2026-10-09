package identity

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

func passkeyTestSessionID(t *testing.T, store Store, user User) string {
	t.Helper()
	session, _, err := store.CreateSession(NewSessionOptions{UserID: user.ID, AuthMethod: LocalProviderID})
	if err != nil {
		t.Fatal(err)
	}
	return session.ID
}

func accountTestPasskey(user User, name string) Passkey {
	credential := newTestPasskey(name)
	return Passkey{UserID: user.ID, Name: name, CredentialID: credential.ID, Credential: credential}
}

func TestAccountPasskeyPersistenceAndScope(t *testing.T) {
	store, peer := openAccountStores(t)
	user, _, current, token := seedAccount(t, store, "alice")
	foreignUser, _, foreignSession, foreignToken := seedAccount(t, peer, "bob")
	passkey, err := store.CreateAccountPasskey(t.Context(), current.ID, accountTestPasskey(user, "电脑"))
	if err != nil {
		t.Fatal(err)
	}
	listed, err := peer.ListAccountPasskeys(t.Context(), user.ID)
	if err != nil || len(listed) != 1 || listed[0].ID != passkey.ID {
		t.Fatalf("persistent list: %d, %v", len(listed), err)
	}
	if err := peer.DeleteAccountPasskey(t.Context(), foreignUser.ID, foreignSession.ID, passkey.ID); !errors.Is(err, ErrPasskeyNotFound) {
		t.Fatal("foreign user deleted a passkey")
	}
	if _, _, err := peer.CreatePasskeySession(t.Context(), foreignUser.ID, passkey.ID, time.Hour); !errors.Is(err, ErrPasskeyNotFound) {
		t.Fatal("credential issued a foreign-user session")
	}
	login, loginToken, err := peer.CreatePasskeySession(t.Context(), user.ID, passkey.ID, time.Hour)
	if err != nil || login.AuthMethod != "passkey" {
		t.Fatal("could not issue a passkey session")
	}
	if err := peer.DeleteAccountPasskey(t.Context(), user.ID, current.ID, passkey.ID); err != nil {
		t.Fatal(err)
	}
	if _, returnedToken, err := store.CreatePasskeySession(t.Context(), user.ID, passkey.ID, time.Hour); !errors.Is(err, ErrPasskeyNotFound) || returnedToken != "" {
		t.Fatal("deleted credential issued a new session")
	}
	if _, err := store.GetSessionByToken(loginToken); err != nil {
		t.Fatal("deleting a passkey implicitly revoked an existing session")
	}
	for _, event := range peer.ListAudit(0) {
		if strings.Contains(event.Detail, token) || strings.Contains(event.Detail, foreignToken) || strings.Contains(event.Detail, loginToken) {
			t.Fatal("audit leaked a session token")
		}
	}
}

func TestAccountPasskeyInitiatingSessionGuard(t *testing.T) {
	for _, condition := range []string{"revoked", "expired", "foreign", "missing"} {
		t.Run(condition, func(t *testing.T) {
			store, peer := openAccountStores(t)
			user, _, current, _ := seedAccount(t, store, "alice")
			foreignUser, _, foreign, _ := seedAccount(t, peer, "bob")
			passkey, err := store.CreateAccountPasskey(t.Context(), current.ID, accountTestPasskey(user, "existing"))
			if err != nil {
				t.Fatal(err)
			}
			initiatingID := current.ID
			switch condition {
			case "revoked":
				if err := peer.RevokeSession(current.ID, "test"); err != nil {
					t.Fatal(err)
				}
			case "expired":
				if _, err := peer.db.Exec("UPDATE sessions SET expires_at = 1 WHERE id = ?", current.ID); err != nil {
					t.Fatal(err)
				}
			case "foreign":
				initiatingID = foreign.ID
			case "missing":
				initiatingID = "missing"
			}
			if _, err := store.CreateAccountPasskey(t.Context(), initiatingID, accountTestPasskey(user, "new")); !errors.Is(err, ErrSessionRevoked) {
				t.Fatalf("registration accepted invalid initiator: %v", err)
			}
			if err := store.DeleteAccountPasskey(t.Context(), user.ID, initiatingID, passkey.ID); !errors.Is(err, ErrSessionRevoked) {
				t.Fatalf("deletion accepted invalid initiator: %v", err)
			}
			listed, err := peer.ListAccountPasskeys(t.Context(), user.ID)
			if err != nil || len(listed) != 1 || len(peer.ListAudit(0)) != 1 {
				t.Fatal("failed operations changed credentials or success audits")
			}
			if listed, err := store.ListAccountPasskeys(t.Context(), foreignUser.ID); err != nil || len(listed) != 0 {
				t.Fatal("foreign credentials were affected")
			}
		})
	}
}

func TestAccountPasskeyAuditRollback(t *testing.T) {
	for _, operation := range []string{"register", "delete", "login"} {
		t.Run(operation, func(t *testing.T) {
			store, peer := openAccountStores(t)
			user, _, current, _ := seedAccount(t, store, "alice")
			passkey := accountTestPasskey(user, "existing")
			if operation != "register" {
				if err := store.CreatePasskey(&passkey); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := peer.db.Exec(`CREATE TRIGGER reject_passkey_audit BEFORE INSERT ON audit_events BEGIN SELECT RAISE(ABORT, 'injected audit failure'); END`); err != nil {
				t.Fatal(err)
			}
			var err error
			switch operation {
			case "register":
				_, err = store.CreateAccountPasskey(t.Context(), current.ID, passkey)
			case "delete":
				err = store.DeleteAccountPasskey(t.Context(), user.ID, current.ID, passkey.ID)
			case "login":
				var token string
				_, token, err = store.CreatePasskeySession(t.Context(), user.ID, passkey.ID, time.Hour)
				if token != "" {
					t.Fatal("failed transaction returned a usable token")
				}
			}
			if err == nil {
				t.Fatal("injected failure was ignored")
			}
			passkeys, err := peer.ListAccountPasskeys(t.Context(), user.ID)
			wantCount := 1
			if operation == "register" {
				wantCount = 0
			}
			if err != nil || len(passkeys) != wantCount || len(peer.ListAudit(0)) != 0 || len(peer.ListSessions(user.ID)) != 1 {
				t.Fatal("audit failure did not roll back the transaction")
			}
		})
	}
}

func TestAccountPasskeyReadFailureAndCancellation(t *testing.T) {
	store := openTestStore(t)
	user, _, current, _ := seedAccount(t, store, "alice")
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := store.ListAccountPasskeys(ctx, user.ID); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled list was accepted")
	}
	if _, err := store.CreateAccountPasskey(ctx, current.ID, accountTestPasskey(user, "new")); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled registration was accepted")
	}
	if err := store.DeleteAccountPasskey(ctx, user.ID, current.ID, "missing"); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled deletion was accepted")
	}
	if _, err := store.db.Exec("DROP TABLE webauthn_credentials"); err != nil {
		t.Fatal(err)
	}
	if listed, err := store.ListAccountPasskeys(t.Context(), user.ID); err == nil || listed != nil {
		t.Fatal("read failure was represented as an empty success")
	}
}

func TestAccountPasskeyRegistrationRevocationRace(t *testing.T) {
	store, peer := openAccountStores(t)
	user := User{LoginName: "alice"}
	if err := store.CreateUser(&user); err != nil {
		t.Fatal(err)
	}
	for iteration := 0; iteration < 8; iteration++ {
		initiatingID := passkeyTestSessionID(t, store, user)
		start := make(chan struct{})
		var group sync.WaitGroup
		var registered Passkey
		var registrationError, revocationError error
		group.Add(2)
		go func() {
			defer group.Done()
			<-start
			registered, registrationError = store.CreateAccountPasskey(t.Context(), initiatingID, accountTestPasskey(user, "race"))
		}()
		go func() {
			defer group.Done()
			<-start
			_, revocationError = peer.RevokeAccountSessions(t.Context(), user.ID, initiatingID, SessionRevocation{Mode: RevokeAllSessions})
		}()
		close(start)
		group.Wait()
		if revocationError != nil {
			t.Fatal(revocationError)
		}
		if registrationError != nil && !errors.Is(registrationError, ErrSessionRevoked) {
			t.Fatal(registrationError)
		}
		if registrationError == nil {
			if err := store.DeletePasskey(registered.ID, user.ID); err != nil {
				t.Fatal(err)
			}
		} else if keys, err := peer.ListAccountPasskeys(t.Context(), user.ID); err != nil || len(keys) != 0 {
			t.Fatal("revoked initiating session still registered a credential")
		}
	}
}
