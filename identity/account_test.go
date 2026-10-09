package identity

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func accountHash(t *testing.T, password string) []byte {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	return hash
}

func seedAccount(t *testing.T, store *SQLiteStore, login string) (User, []byte, Session, string) {
	t.Helper()
	user := User{LoginName: login, Role: RoleMember}
	if err := store.CreateUser(&user); err != nil {
		t.Fatal(err)
	}
	hash := accountHash(t, "original account password")
	if err := store.SetLocalCredential(&LocalCredential{UserID: user.ID, PasswordHash: hash}); err != nil {
		t.Fatal(err)
	}
	session, token, err := store.CreateLocalSession(t.Context(), user.ID, hash, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return user, hash, session, token
}

func openAccountStores(t *testing.T) (*SQLiteStore, *SQLiteStore) {
	t.Helper()
	dsn := "file:" + filepath.Join(t.TempDir(), "account.db") + "?_txlock=immediate&_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)"
	open := func() *SQLiteStore {
		database, err := sql.Open("sqlite", dsn)
		if err != nil {
			t.Fatal(err)
		}
		database.SetMaxOpenConns(1)
		t.Cleanup(func() { database.Close() })
		store, err := NewSQLiteStore(t.Context(), database)
		if err != nil {
			t.Fatal(err)
		}
		return store
	}
	return open(), open()
}

func TestAccountProfilePreservesIdentity(t *testing.T) {
	store := openTestStore(t)
	user, _, _, _ := seedAccount(t, store, "alice")
	user.LoginName = "renamed-alice"
	user.Role = RoleAdmin
	user.Email = "original@example.test"
	if err := store.UpdateUser(user); err != nil {
		t.Fatal(err)
	}
	display := "玄序用户"
	updated, err := store.UpdateUserProfile(t.Context(), user.ID, &display, nil)
	if err != nil {
		t.Fatal(err)
	}
	if updated.DisplayName != display || updated.LoginName != user.LoginName || updated.Role != RoleAdmin || updated.Email != user.Email || !updated.CreatedAt.Equal(user.CreatedAt) {
		t.Fatalf("profile overwrote identity fields: %+v", updated)
	}
	email := ""
	updated, err = store.UpdateUserProfile(t.Context(), user.ID, nil, &email)
	if err != nil || updated.Email != "" || updated.DisplayName != display {
		t.Fatalf("clearing email: %+v, %v", updated, err)
	}
	if _, err := store.UpdateUserProfile(t.Context(), 999, &display, nil); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("unknown user: %v", err)
	}
	if _, err := store.UpdateUserProfile(t.Context(), user.ID, nil, nil); err == nil {
		t.Fatal("empty profile update succeeded")
	}
	for _, event := range store.ListAudit(0) {
		if strings.Contains(event.Detail, user.Email) || strings.Contains(event.Detail, display) {
			t.Fatal("audit leaked profile values")
		}
	}
}

func TestAccountPasswordAtomicRevocation(t *testing.T) {
	store, peer := openAccountStores(t)
	user, originalHash, session, token := seedAccount(t, store, "alice")
	original, _ := store.GetLocalCredential(user.ID)
	_, externalToken, err := peer.CreateSession(NewSessionOptions{UserID: user.ID, AuthMethod: "oidc:test"})
	if err != nil {
		t.Fatal(err)
	}
	_, _, _, otherToken := seedAccount(t, peer, "bob")
	_, apiToken, err := store.CreateAPIKey(NewAPIKeyOptions{UserID: user.ID, Name: "automation", Scopes: []string{ScopeRead}})
	if err != nil {
		t.Fatal(err)
	}
	replacement := accountHash(t, "replacement account password")
	revoked, err := peer.ChangeLocalPassword(t.Context(), user.ID, session.ID, originalHash, replacement)
	if err != nil || revoked != 2 {
		t.Fatalf("password change revoked %d: %v", revoked, err)
	}
	updated, _ := store.GetLocalCredential(user.ID)
	if !bytes.Equal(updated.PasswordHash, replacement) || !updated.CreatedAt.Equal(original.CreatedAt) || !updated.UpdatedAt.After(original.UpdatedAt) {
		t.Fatal("credential replacement or timestamps are incorrect")
	}
	for _, oldToken := range []string{token, externalToken} {
		if _, err := store.GetSessionByToken(oldToken); !errors.Is(err, ErrSessionNotFound) {
			t.Fatal("an old session is still live")
		}
	}
	if _, err := store.GetSessionByToken(otherToken); err != nil {
		t.Fatal("another user's session was revoked")
	}
	if _, err := store.GetAPIKeyByToken(apiToken); err != nil {
		t.Fatal("a service identity was revoked by a human password change")
	}
	if _, _, err := store.CreateLocalSession(t.Context(), user.ID, originalHash, time.Hour); !errors.Is(err, ErrCredentialChanged) {
		t.Fatalf("stale password login: %v", err)
	}
	if _, _, err := store.CreateLocalSession(t.Context(), user.ID, replacement, time.Hour); err != nil {
		t.Fatalf("replacement password login: %v", err)
	}
	events := store.ListAudit(0)
	if len(events) != 1 || events[0].Action != AuditPasswordChanged || events[0].Actor != "user:1" || events[0].Target != "user:1" {
		t.Fatalf("password audit: %+v", events)
	}
	if strings.Contains(events[0].Detail, string(originalHash)) || strings.Contains(events[0].Detail, string(replacement)) {
		t.Fatal("audit leaked credential hashes")
	}
}

func TestAccountPasswordPreconditions(t *testing.T) {
	for _, condition := range []string{"stale hash", "missing credential", "revoked session", "expired session", "foreign session", "deleted user", "empty replacement"} {
		t.Run(condition, func(t *testing.T) {
			store := openTestStore(t)
			user, hash, session, _ := seedAccount(t, store, "alice")
			expected := hash
			replacement := accountHash(t, "replacement account password")
			switch condition {
			case "stale hash":
				expected = []byte("stale")
			case "missing credential":
				if err := store.DeleteLocalCredential(user.ID); err != nil {
					t.Fatal(err)
				}
			case "revoked session":
				if err := store.RevokeSession(session.ID, "test"); err != nil {
					t.Fatal(err)
				}
			case "expired session":
				if _, err := store.db.Exec("UPDATE sessions SET expires_at = 1 WHERE id = ?", session.ID); err != nil {
					t.Fatal(err)
				}
			case "foreign session":
				_, _, session, _ = seedAccount(t, store, "bob")
			case "deleted user":
				if err := store.DeleteUser(user.ID); err != nil {
					t.Fatal(err)
				}
			case "empty replacement":
				replacement = nil
			}
			if _, err := store.ChangeLocalPassword(t.Context(), user.ID, session.ID, expected, replacement); !errors.Is(err, ErrCredentialChanged) {
				t.Fatalf("precondition accepted: %v", err)
			}
			if credential, ok := store.GetLocalCredential(user.ID); ok && !bytes.Equal(credential.PasswordHash, hash) {
				t.Fatal("rejected change modified password")
			}
			if len(store.ListAudit(0)) != 0 {
				t.Fatal("rejected change wrote a success audit")
			}
		})
	}
}

func TestAccountTransactionRollback(t *testing.T) {
	for _, failingTable := range []string{"sessions", "audit_events"} {
		t.Run(failingTable, func(t *testing.T) {
			store := openTestStore(t)
			user, hash, session, token := seedAccount(t, store, "alice")
			operation := "UPDATE"
			if failingTable == "audit_events" {
				operation = "INSERT"
			}
			if _, err := store.db.Exec("CREATE TRIGGER reject_account_write BEFORE " + operation + " ON " + failingTable + " BEGIN SELECT RAISE(ABORT, 'injected failure'); END"); err != nil {
				t.Fatal(err)
			}
			if _, err := store.ChangeLocalPassword(t.Context(), user.ID, session.ID, hash, accountHash(t, "replacement account password")); err == nil {
				t.Fatal("injected storage failure was ignored")
			}
			credential, _ := store.GetLocalCredential(user.ID)
			if !bytes.Equal(credential.PasswordHash, hash) {
				t.Fatal("failed transaction left a changed password")
			}
			if _, err := store.GetSessionByToken(token); err != nil {
				t.Fatal("failed transaction revoked a session")
			}
			if failingTable == "audit_events" {
				display := "not committed"
				if _, err := store.UpdateUserProfile(t.Context(), user.ID, &display, nil); err == nil {
					t.Fatal("profile audit failure was ignored")
				}
				stored, _ := store.GetUser(user.ID)
				if stored.DisplayName == display {
					t.Fatal("failed profile transaction left changed data")
				}
			}
		})
	}
}

func TestAccountConcurrentPasswordChanges(t *testing.T) {
	store, peer := openAccountStores(t)
	user, hash, firstSession, _ := seedAccount(t, store, "alice")
	secondSession, _, err := peer.CreateLocalSession(t.Context(), user.ID, hash, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	replacements := [][]byte{accountHash(t, "first replacement password"), accountHash(t, "second replacement password")}
	results := make(chan error, 2)
	start := make(chan struct{})
	for index, current := range []*SQLiteStore{store, peer} {
		sessionID := []string{firstSession.ID, secondSession.ID}[index]
		go func() {
			<-start
			_, err := current.ChangeLocalPassword(t.Context(), user.ID, sessionID, hash, replacements[index])
			results <- err
		}()
	}
	close(start)
	succeeded := 0
	for range 2 {
		if err := <-results; err == nil {
			succeeded++
		} else if !errors.Is(err, ErrCredentialChanged) {
			t.Fatal(err)
		}
	}
	if succeeded != 1 || len(store.ListAudit(0)) != 1 {
		t.Fatalf("concurrent changes committed %d times", succeeded)
	}
}

func TestAccountPasswordAgainstConcurrentLoginAndRotation(t *testing.T) {
	store, peer := openAccountStores(t)
	user, hash, _, _ := seedAccount(t, store, "alice")
	replacement := accountHash(t, "replacement account password")
	for iteration := range 10 {
		if err := store.SetLocalCredential(&LocalCredential{UserID: user.ID, PasswordHash: hash}); err != nil {
			t.Fatal(err)
		}
		initiator, _, err := store.CreateLocalSession(t.Context(), user.ID, hash, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		_, rotateToken, err := store.CreateLocalSession(t.Context(), user.ID, hash, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		start := make(chan struct{})
		var workers sync.WaitGroup
		workers.Add(2)
		go func() {
			defer workers.Done()
			<-start
			if _, _, err := peer.CreateLocalSession(t.Context(), user.ID, hash, time.Hour); err != nil && !errors.Is(err, ErrCredentialChanged) {
				t.Errorf("concurrent login: %v", err)
			}
		}()
		go func() {
			defer workers.Done()
			<-start
			if _, _, err := store.RotateSession(rotateToken, time.Hour); err != nil && !errors.Is(err, ErrSessionNotFound) && !errors.Is(err, ErrSessionRevoked) {
				t.Errorf("concurrent rotation: %v", err)
			}
		}()
		close(start)
		if _, err := peer.ChangeLocalPassword(t.Context(), user.ID, initiator.ID, hash, replacement); err != nil {
			t.Fatalf("iteration %d: %v", iteration, err)
		}
		workers.Wait()
		for _, session := range store.ListSessions(user.ID) {
			if session.RevokedAt.IsZero() {
				t.Fatalf("iteration %d left an old-password session live", iteration)
			}
		}
	}
}

func TestAccountCanceledContext(t *testing.T) {
	store := openTestStore(t)
	user, hash, session, token := seedAccount(t, store, "alice")
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := store.ChangeLocalPassword(ctx, user.ID, session.ID, hash, accountHash(t, "replacement account password")); err == nil {
		t.Fatal("canceled change succeeded")
	}
	if _, _, err := store.CreateLocalSession(ctx, user.ID, hash, time.Hour); err == nil {
		t.Fatal("canceled sign-in succeeded")
	}
	if _, err := store.GetSessionByToken(token); err != nil {
		t.Fatal("canceled operation changed the original session")
	}
}
