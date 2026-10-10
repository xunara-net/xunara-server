package identity

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestPasswordSessionAtomicAudit(t *testing.T) {
	store := openTestStore(t)
	user, hash, original, originalToken := seedAccount(t, store, "private-login-name")
	session, token, err := store.CreateLocalSession(t.Context(), user.ID, hash, time.Hour)
	if err != nil || token == "" || session.ID == "" || session.AuthMethod != LocalProviderID {
		t.Fatal("password login did not persist a session")
	}
	stored, err := store.GetSessionByToken(token)
	if err != nil || stored.ID != session.ID {
		t.Fatal("returned password token does not identify the committed session")
	}
	events := store.ListAudit(0)
	if len(events) != 2 {
		t.Fatalf("password login persisted %d audits instead of two", len(events))
	}
	seen := make(map[string]bool)
	for _, event := range events {
		seen[event.Action] = true
		if event.Actor != fmt.Sprintf("user:%d", user.ID) || !event.Time.Equal(session.CreatedAt) {
			t.Fatal("login event has an incorrect actor or timestamp")
		}
		if event.Action == AuditLoginSucceeded && event.Target != "provider:"+LocalProviderID {
			t.Fatal("login audit is not bound to the local provider")
		}
		if event.Action == AuditSessionCreated && event.Target != "session:"+session.ID {
			t.Fatal("session audit is not bound to the committed session")
		}
		for _, private := range []string{user.LoginName, string(hash), token, HashSecret(token)} {
			if strings.Contains(event.Detail, private) {
				t.Fatal("password login audit leaked private authentication data")
			}
		}
	}
	if !seen[AuditLoginSucceeded] || !seen[AuditSessionCreated] {
		t.Fatal("password login omitted a required success audit")
	}
	if stored, err := store.GetSessionByToken(originalToken); err != nil || stored.ID != original.ID {
		t.Fatal("new login changed the original session")
	}
}

func TestPasswordSessionAuditFailureRollsBack(t *testing.T) {
	for _, action := range []string{AuditLoginSucceeded, AuditSessionCreated} {
		for _, failure := range []string{"ABORT, 'private password audit failure'", "IGNORE"} {
			t.Run(action+"/"+failure, func(t *testing.T) {
				store := openTestStore(t)
				user, hash, original, originalToken := seedAccount(t, store, "alice")
				if _, err := store.db.Exec("CREATE TRIGGER reject_password_audit BEFORE INSERT ON audit_events WHEN NEW.action = '" + action + "' BEGIN SELECT RAISE(" + failure + "); END"); err != nil {
					t.Fatal(err)
				}
				session, token, err := store.CreateLocalSession(t.Context(), user.ID, hash, time.Hour)
				if err == nil || session.ID != "" || token != "" {
					t.Fatal("failed audit returned a usable password identity")
				}
				if len(store.ListSessions(user.ID)) != 1 || len(store.ListAudit(0)) != 0 {
					t.Fatal("failed password audit left a partial session or success event")
				}
				if stored, err := store.GetSessionByToken(originalToken); err != nil || stored.ID != original.ID {
					t.Fatal("failed password audit invalidated the original session")
				}
				if _, err := store.db.Exec("DROP TRIGGER reject_password_audit"); err != nil {
					t.Fatal(err)
				}
				if _, _, err := store.CreateLocalSession(t.Context(), user.ID, hash, time.Hour); err != nil || len(store.ListAudit(0)) != 2 {
					t.Fatal("password login did not recover after the audit store recovered")
				}
			})
		}
	}
}

func TestPasswordSessionIgnoredInsertionFailsClosed(t *testing.T) {
	store := openTestStore(t)
	user, hash, _, _ := seedAccount(t, store, "alice")
	if _, err := store.db.Exec("CREATE TRIGGER ignore_password_session BEFORE INSERT ON sessions BEGIN SELECT RAISE(IGNORE); END"); err != nil {
		t.Fatal(err)
	}
	session, token, err := store.CreateLocalSession(t.Context(), user.ID, hash, time.Hour)
	if err == nil || session.ID != "" || token != "" || len(store.ListAudit(0)) != 0 || len(store.ListSessions(user.ID)) != 1 {
		t.Fatal("ignored session insertion returned or audited a non-existent identity")
	}
	if session, token, err := store.CreateSession(NewSessionOptions{UserID: user.ID}); err == nil || session.ID != "" || token != "" {
		t.Fatal("generic session insertion fabricated a persisted token")
	}
}

func TestPasswordSessionConcurrentAuditPairs(t *testing.T) {
	store, peer := openAccountStores(t)
	user, hash, _, _ := seedAccount(t, store, "alice")
	start := make(chan struct{})
	results := make(chan error, 12)
	for attempt := range 12 {
		current := []*SQLiteStore{store, peer}[attempt%2]
		go func() {
			<-start
			_, _, err := current.CreateLocalSession(t.Context(), user.ID, hash, time.Hour)
			results <- err
		}()
	}
	close(start)
	for range 12 {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	if len(store.ListSessions(user.ID)) != 13 || len(store.ListAudit(0)) != 24 {
		t.Fatal("concurrent password logins lost sessions or required audit pairs")
	}
	var distinctSessions int
	if err := store.db.QueryRow("SELECT COUNT(DISTINCT target) FROM audit_events WHERE action = ?", AuditSessionCreated).Scan(&distinctSessions); err != nil || distinctSessions != 12 {
		t.Fatal("concurrent audit pairs were duplicated or conflated")
	}
}

func TestPasswordSessionRejectedCredentialAndCancellationDoNotAudit(t *testing.T) {
	store := openTestStore(t)
	user, hash, _, _ := seedAccount(t, store, "alice")
	if session, token, err := store.CreateLocalSession(t.Context(), user.ID, []byte("stale hash"), time.Hour); !errors.Is(err, ErrCredentialChanged) || session.ID != "" || token != "" {
		t.Fatal("stale credential returned a session")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if session, token, err := store.CreateLocalSession(ctx, user.ID, hash, time.Hour); !errors.Is(err, context.Canceled) || session.ID != "" || token != "" {
		t.Fatal("cancelled password login returned a session")
	}
	if len(store.ListSessions(user.ID)) != 1 || len(store.ListAudit(0)) != 0 {
		t.Fatal("rejected password login persisted success state")
	}
}
