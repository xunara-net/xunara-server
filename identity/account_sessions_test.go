package identity

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestAccountSessionsScopedRevocation(t *testing.T) {
	store, peer := openAccountStores(t)
	user, _, current, currentToken := seedAccount(t, store, "alice")
	_, _, _, foreignToken := seedAccount(t, store, "bob")
	other, otherToken, err := store.CreateSession(NewSessionOptions{UserID: user.ID, AuthMethod: "oidc:test"})
	if err != nil {
		t.Fatal(err)
	}
	expired, _, err := store.CreateSession(NewSessionOptions{UserID: user.ID, TTL: time.Nanosecond})
	if err != nil {
		t.Fatal(err)
	}
	revoked, err := store.RevokeAccountSessions(t.Context(), user.ID, current.ID, SessionRevocation{Mode: RevokeOtherSessions})
	if err != nil || revoked != 1 {
		t.Fatalf("other sessions: %d, %v", revoked, err)
	}
	if _, err := peer.GetSessionByToken(currentToken); err != nil {
		t.Fatal("initiating session was revoked")
	}
	if _, err := peer.GetSessionByToken(foreignToken); err != nil {
		t.Fatal("another user's session was revoked")
	}
	if _, err := peer.GetSessionByToken(otherToken); !errors.Is(err, ErrSessionNotFound) {
		t.Fatal("revocation was not visible to the other connection")
	}
	previous, _ := peer.GetSessionByID(other.ID)
	if previous.RevokedReason != "signed out other sessions" || previous.RevokedAt.IsZero() {
		t.Fatal("revocation history was not persisted")
	}
	for _, selection := range []SessionRevocation{{Mode: RevokeOtherSessions}, {Mode: RevokeSingleSession, SessionID: other.ID}, {Mode: RevokeSingleSession, SessionID: expired.ID}} {
		if count, err := peer.RevokeAccountSessions(t.Context(), user.ID, current.ID, selection); err != nil || count != 0 {
			t.Fatalf("idempotent revocation: %d, %v", count, err)
		}
	}
	unchanged, _ := peer.GetSessionByID(other.ID)
	if !unchanged.RevokedAt.Equal(previous.RevokedAt) || unchanged.RevokedReason != previous.RevokedReason {
		t.Fatal("idempotent revocation rewrote history")
	}
	expired, _ = peer.GetSessionByID(expired.ID)
	if !expired.RevokedAt.IsZero() {
		t.Fatal("an already expired session was counted as live")
	}
	if count, err := peer.RevokeAccountSessions(t.Context(), user.ID, current.ID, SessionRevocation{Mode: RevokeAllSessions}); err != nil || count != 1 {
		t.Fatalf("all sessions: %d, %v", count, err)
	}
	if _, err := store.GetSessionByToken(currentToken); !errors.Is(err, ErrSessionNotFound) {
		t.Fatal("all-session revocation left the initiating session alive")
	}
	for _, event := range peer.ListAudit(0) {
		if event.Action != AuditSessionRevoked || event.Actor != fmt.Sprintf("user:%d", user.ID) || event.Target != event.Actor {
			t.Fatalf("incorrect audit scope: %+v", event)
		}
		if strings.Contains(event.Detail, currentToken) || strings.Contains(event.Detail, otherToken) || strings.Contains(event.Detail, foreignToken) {
			t.Fatal("audit leaked a session token")
		}
	}
}

func TestAccountSessionsRevocationPreconditions(t *testing.T) {
	for _, condition := range []string{"revoked", "expired", "foreign initiator", "deleted user", "missing initiator", "foreign target", "missing target"} {
		t.Run(condition, func(t *testing.T) {
			store := openTestStore(t)
			user, _, current, _ := seedAccount(t, store, "alice")
			_, _, foreign, foreignToken := seedAccount(t, store, "bob")
			other, otherToken, err := store.CreateSession(NewSessionOptions{UserID: user.ID})
			if err != nil {
				t.Fatal(err)
			}
			initiatingID := current.ID
			selection := SessionRevocation{Mode: RevokeOtherSessions}
			wantError := ErrSessionRevoked
			switch condition {
			case "revoked":
				if err := store.RevokeSession(current.ID, "test"); err != nil {
					t.Fatal(err)
				}
			case "expired":
				if _, err := store.db.Exec("UPDATE sessions SET expires_at = 1 WHERE id = ?", current.ID); err != nil {
					t.Fatal(err)
				}
			case "foreign initiator":
				initiatingID = foreign.ID
			case "deleted user":
				if err := store.DeleteUser(user.ID); err != nil {
					t.Fatal(err)
				}
			case "missing initiator":
				initiatingID = "missing"
			case "foreign target":
				selection = SessionRevocation{Mode: RevokeSingleSession, SessionID: foreign.ID}
				wantError = ErrSessionNotFound
			case "missing target":
				selection = SessionRevocation{Mode: RevokeSingleSession, SessionID: "missing"}
				wantError = ErrSessionNotFound
			}
			if count, err := store.RevokeAccountSessions(t.Context(), user.ID, initiatingID, selection); !errors.Is(err, wantError) || count != 0 {
				t.Fatalf("invalid revocation: %d, %v", count, err)
			}
			if stored, ok := store.GetSessionByID(other.ID); ok && !stored.RevokedAt.IsZero() {
				t.Fatal("failed operation revoked another session")
			}
			if condition != "deleted user" {
				if _, err := store.GetSessionByToken(otherToken); err != nil {
					t.Fatal("failed operation invalidated an unrelated token")
				}
			}
			if _, err := store.GetSessionByToken(foreignToken); err != nil || len(store.ListAudit(0)) != 0 {
				t.Fatal("failed operation changed foreign sessions or wrote a success audit")
			}
		})
	}
}

func TestAccountSessionsSelectionValidation(t *testing.T) {
	store := openTestStore(t)
	user, _, current, token := seedAccount(t, store, "alice")
	for _, selection := range []SessionRevocation{
		{}, {Mode: "unknown"}, {Mode: RevokeSingleSession},
		{Mode: RevokeAllSessions, SessionID: current.ID}, {Mode: RevokeOtherSessions, SessionID: current.ID},
	} {
		if _, err := store.RevokeAccountSessions(t.Context(), user.ID, current.ID, selection); !errors.Is(err, ErrInvalidSessionRevocation) {
			t.Fatalf("invalid selection accepted: %v", err)
		}
	}
	if _, err := store.GetSessionByToken(token); err != nil || len(store.ListAudit(0)) != 0 {
		t.Fatal("invalid selection changed state")
	}
	if count, err := store.RevokeAccountSessions(t.Context(), user.ID, current.ID, SessionRevocation{Mode: RevokeSingleSession, SessionID: current.ID}); err != nil || count != 1 {
		t.Fatalf("current-session revocation: %d, %v", count, err)
	}
}

func TestAccountSessionsFailureRollback(t *testing.T) {
	for _, failingTable := range []string{"sessions", "audit_events"} {
		t.Run(failingTable, func(t *testing.T) {
			store := openTestStore(t)
			user, _, current, token := seedAccount(t, store, "alice")
			operation := "UPDATE"
			if failingTable == "audit_events" {
				operation = "INSERT"
			}
			if _, err := store.db.Exec("CREATE TRIGGER reject_session_write BEFORE " + operation + " ON " + failingTable + " BEGIN SELECT RAISE(ABORT, 'injected failure'); END"); err != nil {
				t.Fatal(err)
			}
			if count, err := store.RevokeAccountSessions(t.Context(), user.ID, current.ID, SessionRevocation{Mode: RevokeAllSessions}); err == nil || count != 0 {
				t.Fatalf("storage failure ignored: %d, %v", count, err)
			}
			if _, err := store.GetSessionByToken(token); err != nil || len(store.ListAudit(0)) != 0 {
				t.Fatal("failed transaction committed revocation or success audit")
			}
		})
	}
}

func TestAccountSessionsConcurrentRotation(t *testing.T) {
	for iteration := 0; iteration < 12; iteration++ {
		t.Run(fmt.Sprint(iteration), func(t *testing.T) {
			store, peer := openAccountStores(t)
			user, _, current, token := seedAccount(t, store, "alice")
			_, otherToken, err := store.CreateSession(NewSessionOptions{UserID: user.ID})
			if err != nil {
				t.Fatal(err)
			}
			start := make(chan struct{})
			var group sync.WaitGroup
			var revokeError, rotateError error
			group.Add(2)
			go func() {
				defer group.Done()
				<-start
				_, revokeError = store.RevokeAccountSessions(t.Context(), user.ID, current.ID, SessionRevocation{Mode: RevokeOtherSessions})
			}()
			go func() {
				defer group.Done()
				<-start
				_, _, rotateError = peer.RotateSession(otherToken, time.Hour)
			}()
			close(start)
			group.Wait()
			if revokeError != nil || rotateError != nil && !errors.Is(rotateError, ErrSessionNotFound) && !errors.Is(rotateError, ErrSessionRevoked) {
				t.Fatalf("concurrent revoke/rotate: %v, %v", revokeError, rotateError)
			}
			sessions, err := peer.ListAccountSessions(t.Context(), user.ID)
			if err != nil {
				t.Fatal(err)
			}
			for _, session := range sessions {
				if session.ID != current.ID && session.RevokedAt.IsZero() {
					t.Fatal("rotation resurrected an old login")
				}
			}
			if _, err := peer.GetSessionByToken(token); err != nil {
				t.Fatal("concurrent revocation signed out the initiating session")
			}
		})
	}
}

func TestAccountSessionsListAndContextErrors(t *testing.T) {
	store := openTestStore(t)
	user, _, current, token := seedAccount(t, store, "alice")
	_, _, _, _ = seedAccount(t, store, "bob")
	sessions, err := store.ListAccountSessions(t.Context(), user.ID)
	if err != nil || len(sessions) != 1 || sessions[0].ID != current.ID {
		t.Fatalf("scoped session list: %v, %v", sessions, err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := store.ListAccountSessions(ctx, user.ID); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled list: %v", err)
	}
	if _, err := store.RevokeAccountSessions(ctx, user.ID, current.ID, SessionRevocation{Mode: RevokeAllSessions}); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled revocation: %v", err)
	}
	if _, err := store.GetSessionByToken(token); err != nil {
		t.Fatal("canceled revocation changed state")
	}
	if _, err := store.db.Exec("DROP TABLE sessions"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ListAccountSessions(t.Context(), user.ID); err == nil {
		t.Fatal("storage failure became an empty session list")
	}
}
