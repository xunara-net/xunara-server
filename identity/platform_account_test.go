package identity

import (
	"database/sql"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

func platformAccountFixture(login string) PlatformLocalAccount {
	return PlatformLocalAccount{LoginName: login, Role: RoleMember, PasswordHash: []byte("test-hash"), MaxUsers: -1, Actor: "platform-user:1"}
}

func TestPlatformAccountAtomicRollback(test *testing.T) {
	for _, table := range []string{"users", "local_credentials", "external_identities", "audit_events"} {
		test.Run(table, func(test *testing.T) {
			store := openTestStore(test)
			if _, err := store.db.Exec("CREATE TRIGGER reject_write BEFORE INSERT ON " + table + " BEGIN SELECT RAISE(ABORT, 'test'); END"); err != nil {
				test.Fatal(err)
			}
			if _, err := store.CreateLocalAccountByPlatform(test.Context(), platformAccountFixture("new-user")); err == nil {
				test.Fatal("fault did not stop creation")
			}
			for _, target := range []string{"users", "local_credentials", "external_identities", "sessions", "audit_events"} {
				var count int
				if err := store.db.QueryRow("SELECT COUNT(*) FROM " + target).Scan(&count); err != nil || count != 0 {
					test.Fatal("partial identity escaped rollback", target, count, err)
				}
			}
		})
	}
}

func TestPlatformAccountIgnoredWritesRollback(test *testing.T) {
	for _, table := range []string{"users", "local_credentials", "external_identities", "audit_events"} {
		test.Run(table, func(test *testing.T) {
			store := openTestStore(test)
			if _, err := store.db.Exec("CREATE TRIGGER ignore_write BEFORE INSERT ON " + table + " BEGIN SELECT RAISE(IGNORE); END"); err != nil {
				test.Fatal(err)
			}
			if _, err := store.CreateLocalAccountByPlatform(test.Context(), platformAccountFixture("ignored")); err == nil {
				test.Fatal("ignored write reported success")
			}
			for _, target := range []string{"users", "local_credentials", "external_identities", "audit_events"} {
				var count int
				if err := store.db.QueryRow("SELECT COUNT(*) FROM " + target).Scan(&count); err != nil || count != 0 {
					test.Fatal("ignored write left a partial account", target, count, err)
				}
			}
		})
	}
}

func TestPlatformAccountAcrossConnectionsRespectsQuota(test *testing.T) {
	first := openTestStore(test)
	var sequence int
	var name, path string
	if err := first.db.QueryRow("PRAGMA database_list").Scan(&sequence, &name, &path); err != nil {
		test.Fatal(err)
	}
	database, err := sql.Open("sqlite", "file:"+path+"?_txlock=immediate&_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)")
	if err != nil {
		test.Fatal(err)
	}
	defer database.Close()
	second, err := NewSQLiteStore(test.Context(), database)
	if err != nil {
		test.Fatal(err)
	}
	start := make(chan struct{})
	failures := make(chan error, 2)
	var workers sync.WaitGroup
	for index, store := range []*SQLiteStore{first, second} {
		workers.Add(1)
		go func(store *SQLiteStore, index int) {
			defer workers.Done()
			<-start
			input := platformAccountFixture(fmt.Sprintf("member-%d", index))
			input.MaxUsers = 1
			_, err := store.CreateLocalAccountByPlatform(test.Context(), input)
			failures <- err
		}(store, index)
	}
	close(start)
	workers.Wait()
	close(failures)
	success, denied := 0, 0
	for failure := range failures {
		if failure == nil {
			success++
		} else if errors.Is(failure, ErrMemberLimitReached) {
			denied++
		} else {
			test.Fatal(failure)
		}
	}
	if success != 1 || denied != 1 {
		test.Fatal("last member slot oversubscribed", success, denied)
	}
}

func TestPlatformBootstrapAuditFailureAndSession(test *testing.T) {
	store := openTestStore(test)
	if _, err := store.db.Exec("CREATE TRIGGER ignore_audit BEFORE INSERT ON audit_events BEGIN SELECT RAISE(IGNORE); END"); err != nil {
		test.Fatal(err)
	}
	if _, _, err := store.CreatePlatformSession(test.Context(), time.Hour, SessionClientInfo{}); err == nil {
		test.Fatal("bootstrap allowed missing audit")
	}
	if len(store.ListUsers()) != 0 {
		test.Fatal("bootstrap left an incomplete platform identity")
	}
	if _, err := store.db.Exec("DROP TRIGGER ignore_audit"); err != nil {
		test.Fatal(err)
	}
	session, token, err := store.CreatePlatformSession(test.Context(), time.Hour, SessionClientInfo{})
	if err != nil {
		test.Fatal(err)
	}
	if session.AuthMethod != "platform-token" || session.UserID == 0 {
		test.Fatal("wrong platform session")
	}
	if _, err := store.GetSessionByToken(token); err != nil {
		test.Fatal(err)
	}
	if _, _, err := store.CreatePlatformSession(test.Context(), time.Hour, SessionClientInfo{}); err != nil || len(store.ListUsers()) != 1 {
		test.Fatal("bootstrap duplicated account", err)
	}
}

func TestPlatformPasskeyLastMethodAndAuditRollback(test *testing.T) {
	store := openTestStore(test)
	session, token, err := store.CreatePlatformSession(test.Context(), time.Hour, SessionClientInfo{})
	if err != nil {
		test.Fatal(err)
	}
	user, _ := store.GetUser(session.UserID)
	key, err := store.CreateAccountPasskey(test.Context(), session.ID, accountTestPasskey(user, "first"))
	if err != nil {
		test.Fatal(err)
	}
	passkeySession, passkeyToken, err := store.CreatePasskeySession(test.Context(), user.ID, key.ID, time.Hour)
	if err != nil {
		test.Fatal(err)
	}
	if err := store.DeletePlatformPasskey(test.Context(), user.ID, session.ID, key.ID, false); !errors.Is(err, ErrLastLoginMethod) {
		test.Fatal("last key removed without recovery", err)
	}
	if _, err := store.db.Exec("CREATE TRIGGER ignore_delete_audit BEFORE INSERT ON audit_events BEGIN SELECT RAISE(IGNORE); END"); err != nil {
		test.Fatal(err)
	}
	if err := store.DeletePlatformPasskey(test.Context(), user.ID, session.ID, key.ID, true); err == nil {
		test.Fatal("unlink allowed missing audit")
	}
	if _, err := store.GetSessionByToken(passkeyToken); err != nil {
		test.Fatal("failed unlink partially revoked session")
	}
	if _, err := store.db.Exec("DROP TRIGGER ignore_delete_audit"); err != nil {
		test.Fatal(err)
	}
	if err := store.DeletePlatformPasskey(test.Context(), user.ID, passkeySession.ID, key.ID, true); err != nil {
		test.Fatal(err)
	}
	if _, err := store.GetSessionByToken(passkeyToken); err == nil {
		test.Fatal("unlink failed to revoke current passkey session")
	}
	if _, err := store.GetSessionByToken(token); err != nil {
		test.Fatal("unlink revoked recovery session")
	}
}
