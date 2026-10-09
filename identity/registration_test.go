package identity

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

// 存储测试不验证 bcrypt 算法；真正的密码哈希与登录由控制面集成测试覆盖。
func registrationFixture(login, token string) LocalRegistration {
	return LocalRegistration{
		LoginName: login, PasswordHash: []byte("fixture-password-hash"), InviteToken: token,
		MaxUsers: -1, SessionTTL: time.Hour,
	}
}

func TestLocalRegistrationCommitsAccountSessionAndAudit(t *testing.T) {
	store := openTestStore(t)
	invite, code, err := store.CreateRegistrationInvite(NewRegistrationInviteOptions{Role: RoleAdmin, TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	user, session, sessionToken, err := store.RegisterLocalAccount(context.Background(), registrationFixture("registered", code))
	if err != nil {
		t.Fatal(err)
	}
	if user.Role != RoleAdmin || session.UserID != user.ID || session.AuthMethod != LocalProviderID {
		t.Fatal("invite role or session identity was not retained")
	}
	credential, ok := store.GetLocalCredential(user.ID)
	if !ok || len(credential.PasswordHash) == 0 {
		t.Fatal("registration omitted the password")
	}
	link, ok := store.GetExternalIdentity(LocalProviderID, "registered")
	if !ok || link.UserID != user.ID {
		t.Fatal("registration omitted the identity link")
	}
	storedSession, err := store.GetSessionByToken(sessionToken)
	if err != nil || storedSession.ID != session.ID {
		t.Fatal("returned session is not usable")
	}
	redeemed, ok := store.GetRegistrationInvite(invite.ID)
	if !ok || redeemed.UsedBy != user.ID || !redeemed.Redeemed() {
		t.Fatal("invitation was not redeemed")
	}
	audits := store.ListAudit(0)
	if len(audits) != 4 {
		t.Fatalf("audit count = %d, want 4", len(audits))
	}
	for _, event := range audits {
		if event.Detail == code || event.Detail == sessionToken {
			t.Fatal("audit exposed a credential")
		}
	}
}

func TestLocalRegistrationRollbackAtEveryWrite(t *testing.T) {
	for _, failure := range []struct {
		table     string
		operation string
	}{
		{"users", "INSERT"}, {"local_credentials", "INSERT"}, {"external_identities", "INSERT"},
		{"registration_invites", "UPDATE"}, {"sessions", "INSERT"}, {"audit_events", "INSERT"},
	} {
		t.Run(failure.table, func(t *testing.T) {
			store := openTestStore(t)
			invite, code, err := store.CreateRegistrationInvite(NewRegistrationInviteOptions{Role: RoleMember, TTL: time.Hour})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := store.db.Exec(fmt.Sprintf("CREATE TRIGGER fail_registration BEFORE %s ON %s BEGIN SELECT RAISE(ABORT, 'injected registration failure'); END", failure.operation, failure.table)); err != nil {
				t.Fatal(err)
			}
			user, session, token, err := store.RegisterLocalAccount(context.Background(), registrationFixture("retry-member", code))
			if err == nil || user.ID != 0 || session.ID != "" || token != "" {
				t.Fatal("failed registration returned success or a partial identity")
			}
			for _, table := range []string{"users", "local_credentials", "external_identities", "sessions", "audit_events"} {
				var count int
				if err := store.db.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&count); err != nil || count != 0 {
					t.Fatalf("%s has partial writes, count %d, error %v", table, count, err)
				}
			}
			stored, ok := store.GetRegistrationInvite(invite.ID)
			if !ok || stored.Redeemed() {
				t.Fatal("failed registration consumed its invitation")
			}
			if _, err := store.db.Exec("DROP TRIGGER fail_registration"); err != nil {
				t.Fatal(err)
			}
			if _, _, _, err := store.RegisterLocalAccount(context.Background(), registrationFixture("retry-member", code)); err != nil {
				t.Fatalf("registration could not retry after rollback: %v", err)
			}
		})
	}
}

func TestLocalRegistrationAcrossConnectionsRespectsLastMemberSlot(t *testing.T) {
	first := openTestStore(t)
	var databaseFile string
	var sequence int
	var name string
	if err := first.db.QueryRow("PRAGMA database_list").Scan(&sequence, &name, &databaseFile); err != nil {
		t.Fatal(err)
	}
	database, err := sql.Open("sqlite", "file:"+databaseFile+"?_txlock=immediate&_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	second, err := NewSQLiteStore(context.Background(), database)
	if err != nil {
		t.Fatal(err)
	}
	for _, invited := range []bool{false, true} {
		t.Run(fmt.Sprint(invited), func(t *testing.T) {
			var used int
			if err := first.db.QueryRow("SELECT COUNT(*) FROM users").Scan(&used); err != nil {
				t.Fatal(err)
			}
			var codes [2]string
			if invited {
				for index := range codes {
					_, codes[index], err = first.CreateRegistrationInvite(NewRegistrationInviteOptions{Role: RoleMember, TTL: time.Hour})
					if err != nil {
						t.Fatal(err)
					}
				}
			}
			start := make(chan struct{})
			results := make(chan error, 2)
			var workers sync.WaitGroup
			for index, store := range []*SQLiteStore{first, second} {
				registration := registrationFixture(fmt.Sprintf("racer-%t-%d", invited, index), codes[index])
				registration.MaxUsers = used + 1
				workers.Add(1)
				go func() {
					defer workers.Done()
					<-start
					_, _, _, err := store.RegisterLocalAccount(context.Background(), registration)
					results <- err
				}()
			}
			close(start)
			workers.Wait()
			close(results)
			var successes, limited int
			for result := range results {
				if result == nil {
					successes++
				} else if errors.Is(result, ErrMemberLimitReached) {
					limited++
				} else {
					t.Fatalf("unexpected registration error: %v", result)
				}
			}
			if successes != 1 || limited != 1 || len(first.ListUsers()) != used+1 {
				t.Fatalf("last slot results: success %d, limited %d", successes, limited)
			}
			if invited {
				unused := 0
				for _, code := range codes {
					if _, err := first.FindRegistrationInvite(code); err == nil {
						unused++
					}
				}
				if unused != 1 {
					t.Fatal("member quota refusal consumed an invitation")
				}
			}
		})
	}
}

func TestLocalRegistrationCancellationAndStoreFailure(t *testing.T) {
	store := openTestStore(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, _, err := store.RegisterLocalAccount(ctx, registrationFixture("cancelled", "")); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled request = %v", err)
	}
	if err := store.db.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := store.FindRegistrationInvite("unavailable"); err == nil || errors.Is(err, ErrInviteNotFound) {
		t.Fatal("store failure looked like an invalid invitation")
	}
	if _, err := store.ListRegistrationInvitesContext(context.Background()); err == nil {
		t.Fatal("store failure looked like an empty invitation list")
	}
}
