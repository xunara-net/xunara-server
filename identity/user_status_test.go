package identity

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

func statusFixture(test *testing.T, store *SQLiteStore) (User, User, Session, string) {
	test.Helper()
	owner := User{LoginName: "owner", Role: RoleOwner}
	member := User{LoginName: "member", Role: RoleMember}
	for _, user := range []*User{&owner, &member} {
		if err := store.CreateUser(user); err != nil {
			test.Fatal(err)
		}
	}
	session, token, err := store.CreateSession(NewSessionOptions{UserID: member.ID})
	if err != nil {
		test.Fatal(err)
	}
	return owner, member, session, token
}

func statusChange(user User, disabled bool) UserStatusChange {
	return UserStatusChange{Disabled: disabled, Reason: "管理员核对账号", ExpectedUpdatedAt: user.UpdatedAt}
}

func TestUserStatusPersistentRevocationAndEnable(test *testing.T) {
	store, peer := openAccountStores(test)
	_, member, session, token := statusFixture(test, store)
	if err := store.SetLocalCredential(&LocalCredential{UserID: member.ID, PasswordHash: []byte("persisted hash")}); err != nil {
		test.Fatal(err)
	}
	link := ExternalIdentity{ProviderID: "external", Subject: "member-subject", UserID: member.ID}
	if err := store.LinkExternalIdentity(&link); err != nil {
		test.Fatal(err)
	}
	saved, err := store.SetUserStatusByPlatform(test.Context(), member.ID, statusChange(member, true))
	if err != nil || saved.User.DisabledAt.IsZero() || saved.RevokedSessions != 1 || !saved.User.UpdatedAt.After(member.UpdatedAt) {
		test.Fatalf("disable: %+v %v", saved, err)
	}
	read, err := peer.LookupUser(test.Context(), member.ID)
	if err != nil || !reflect.DeepEqual(read, saved.User) {
		test.Fatal("second instance lost the committed account status")
	}
	if _, err := peer.GetSessionByToken(token); !errors.Is(err, ErrSessionNotFound) {
		test.Fatal("disabled session still authenticates")
	}
	if _, err := peer.ChangeLocalPassword(test.Context(), member.ID, session.ID, []byte("persisted hash"), []byte("replacement hash")); !errors.Is(err, ErrCredentialChanged) {
		test.Fatal("revoked session changed the account")
	}
	if _, err := peer.SetUserStatusByPlatform(test.Context(), member.ID, statusChange(member, false)); !errors.Is(err, ErrMemberConflict) {
		test.Fatal("old page enabled a changed account")
	}
	unchanged, err := peer.SetUserStatusByPlatform(test.Context(), member.ID, statusChange(saved.User, true))
	if err != nil || !unchanged.User.UpdatedAt.Equal(saved.User.UpdatedAt) || len(store.ListAudit(0)) != 1 {
		test.Fatal("same status added an unnecessary revision or audit")
	}
	enabled, err := peer.SetUserStatusByPlatform(test.Context(), member.ID, statusChange(saved.User, false))
	if err != nil || !enabled.User.DisabledAt.IsZero() || enabled.User.DisabledReason != "" || enabled.RevokedSessions != 0 {
		test.Fatal("could not re-enable the account")
	}
	if _, err := store.GetSessionByToken(token); !errors.Is(err, ErrSessionNotFound) {
		test.Fatal("re-enable resurrected an old session")
	}
	if _, _, err := store.CreateLocalSession(test.Context(), member.ID, []byte("persisted hash"), time.Hour); err != nil {
		test.Fatal("re-enabled password could not create a fresh session")
	}
	if stored, found := store.GetExternalIdentity(link.ProviderID, link.Subject); !found || stored.UserID != member.ID {
		test.Fatal("status change deleted the external identity")
	}
	for _, event := range store.ListAudit(0) {
		if strings.Contains(event.Detail, token) || strings.Contains(event.Detail, "persisted hash") {
			test.Fatal("audit contains a credential")
		}
	}
}

func TestUserStatusRejectsAllSessionIssuers(test *testing.T) {
	store := openTestStore(test)
	_, member, session, token := statusFixture(test, store)
	hash := []byte("persisted hash")
	if err := store.SetLocalCredential(&LocalCredential{UserID: member.ID, PasswordHash: hash}); err != nil {
		test.Fatal(err)
	}
	passkey, err := store.CreateAccountPasskey(test.Context(), session.ID, accountTestPasskey(member, "电脑"))
	if err != nil {
		test.Fatal(err)
	}
	if err := store.LinkExternalIdentity(&ExternalIdentity{ProviderID: "external", Subject: "same-subject", UserID: member.ID}); err != nil {
		test.Fatal(err)
	}
	authorization := accountAuthorization(test, store, NewAuthTransactionOptions{ProviderID: "external"})
	if _, err := store.SetUserStatusByPlatform(test.Context(), member.ID, statusChange(member, true)); err != nil {
		test.Fatal(err)
	}
	for name, issue := range map[string]func() (Session, string, error){
		"generic": func() (Session, string, error) { return store.CreateSession(NewSessionOptions{UserID: member.ID}) },
		"password": func() (Session, string, error) {
			return store.CreateLocalSession(test.Context(), member.ID, hash, time.Hour)
		},
		"passkey": func() (Session, string, error) {
			return store.CreatePasskeySession(test.Context(), member.ID, passkey.ID, time.Hour)
		},
	} {
		test.Run(name, func(test *testing.T) {
			issued, returned, err := issue()
			if !errors.Is(err, ErrUserDisabled) || returned != "" || issued.ID != "" {
				test.Fatal("disabled account received a session")
			}
		})
	}
	if _, returned, err := store.RotateSession(token, time.Hour); !errors.Is(err, ErrSessionNotFound) || returned != "" {
		test.Fatal("disabled session rotated")
	}
	completed, err := store.CompleteExternalAuthentication(test.Context(), authorization.ID, IdentityResult{ProviderID: "external", Subject: "same-subject"}, ExternalAuthenticationOptions{})
	if !errors.Is(err, ErrUserDisabled) || completed.Token != "" || len(store.ListSessions(member.ID)) != 1 {
		test.Fatal("disabled external identity received a session")
	}
	stored, _ := store.GetAuthTransaction(authorization.ID)
	if !stored.ConsumedAt.IsZero() {
		test.Fatal("rejected authentication partially committed")
	}
}

func TestUserStatusRollbackOnRequiredWrites(test *testing.T) {
	for name, trigger := range map[string]string{
		"status ignored":     "BEFORE UPDATE OF disabled_at ON users BEGIN SELECT RAISE(IGNORE); END",
		"revocation error":   "BEFORE UPDATE OF revoked_at ON sessions BEGIN SELECT RAISE(ABORT, 'injected'); END",
		"revocation ignored": "BEFORE UPDATE OF revoked_at ON sessions BEGIN SELECT RAISE(IGNORE); END",
		"audit error":        "BEFORE INSERT ON audit_events BEGIN SELECT RAISE(ABORT, 'injected'); END",
		"audit ignored":      "BEFORE INSERT ON audit_events BEGIN SELECT RAISE(IGNORE); END",
	} {
		test.Run(name, func(test *testing.T) {
			store := openTestStore(test)
			_, member, _, token := statusFixture(test, store)
			if _, err := store.db.Exec("CREATE TRIGGER injected " + trigger); err != nil {
				test.Fatal(err)
			}
			if _, err := store.SetUserStatusByPlatform(test.Context(), member.ID, statusChange(member, true)); err == nil {
				test.Fatal("required write failure was reported as success")
			}
			stored, _ := store.GetUser(member.ID)
			if !reflect.DeepEqual(stored, member) || len(store.ListAudit(0)) != 0 {
				test.Fatal("failed status change partially persisted")
			}
			if _, err := store.GetSessionByToken(token); err != nil {
				test.Fatal("failed status change revoked a live session")
			}
		})
	}
}

func TestUserStatusLastEnabledOwnerInvariant(test *testing.T) {
	store := openTestStore(test)
	owner, member, _, _ := statusFixture(test, store)
	if _, err := store.SetUserStatusByPlatform(test.Context(), owner.ID, statusChange(owner, true)); !errors.Is(err, ErrLastOwner) {
		test.Fatal("disabled the only enabled owner")
	}
	member.Role = RoleOwner
	if err := store.UpdateUser(member); err != nil {
		test.Fatal(err)
	}
	member, _ = store.GetUser(member.ID)
	if _, err := store.SetUserStatusByPlatform(test.Context(), member.ID, statusChange(member, true)); err != nil {
		test.Fatal(err)
	}
	if err := store.DeleteUser(owner.ID); !errors.Is(err, ErrLastOwner) {
		test.Fatal("disabled owner counted as a recovery owner on deletion")
	}
	if _, err := store.UpdateUserByOperator(test.Context(), owner.ID, memberRolePatch(owner, RoleMember)); !errors.Is(err, ErrLastOwner) {
		test.Fatal("disabled owner counted as a recovery owner on demotion")
	}
	if err := store.DeleteUser(member.ID); err != nil {
		test.Fatal("inactive owner could not be removed while an enabled owner exists")
	}
}

func TestUserStatusCrossConnectionOwnerRace(test *testing.T) {
	for _, operation := range []string{"disable", "delete", "demote"} {
		for iteration := 0; iteration < 8; iteration++ {
			test.Run(fmt.Sprintf("%s/%d", operation, iteration), func(test *testing.T) {
				store, peer := openAccountStores(test)
				owner, member, _, _ := statusFixture(test, store)
				member.Role = RoleOwner
				if err := store.UpdateUser(member); err != nil {
					test.Fatal(err)
				}
				member, _ = store.GetUser(member.ID)
				start := make(chan struct{})
				var first, second error
				var wait sync.WaitGroup
				wait.Go(func() {
					<-start
					_, first = store.SetUserStatusByPlatform(test.Context(), owner.ID, statusChange(owner, true))
				})
				wait.Go(func() {
					<-start
					switch operation {
					case "disable":
						_, second = peer.SetUserStatusByPlatform(test.Context(), member.ID, statusChange(member, true))
					case "delete":
						second = peer.DeleteUser(member.ID)
					case "demote":
						_, second = peer.UpdateUserByOperator(test.Context(), member.ID, memberRolePatch(member, RoleMember))
					}
				})
				close(start)
				wait.Wait()
				if !((first == nil && errors.Is(second, ErrLastOwner)) || (second == nil && errors.Is(first, ErrLastOwner))) {
					test.Fatalf("owner removals were not serialized: %v / %v", first, second)
				}
			})
		}
	}
}

func TestUserStatusCASAndInput(test *testing.T) {
	store := openTestStore(test)
	_, member, _, _ := statusFixture(test, store)
	for _, change := range []UserStatusChange{
		{Disabled: true, Reason: "missing revision"},
		{Disabled: true, ExpectedUpdatedAt: member.UpdatedAt},
		{Disabled: true, ExpectedUpdatedAt: member.UpdatedAt, Reason: "two\nlines"},
		{Disabled: true, ExpectedUpdatedAt: member.UpdatedAt, Reason: strings.Repeat("长", 257)},
	} {
		if _, err := store.SetUserStatusByPlatform(test.Context(), member.ID, change); !errors.Is(err, ErrMemberInvalid) {
			test.Fatal("invalid status update accepted")
		}
	}
	if _, err := store.SetUserStatusByPlatform(test.Context(), 999, statusChange(member, true)); !errors.Is(err, ErrUserNotFound) {
		test.Fatal("unknown account accepted")
	}
	if _, err := store.UpdateUserByOperator(test.Context(), member.ID, MemberPatch{DisplayName: new("new display")}); err != nil {
		test.Fatal(err)
	}
	if _, err := store.SetUserStatusByPlatform(test.Context(), member.ID, statusChange(member, true)); !errors.Is(err, ErrMemberConflict) {
		test.Fatal("profile change did not invalidate an old status request")
	}
}

func TestUserStatusMigrationPreservesOldAccounts(test *testing.T) {
	store := openTestStore(test)
	_, member, session, token := statusFixture(test, store)
	if _, err := store.db.Exec(`ALTER TABLE users DROP COLUMN disabled_at;
		ALTER TABLE users DROP COLUMN disabled_reason;
		UPDATE schema_migrations SET version = 15 WHERE module = 'identity'`); err != nil {
		test.Fatal(err)
	}
	upgraded, err := NewSQLiteStore(test.Context(), store.db)
	if err != nil {
		test.Fatal(err)
	}
	user, err := upgraded.LookupUser(test.Context(), member.ID)
	if err != nil || !reflect.DeepEqual(user, member) {
		test.Fatal("migration changed an existing account")
	}
	current, err := upgraded.GetSessionByToken(token)
	if err != nil || current != session {
		test.Fatal("migration invalidated an existing session")
	}
}

func TestUserStatusSessionIssueRaceAcrossConnections(test *testing.T) {
	for iteration := 0; iteration < 16; iteration++ {
		test.Run(fmt.Sprint(iteration), func(test *testing.T) {
			store, peer := openAccountStores(test)
			_, member, _, _ := statusFixture(test, store)
			if err := store.SetLocalCredential(&LocalCredential{UserID: member.ID, PasswordHash: []byte("checked hash")}); err != nil {
				test.Fatal(err)
			}
			start := make(chan struct{})
			var disableError, loginError error
			var token string
			var wait sync.WaitGroup
			wait.Go(func() {
				<-start
				_, disableError = store.SetUserStatusByPlatform(test.Context(), member.ID, statusChange(member, true))
			})
			wait.Go(func() {
				<-start
				_, token, loginError = peer.CreateLocalSession(test.Context(), member.ID, []byte("checked hash"), time.Hour)
			})
			close(start)
			wait.Wait()
			if disableError != nil || loginError != nil && !errors.Is(loginError, ErrUserDisabled) {
				test.Fatalf("unexpected concurrent result: %v / %v", disableError, loginError)
			}
			if _, err := store.GetSessionByToken(token); !errors.Is(err, ErrSessionNotFound) {
				test.Fatal("session survived a committed disable")
			}
			var live int
			if err := store.db.QueryRow("SELECT COUNT(*) FROM sessions WHERE user_id = ? AND revoked_at IS NULL", int64(member.ID)).Scan(&live); err != nil || live != 0 {
				test.Fatal("disable left a session issued by the other connection")
			}
		})
	}
}

func TestUserStatusGuardsStaleSessionAndServiceWriter(test *testing.T) {
	store := openTestStore(test)
	_, member, session, token := statusFixture(test, store)
	member.Role = RoleAdmin
	if err := store.UpdateUser(member); err != nil {
		test.Fatal(err)
	}
	member, _ = store.GetUser(member.ID)
	service, _, err := store.CreateAPIKey(NewAPIKeyOptions{Name: "delegated service", UserID: member.ID, Scopes: []string{ScopeRead, ScopeWrite}})
	if err != nil {
		test.Fatal(err)
	}
	if _, err := store.SetUserStatusByPlatform(test.Context(), member.ID, statusChange(member, true)); err != nil {
		test.Fatal(err)
	}
	// 模拟一个仍带旧事实的历史会话，读取和事务门禁不能只依赖撤销字段。
	if _, err := store.db.Exec("UPDATE sessions SET revoked_at = NULL WHERE id = ?", session.ID); err != nil {
		test.Fatal(err)
	}
	if _, err := store.GetSessionByToken(token); !errors.Is(err, ErrSessionNotFound) {
		test.Fatal("disabled status did not reject a stale session")
	}
	transaction, err := store.db.BeginTx(test.Context(), nil)
	if err != nil {
		test.Fatal(err)
	}
	defer transaction.Rollback()
	if err := lockAccountSession(test.Context(), transaction, member.ID, session.ID, time.Now()); !errors.Is(err, ErrSessionRevoked) {
		test.Fatal("stale session changed security settings")
	}
	if err := CheckNetworkWriter(test.Context(), transaction, member.ID, "", service.ID, time.Now()); !errors.Is(err, ErrNetworkWriterForbidden) {
		test.Fatal("disabled delegated key retained write authorization")
	}
	if err := checkMemberLimit(test.Context(), transaction, 2); !errors.Is(err, ErrMemberLimitReached) {
		test.Fatal("disabled account stopped consuming member quota")
	}
}
