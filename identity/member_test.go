package identity

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"tailscale.com/tailcfg"
)

func memberFixture(test *testing.T, store *SQLiteStore) (MemberCaller, User, User) {
	test.Helper()
	owner := User{LoginName: "owner", Role: RoleOwner}
	member := User{LoginName: "member", DisplayName: "原昵称", Email: "contact@example.test", Role: RoleMember}
	for _, user := range []*User{&owner, &member} {
		if err := store.CreateUser(user); err != nil {
			test.Fatal(err)
		}
	}
	session, _, err := store.CreateSession(NewSessionOptions{UserID: owner.ID, TTL: time.Hour})
	if err != nil {
		test.Fatal(err)
	}
	return MemberCaller{UserID: owner.ID, SessionID: session.ID}, owner, member
}

func memberRolePatch(user User, role Role) MemberPatch {
	return MemberPatch{Role: &role, ExpectedUpdatedAt: &user.UpdatedAt}
}

func assertMemberUnchanged(test *testing.T, store *SQLiteStore, previous User, audits int) {
	test.Helper()
	current, err := store.LookupUser(test.Context(), previous.ID)
	if err != nil || current != previous || len(store.ListAudit(0)) != audits {
		test.Fatalf("rejected operation changed user or audit: %+v, %v", current, err)
	}
}

func TestMemberPatchPreservesFactsAndAuditsOnce(test *testing.T) {
	store := openTestStore(test)
	caller, _, member := memberFixture(test, store)
	updated, err := store.UpdateMember(test.Context(), caller, member.ID, memberRolePatch(member, RoleAdmin))
	if err != nil || updated.Role != RoleAdmin || updated.ID != member.ID || updated.LoginName != member.LoginName ||
		updated.DisplayName != member.DisplayName || updated.Email != member.Email || !updated.CreatedAt.Equal(member.CreatedAt) || !updated.UpdatedAt.After(member.UpdatedAt) {
		test.Fatalf("invalid committed member: %+v, %v", updated, err)
	}
	audits := store.ListAudit(0)
	if len(audits) != 1 || audits[0].Action != AuditUserRoleChanged || audits[0].Actor != fmt.Sprintf("user:%d", caller.UserID) ||
		audits[0].Target != fmt.Sprintf("user:%d", member.ID) || audits[0].Detail != "updated role; role member -> admin" {
		test.Fatal("role change and audit did not describe the same operation")
	}
	repeated, err := store.UpdateMember(test.Context(), caller, updated.ID, memberRolePatch(updated, RoleAdmin))
	if err != nil || repeated != updated {
		test.Fatalf("no-op changed facts: %+v, %v", repeated, err)
	}
	assertMemberUnchanged(test, store, updated, 1)
	display := "仅改昵称"
	profile, err := store.UpdateUserByOperator(test.Context(), member.ID, MemberPatch{DisplayName: &display})
	if err != nil || profile.Role != RoleAdmin || profile.DisplayName != display || profile.Email != member.Email || !profile.CreatedAt.Equal(member.CreatedAt) {
		test.Fatalf("operator profile patch overwrote other fields: %+v, %v", profile, err)
	}
	if events := store.ListAudit(0); len(events) != 2 || events[1].Actor != "cli" || events[1].Action != AuditUserUpdated {
		test.Fatal("operator update did not use the same transactional audit")
	}
}

func TestMemberUpdateRechecksSessionAndOwner(test *testing.T) {
	for _, changed := range []string{"revoked", "expired", "rotated", "wrong user", "missing", "both", "demoted", "deleted", "admin", "unknown role"} {
		test.Run(changed, func(test *testing.T) {
			store := openTestStore(test)
			caller, owner, member := memberFixture(test, store)
			if err := store.CreateUser(&User{LoginName: "backup", Role: RoleOwner}); err != nil {
				test.Fatal(err)
			}
			want := ErrSessionRevoked
			switch changed {
			case "revoked", "rotated":
				if err := store.RevokeSession(caller.SessionID, "test revocation"); err != nil {
					test.Fatal(err)
				}
				if changed == "rotated" {
					if _, _, err := store.CreateSession(NewSessionOptions{UserID: owner.ID}); err != nil {
						test.Fatal(err)
					}
				}
			case "expired":
				if _, err := store.db.Exec("UPDATE sessions SET expires_at = ? WHERE id = ?", time.Now().Add(-time.Hour).UnixNano(), caller.SessionID); err != nil {
					test.Fatal(err)
				}
			case "wrong user":
				caller.UserID = member.ID
			case "missing":
				caller.SessionID = ""
				want = ErrNetworkWriterForbidden
			case "both":
				caller.APIKeyID = "not-a-session"
				want = ErrNetworkWriterForbidden
			case "demoted", "admin":
				owner.Role = RoleMember
				want = ErrNetworkWriterForbidden
				if changed == "admin" {
					owner.Role = RoleAdmin
					want = ErrMemberOwnerRequired
				}
				if err := store.UpdateUser(owner); err != nil {
					test.Fatal(err)
				}
			case "unknown role":
				if _, err := store.db.Exec("UPDATE users SET role = 'unknown' WHERE id = ?", int64(owner.ID)); err != nil {
					test.Fatal(err)
				}
				want = ErrNetworkWriterForbidden
			case "deleted":
				if err := store.DeleteUser(owner.ID); err != nil {
					test.Fatal(err)
				}
			}
			for _, patch := range []MemberPatch{memberRolePatch(member, RoleAdmin), {}} {
				if result, err := store.UpdateMember(test.Context(), caller, member.ID, patch); !errors.Is(err, want) || result.ID != 0 {
					test.Fatalf("changed credential still writes or returns facts: %+v, %v", result, err)
				}
			}
			assertMemberUnchanged(test, store, member, 0)
		})
	}
}

func TestMemberUpdateChecksServiceKeyScopeAndIdentity(test *testing.T) {
	for _, changed := range []string{"write", "read", "revoked", "expired", "foreign user", "unknown scope", "malformed scopes", "demoted owner"} {
		test.Run(changed, func(test *testing.T) {
			store := openTestStore(test)
			caller, owner, member := memberFixture(test, store)
			credential, _, err := store.CreateAPIKey(NewAPIKeyOptions{UserID: owner.ID, Name: "member management", Scopes: []string{ScopeWrite}})
			if err != nil {
				test.Fatal(err)
			}
			caller.SessionID, caller.APIKeyID = "", credential.ID
			switch changed {
			case "read", "unknown scope", "malformed scopes":
				scopes := map[string]string{"read": "read", "unknown scope": "write,unknown", "malformed scopes": `["write"]`}[changed]
				if _, err := store.db.Exec("UPDATE api_keys SET scopes = ? WHERE id = ?", scopes, credential.ID); err != nil {
					test.Fatal(err)
				}
			case "revoked":
				if err := store.RevokeAPIKey(credential.ID); err != nil {
					test.Fatal(err)
				}
			case "expired":
				if _, err := store.db.Exec("UPDATE api_keys SET expires_at = ? WHERE id = ?", time.Now().Add(-time.Hour).UnixNano(), credential.ID); err != nil {
					test.Fatal(err)
				}
			case "foreign user":
				caller.UserID = member.ID
			case "demoted owner":
				if err := store.CreateUser(&User{LoginName: "backup", Role: RoleOwner}); err != nil {
					test.Fatal(err)
				}
				owner.Role = RoleMember
				if err := store.UpdateUser(owner); err != nil {
					test.Fatal(err)
				}
			}
			updated, err := store.UpdateMember(test.Context(), caller, member.ID, memberRolePatch(member, RoleAdmin))
			if changed != "write" {
				if !errors.Is(err, ErrNetworkWriterForbidden) || updated.ID != 0 {
					test.Fatalf("service identity gained authority: %+v, %v", updated, err)
				}
				assertMemberUnchanged(test, store, member, 0)
				return
			}
			if err != nil || updated.Role != RoleAdmin {
				test.Fatal(err)
			}
			if events := store.ListAudit(0); len(events) != 1 || events[0].Actor != fmt.Sprintf("user:%d/apikey:%s", owner.ID, credential.ID) {
				test.Fatal("service actor was confused with a human session")
			}
		})
	}
}

func TestMemberUpdateFailureRollsBack(test *testing.T) {
	for _, table := range []string{"users", "audit_events"} {
		test.Run(table, func(test *testing.T) {
			store := openTestStore(test)
			caller, _, member := memberFixture(test, store)
			operation := "UPDATE"
			if table == "audit_events" {
				operation = "INSERT"
			}
			if _, err := store.db.Exec("CREATE TRIGGER fail_member_change BEFORE " + operation + " ON " + table + " BEGIN SELECT RAISE(ABORT, 'injected private failure'); END"); err != nil {
				test.Fatal(err)
			}
			if updated, err := store.UpdateMember(test.Context(), caller, member.ID, memberRolePatch(member, RoleAdmin)); err == nil || updated.ID != 0 {
				test.Fatal("failed transaction returned success")
			}
			assertMemberUnchanged(test, store, member, 0)
			if _, err := store.db.Exec("DROP TRIGGER fail_member_change"); err != nil {
				test.Fatal(err)
			}
			if _, err := store.UpdateUserByOperator(test.Context(), member.ID, memberRolePatch(member, RoleAdmin)); err != nil {
				test.Fatal(err)
			}
		})
	}
}

func TestMemberVersionAndLegacySnapshotProtection(test *testing.T) {
	store := openTestStore(test)
	caller, _, member := memberFixture(test, store)
	updated, err := store.UpdateMember(test.Context(), caller, member.ID, memberRolePatch(member, RoleAdmin))
	if err != nil {
		test.Fatal(err)
	}
	restored, err := store.UpdateMember(test.Context(), caller, member.ID, memberRolePatch(updated, RoleMember))
	if err != nil {
		test.Fatal(err)
	}
	if _, err := store.UpdateMember(test.Context(), caller, member.ID, memberRolePatch(member, RoleAdmin)); !errors.Is(err, ErrMemberConflict) {
		test.Fatalf("ABA role transition accepted stale page: %v", err)
	}
	member.Role = RoleOwner
	member.Email = "old-snapshot@example.test"
	if err := store.UpdateUser(member); !errors.Is(err, ErrMemberConflict) {
		test.Fatalf("legacy complete snapshot restored stale authority: %v", err)
	}
	assertMemberUnchanged(test, store, restored, 2)
	// 同一版本下字段未变也不能自动吞掉冲突，以免把旧确认当作最新确认。
	if _, err := store.UpdateMember(test.Context(), caller, member.ID, MemberPatch{ExpectedUpdatedAt: &member.UpdatedAt}); !errors.Is(err, ErrMemberConflict) {
		test.Fatal("stale no-op accepted old confirmation")
	}
}

func TestMemberIgnoredWritesAreNotSuccessfulFacts(test *testing.T) {
	for _, table := range []string{"users", "audit_events"} {
		test.Run(table, func(test *testing.T) {
			store := openTestStore(test)
			caller, _, member := memberFixture(test, store)
			operation := "UPDATE"
			if table == "audit_events" {
				operation = "INSERT"
			}
			if _, err := store.db.Exec("CREATE TRIGGER ignore_member_write BEFORE " + operation + " ON " + table + " BEGIN SELECT RAISE(IGNORE); END"); err != nil {
				test.Fatal(err)
			}
			if updated, err := store.UpdateMember(test.Context(), caller, member.ID, memberRolePatch(member, RoleAdmin)); err == nil || updated.ID != 0 {
				test.Fatal("zero-row write was published as a committed role or audit")
			}
			assertMemberUnchanged(test, store, member, 0)
		})
	}
}

func TestMemberConcurrentCASAcrossConnections(test *testing.T) {
	store, peer := openAccountStores(test)
	caller, _, member := memberFixture(test, store)
	start := make(chan struct{})
	errorsFound := make(chan error, 12)
	var group sync.WaitGroup
	for attempt := 0; attempt < 12; attempt++ {
		connection := store
		if attempt%2 == 1 {
			connection = peer
		}
		group.Go(func() {
			<-start
			_, err := connection.UpdateMember(test.Context(), caller, member.ID, memberRolePatch(member, RoleAdmin))
			errorsFound <- err
		})
	}
	close(start)
	group.Wait()
	close(errorsFound)
	success := 0
	for err := range errorsFound {
		if err == nil {
			success++
		} else if !errors.Is(err, ErrMemberConflict) {
			test.Fatal(err)
		}
	}
	if success != 1 || len(store.ListAudit(0)) != 1 {
		test.Fatalf("stale requests committed more than once: %d", success)
	}
}

func TestMemberConcurrentOwnerRemovalAcrossConnections(test *testing.T) {
	for _, operation := range []string{"session demotion", "operator demotion", "legacy demotion", "delete"} {
		for iteration := 0; iteration < 12; iteration++ {
			test.Run(fmt.Sprintf("%s/%d", operation, iteration), func(test *testing.T) {
				store, peer := openAccountStores(test)
				caller, owner, member := memberFixture(test, store)
				member.Role = RoleOwner
				if err := store.UpdateUser(member); err != nil {
					test.Fatal(err)
				}
				member, _ = store.GetUser(member.ID)
				session, _, err := store.CreateSession(NewSessionOptions{UserID: member.ID})
				if err != nil {
					test.Fatal(err)
				}
				start := make(chan struct{})
				var firstError, secondError error
				var group sync.WaitGroup
				group.Go(func() {
					<-start
					_, firstError = store.UpdateMember(test.Context(), caller, owner.ID, memberRolePatch(owner, RoleMember))
				})
				group.Go(func() {
					<-start
					switch operation {
					case "session demotion":
						_, secondError = peer.UpdateMember(test.Context(), MemberCaller{UserID: member.ID, SessionID: session.ID}, member.ID, memberRolePatch(member, RoleMember))
					case "operator demotion":
						_, secondError = peer.UpdateUserByOperator(test.Context(), member.ID, memberRolePatch(member, RoleMember))
					case "legacy demotion":
						member.Role = RoleMember
						secondError = peer.UpdateUser(member)
					case "delete":
						secondError = peer.DeleteUserContext(test.Context(), member.ID)
					}
				})
				close(start)
				group.Wait()
				if !((firstError == nil && errors.Is(secondError, ErrLastOwner)) || (errors.Is(firstError, ErrLastOwner) && secondError == nil)) {
					test.Fatalf("removal was not serialized: %v, %v", firstError, secondError)
				}
				owners := 0
				for _, user := range store.ListUsers() {
					if user.Role.IsOwner() {
						owners++
					}
				}
				if owners != 1 {
					test.Fatalf("lost the last owner: %d", owners)
				}
			})
		}
	}
}

func TestMemberInvalidInputAndReadFailures(test *testing.T) {
	store := openTestStore(test)
	caller, owner, member := memberFixture(test, store)
	invalidRole, emptyLogin, zeroTime := Role("viewer"), " ", time.Time{}
	for _, patch := range []MemberPatch{{Role: &invalidRole}, {LoginName: &emptyLogin}, {ExpectedUpdatedAt: &zeroTime}, {LoginName: &owner.LoginName}} {
		if updated, err := store.UpdateMember(test.Context(), caller, member.ID, patch); err == nil || updated.ID != 0 {
			test.Fatal("invalid or duplicate member input was committed")
		}
		assertMemberUnchanged(test, store, member, 0)
	}
	if _, err := store.UpdateMember(test.Context(), caller, tailcfg.UserID(999), MemberPatch{}); !errors.Is(err, ErrUserNotFound) {
		test.Fatal(err)
	}
	ctx, cancel := context.WithCancel(test.Context())
	cancel()
	if _, err := store.UpdateMember(ctx, caller, member.ID, MemberPatch{}); !errors.Is(err, context.Canceled) {
		test.Fatal("cancelled write was not cancelled")
	}
	if _, err := store.db.Exec("UPDATE users SET created_at = 'injected private timestamp' WHERE id = ?", int64(member.ID)); err != nil {
		test.Fatal(err)
	}
	if _, err := store.UpdateMember(test.Context(), caller, member.ID, MemberPatch{}); err == nil || errors.Is(err, ErrUserNotFound) {
		test.Fatal("scan failure was treated as a missing member")
	}
	if users, err := store.ListUsersContext(test.Context()); err == nil || users != nil {
		test.Fatal("broken list returned empty success")
	}
}

func TestMemberCredentialsStayWithinTenant(test *testing.T) {
	first, second := openTestStore(test), openTestStore(test)
	caller, _, _ := memberFixture(test, first)
	_, _, member := memberFixture(test, second)
	if _, err := second.UpdateMember(test.Context(), caller, member.ID, memberRolePatch(member, RoleAdmin)); !errors.Is(err, ErrSessionRevoked) {
		test.Fatalf("same numeric user IDs accepted a foreign tenant's session: %v", err)
	}
	assertMemberUnchanged(test, second, member, 0)
}
