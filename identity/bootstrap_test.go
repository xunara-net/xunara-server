package identity

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

func localOwnerClaimFixture(t *testing.T, kind LocalAccountClaimKind, login string) LocalAccountClaim {
	t.Helper()
	hash, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	return LocalAccountClaim{
		Kind: kind, LoginName: login, DisplayName: "网络所有者", Email: "owner@example.test",
		PasswordHash: hash, SessionTTL: time.Hour,
	}
}

func seededBootstrapStore(t *testing.T) (*SQLiteStore, User) {
	t.Helper()
	store := openTestStore(t)
	owner, created, err := EnsureLocalUser(store)
	if err != nil || !created || owner.ID != 1 {
		t.Fatal("could not seed a built-in owner")
	}
	return store, owner
}

func TestLocalOwnerClaimCommitsOnceAndKeepsIdentity(t *testing.T) {
	for _, kind := range []LocalAccountClaimKind{ClaimAdministrator, ClaimTenantOwner} {
		t.Run(string(kind), func(t *testing.T) {
			store, previous := seededBootstrapStore(t)
			if err := store.LinkExternalIdentity(&ExternalIdentity{ProviderID: "fixture-oidc", Subject: "stable-subject", UserID: previous.ID, Email: "attribute@example.test"}); err != nil {
				t.Fatal(err)
			}
			linksBefore := store.ListExternalIdentities(previous.ID)
			claim := localOwnerClaimFixture(t, kind, "owner")
			user, session, token, err := store.ClaimLocalAccount(t.Context(), claim)
			if err != nil || user.ID != previous.ID || user.Role != RoleOwner || user.CreatedAt != previous.CreatedAt || session.UserID != user.ID || session.AuthMethod != LocalProviderID {
				t.Fatalf("owner claim did not preserve the built-in identity: %v", err)
			}
			if user.LoginName != claim.LoginName || user.DisplayName != claim.DisplayName || user.Email != claim.Email || len(store.ListUsers()) != 1 {
				t.Fatal("owner claim changed the account count or lost profile fields")
			}
			if !reflect.DeepEqual(linksBefore, store.ListExternalIdentities(user.ID)) {
				t.Fatal("owner claim rekeyed or merged external identities")
			}
			credential, err := store.LookupLocalCredential(t.Context(), user.ID)
			if err != nil || !VerifyPassword(credential.PasswordHash, "correct horse battery staple") {
				t.Fatal("owner claim did not persist a usable password")
			}
			resolved, err := store.GetSessionByToken(token)
			if err != nil || resolved.ID != session.ID {
				t.Fatal("owner claim did not persist its session")
			}
			var sessionHash string
			if err := store.db.QueryRow("SELECT token_hash FROM sessions WHERE id = ?", session.ID).Scan(&sessionHash); err != nil || sessionHash != HashSecret(token) || sessionHash == token {
				t.Fatal("owner claim stored a plaintext session token")
			}
			audit := store.ListAudit(0)
			expected := []string{AuditUserRegistered, AuditLoginSucceeded, AuditSessionCreated}
			if kind == ClaimAdministrator {
				expected = []string{AuditAdminBootstrap, AuditUserUpdated, AuditLoginSucceeded, AuditSessionCreated}
			}
			if len(audit) != len(expected) {
				t.Fatal("owner claim omitted a required audit")
			}
			for index, event := range audit {
				if event.Action != expected[index] || strings.Contains(event.Detail, token) || strings.Contains(event.Detail, "correct horse battery staple") {
					t.Fatal("owner claim changed audit order or exposed a secret")
				}
			}
			if err := store.DeleteLocalCredential(user.ID); err != nil {
				t.Fatal(err)
			}
			if required, err := store.LocalAccountSetupRequired(t.Context()); err != nil || required {
				t.Fatal("deleting a password reopened completed initialization")
			}
			claim.LoginName = "replacement-owner"
			returnedUser, returnedSession, returnedToken, err := store.ClaimLocalAccount(t.Context(), claim)
			if !errors.Is(err, ErrLocalAccountClaimed) || returnedUser.ID != 0 || returnedSession.ID != "" || returnedToken != "" {
				t.Fatal("replaying an owner claim returned a partial identity")
			}
			after, err := store.LookupUser(t.Context(), user.ID)
			if err != nil || !reflect.DeepEqual(user, after) || !reflect.DeepEqual(audit, store.ListAudit(0)) {
				t.Fatal("a repeated claim changed profile or audits")
			}
			if sessions, err := store.ListAccountSessions(t.Context(), user.ID); err != nil || len(sessions) != 1 || sessions[0].ID != session.ID {
				t.Fatal("a repeated claim created or removed sessions")
			}
		})
	}
}

func TestLocalOwnerClaimRollsBackAtEveryWrite(t *testing.T) {
	for _, failure := range []struct {
		table     string
		operation string
		condition string
	}{
		{"local_bootstrap_state", "INSERT", ""}, {"users", "UPDATE", ""}, {"local_credentials", "INSERT", ""},
		{"sessions", "INSERT", ""}, {"audit_events", "INSERT", ""},
		{"audit_events", "INSERT", " WHEN NEW.action = 'session.created'"},
	} {
		t.Run(failure.table+failure.condition, func(t *testing.T) {
			store, before := seededBootstrapStore(t)
			linksBefore := store.ListExternalIdentities(before.ID)
			claim := localOwnerClaimFixture(t, ClaimAdministrator, "retry-owner")
			if _, err := store.db.Exec(fmt.Sprintf("CREATE TRIGGER fail_owner_claim BEFORE %s ON %s%s BEGIN SELECT RAISE(ABORT, 'private owner claim diagnostic'); END", failure.operation, failure.table, failure.condition)); err != nil {
				t.Fatal(err)
			}
			user, session, token, err := store.ClaimLocalAccount(t.Context(), claim)
			if err == nil || user.ID != 0 || session.ID != "" || token != "" {
				t.Fatal("failed owner claim returned success or a partial identity")
			}
			after, err := store.LookupUser(t.Context(), before.ID)
			if err != nil || !reflect.DeepEqual(before, after) || !reflect.DeepEqual(linksBefore, store.ListExternalIdentities(before.ID)) {
				t.Fatal("failed owner claim changed identity or profile")
			}
			for _, table := range []string{"local_bootstrap_state", "local_credentials", "sessions", "audit_events"} {
				var count int
				if err := store.db.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&count); err != nil || count != 0 {
					t.Fatalf("failed owner claim left data in %s", table)
				}
			}
			if required, err := store.LocalAccountSetupRequired(t.Context()); err != nil || !required {
				t.Fatal("rolled-back initialization could not retry")
			}
			if _, err := store.db.Exec("DROP TRIGGER fail_owner_claim"); err != nil {
				t.Fatal(err)
			}
			if _, _, _, err := store.ClaimLocalAccount(t.Context(), claim); err != nil {
				t.Fatalf("owner claim could not recover: %v", err)
			}
		})
	}
}

func TestLocalOwnerClaimAcrossConnectionsHasOneWinner(t *testing.T) {
	for _, mode := range []string{"immediate", "deferred"} {
		t.Run(mode, func(t *testing.T) {
			first, _ := seededBootstrapStore(t)
			var sequence int
			var name, databaseFile string
			if err := first.db.QueryRow("PRAGMA database_list").Scan(&sequence, &name, &databaseFile); err != nil {
				t.Fatal(err)
			}
			database, err := sql.Open("sqlite", "file:"+databaseFile+"?_txlock="+mode+"&_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)")
			if err != nil {
				t.Fatal(err)
			}
			database.SetMaxOpenConns(1)
			t.Cleanup(func() { database.Close() })
			second, err := NewSQLiteStore(t.Context(), database)
			if err != nil {
				t.Fatal(err)
			}
			claim := localOwnerClaimFixture(t, ClaimAdministrator, "owner-race")
			start := make(chan struct{})
			type claimResult struct {
				user    User
				session Session
				token   string
				err     error
			}
			results := make(chan claimResult, 2)
			for index, store := range []*SQLiteStore{first, second} {
				candidate := claim
				candidate.LoginName = fmt.Sprintf("owner-race-%d", index)
				go func() {
					<-start
					user, session, token, err := store.ClaimLocalAccount(t.Context(), candidate)
					results <- claimResult{user: user, session: session, token: token, err: err}
				}()
			}
			close(start)
			var winner claimResult
			var successes, rejected int
			for attempt := 0; attempt < 2; attempt++ {
				result := <-results
				if result.err == nil {
					winner = result
					successes++
				} else if errors.Is(result.err, ErrLocalAccountClaimed) && result.user.ID == 0 && result.session.ID == "" && result.token == "" {
					rejected++
				} else {
					t.Fatalf("unexpected competing owner claim: %v", result.err)
				}
			}
			if successes != 1 || rejected != 1 || len(first.ListUsers()) != 1 {
				t.Fatal("competing claims did not choose exactly one owner")
			}
			stored, err := first.LookupUser(t.Context(), winner.user.ID)
			if err != nil || !reflect.DeepEqual(stored, winner.user) {
				t.Fatal("losing owner claim overwrote the winner")
			}
			if sessions, err := first.ListAccountSessions(t.Context(), winner.user.ID); err != nil || len(sessions) != 1 || sessions[0].ID != winner.session.ID {
				t.Fatal("competing owner claims created multiple sessions")
			}
			if len(first.ListAudit(0)) != 4 {
				t.Fatal("competing owner claims duplicated success audits")
			}
		})
	}
}

func TestLocalOwnerClaimPreservesTypedErrors(t *testing.T) {
	claim := localOwnerClaimFixture(t, ClaimAdministrator, "owner")
	for _, failure := range []struct {
		name  string
		fault func(*testing.T, *SQLiteStore) context.Context
		want  error
	}{
		{"cancelled", func(t *testing.T, store *SQLiteStore) context.Context {
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			return ctx
		}, context.Canceled},
		{"missing owner", func(t *testing.T, store *SQLiteStore) context.Context {
			if err := store.DeleteUser(1); err != nil {
				t.Fatal(err)
			}
			return t.Context()
		}, ErrUserNotFound},
		{"duplicate login", func(t *testing.T, store *SQLiteStore) context.Context {
			if err := store.CreateUser(&User{LoginName: "OWNER", Role: RoleMember}); err != nil {
				t.Fatal(err)
			}
			return t.Context()
		}, ErrLoginNameTaken},
		{"scan failure", func(t *testing.T, store *SQLiteStore) context.Context {
			if _, err := store.db.Exec("UPDATE users SET created_at = 'private invalid timestamp' WHERE id = 1"); err != nil {
				t.Fatal(err)
			}
			return t.Context()
		}, nil},
	} {
		t.Run(failure.name, func(t *testing.T) {
			store, _ := seededBootstrapStore(t)
			ctx := failure.fault(t, store)
			user, session, token, err := store.ClaimLocalAccount(ctx, claim)
			if err == nil || user.ID != 0 || session.ID != "" || token != "" || (failure.want != nil && !errors.Is(err, failure.want)) {
				t.Fatal("owner claim lost its error or returned a partial identity")
			}
			if failure.want == nil && (errors.Is(err, ErrUserNotFound) || errors.Is(err, ErrLocalAccountClaimed)) {
				t.Fatal("scan failure became a missing or initialized account")
			}
			if required, err := store.LocalAccountSetupRequired(t.Context()); err != nil || !required {
				t.Fatal("rejected owner claim consumed initialization")
			}
		})
	}
	store, _ := seededBootstrapStore(t)
	if err := store.db.Close(); err != nil {
		t.Fatal(err)
	}
	if required, err := store.LocalAccountSetupRequired(t.Context()); err == nil || required {
		t.Fatal("closed storage was treated as pending initialization")
	}
	if _, _, _, err := store.ClaimLocalAccount(t.Context(), claim); err == nil || errors.Is(err, ErrLocalAccountClaimed) || errors.Is(err, ErrUserNotFound) {
		t.Fatal("closed storage was treated as a domain rejection")
	}
}

func TestBootstrapMigrationSealsExistingAccountsWithoutChangingData(t *testing.T) {
	for _, history := range []string{"fresh", "credential", "administrator audit", "tenant owner audit", "member audit"} {
		t.Run(history, func(t *testing.T) {
			store, owner := seededBootstrapStore(t)
			if history == "credential" {
				claim := localOwnerClaimFixture(t, ClaimAdministrator, "owner")
				if err := store.SetLocalCredential(&LocalCredential{UserID: owner.ID, PasswordHash: claim.PasswordHash}); err != nil {
					t.Fatal(err)
				}
			}
			if strings.HasSuffix(history, "audit") {
				event := AuditEvent{Actor: "system", Action: AuditUserRegistered, Target: "user:2"}
				if history == "administrator audit" {
					event.Action, event.Target = AuditAdminBootstrap, "user:owner"
				} else if history == "tenant owner audit" {
					event.Target = "user:1"
				}
				if err := store.AppendAudit(&event); err != nil {
					t.Fatal(err)
				}
			}
			session, token, err := store.CreateSession(NewSessionOptions{UserID: owner.ID, TTL: time.Hour})
			if err != nil {
				t.Fatal(err)
			}
			linksBefore, auditBefore := store.ListExternalIdentities(owner.ID), store.ListAudit(0)
			credentialBefore, credentialExists := store.GetLocalCredential(owner.ID)
			if _, err := store.db.Exec("DROP TABLE local_bootstrap_state; UPDATE schema_migrations SET version = 12 WHERE module = 'identity'"); err != nil {
				t.Fatal(err)
			}
			upgraded, err := NewSQLiteStore(t.Context(), store.db)
			if err != nil {
				t.Fatal(err)
			}
			wantPending := history == "fresh" || history == "member audit"
			if required, err := upgraded.LocalAccountSetupRequired(t.Context()); err != nil || required != wantPending {
				t.Fatal("migration inferred the wrong initialization state")
			}
			after, err := upgraded.LookupUser(t.Context(), owner.ID)
			credentialAfter, exists := upgraded.GetLocalCredential(owner.ID)
			if err != nil || !reflect.DeepEqual(owner, after) || !reflect.DeepEqual(linksBefore, upgraded.ListExternalIdentities(owner.ID)) || !reflect.DeepEqual(auditBefore, upgraded.ListAudit(0)) || exists != credentialExists || !reflect.DeepEqual(credentialBefore, credentialAfter) {
				t.Fatal("bootstrap migration changed existing identity data")
			}
			if resolved, err := upgraded.GetSessionByToken(token); err != nil || resolved.ID != session.ID {
				t.Fatal("bootstrap migration invalidated an existing login")
			}
			if history == "credential" {
				if err := upgraded.DeleteLocalCredential(owner.ID); err != nil {
					t.Fatal(err)
				}
				if required, err := upgraded.LocalAccountSetupRequired(t.Context()); err != nil || required {
					t.Fatal("an upgraded account reopened after password deletion")
				}
			}
			if _, err := NewSQLiteStore(t.Context(), store.db); err != nil {
				t.Fatal("completed bootstrap migration could not reopen")
			}
		})
	}
}
