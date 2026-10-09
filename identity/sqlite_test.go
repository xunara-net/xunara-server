package identity

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"tailscale.com/tailcfg"

	_ "modernc.org/sqlite" // pure-Go SQLite driver
)

// openTestStore opens the identity store on a fresh temporary database.
func openTestStore(t *testing.T) *SQLiteStore {
	t.Helper()

	db, err := sql.Open("sqlite", "file:"+filepath.Join(t.TempDir(), "identity.db")+
		"?_txlock=immediate&_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)")
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })

	s, err := NewSQLiteStore(context.Background(), db)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	return s
}

func TestUserCRUD(t *testing.T) {
	s := openTestStore(t)

	u := User{LoginName: "alice@example.com", DisplayName: "Alice", Email: "alice@example.com"}
	if err := s.CreateUser(&u); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if u.ID == 0 {
		t.Fatal("CreateUser did not assign an ID")
	}
	if u.CreatedAt.IsZero() || u.UpdatedAt.IsZero() {
		t.Fatal("CreateUser did not assign timestamps")
	}

	got, ok := s.GetUser(u.ID)
	if !ok || got.DisplayName != "Alice" {
		t.Fatalf("GetUser = %+v, %v", got, ok)
	}

	byLogin, ok := s.GetUserByLoginName("ALICE@example.com")
	if !ok || byLogin.ID != u.ID {
		t.Fatalf("GetUserByLoginName(mixed case) = %+v, %v", byLogin, ok)
	}

	if _, ok := s.GetUser(tailcfg.UserID(99999)); ok {
		t.Error("GetUser returned an unknown user")
	}
	if _, ok := s.GetUserByLoginName("nobody@example.com"); ok {
		t.Error("GetUserByLoginName returned an unknown user")
	}

	u.DisplayName = "Alice Smith"
	if err := s.UpdateUser(u); err != nil {
		t.Fatalf("UpdateUser: %v", err)
	}
	got, _ = s.GetUser(u.ID)
	if got.DisplayName != "Alice Smith" {
		t.Errorf("after update DisplayName = %q", got.DisplayName)
	}

	if err := s.UpdateUser(User{ID: 99999, LoginName: "ghost"}); err != ErrUserNotFound {
		t.Errorf("UpdateUser(unknown) = %v, want ErrUserNotFound", err)
	}

	users := s.ListUsers()
	if len(users) != 1 || users[0].ID != u.ID {
		t.Fatalf("ListUsers = %+v", users)
	}
}

func TestCreateUserLoginNameIsCaseInsensitivelyUnique(t *testing.T) {
	s := openTestStore(t)

	if err := s.CreateUser(&User{LoginName: "Alice@Example.com"}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if err := s.CreateUser(&User{LoginName: "alice@example.com"}); err != ErrLoginNameTaken {
		t.Fatalf("duplicate login name = %v, want ErrLoginNameTaken", err)
	}
}

func TestCreateUserRequiresLoginName(t *testing.T) {
	s := openTestStore(t)

	if err := s.CreateUser(&User{}); err == nil {
		t.Fatal("CreateUser with empty login name succeeded")
	}
	if err := s.CreateUser(nil); err == nil {
		t.Fatal("CreateUser(nil) succeeded")
	}
}

func TestExternalIdentityKey(t *testing.T) {
	s := openTestStore(t)

	alice := User{LoginName: "alice"}
	bob := User{LoginName: "bob"}
	if err := s.CreateUser(&alice); err != nil {
		t.Fatalf("CreateUser(alice): %v", err)
	}
	if err := s.CreateUser(&bob); err != nil {
		t.Fatalf("CreateUser(bob): %v", err)
	}

	ei := ExternalIdentity{
		ProviderID:  "dex",
		Subject:     "sub-1",
		UserID:      alice.ID,
		Email:       "alice@example.com",
		DisplayName: "Alice",
	}
	if err := s.LinkExternalIdentity(&ei); err != nil {
		t.Fatalf("LinkExternalIdentity: %v", err)
	}

	got, ok := s.GetExternalIdentity("dex", "sub-1")
	if !ok || got.UserID != alice.ID || got.Email != "alice@example.com" {
		t.Fatalf("GetExternalIdentity = %+v, %v", got, ok)
	}

	// Re-linking the same (provider, subject) to the same user updates
	// display attributes in place.
	ei.Email = "alice+new@example.com"
	ei.UserID = alice.ID
	if err := s.LinkExternalIdentity(&ei); err != nil {
		t.Fatalf("re-LinkExternalIdentity: %v", err)
	}
	got, _ = s.GetExternalIdentity("dex", "sub-1")
	if got.Email != "alice+new@example.com" {
		t.Errorf("updated email = %q", got.Email)
	}

	// The identity key may not be rebound to another user.
	stolen := ExternalIdentity{ProviderID: "dex", Subject: "sub-1", UserID: bob.ID}
	if err := s.LinkExternalIdentity(&stolen); err != ErrExternalIdentityExists {
		t.Fatalf("rebinding = %v, want ErrExternalIdentityExists", err)
	}

	// The same subject at a different provider is a different identity.
	other := ExternalIdentity{ProviderID: "github", Subject: "sub-1", UserID: bob.ID}
	if err := s.LinkExternalIdentity(&other); err != nil {
		t.Fatalf("LinkExternalIdentity(other provider): %v", err)
	}

	if links := s.ListExternalIdentities(alice.ID); len(links) != 1 || links[0].ProviderID != "dex" {
		t.Fatalf("ListExternalIdentities(alice) = %+v", links)
	}
	if links := s.ListExternalIdentities(bob.ID); len(links) != 1 || links[0].ProviderID != "github" {
		t.Fatalf("ListExternalIdentities(bob) = %+v", links)
	}

	if err := s.UnlinkExternalIdentity("dex", "sub-1"); err != nil {
		t.Fatalf("UnlinkExternalIdentity: %v", err)
	}
	if _, ok := s.GetExternalIdentity("dex", "sub-1"); ok {
		t.Error("external identity still present after unlink")
	}

	if err := s.LinkExternalIdentity(&ExternalIdentity{ProviderID: "", Subject: "x", UserID: alice.ID}); err == nil {
		t.Error("LinkExternalIdentity accepted an empty provider")
	}
}

func TestEnsureLocalUserIsIdempotent(t *testing.T) {
	s := openTestStore(t)

	u, created, err := EnsureLocalUser(s)
	if err != nil {
		t.Fatalf("EnsureLocalUser: %v", err)
	}
	if !created {
		t.Fatal("first EnsureLocalUser did not create a user")
	}
	if u.ID != 1 {
		t.Errorf("local user ID = %d, want 1", u.ID)
	}
	if u.LoginName != LocalLoginName {
		t.Errorf("local user login = %q", u.LoginName)
	}

	ei, ok := s.GetExternalIdentity(LocalProviderID, LocalLoginName)
	if !ok || ei.UserID != u.ID {
		t.Fatalf("local external identity = %+v, %v", ei, ok)
	}

	again, created, err := EnsureLocalUser(s)
	if err != nil {
		t.Fatalf("EnsureLocalUser (second): %v", err)
	}
	if created {
		t.Error("second EnsureLocalUser created a user")
	}
	if again.ID != u.ID {
		t.Errorf("second EnsureLocalUser ID = %d, want %d", again.ID, u.ID)
	}
	if users := s.ListUsers(); len(users) != 1 {
		t.Errorf("ListUsers after two calls = %d users", len(users))
	}
}

func TestAuditAppendAndList(t *testing.T) {
	s := openTestStore(t)

	if err := s.AppendAudit(&AuditEvent{}); err == nil {
		t.Error("AppendAudit accepted an empty action")
	}
	if err := s.AppendAudit(nil); err == nil {
		t.Error("AppendAudit(nil) succeeded")
	}

	for i, action := range []string{"user.created", "node.registered", "node.approved"} {
		e := AuditEvent{Actor: "cli", Action: action, Target: "target", Detail: string(rune('a' + i))}
		if err := s.AppendAudit(&e); err != nil {
			t.Fatalf("AppendAudit(%s): %v", action, err)
		}
		if e.ID == 0 {
			t.Errorf("AppendAudit(%s) did not assign an ID", action)
		}
		if e.Time.IsZero() {
			t.Errorf("AppendAudit(%s) did not assign a time", action)
		}
	}

	all := s.ListAudit(0)
	if len(all) != 3 {
		t.Fatalf("ListAudit(0) = %d events", len(all))
	}
	for i := 1; i < len(all); i++ {
		if all[i].ID <= all[i-1].ID {
			t.Fatalf("ListAudit is not ordered by ID: %+v", all)
		}
	}
	if all[0].Action != "user.created" || all[2].Action != "node.approved" {
		t.Errorf("ListAudit actions = %q..%q", all[0].Action, all[2].Action)
	}

	limited := s.ListAudit(2)
	if len(limited) != 2 || limited[0].ID != all[0].ID || limited[1].ID != all[1].ID {
		t.Fatalf("ListAudit(2) = %+v", limited)
	}
}

func TestCreateUserDefaultsToMember(t *testing.T) {
	s := openTestStore(t)

	u := User{LoginName: "member@example.com"}
	if err := s.CreateUser(&u); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	got, ok := s.GetUser(u.ID)
	if !ok {
		t.Fatal("GetUser: not found")
	}
	if got.Role != RoleMember {
		t.Errorf("Role = %q, want %q", got.Role, RoleMember)
	}
}

func TestEnsureLocalUserIsOwner(t *testing.T) {
	s := openTestStore(t)

	u, created, err := EnsureLocalUser(s)
	if err != nil {
		t.Fatalf("EnsureLocalUser: %v", err)
	}
	if !created {
		t.Fatal("EnsureLocalUser did not create the user")
	}
	if u.Role != RoleOwner {
		t.Errorf("local user role = %q, want %q", u.Role, RoleOwner)
	}

	// Idempotent: a second call returns the same owner.
	again, created, err := EnsureLocalUser(s)
	if err != nil {
		t.Fatalf("EnsureLocalUser (again): %v", err)
	}
	if created || again.ID != u.ID || again.Role != RoleOwner {
		t.Errorf("second EnsureLocalUser = %+v, created=%v", again, created)
	}
}

func TestRoleRoundTrip(t *testing.T) {
	s := openTestStore(t)

	u := User{LoginName: "admin@example.com", Role: RoleAdmin}
	if err := s.CreateUser(&u); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if got, _ := s.GetUser(u.ID); got.Role != RoleAdmin {
		t.Errorf("stored role = %q, want admin", got.Role)
	}

	u.Role = RoleOwner
	if err := s.UpdateUser(u); err != nil {
		t.Fatalf("UpdateUser: %v", err)
	}
	if got, _ := s.GetUser(u.ID); got.Role != RoleOwner {
		t.Errorf("updated role = %q, want owner", got.Role)
	}
	if got := s.ListUsers()[0]; got.Role != RoleOwner {
		t.Errorf("ListUsers role = %q, want owner", got.Role)
	}
}

// TestMigrationPromotesExistingUsersToOwner simulates upgrading a database
// written before roles existed: every user could already do everything, so the
// migration must not silently demote them.
func TestMigrationPromotesExistingUsersToOwner(t *testing.T) {
	ctx := context.Background()
	db, err := sql.Open("sqlite", "file:"+filepath.Join(t.TempDir(), "old.db")+
		"?_txlock=immediate&_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)

	// A v1 database: the users table without a role column.
	if _, err := db.ExecContext(ctx, identityMigrations[0]+`
CREATE TABLE schema_migrations (module TEXT NOT NULL, version INTEGER NOT NULL, PRIMARY KEY (module));
INSERT INTO schema_migrations (module, version) VALUES ('identity', 1);
INSERT INTO users (login_name, display_name, email, created_at, updated_at)
VALUES ('veteran@example.com', 'Veteran', '', 1, 1);
`); err != nil {
		t.Fatalf("building v1 schema: %v", err)
	}

	s, err := NewSQLiteStore(ctx, db)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	veteran, ok := s.GetUserByLoginName("veteran@example.com")
	if !ok {
		t.Fatal("pre-existing user missing after migration")
	}
	if veteran.Role != RoleOwner {
		t.Errorf("pre-existing user role = %q, want owner", veteran.Role)
	}
}

// TestMigrationTwelveCreatesCredentialAndInviteTables simulates the databases
// that recorded v11 from the build in which the credential and invite tables
// were briefly appended to that already-shipped migration. Those databases
// never ran the new DDL, so the tables must be created by the later migration
// instead: otherwise every password sign-in and every invite is a "no such
// table" error.
func TestMigrationTwelveCreatesCredentialAndInviteTables(t *testing.T) {
	ctx := context.Background()
	db, err := sql.Open("sqlite", "file:"+filepath.Join(t.TempDir(), "stuck.db")+
		"?_txlock=immediate&_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)")
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)

	// A current database, then rewound to exactly the deployed v11 state:
	// migrations 1-11 recorded, credential and invite tables absent.
	if _, err := NewSQLiteStore(ctx, db); err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	if _, err := db.ExecContext(ctx, `
DROP TABLE local_credentials;
DROP TABLE registration_invites;
UPDATE schema_migrations SET version = 11 WHERE module = 'identity';
`); err != nil {
		t.Fatalf("rewinding to v11: %v", err)
	}

	s, err := NewSQLiteStore(ctx, db)
	if err != nil {
		t.Fatalf("NewSQLiteStore after rewind: %v", err)
	}
	if got, want := s.CountLocalCredentials(), 0; got != want {
		t.Errorf("CountLocalCredentials = %d, want %d", got, want)
	}
	if invites := s.ListRegistrationInvites(); len(invites) != 0 {
		t.Errorf("ListRegistrationInvites = %d invites, want 0", len(invites))
	}

	user := &User{LoginName: "revived@example.com", Role: RoleAdmin}
	if err := s.CreateUser(user); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if err := s.SetLocalCredential(&LocalCredential{
		UserID:       user.ID,
		PasswordHash: []byte("hash"),
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}); err != nil {
		t.Fatalf("SetLocalCredential: %v", err)
	}
	if got, want := s.CountLocalCredentials(), 1; got != want {
		t.Errorf("CountLocalCredentials after set = %d, want %d", got, want)
	}
	if _, _, err := s.CreateRegistrationInvite(NewRegistrationInviteOptions{
		Role:      RoleMember,
		CreatedBy: "admin",
		TTL:       time.Hour,
	}); err != nil {
		t.Fatalf("CreateRegistrationInvite: %v", err)
	}
	if invites := s.ListRegistrationInvites(); len(invites) != 1 {
		t.Errorf("ListRegistrationInvites = %d invites, want 1", len(invites))
	}
}
