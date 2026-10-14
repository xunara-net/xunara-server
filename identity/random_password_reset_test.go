package identity

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

func randomResetOptions(user User) PasswordResetOptions {
	return PasswordResetOptions{Reason: "已通过可靠渠道核实持有人", ExpectedUpdatedAt: user.UpdatedAt, OwnershipVerified: true}
}

func seedLegacyReset(test *testing.T, store *SQLiteStore, user User) {
	test.Helper()
	credential, err := store.LookupLocalCredential(test.Context(), user.ID)
	if err != nil {
		test.Fatal(err)
	}
	now := time.Now()
	_, err = store.db.Exec(`INSERT INTO password_reset_tickets
		(user_id, id, token_hash, credential_fingerprint, credential_updated_at, created_at, expires_at)
		VALUES (?, 'legacy-reset', ?, ?, ?, ?, ?)`, int64(user.ID), HashSecret("isolated legacy reset"), HashSecret(string(credential.PasswordHash)), credential.UpdatedAt.UnixNano(), now.UnixNano(), now.Add(time.Hour).UnixNano())
	if err != nil {
		test.Fatal(err)
	}
}

func TestRandomPasswordResetPersistsAndOnlyRevokesTargetHumanSessions(test *testing.T) {
	store, peer := openAccountStores(test)
	user, originalHash, _, token := seedAccount(test, store, "recover-user")
	other, _, _, otherToken := seedAccount(test, store, "other-user")
	foreign := openTestStore(test)
	foreignUser, foreignHash, _, foreignToken := seedAccount(test, foreign, "foreign-user")
	if foreignUser.ID != user.ID {
		test.Fatal("fixture must exercise tenant-local user ID collisions")
	}
	_, apiToken, err := store.CreateAPIKey(NewAPIKeyOptions{UserID: user.ID, Name: "service", Scopes: []string{ScopeRead}})
	if err != nil {
		test.Fatal(err)
	}
	if err := store.LinkExternalIdentity(&ExternalIdentity{ProviderID: "external", Subject: "independent-subject", UserID: user.ID}); err != nil {
		test.Fatal(err)
	}
	seedLegacyReset(test, store, user)
	result, err := store.ResetRandomPasswordByPlatform(test.Context(), user.ID, randomResetOptions(user), "platform-token")
	if err != nil || len(result.TemporaryPassword) != 32 || !result.User.PasswordChangeRequired || !result.User.UpdatedAt.After(user.UpdatedAt) || result.RevokedSessions != 1 {
		test.Fatal("direct random reset acknowledgement failed")
	}
	current, err := peer.LookupUser(test.Context(), user.ID)
	credential, credentialErr := peer.LookupLocalCredential(test.Context(), user.ID)
	if err != nil || credentialErr != nil || !current.PasswordChangeRequired || !VerifyPassword(credential.PasswordHash, result.TemporaryPassword) || VerifyPassword(originalHash, result.TemporaryPassword) || VerifyPassword(credential.PasswordHash, "original account password") {
		test.Fatal("password replacement or durable flag is incorrect")
	}
	if _, err := peer.GetSessionByToken(token); !errors.Is(err, ErrSessionNotFound) {
		test.Fatal("target human session survived reset")
	}
	for _, existing := range []struct {
		store *SQLiteStore
		token string
	}{{store, otherToken}, {foreign, foreignToken}} {
		if _, err := existing.store.GetSessionByToken(existing.token); err != nil {
			test.Fatal("another account or tenant was revoked")
		}
	}
	if foreignCredential, err := foreign.LookupLocalCredential(test.Context(), foreignUser.ID); err != nil || !bytes.Equal(foreignCredential.PasswordHash, foreignHash) {
		test.Fatal("another tenant's credential changed")
	}
	if _, err := store.GetAPIKeyByToken(apiToken); err != nil {
		test.Fatal("service identity was revoked by human password reset")
	}
	if identities, err := store.ListAccountIdentities(test.Context(), user.ID); err != nil || len(identities) != 1 {
		test.Fatal("external identity binding changed")
	}
	if unchanged, _ := store.GetUser(other.ID); unchanged.PasswordChangeRequired {
		test.Fatal("another account requires password change")
	}
	var remaining int
	if err := store.db.QueryRow("SELECT COUNT(*) FROM password_reset_tickets").Scan(&remaining); err != nil || remaining != 0 {
		test.Fatal("legacy code survived direct reset")
	}
	serialized, err := json.Marshal(result)
	if err != nil || strings.Contains(string(serialized), result.TemporaryPassword) || bytes.Contains(credential.PasswordHash, []byte(result.TemporaryPassword)) {
		test.Fatal("plain password was persisted or automatically serialized")
	}
	for _, event := range store.ListAudit(0) {
		if strings.Contains(event.Detail, result.TemporaryPassword) {
			test.Fatal("plain password leaked in audit")
		}
	}
	if _, _, err := peer.CreateLocalSession(test.Context(), user.ID, originalHash, time.Hour); !errors.Is(err, ErrCredentialChanged) {
		test.Fatal("a slow old-password login survived reset")
	}
	if _, err := store.ResetRandomPasswordByPlatform(test.Context(), user.ID, randomResetOptions(user), "platform-token"); !errors.Is(err, ErrMemberConflict) {
		test.Fatal("stale administrator could reset again")
	}
}

func TestRandomPasswordResetFailureAndIgnoredWritesRollback(test *testing.T) {
	for _, trigger := range []string{
		"BEFORE UPDATE ON local_credentials", "BEFORE DELETE ON password_reset_tickets",
		"BEFORE UPDATE ON sessions", "BEFORE UPDATE ON users", "BEFORE INSERT ON audit_events",
	} {
		for _, failure := range []string{"ABORT, 'isolated reset fault'", "IGNORE"} {
			test.Run(trigger+failure, func(test *testing.T) {
				store := openTestStore(test)
				user, hash, _, token := seedAccount(test, store, "fault-user")
				seedLegacyReset(test, store, user)
				if _, err := store.db.Exec("CREATE TRIGGER reset_fault " + trigger + " BEGIN SELECT RAISE(" + failure + "); END"); err != nil {
					test.Fatal(err)
				}
				result, err := store.ResetRandomPasswordByPlatform(test.Context(), user.ID, randomResetOptions(user), "platform-token")
				if err == nil || result.TemporaryPassword != "" {
					test.Fatal("failed or ignored write returned a password")
				}
				current, _ := store.GetUser(user.ID)
				credential, _ := store.GetLocalCredential(user.ID)
				if current != user || !bytes.Equal(credential.PasswordHash, hash) || len(store.ListAudit(0)) != 0 {
					test.Fatal("failed reset changed account, hash or audit")
				}
				if _, err := store.GetSessionByToken(token); err != nil {
					test.Fatal("failed reset revoked the original session")
				}
				var remaining int
				if err := store.db.QueryRow("SELECT COUNT(*) FROM password_reset_tickets").Scan(&remaining); err != nil || remaining != 1 {
					test.Fatal("failed reset consumed a legacy credential")
				}
			})
		}
	}
}

func TestRandomPasswordResetRequiresExactEnabledPasswordAccount(test *testing.T) {
	store := openTestStore(test)
	user, _, _, _ := seedAccount(test, store, "input-user")
	for _, options := range []PasswordResetOptions{
		{Reason: "verified", ExpectedUpdatedAt: user.UpdatedAt},
		{OwnershipVerified: true, ExpectedUpdatedAt: user.UpdatedAt},
		{Reason: "bad\x00reason", OwnershipVerified: true, ExpectedUpdatedAt: user.UpdatedAt},
		{Reason: strings.Repeat("长", 257), OwnershipVerified: true, ExpectedUpdatedAt: user.UpdatedAt},
		{Reason: "verified", OwnershipVerified: true},
	} {
		if _, err := store.ResetRandomPasswordByPlatform(test.Context(), user.ID, options, "platform-token"); !errors.Is(err, ErrMemberInvalid) {
			test.Fatal("invalid reset admission accepted")
		}
	}
	if _, err := store.ResetRandomPasswordByPlatform(test.Context(), user.ID+100, randomResetOptions(user), "platform-token"); !errors.Is(err, ErrUserNotFound) {
		test.Fatal("missing user accepted")
	}
	disabled, err := store.SetUserStatusByPlatform(test.Context(), user.ID, statusChange(user, true))
	if err != nil {
		test.Fatal(err)
	}
	if _, err := store.ResetRandomPasswordByPlatform(test.Context(), user.ID, randomResetOptions(disabled.User), "platform-token"); !errors.Is(err, ErrUserDisabled) {
		test.Fatal("disabled account accepted")
	}
	other, _, _, _ := seedAccount(test, store, "external-only")
	if err := store.DeleteLocalCredential(other.ID); err != nil {
		test.Fatal(err)
	}
	if _, err := store.ResetRandomPasswordByPlatform(test.Context(), other.ID, randomResetOptions(other), "platform-token"); !errors.Is(err, ErrCredentialNotFound) {
		test.Fatal("reset added a password to an external-only account")
	}
}

func TestRandomPasswordResetChangeClearsFlagAndRollsBackOnFault(test *testing.T) {
	for _, trigger := range []string{"", "BEFORE UPDATE ON users", "BEFORE UPDATE ON sessions", "BEFORE INSERT ON audit_events"} {
		name := trigger
		if name == "" {
			name = "success"
		}
		test.Run(name, func(test *testing.T) {
			store, peer := openAccountStores(test)
			user, _, _, _ := seedAccount(test, store, "temporary-user")
			result, err := store.ResetRandomPasswordByPlatform(test.Context(), user.ID, randomResetOptions(user), "platform-token")
			if err != nil {
				test.Fatal(err)
			}
			credential, _ := store.GetLocalCredential(user.ID)
			session, token, err := peer.CreateLocalSession(test.Context(), user.ID, credential.PasswordHash, time.Hour)
			if err != nil {
				test.Fatal(err)
			}
			if trigger != "" {
				if _, err := store.db.Exec("CREATE TRIGGER change_fault " + trigger + " BEGIN SELECT RAISE(IGNORE); END"); err != nil {
					test.Fatal(err)
				}
			}
			replacement := accountHash(test, "my personal new password")
			revoked, err := store.ChangeLocalPassword(test.Context(), user.ID, session.ID, credential.PasswordHash, replacement)
			current, _ := peer.GetUser(user.ID)
			if trigger != "" {
				if err == nil || current != result.User {
					test.Fatal("failed password change cleared forced change")
				}
				if _, err := peer.GetSessionByToken(token); err != nil {
					test.Fatal("failed password change revoked its initiating session")
				}
				if stored, _ := peer.GetLocalCredential(user.ID); !bytes.Equal(stored.PasswordHash, credential.PasswordHash) {
					test.Fatal("failed password change replaced the temporary hash")
				}
				return
			}
			if err != nil || revoked != 1 || current.PasswordChangeRequired {
				test.Fatal("personal password change failed to clear durable restriction")
			}
			if _, err := peer.GetSessionByToken(token); !errors.Is(err, ErrSessionNotFound) {
				test.Fatal("personal password change left a live temporary session")
			}
		})
	}
}

func TestRandomPasswordResetCrossInstanceCompetition(test *testing.T) {
	for _, operation := range []string{"reset", "change", "login", "disable"} {
		test.Run(operation, func(test *testing.T) {
			for attempt := 0; attempt < 4; attempt++ {
				store, peer := openAccountStores(test)
				user, hash, session, _ := seedAccount(test, store, "race-user")
				resetResult := make(chan error, 1)
				otherResult := make(chan error, 1)
				admittedToken := make(chan string, 1)
				go func() {
					_, err := store.ResetRandomPasswordByPlatform(test.Context(), user.ID, randomResetOptions(user), "platform-token")
					resetResult <- err
				}()
				go func() {
					var err error
					switch operation {
					case "reset":
						_, err = peer.ResetRandomPasswordByPlatform(test.Context(), user.ID, randomResetOptions(user), "platform-token")
					case "change":
						_, err = peer.ChangeLocalPassword(test.Context(), user.ID, session.ID, hash, []byte("isolated replacement"))
					case "login":
						_, token, loginErr := peer.CreateLocalSession(test.Context(), user.ID, hash, time.Hour)
						admittedToken <- token
						err = loginErr
					case "disable":
						_, err = peer.SetUserStatusByPlatform(test.Context(), user.ID, statusChange(user, true))
					}
					otherResult <- err
				}()
				resetErr, otherErr := <-resetResult, <-otherResult
				if operation != "login" && (resetErr == nil) == (otherErr == nil) {
					test.Fatal("competing account mutations did not serialize")
				}
				if resetErr != nil && !errors.Is(resetErr, ErrMemberConflict) {
					test.Fatal(resetErr)
				}
				if otherErr != nil && !errors.Is(otherErr, ErrMemberConflict) && !errors.Is(otherErr, ErrCredentialChanged) {
					test.Fatal(otherErr)
				}
				if operation == "login" {
					if resetErr != nil {
						test.Fatal("login unexpectedly changed the account revision")
					}
					if token := <-admittedToken; token != "" {
						if _, err := peer.GetSessionByToken(token); !errors.Is(err, ErrSessionNotFound) {
							test.Fatal("an old-password concurrent login survived reset")
						}
					}
				}
			}
		})
	}
}

func TestRandomPasswordResetMigrationPreservesAccountsAndRetiresCodes(test *testing.T) {
	store := openTestStore(test)
	user, _, session, token := seedAccount(test, store, "legacy-user")
	credential, _ := store.GetLocalCredential(user.ID)
	seedLegacyReset(test, store, user)
	if _, err := store.db.Exec("ALTER TABLE users DROP COLUMN password_change_required; UPDATE schema_migrations SET version = 18 WHERE module = 'identity'"); err != nil {
		test.Fatal(err)
	}
	upgraded, err := NewSQLiteStore(test.Context(), store.db)
	if err != nil {
		test.Fatal(err)
	}
	current, _ := upgraded.GetUser(user.ID)
	login, err := upgraded.GetSessionByToken(token)
	password, _ := upgraded.GetLocalCredential(user.ID)
	if err != nil || current != user || login != session || !reflect.DeepEqual(password, credential) {
		test.Fatal("migration changed an original account, credential or session")
	}
	var remaining int
	if err := upgraded.db.QueryRow("SELECT COUNT(*) FROM password_reset_tickets").Scan(&remaining); err != nil || remaining != 0 {
		test.Fatal("migration retained an issued legacy code")
	}
	if _, err := NewSQLiteStore(test.Context(), store.db); err != nil {
		test.Fatal("migration was not idempotent")
	}
}
