package identity

import (
	"bytes"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

func passwordResetFixture(test *testing.T, store *SQLiteStore) (User, Session, string) {
	test.Helper()
	_, member, session, token := statusFixture(test, store)
	if err := store.SetLocalCredential(&LocalCredential{UserID: member.ID, PasswordHash: []byte("original credential")}); err != nil {
		test.Fatal(err)
	}
	return member, session, token
}

func passwordResetOptions(user User) PasswordResetOptions {
	return PasswordResetOptions{Reason: "已通过可靠渠道核实持有人", ExpectedUpdatedAt: user.UpdatedAt, OwnershipVerified: true}
}

func TestPasswordResetPersistentSingleUseAndSessionBoundaries(test *testing.T) {
	store, peer := openAccountStores(test)
	member, _, token := passwordResetFixture(test, store)
	credential, _ := store.GetLocalCredential(member.ID)
	other, _ := store.GetUser(1)
	_, otherToken, err := store.CreateSession(NewSessionOptions{UserID: other.ID})
	if err != nil {
		test.Fatal(err)
	}
	_, apiToken, err := store.CreateAPIKey(NewAPIKeyOptions{UserID: member.ID, Name: "自动化", Scopes: []string{ScopeRead}})
	if err != nil {
		test.Fatal(err)
	}
	if err := store.LinkExternalIdentity(&ExternalIdentity{ProviderID: "external", Subject: "independent-subject", UserID: member.ID}); err != nil {
		test.Fatal(err)
	}
	issued, err := store.IssuePasswordResetByPlatform(test.Context(), member.ID, passwordResetOptions(member))
	if err != nil || !validPasswordResetCode(issued.Code) || issued.Status.ExpiresAt.Sub(issued.Status.CreatedAt) != PasswordResetTTL || !issued.User.UpdatedAt.After(member.UpdatedAt) {
		test.Fatal("invalid issuance")
	}
	if current, _ := store.GetLocalCredential(member.ID); !reflect.DeepEqual(current, credential) {
		test.Fatal("issuing a code changed the password")
	}
	if _, err := store.GetSessionByToken(token); err != nil {
		test.Fatal("issuing a code revoked a session")
	}
	var storedHash string
	if err := store.db.QueryRow("SELECT token_hash FROM password_reset_tickets WHERE user_id = ?", member.ID).Scan(&storedHash); err != nil || storedHash == issued.Code || !SecretEqual(storedHash, issued.Code) {
		test.Fatal("raw code was stored")
	}
	status, found, err := peer.GetPasswordResetStatus(test.Context(), member.ID)
	if err != nil || !found || status != issued.Status {
		test.Fatal("another instance cannot read pending status")
	}
	if user, err := peer.LookupPasswordReset(test.Context(), issued.Code); err != nil || user.ID != member.ID {
		test.Fatal("another instance cannot validate the code")
	}
	result, err := peer.RedeemPasswordReset(test.Context(), issued.Code, []byte("replacement credential"))
	if err != nil || result.UserID != member.ID || result.RevokedSessions != 1 {
		test.Fatal("code could not be redeemed")
	}
	if _, err := store.RedeemPasswordReset(test.Context(), issued.Code, []byte("replayed credential")); !errors.Is(err, ErrPasswordResetInvalid) {
		test.Fatal("code replay was accepted")
	}
	if _, found, err := store.GetPasswordResetStatus(test.Context(), member.ID); err != nil || found {
		test.Fatal("consumed code is still pending")
	}
	if _, err := store.GetSessionByToken(token); !errors.Is(err, ErrSessionNotFound) {
		test.Fatal("old session is still live")
	}
	if _, err := store.GetSessionByToken(otherToken); err != nil {
		test.Fatal("another account was signed out")
	}
	if _, err := store.GetAPIKeyByToken(apiToken); err != nil {
		test.Fatal("service identity was revoked")
	}
	if _, found := store.GetExternalIdentity("external", "independent-subject"); !found {
		test.Fatal("external binding was removed")
	}
	if _, _, err := store.CreateLocalSession(test.Context(), member.ID, credential.PasswordHash, time.Hour); !errors.Is(err, ErrCredentialChanged) {
		test.Fatal("old password snapshot can issue a session")
	}
	if _, _, err := store.CreateLocalSession(test.Context(), member.ID, []byte("replacement credential"), time.Hour); err != nil {
		test.Fatal("new password cannot issue a normal session")
	}
	for _, event := range store.ListAudit(0) {
		if strings.Contains(event.Detail, issued.Code) || strings.Contains(event.Detail, storedHash) || strings.Contains(event.Detail, string(credential.PasswordHash)) {
			test.Fatal("audit leaked a secret")
		}
	}
}

func TestPasswordResetReissueExpiryAndInvalidation(test *testing.T) {
	for _, change := range []string{"reissue", "expired", "credential", "change password", "disable and enable", "delete"} {
		test.Run(change, func(test *testing.T) {
			store := openTestStore(test)
			member, session, token := passwordResetFixture(test, store)
			issued, err := store.IssuePasswordResetByPlatform(test.Context(), member.ID, passwordResetOptions(member))
			if err != nil {
				test.Fatal(err)
			}
			switch change {
			case "reissue":
				second, err := store.IssuePasswordResetByPlatform(test.Context(), member.ID, passwordResetOptions(issued.User))
				if err != nil || second.Code == issued.Code {
					test.Fatal("code did not rotate")
				}
				if _, err := store.LookupPasswordReset(test.Context(), second.Code); err != nil {
					test.Fatal("replacement code is not usable")
				}
			case "expired":
				if _, err := store.db.Exec("UPDATE password_reset_tickets SET created_at = ?, expires_at = ? WHERE user_id = ?", time.Now().Add(-time.Hour).UnixNano(), time.Now().Add(-time.Minute).UnixNano(), member.ID); err != nil {
					test.Fatal(err)
				}
			case "credential":
				if err := store.SetLocalCredential(&LocalCredential{UserID: member.ID, PasswordHash: []byte("different credential")}); err != nil {
					test.Fatal(err)
				}
			case "change password":
				if _, err := store.ChangeLocalPassword(test.Context(), member.ID, session.ID, []byte("original credential"), []byte("changed by account")); err != nil {
					test.Fatal(err)
				}
			case "disable and enable":
				disabled, err := store.SetUserStatusByPlatform(test.Context(), member.ID, statusChange(issued.User, true))
				if err != nil {
					test.Fatal(err)
				}
				if _, err := store.SetUserStatusByPlatform(test.Context(), member.ID, statusChange(disabled.User, false)); err != nil {
					test.Fatal(err)
				}
			case "delete":
				if err := store.DeleteUserContext(test.Context(), member.ID); err != nil {
					test.Fatal(err)
				}
			}
			if _, err := store.LookupPasswordReset(test.Context(), issued.Code); !errors.Is(err, ErrPasswordResetInvalid) {
				test.Fatal("invalidated code can be inspected")
			}
			if _, err := store.RedeemPasswordReset(test.Context(), issued.Code, []byte("unwanted replacement")); !errors.Is(err, ErrPasswordResetInvalid) {
				test.Fatal("invalidated code can change a password")
			}
			if change == "reissue" || change == "expired" || change == "credential" {
				if _, err := store.GetSessionByToken(token); err != nil {
					test.Fatal("invalid code validation revoked a session")
				}
			}
		})
	}
}

func TestPasswordResetRequiredWritesRollback(test *testing.T) {
	for _, operation := range []string{"issue", "redeem"} {
		triggers := map[string]string{
			"user failure":  "BEFORE UPDATE ON users BEGIN SELECT RAISE(ABORT, 'injected'); END",
			"user ignored":  "BEFORE UPDATE ON users BEGIN SELECT RAISE(IGNORE); END",
			"audit failure": "BEFORE INSERT ON audit_events BEGIN SELECT RAISE(ABORT, 'injected'); END",
			"audit ignored": "BEFORE INSERT ON audit_events BEGIN SELECT RAISE(IGNORE); END",
		}
		if operation == "issue" {
			triggers["ticket failure"] = "BEFORE INSERT ON password_reset_tickets BEGIN SELECT RAISE(ABORT, 'injected'); END"
			triggers["ticket ignored"] = "BEFORE INSERT ON password_reset_tickets BEGIN SELECT RAISE(IGNORE); END"
		} else {
			triggers["ticket failure"] = "BEFORE DELETE ON password_reset_tickets BEGIN SELECT RAISE(ABORT, 'injected'); END"
			triggers["ticket ignored"] = "BEFORE DELETE ON password_reset_tickets BEGIN SELECT RAISE(IGNORE); END"
			triggers["password failure"] = "BEFORE UPDATE ON local_credentials BEGIN SELECT RAISE(ABORT, 'injected'); END"
			triggers["password ignored"] = "BEFORE UPDATE ON local_credentials BEGIN SELECT RAISE(IGNORE); END"
			triggers["session failure"] = "BEFORE UPDATE OF revoked_at ON sessions BEGIN SELECT RAISE(ABORT, 'injected'); END"
			triggers["session ignored"] = "BEFORE UPDATE OF revoked_at ON sessions BEGIN SELECT RAISE(IGNORE); END"
		}
		for name, trigger := range triggers {
			test.Run(operation+"/"+name, func(test *testing.T) {
				store := openTestStore(test)
				member, _, token := passwordResetFixture(test, store)
				var issued PasswordResetIssuance
				if operation == "redeem" {
					var err error
					issued, err = store.IssuePasswordResetByPlatform(test.Context(), member.ID, passwordResetOptions(member))
					if err != nil {
						test.Fatal(err)
					}
					member = issued.User
				}
				events := len(store.ListAudit(0))
				if _, err := store.db.Exec("CREATE TRIGGER injected " + trigger); err != nil {
					test.Fatal(err)
				}
				var err error
				if operation == "issue" {
					_, err = store.IssuePasswordResetByPlatform(test.Context(), member.ID, passwordResetOptions(member))
				} else {
					_, err = store.RedeemPasswordReset(test.Context(), issued.Code, []byte("replacement credential"))
				}
				if err == nil {
					test.Fatal("required write failure was reported as success")
				}
				user, _ := store.GetUser(member.ID)
				credential, _ := store.GetLocalCredential(member.ID)
				if !reflect.DeepEqual(user, member) || !bytes.Equal(credential.PasswordHash, []byte("original credential")) || len(store.ListAudit(0)) != events {
					test.Fatal("a failed operation partially persisted")
				}
				if _, err := store.GetSessionByToken(token); err != nil {
					test.Fatal("a failed operation signed out the account")
				}
				_, pending, err := store.GetPasswordResetStatus(test.Context(), member.ID)
				if err != nil || pending != (operation == "redeem") {
					test.Fatal("failed operation changed the pending code")
				}
			})
		}
	}
}

func TestPasswordResetInputVersionAndTenantBoundary(test *testing.T) {
	store := openTestStore(test)
	member, _, _ := passwordResetFixture(test, store)
	for _, options := range []PasswordResetOptions{
		{}, {Reason: "原因", ExpectedUpdatedAt: member.UpdatedAt},
		{Reason: " ", ExpectedUpdatedAt: member.UpdatedAt, OwnershipVerified: true},
		{Reason: "reason\nwith control", ExpectedUpdatedAt: member.UpdatedAt, OwnershipVerified: true},
		{Reason: strings.Repeat("中", 257), ExpectedUpdatedAt: member.UpdatedAt, OwnershipVerified: true},
	} {
		if _, err := store.IssuePasswordResetByPlatform(test.Context(), member.ID, options); !errors.Is(err, ErrMemberInvalid) {
			test.Fatal("invalid issuance options accepted")
		}
	}
	stale := passwordResetOptions(member)
	stale.ExpectedUpdatedAt = stale.ExpectedUpdatedAt.Add(time.Nanosecond)
	if _, err := store.IssuePasswordResetByPlatform(test.Context(), member.ID, stale); !errors.Is(err, ErrMemberConflict) {
		test.Fatal("stale issuance accepted")
	}
	issued, err := store.IssuePasswordResetByPlatform(test.Context(), member.ID, passwordResetOptions(member))
	if err != nil {
		test.Fatal(err)
	}
	other := openTestStore(test)
	passwordResetFixture(test, other)
	if _, err := other.RedeemPasswordReset(test.Context(), issued.Code, []byte("replacement")); !errors.Is(err, ErrPasswordResetInvalid) {
		test.Fatal("same user ID allowed cross-tenant recovery")
	}
}

func TestPasswordResetCrossInstanceCompetingIssuanceAndRedemption(test *testing.T) {
	for attempt := 0; attempt < 12; attempt++ {
		store, peer := openAccountStores(test)
		member, _, token := passwordResetFixture(test, store)
		results := make(chan PasswordResetIssuance, 2)
		errorsFound := make(chan error, 2)
		for _, writer := range []*SQLiteStore{store, peer} {
			go func() {
				issued, err := writer.IssuePasswordResetByPlatform(test.Context(), member.ID, passwordResetOptions(member))
				results <- issued
				errorsFound <- err
			}()
		}
		var active PasswordResetIssuance
		var successes int
		for range 2 {
			issued := <-results
			if issued.Code != "" {
				active = issued
			}
			if err := <-errorsFound; err == nil {
				successes++
			} else if !errors.Is(err, ErrMemberConflict) {
				test.Fatal(err)
			}
		}
		if successes != 1 {
			test.Fatal("competing administrators issued multiple codes")
		}
		for _, writer := range []*SQLiteStore{store, peer} {
			go func() {
				_, err := writer.RedeemPasswordReset(test.Context(), active.Code, []byte("replacement credential"))
				errorsFound <- err
			}()
		}
		successes = 0
		for range 2 {
			if err := <-errorsFound; err == nil {
				successes++
			} else if !errors.Is(err, ErrPasswordResetInvalid) {
				test.Fatal(err)
			}
		}
		if successes != 1 || len(store.ListAudit(0)) != 2 {
			test.Fatal("competing redeemers succeeded more than once")
		}
		if _, err := store.GetSessionByToken(token); !errors.Is(err, ErrSessionNotFound) {
			test.Fatal("redemption left a live old session")
		}
	}
}

func TestPasswordResetMigrationPreservesOldIdentity(test *testing.T) {
	store := openTestStore(test)
	member, session, token := passwordResetFixture(test, store)
	credential, _ := store.GetLocalCredential(member.ID)
	if _, err := store.db.Exec("DROP TABLE password_reset_tickets; UPDATE schema_migrations SET version = 16 WHERE module = 'identity'"); err != nil {
		test.Fatal(err)
	}
	upgraded, err := NewSQLiteStore(test.Context(), store.db)
	if err != nil {
		test.Fatal(err)
	}
	user, _ := upgraded.GetUser(member.ID)
	current, err := upgraded.GetSessionByToken(token)
	password, _ := upgraded.GetLocalCredential(member.ID)
	if err != nil || user != member || current != session || !reflect.DeepEqual(password, credential) {
		test.Fatal("migration changed an old account, password or session")
	}
	if _, found, err := upgraded.GetPasswordResetStatus(test.Context(), member.ID); err != nil || found {
		test.Fatal("migration invented a pending reset")
	}
}

func TestPasswordResetCompetesWithPasswordChangeAndOldPasswordLogin(test *testing.T) {
	for _, operation := range []string{"change", "login"} {
		test.Run(operation, func(test *testing.T) {
			for attempt := 0; attempt < 12; attempt++ {
				store, peer := openAccountStores(test)
				member, session, _ := passwordResetFixture(test, store)
				issued, err := store.IssuePasswordResetByPlatform(test.Context(), member.ID, passwordResetOptions(member))
				if err != nil {
					test.Fatal(err)
				}
				resetOutcome := make(chan error, 1)
				otherOutcome := make(chan error, 1)
				go func() {
					_, err := store.RedeemPasswordReset(test.Context(), issued.Code, []byte("reset replacement"))
					resetOutcome <- err
				}()
				go func() {
					var err error
					if operation == "change" {
						_, err = peer.ChangeLocalPassword(test.Context(), member.ID, session.ID, []byte("original credential"), []byte("account replacement"))
					} else {
						_, _, err = peer.CreateLocalSession(test.Context(), member.ID, []byte("original credential"), time.Hour)
					}
					otherOutcome <- err
				}()
				resetErr, otherErr := <-resetOutcome, <-otherOutcome
				if operation == "change" {
					if (resetErr == nil) == (otherErr == nil) || (resetErr != nil && !errors.Is(resetErr, ErrPasswordResetInvalid)) || (otherErr != nil && !errors.Is(otherErr, ErrCredentialChanged)) {
						test.Fatal("competing password mutations did not serialize")
					}
				} else if resetErr != nil || (otherErr != nil && !errors.Is(otherErr, ErrCredentialChanged)) {
					test.Fatal("old password login interfered with recovery")
				}
				sessions, err := store.ListAccountSessions(test.Context(), member.ID)
				if err != nil {
					test.Fatal(err)
				}
				for _, existing := range sessions {
					if existing.RevokedAt.IsZero() {
						test.Fatal("concurrent old password login survived a credential mutation")
					}
				}
				if _, err := store.LookupPasswordReset(test.Context(), issued.Code); !errors.Is(err, ErrPasswordResetInvalid) {
					test.Fatal("password mutation left the reset code usable")
				}
			}
		})
	}
}

func TestPasswordResetInvalidationFailureRollsBackAccountChanges(test *testing.T) {
	for _, operation := range []string{"disable", "delete", "change password"} {
		test.Run(operation, func(test *testing.T) {
			store := openTestStore(test)
			member, session, token := passwordResetFixture(test, store)
			issued, err := store.IssuePasswordResetByPlatform(test.Context(), member.ID, passwordResetOptions(member))
			if err != nil {
				test.Fatal(err)
			}
			if _, err := store.db.Exec("CREATE TRIGGER reset_invalidation_ignored BEFORE DELETE ON password_reset_tickets BEGIN SELECT RAISE(IGNORE); END"); err != nil {
				test.Fatal(err)
			}
			switch operation {
			case "disable":
				_, err = store.SetUserStatusByPlatform(test.Context(), member.ID, statusChange(issued.User, true))
			case "delete":
				err = store.DeleteUserContext(test.Context(), member.ID)
			case "change password":
				_, err = store.ChangeLocalPassword(test.Context(), member.ID, session.ID, []byte("original credential"), []byte("replacement"))
			}
			if err == nil {
				test.Fatal("ignored invalidation was reported as success")
			}
			user, _ := store.GetUser(member.ID)
			credential, _ := store.GetLocalCredential(member.ID)
			if user != issued.User || !bytes.Equal(credential.PasswordHash, []byte("original credential")) || len(store.ListAudit(0)) != 1 {
				test.Fatal("failed invalidation partially changed the account")
			}
			if _, err := store.GetSessionByToken(token); err != nil {
				test.Fatal("failed invalidation revoked a login")
			}
			if _, err := store.LookupPasswordReset(test.Context(), issued.Code); err != nil {
				test.Fatal("failed invalidation lost the pending code")
			}
		})
	}
}
