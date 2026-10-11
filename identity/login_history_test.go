package identity

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"tailscale.com/tailcfg"
)

func rewindLoginHistorySchema(test *testing.T, database *sql.DB) {
	test.Helper()
	if _, err := database.Exec(`DROP TRIGGER account_login_record_created;
		DROP TRIGGER account_login_record_updated; DROP TABLE account_login_records;
		ALTER TABLE sessions DROP COLUMN client_ip; ALTER TABLE sessions DROP COLUMN user_agent;`); err != nil {
		test.Fatal(err)
	}
}

func loginHistoryRecord(test *testing.T, store *SQLiteStore, userID tailcfg.UserID, id string) LoginRecord {
	test.Helper()
	page, err := store.ListAccountLoginHistory(test.Context(), userID, LoginHistoryOptions{Limit: 100})
	if err != nil {
		test.Fatal(err)
	}
	for _, record := range page.Records {
		if record.ID == id {
			return record
		}
	}
	test.Fatal("login record missing")
	return LoginRecord{}
}

func TestSessionClientInfoNormalization(test *testing.T) {
	info := (SessionClientInfo{IP: " ::ffff:192.0.2.4 ", UserAgent: "Chrome\r\n\x00\u202e " + strings.Repeat("中", 500)}).Normalize()
	if info.IP != "192.0.2.4" || len(info.UserAgent) > MaxSessionUserAgentBytes || !utf8.ValidString(info.UserAgent) || strings.ContainsAny(info.UserAgent, "\r\n\x00\u202e") {
		test.Fatal("client source is not canonical, bounded and safe to display")
	}
	for _, address := range []string{"forged", "192.0.2.4, 198.51.100.1", "fe80::1%eth0", "https://example.test"} {
		if got := (SessionClientInfo{IP: address}).Normalize(); got.IP != "" {
			test.Fatal("invalid or scoped IP was stored")
		}
	}
}

func TestLoginHistoryLifecycleAndGarbageCollection(test *testing.T) {
	store, peer := openAccountStores(test)
	user, _, original, token := seedAccount(test, store, "history-user")
	source := SessionClientInfo{IP: "2001:db8::5", UserAgent: "Firefox/120 Linux"}
	active, activeToken, err := store.CreateSession(NewSessionOptions{UserID: user.ID, TTL: time.Hour, AuthMethod: LocalProviderID, ClientInfo: source})
	if err != nil {
		test.Fatal(err)
	}
	rotated, rotatedToken, err := peer.RotateSession(activeToken, time.Hour)
	if err != nil || rotated.ClientInfo != source {
		test.Fatal("rotation did not inherit the original source")
	}
	if record := loginHistoryRecord(test, store, user.ID, rotated.ID); record.Kind != "rotation" || record.ClientInfo != source {
		test.Fatal("rotation was presented as a fresh human login")
	}
	if record := loginHistoryRecord(test, peer, user.ID, active.ID); record.RevokedReason != "rotated" || record.RevokedAt.IsZero() {
		test.Fatal("rotation did not synchronize the previous record")
	}
	if _, err := store.RevokeAccountSessions(test.Context(), user.ID, original.ID, SessionRevocation{Mode: RevokeSingleSession, SessionID: rotated.ID}); err != nil {
		test.Fatal(err)
	}
	if record := loginHistoryRecord(test, peer, user.ID, rotated.ID); record.RevokedReason != "signed out one session" {
		test.Fatal("account revocation and history disagree")
	}
	if _, err := peer.GetSessionByToken(rotatedToken); !errors.Is(err, ErrSessionNotFound) {
		test.Fatal("revoked session still authenticates")
	}
	if _, err := store.db.Exec("UPDATE sessions SET expires_at = ? WHERE id = ?", time.Now().Add(-time.Minute).UnixNano(), active.ID); err != nil {
		test.Fatal(err)
	}
	if count, err := peer.DeleteExpiredSessions(time.Now()); err != nil || count != 1 {
		test.Fatal("expired session cleanup failed")
	}
	if _, exists := store.GetSessionByID(active.ID); exists {
		test.Fatal("expired session was not removed")
	}
	if record := loginHistoryRecord(test, peer, user.ID, active.ID); record.ClientInfo != source || record.Kind != "login" {
		test.Fatal("garbage collection lost independent history")
	}
	if _, err := store.GetSessionByToken(token); err != nil {
		test.Fatal("history affected an unrelated live login")
	}
}

func TestLoginHistoryRequiredWritesRollback(test *testing.T) {
	for _, operation := range []string{"create", "revoke", "activity", "rotate", "delete"} {
		for _, failure := range []string{"ABORT", "IGNORE"} {
			test.Run(operation+"-"+failure, func(test *testing.T) {
				store := openTestStore(test)
				user, hash, session, token := seedAccount(test, store, "fault-user")
				if operation == "activity" {
					if _, err := store.db.Exec("UPDATE sessions SET last_seen_at = ? WHERE id = ?", time.Now().Add(-time.Hour).UnixNano(), session.ID); err != nil {
						test.Fatal(err)
					}
				}
				before, _ := store.GetSessionByID(session.ID)
				verb := "UPDATE"
				if operation == "create" {
					verb = "INSERT"
				} else if operation == "delete" {
					verb = "DELETE"
				}
				body := "SELECT RAISE(IGNORE);"
				if failure == "ABORT" {
					body = "SELECT RAISE(ABORT, 'injected');"
				}
				if _, err := store.db.Exec("CREATE TRIGGER fail_login_record BEFORE " + verb + " ON account_login_records BEGIN " + body + " END"); err != nil {
					test.Fatal(err)
				}
				var err error
				switch operation {
				case "create":
					created, secret, createErr := store.CreateLocalSession(test.Context(), user.ID, hash, time.Hour)
					err = createErr
					if created.ID != "" || secret != "" {
						test.Fatal("incomplete login returned credentials")
					}
				case "revoke":
					_, err = store.RevokeAccountSessions(test.Context(), user.ID, session.ID, SessionRevocation{Mode: RevokeAllSessions})
				case "activity":
					_, err = store.UseSession(test.Context(), token)
				case "rotate":
					created, secret, rotateErr := store.RotateSession(token, time.Hour)
					err = rotateErr
					if created.ID != "" || secret != "" {
						test.Fatal("incomplete rotation returned credentials")
					}
				case "delete":
					err = store.DeleteUserContext(test.Context(), user.ID)
				}
				if err == nil || errors.Is(err, ErrSessionNotFound) {
					test.Fatal("record write failure was ignored or treated as bad credentials")
				}
				after, found := store.GetSessionByID(session.ID)
				if !found || !after.RevokedAt.Equal(before.RevokedAt) || !after.LastSeenAt.Equal(before.LastSeenAt) || len(store.ListSessions(user.ID)) != 1 || len(store.ListAudit(0)) != 0 {
					test.Fatal("failed record write left partial session or audit facts")
				}
				if _, found := store.GetUser(user.ID); !found {
					test.Fatal("failed privacy cleanup deleted the user")
				}
				loginHistoryRecord(test, store, user.ID, session.ID)
			})
		}
	}
}

func TestSessionActivityThrottledMonotonicAndShared(test *testing.T) {
	store, peer := openAccountStores(test)
	user, _, session, token := seedAccount(test, store, "active-user")
	if _, err := store.db.Exec("UPDATE sessions SET last_seen_at = ? WHERE id = ?", time.Now().Add(-time.Hour).UnixNano(), session.ID); err != nil {
		test.Fatal(err)
	}
	var workers sync.WaitGroup
	errorsFound := make(chan error, 12)
	for index := 0; index < 12; index++ {
		workers.Add(1)
		go func(index int) {
			defer workers.Done()
			current := store
			if index%2 == 1 {
				current = peer
			}
			_, err := current.UseSession(test.Context(), token)
			errorsFound <- err
		}(index)
	}
	workers.Wait()
	close(errorsFound)
	for err := range errorsFound {
		if err != nil {
			test.Fatal(err)
		}
	}
	seen, _ := store.GetSessionByID(session.ID)
	if seen.LastSeenAt.Before(session.CreatedAt) || !seen.ExpiresAt.Equal(session.ExpiresAt) || !loginHistoryRecord(test, peer, user.ID, session.ID).LastSeenAt.Equal(seen.LastSeenAt) {
		test.Fatal("activity is stale, changed expiry or disagrees with history")
	}
	if err := peer.TouchSession(session.ID, seen.LastSeenAt.Add(-time.Hour)); err != nil {
		test.Fatal(err)
	}
	if _, err := store.db.Exec("CREATE TRIGGER activity_must_be_throttled BEFORE UPDATE ON sessions BEGIN SELECT RAISE(ABORT, 'unnecessary write'); END"); err != nil {
		test.Fatal(err)
	}
	if current, err := peer.UseSession(test.Context(), token); err != nil || !current.LastSeenAt.Equal(seen.LastSeenAt) {
		test.Fatal("rapid requests wrote again or moved activity backwards")
	}
	ctx, cancel := context.WithCancel(test.Context())
	cancel()
	if _, err := store.UseSession(ctx, token); !errors.Is(err, context.Canceled) {
		test.Fatal("session lookup ignored context cancellation")
	}
}

func TestLoginHistoryPaginationAndPrivacyCleanup(test *testing.T) {
	store := openTestStore(test)
	user, _, _, _ := seedAccount(test, store, "paged-user")
	foreign, _, _, _ := seedAccount(test, store, "other-user")
	for index := 0; index < 6; index++ {
		if _, _, err := store.CreateSession(NewSessionOptions{UserID: user.ID}); err != nil {
			test.Fatal(err)
		}
	}
	if _, err := store.db.Exec("UPDATE account_login_records SET created_at = ? WHERE user_id = ?", time.Now().Add(-time.Hour).UnixNano(), user.ID); err != nil {
		test.Fatal(err)
	}
	seen := make(map[string]bool)
	cursor := ""
	for {
		page, err := store.ListAccountLoginHistory(test.Context(), user.ID, LoginHistoryOptions{Limit: 2, Cursor: cursor})
		if err != nil || len(page.Records) > 2 {
			test.Fatal("bounded history pagination failed")
		}
		for _, record := range page.Records {
			if seen[record.ID] || record.UserID != user.ID {
				test.Fatal("page duplicated records or crossed user boundary")
			}
			seen[record.ID] = true
		}
		cursor = page.NextCursor
		if cursor == "" {
			break
		}
	}
	if len(seen) != 7 {
		test.Fatal("equal-timestamp pages lost records")
	}
	for _, options := range []LoginHistoryOptions{{Limit: -1}, {Limit: 101}, {Cursor: "forged"}, {Cursor: strings.Repeat("a", 129)}} {
		if _, err := store.ListAccountLoginHistory(test.Context(), user.ID, options); !errors.Is(err, ErrInvalidLoginHistoryOptions) {
			test.Fatal("invalid pagination was accepted")
		}
	}
	if err := store.DeleteUserContext(test.Context(), user.ID); err != nil {
		test.Fatal(err)
	}
	if page, err := store.ListAccountLoginHistory(test.Context(), user.ID, LoginHistoryOptions{}); err != nil || len(page.Records) != 0 || len(store.ListSessions(user.ID)) != 0 {
		test.Fatal("account deletion left private session history")
	}
	if page, err := store.ListAccountLoginHistory(test.Context(), foreign.ID, LoginHistoryOptions{}); err != nil || len(page.Records) != 1 {
		test.Fatal("deletion affected another account")
	}
}

func TestLoginHistoryMigrationPreservesSessionFacts(test *testing.T) {
	store := openTestStore(test)
	user, _, session, token := seedAccount(test, store, "legacy-user")
	rewindLoginHistorySchema(test, store.db)
	if _, err := store.db.Exec("UPDATE schema_migrations SET version = 17 WHERE module = 'identity'"); err != nil {
		test.Fatal(err)
	}
	upgraded, err := NewSQLiteStore(test.Context(), store.db)
	if err != nil {
		test.Fatal(err)
	}
	current, err := upgraded.GetSessionByToken(token)
	if err != nil || current != session {
		test.Fatal("migration changed original session facts or credentials")
	}
	if record := loginHistoryRecord(test, upgraded, user.ID, session.ID); record.Kind != "legacy" || record.ClientInfo != (SessionClientInfo{}) || !record.CreatedAt.Equal(session.CreatedAt) {
		test.Fatal("migration invented an origin or changed historical time")
	}
	if _, err := NewSQLiteStore(test.Context(), store.db); err != nil {
		test.Fatal("second startup attempted to replay the migration")
	}
}

func TestLoginHistoryAllAuthenticationSources(test *testing.T) {
	source := SessionClientInfo{IP: "192.0.2.7", UserAgent: "Chrome Windows"}
	for _, method := range []string{"password", "passkey", "external", "registration", "bootstrap"} {
		test.Run(method, func(test *testing.T) {
			store := openTestStore(test)
			var session Session
			var err error
			if method == "bootstrap" {
				if _, _, err := EnsureLocalUser(store); err != nil {
					test.Fatal(err)
				}
				_, session, _, err = store.ClaimLocalAccount(test.Context(), LocalAccountClaim{Kind: ClaimAdministrator, LoginName: "owner", PasswordHash: []byte("hash"), ClientInfo: source})
			} else if method == "registration" {
				registration := registrationFixture("joined", "")
				registration.ClientInfo = source
				_, session, _, err = store.RegisterLocalAccount(test.Context(), registration)
			} else {
				user, hash, initiating, _ := seedAccount(test, store, "signed-in")
				switch method {
				case "password":
					session, _, err = store.CreateLocalSession(test.Context(), user.ID, hash, time.Hour, source)
				case "passkey":
					credential, createErr := store.CreateAccountPasskey(test.Context(), initiating.ID, accountTestPasskey(user, "test key"))
					if createErr != nil {
						test.Fatal(createErr)
					}
					session, _, err = store.CreatePasskeySession(test.Context(), user.ID, credential.ID, time.Hour, source)
				case "external":
					authorization := accountAuthorization(test, store, NewAuthTransactionOptions{})
					completed, finishErr := store.CompleteExternalAuthentication(test.Context(), authorization.ID,
						IdentityResult{ProviderID: authorization.ProviderID, Subject: "external-subject"}, ExternalAuthenticationOptions{AllowCreate: true, MaxUsers: -1, LoginName: "external-member", ClientInfo: source})
					err, session = finishErr, completed.Session
				}
			}
			if err != nil || session.ClientInfo != source {
				test.Fatalf("%s origin missing: %v", method, err)
			}
			if record := loginHistoryRecord(test, store, session.UserID, session.ID); record.Kind != "login" || record.ClientInfo != source {
				test.Fatal("successful authentication did not atomically record its source")
			}
		})
	}
}

func TestLoginHistoryStorageErrorIsNotEmpty(test *testing.T) {
	store := openTestStore(test)
	user, _, _, _ := seedAccount(test, store, "read-fault")
	if _, err := store.db.Exec("DROP TABLE account_login_records"); err != nil {
		test.Fatal(err)
	}
	if page, err := store.ListAccountLoginHistory(test.Context(), user.ID, LoginHistoryOptions{}); err == nil || page.Records != nil {
		test.Fatal("storage failure was represented as empty history")
	}
}

func TestLoginHistorySynchronizesSecurityRevocations(test *testing.T) {
	for _, operation := range []string{"password", "disabled", "reset", "external unlink", "generic logout"} {
		test.Run(operation, func(test *testing.T) {
			store := openTestStore(test)
			user, hash, session, _ := seedAccount(test, store, "revocation-user")
			var err error
			switch operation {
			case "password":
				_, err = store.ChangeLocalPassword(test.Context(), user.ID, session.ID, hash, []byte("replacement"))
			case "disabled":
				_, err = store.SetUserStatusByPlatform(test.Context(), user.ID, statusChange(user, true))
			case "reset":
				issued, issueErr := store.IssuePasswordResetByPlatform(test.Context(), user.ID, PasswordResetOptions{ExpectedUpdatedAt: user.UpdatedAt, OwnershipVerified: true, Reason: "verified holder"})
				if issueErr != nil {
					test.Fatal(issueErr)
				}
				_, err = store.RedeemPasswordReset(test.Context(), issued.Code, []byte("replacement"))
			case "external unlink":
				link := ExternalIdentity{ProviderID: "test-oidc", Subject: "bound-subject", UserID: user.ID}
				if err := store.LinkExternalIdentity(&link); err != nil {
					test.Fatal(err)
				}
				external, _, createErr := store.CreateSession(NewSessionOptions{UserID: user.ID, AuthMethod: link.ProviderID})
				if createErr != nil {
					test.Fatal(createErr)
				}
				_, err = store.UnlinkAccountIdentity(test.Context(), user.ID, session.ID, IdentityReference(link), LoginMethods{Local: true, Providers: []string{link.ProviderID}})
				session = external
			case "generic logout":
				err = store.RevokeSession(session.ID, "logout")
			}
			if err != nil {
				test.Fatal(err)
			}
			current, found := store.GetSessionByID(session.ID)
			record := loginHistoryRecord(test, store, user.ID, session.ID)
			if !found || current.RevokedAt.IsZero() || !record.RevokedAt.Equal(current.RevokedAt) || record.RevokedReason != current.RevokedReason {
				test.Fatal("security action left stale login history")
			}
		})
	}
}
