package identity

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestAccountExportPrivateSnapshotAndHistory(test *testing.T) {
	store, _ := openAccountStores(test)
	user, _, session, _ := seedAccount(test, store, "export-self")
	other, _, _, _ := seedAccount(test, store, "export-other")
	for _, target := range []User{user, other} {
		link := ExternalIdentity{ProviderID: "oidc:example", Subject: fmt.Sprintf("private-subject-%d", target.ID), UserID: target.ID,
			DisplayName: target.LoginName, Email: target.LoginName + "@example.test"}
		if err := store.LinkExternalIdentity(&link); err != nil {
			test.Fatal(err)
		}
		passkey := Passkey{UserID: target.ID, Name: target.LoginName, CredentialID: []byte(target.LoginName + "-credential")}
		if err := store.CreatePasskey(&passkey); err != nil {
			test.Fatal(err)
		}
	}
	expired, _, err := store.CreateSession(NewSessionOptions{UserID: user.ID, AuthMethod: LocalProviderID})
	if err != nil {
		test.Fatal(err)
	}
	if _, err := store.db.Exec("UPDATE sessions SET expires_at = ? WHERE id = ?", time.Now().Add(-time.Hour).UnixNano(), expired.ID); err != nil {
		test.Fatal(err)
	}
	if _, err := store.DeleteExpiredSessions(time.Now()); err != nil {
		test.Fatal(err)
	}
	snapshot, err := store.PrepareAccountExport(test.Context(), user.ID, session.ID, AccountExportOptions{Scope: AccountSecurityExportScope})
	if err != nil {
		test.Fatal(err)
	}
	if snapshot.User.ID != user.ID || !snapshot.LocalPasswordConfigured || len(snapshot.Sessions) != 1 || len(snapshot.LoginHistory) != 2 || len(snapshot.Identities) != 1 || len(snapshot.Passkeys) != 1 {
		test.Fatal("own snapshot lost metadata or included another user")
	}
	if snapshot.Identities[0].DisplayName != user.LoginName || snapshot.Passkeys[0].Name != user.LoginName {
		test.Fatal("cross-user bindings or passkeys exported")
	}
	if !snapshot.Passkeys[0].LastUsedAt.IsZero() {
		test.Fatal("never-used passkey fabricated an epoch activity")
	}
	after, found := store.GetSessionByID(session.ID)
	if !found || !reflect.DeepEqual(after, session) {
		test.Fatal("export changed the initiating session")
	}
	for _, event := range store.ListAudit(0) {
		if event.Action != AuditAccountExportPrepared || strings.Contains(event.Detail, user.LoginName) || strings.Contains(event.Detail, "private-subject") {
			test.Fatal("export audit contains content rather than preparation metadata")
		}
	}
	filtered, err := store.PrepareAccountExport(test.Context(), user.ID, session.ID, AccountExportOptions{
		Scope: LoginHistoryExportScope, From: expired.CreatedAt, Until: expired.CreatedAt.Add(time.Nanosecond),
	})
	if err != nil || len(filtered.LoginHistory) != 1 || filtered.LoginHistory[0].ID != expired.ID || len(filtered.Passkeys) != 0 || filtered.User.ID != 0 {
		test.Fatal("history interval was not half-open or history scope read profile data")
	}
}

func TestAccountExportAuthorizationCancellationAndAuditFailure(test *testing.T) {
	for _, failure := range []string{"other-session", "revoked", "disabled", "expired", "cancelled", "read", "audit-abort", "audit-ignore", "session-ignore"} {
		test.Run(failure, func(test *testing.T) {
			store, otherStore := openAccountStores(test)
			user, _, session, _ := seedAccount(test, store, "export-failure")
			ctx := test.Context()
			expected := error(nil)
			switch failure {
			case "other-session":
				_, _, other, _ := seedAccount(test, store, "another-user")
				session.ID = other.ID
				expected = ErrSessionRevoked
			case "revoked":
				if err := otherStore.RevokeSession(session.ID, "isolated test"); err != nil {
					test.Fatal(err)
				}
				expected = ErrSessionRevoked
			case "disabled", "expired":
				query, arguments := "UPDATE users SET disabled_at = ? WHERE id = ?", []any{time.Now().UnixNano(), int64(user.ID)}
				if failure == "expired" {
					query, arguments = "UPDATE sessions SET expires_at = ? WHERE id = ?", []any{time.Now().Add(-time.Hour).UnixNano(), session.ID}
				}
				if _, err := otherStore.db.Exec(query, arguments...); err != nil {
					test.Fatal(err)
				}
				expected = ErrSessionRevoked
			case "cancelled":
				cancelled, cancel := context.WithCancel(ctx)
				cancel()
				ctx, expected = cancelled, context.Canceled
			case "read":
				if _, err := store.db.Exec("ALTER TABLE webauthn_credentials RENAME TO unavailable_passkeys"); err != nil {
					test.Fatal(err)
				}
			default:
				body, table, operation := "SELECT RAISE(ABORT, 'isolated audit failure');", "audit_events", "INSERT"
				if failure == "audit-ignore" || failure == "session-ignore" {
					body = "SELECT RAISE(IGNORE);"
				}
				if failure == "session-ignore" {
					table, operation = "sessions", "UPDATE"
				}
				if _, err := store.db.Exec("CREATE TRIGGER export_failure BEFORE " + operation + " ON " + table + " BEGIN " + body + " END"); err != nil {
					test.Fatal(err)
				}
			}
			snapshot, err := store.PrepareAccountExport(ctx, user.ID, session.ID, AccountExportOptions{Scope: AccountSecurityExportScope})
			if err == nil || snapshot.GeneratedAt != (time.Time{}) || expected != nil && !errors.Is(err, expected) {
				test.Fatalf("export did not fail closed: %v", err)
			}
			if len(store.ListAudit(0)) != 0 {
				test.Fatal("rejected export left preparation audit")
			}
		})
	}
}

func TestAccountExportRowLimitAndOptions(test *testing.T) {
	store, _ := openAccountStores(test)
	user, _, session, _ := seedAccount(test, store, "export-limit")
	for _, options := range []AccountExportOptions{
		{}, {Scope: "other"}, {Scope: LoginHistoryExportScope, From: time.Unix(-1, 0)},
		{Scope: LoginHistoryExportScope, From: time.Date(3000, 1, 1, 0, 0, 0, 0, time.UTC)},
		{Scope: LoginHistoryExportScope, From: time.Unix(10, 0), Until: time.Unix(10, 0)},
		{Scope: LoginHistoryExportScope, From: time.Unix(11, 0), Until: time.Unix(10, 0)},
	} {
		if _, err := store.PrepareAccountExport(test.Context(), user.ID, session.ID, options); !errors.Is(err, ErrInvalidAccountExport) {
			test.Fatal("invalid export options accepted")
		}
	}
	// 明确的隔离历史种子不是 5000 次真实认证。
	if _, err := store.db.Exec(`WITH RECURSIVE samples(number) AS (SELECT 1 UNION ALL SELECT number+1 FROM samples WHERE number < ?)
		INSERT INTO account_login_records (id,user_id,auth_method,kind,created_at,expires_at,revoked_reason,client_ip,user_agent)
		SELECT printf('export-sample-%05d',number),?,'local','legacy',?,?, '', '', '' FROM samples`,
		MaxAccountExportRows, int64(user.ID), time.Now().Add(-time.Hour).UnixNano(), time.Now().Add(time.Hour).UnixNano()); err != nil {
		test.Fatal(err)
	}
	if _, err := store.PrepareAccountExport(test.Context(), user.ID, session.ID, AccountExportOptions{Scope: LoginHistoryExportScope}); !errors.Is(err, ErrAccountExportTooLarge) {
		test.Fatal("oversize history silently truncated")
	}
	if len(store.ListAudit(0)) != 0 {
		test.Fatal("oversize export committed a preparation audit")
	}
	if _, err := store.db.Exec("DELETE FROM account_login_records WHERE id = 'export-sample-00001'"); err != nil {
		test.Fatal(err)
	}
	snapshot, err := store.PrepareAccountExport(test.Context(), user.ID, session.ID, AccountExportOptions{Scope: LoginHistoryExportScope})
	if err != nil || len(snapshot.LoginHistory) != MaxAccountExportRows {
		test.Fatal("exact row limit was not exportable")
	}
}

func TestAccountExportConsistentAcrossConnections(test *testing.T) {
	store, writer := openAccountStores(test)
	user, _, session, _ := seedAccount(test, store, "export-version")
	passkey := Passkey{UserID: user.ID, Name: "version-0", CredentialID: []byte("snapshot-passkey")}
	if err := store.CreatePasskey(&passkey); err != nil {
		test.Fatal(err)
	}
	if _, err := store.db.Exec("UPDATE users SET display_name = 'version-0' WHERE id = ?", int64(user.ID)); err != nil {
		test.Fatal(err)
	}
	var workers sync.WaitGroup
	failures := make(chan error, 2)
	workers.Add(1)
	go func() {
		defer workers.Done()
		for version := 1; version <= 20; version++ {
			transaction, err := writer.db.BeginTx(test.Context(), nil)
			if err != nil {
				failures <- err
				return
			}
			label := fmt.Sprintf("version-%d", version)
			_, firstErr := transaction.ExecContext(test.Context(), "UPDATE users SET display_name = ? WHERE id = ?", label, int64(user.ID))
			_, secondErr := transaction.ExecContext(test.Context(), "UPDATE webauthn_credentials SET name = ? WHERE id = ?", label, passkey.ID)
			if firstErr != nil || secondErr != nil {
				transaction.Rollback()
				failures <- fmt.Errorf("snapshot writer failed: %v %v", firstErr, secondErr)
				return
			}
			if err := transaction.Commit(); err != nil {
				failures <- err
				return
			}
		}
	}()
	for iteration := 0; iteration < 20; iteration++ {
		snapshot, err := store.PrepareAccountExport(test.Context(), user.ID, session.ID, AccountExportOptions{Scope: AccountSecurityExportScope})
		if err != nil {
			failures <- err
			break
		}
		if len(snapshot.Passkeys) != 1 || snapshot.Passkeys[0].Name != snapshot.User.DisplayName {
			failures <- errors.New("export mixed two committed versions")
			break
		}
	}
	workers.Wait()
	close(failures)
	for err := range failures {
		test.Error(err)
	}
}

func TestAccountExportEveryCollectionIsBounded(test *testing.T) {
	for _, collection := range []string{"sessions", "identities", "passkeys"} {
		test.Run(collection, func(test *testing.T) {
			store, _ := openAccountStores(test)
			user, _, session, _ := seedAccount(test, store, "export-collection")
			prefix := `WITH RECURSIVE samples(number) AS (SELECT 1 UNION ALL SELECT number+1 FROM samples WHERE number < ?)`
			query := prefix + ` INSERT INTO webauthn_credentials(id,user_id,name,credential_id,credential,created_at,last_used_at)
				SELECT printf('export-key-%05d',number),?,'isolated key',CAST(printf('fixture-%05d',number) AS BLOB),'{}',?,0 FROM samples`
			arguments := []any{MaxAccountExportRows + 1, int64(user.ID), time.Now().UnixNano()}
			if collection == "identities" {
				query = prefix + ` INSERT INTO external_identities(provider_id,subject,user_id,email,display_name,created_at,updated_at)
					SELECT 'fixture',printf('sample-%05d',number),?,'','',?,? FROM samples`
				arguments = append(arguments, time.Now().UnixNano())
			} else if collection == "sessions" {
				query = prefix + ` INSERT INTO sessions(id,token_hash,user_id,auth_method,created_at,expires_at)
					SELECT printf('export-session-%05d',number),printf('fixture-hash-%05d',number),?,'local',?,? FROM samples`
				arguments = append(arguments, time.Now().Add(2*time.Hour).UnixNano())
			}
			if _, err := store.db.Exec(query, arguments...); err != nil {
				test.Fatal(err)
			}
			// 过滤全部历史仍不得截断其他集合；这些行只用于明确的规模边界夹具。
			options := AccountExportOptions{Scope: AccountSecurityExportScope, From: time.Now().Add(time.Hour)}
			if _, err := store.PrepareAccountExport(test.Context(), user.ID, session.ID, options); !errors.Is(err, ErrAccountExportTooLarge) {
				test.Fatalf("unbounded %s collection: %v", collection, err)
			}
			if len(store.ListAudit(0)) != 0 {
				test.Fatal("rejected collection committed preparation audit")
			}
		})
	}
}

func TestAccountExportTextBudgetDoesNotCommitPartialSnapshot(test *testing.T) {
	store, _ := openAccountStores(test)
	user, _, session, _ := seedAccount(test, store, "export-text")
	// 模拟旧库的大外部属性；不把测试种子当作正常账号可提交的资料。
	for index := 0; index < 3; index++ {
		link := ExternalIdentity{UserID: user.ID, ProviderID: "fixture", Subject: fmt.Sprintf("budget-%d", index), DisplayName: strings.Repeat("x", MaxAccountExportTextBytes/2)}
		if err := store.LinkExternalIdentity(&link); err != nil {
			test.Fatal(err)
		}
	}
	if snapshot, err := store.PrepareAccountExport(test.Context(), user.ID, session.ID, AccountExportOptions{Scope: AccountSecurityExportScope}); !errors.Is(err, ErrAccountExportTooLarge) || !snapshot.GeneratedAt.IsZero() {
		test.Fatal("raw text budget returned a partial snapshot")
	}
	if len(store.ListAudit(0)) != 0 {
		test.Fatal("text budget failure committed preparation audit")
	}
	if _, err := store.PrepareAccountExport(test.Context(), user.ID, session.ID, AccountExportOptions{Scope: LoginHistoryExportScope}); err != nil {
		test.Fatal("CSV scope unnecessarily read oversized bindings")
	}
}
