package networkconfig

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"tailscale.com/types/key"

	"github.com/xunara-net/xunara-server/identity"
	"github.com/xunara-net/xunara-server/state"
)

func configurationFixture(t *testing.T) (*state.SQLiteStore, *identity.SQLiteStore, *SQLiteStore, Writer) {
	t.Helper()
	core, err := state.OpenSQLite(t.Context(), filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { core.Close() })
	identities, err := identity.NewSQLiteStore(t.Context(), core.DB())
	if err != nil {
		t.Fatal(err)
	}
	user, _, err := identity.EnsureLocalUser(identities)
	if err != nil {
		t.Fatal(err)
	}
	session, _, err := identities.CreateSession(identity.NewSessionOptions{UserID: user.ID, TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	return core, identities, NewSQLiteStore(core.DB()), Writer{UserID: user.ID, SessionID: session.ID}
}

func countRows(t *testing.T, database *sql.DB, table string) int {
	t.Helper()
	var count int
	if err := database.QueryRowContext(t.Context(), "SELECT count(*) FROM "+table).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func TestConfigurationHistoryRestoreAndTenantBoundary(t *testing.T) {
	_, _, store, writer := configurationFixture(t)
	first, err := store.Save(t.Context(), Policy, "{}", "initial", 0, writer)
	if err != nil || first.Revision != 1 {
		t.Fatalf("first publication: %+v %v", first, err)
	}
	previous, err := store.Version(t.Context(), Policy, 0)
	if err != nil || previous.Content != "initial" || previous.Actor != "system:import" {
		t.Fatalf("import: %+v %v", previous, err)
	}
	restored, err := store.Save(t.Context(), Policy, previous.Content, "must not overwrite", 1, writer)
	if err != nil || restored.Revision != 2 {
		t.Fatalf("restore: %+v %v", restored, err)
	}
	history, err := store.History(t.Context(), Policy)
	if err != nil || len(history) != 3 || history[0].Revision != 2 || history[2].Content != "initial" {
		t.Fatalf("immutable history: %+v %v", history, err)
	}
	_, _, other, _ := configurationFixture(t)
	if _, found, err := other.Get(t.Context(), Policy); err != nil || found {
		t.Fatalf("foreign configuration exposed: %v %v", found, err)
	}
	if _, err := other.Version(t.Context(), Policy, 1); !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign version: %v", err)
	}
}

func TestConfigurationCASAcrossConnections(t *testing.T) {
	core, _, store, writer := configurationFixture(t)
	var filename string
	if err := core.DB().QueryRowContext(t.Context(), "SELECT file FROM pragma_database_list WHERE name = 'main'").Scan(&filename); err != nil {
		t.Fatal(err)
	}
	second, err := state.OpenSQLite(t.Context(), filename)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { second.Close() })
	start := make(chan struct{})
	results := make(chan error, 2)
	var workers sync.WaitGroup
	for _, connection := range []*SQLiteStore{store, NewSQLiteStore(second.DB())} {
		workers.Go(func() {
			<-start
			_, err := connection.Save(t.Context(), Policy, "{}", "initial", 0, writer)
			results <- err
		})
	}
	close(start)
	workers.Wait()
	close(results)
	var successes, conflicts int
	for err := range results {
		if err == nil {
			successes++
		} else if errors.Is(err, ErrConflict) {
			conflicts++
		} else {
			t.Fatal(err)
		}
	}
	if successes != 1 || conflicts != 1 || countRows(t, core.DB(), "network_document_history") != 2 {
		t.Fatalf("CAS results: success=%d conflicts=%d", successes, conflicts)
	}
}

func TestConfigurationTransactionFailureRollsBack(t *testing.T) {
	for _, failure := range []struct{ name, trigger string }{
		{"history", "BEFORE INSERT ON network_document_history"},
		{"audit", "BEFORE INSERT ON audit_events"},
		{"revision", "BEFORE INSERT ON counters WHEN NEW.name = 'config_revision'"},
		{"ssh authorization", "BEFORE DELETE ON ssh_check_auth"},
	} {
		t.Run(failure.name, func(t *testing.T) {
			core, _, store, writer := configurationFixture(t)
			if _, err := core.DB().ExecContext(t.Context(), "INSERT INTO ssh_check_auth VALUES (1, 2, 1)"); err != nil {
				t.Fatal(err)
			}
			beforeAudit := countRows(t, core.DB(), "audit_events")
			if _, err := core.DB().ExecContext(t.Context(), "CREATE TRIGGER reject_network_change "+failure.trigger+" BEGIN SELECT RAISE(ABORT, 'injected storage failure'); END"); err != nil {
				t.Fatal(err)
			}
			if _, err := store.Save(t.Context(), Policy, "{}", "initial", 0, writer); err == nil {
				t.Fatal("failed transaction reported success")
			}
			if countRows(t, core.DB(), "network_documents") != 0 || countRows(t, core.DB(), "network_document_history") != 0 || countRows(t, core.DB(), "ssh_check_auth") != 1 || countRows(t, core.DB(), "audit_events") != beforeAudit {
				t.Fatal("partial publication survived rollback")
			}
			var revision int
			if err := core.DB().QueryRowContext(t.Context(), "SELECT coalesce(sum(value), 0) FROM counters WHERE name = 'config_revision'").Scan(&revision); err != nil || revision != 0 {
				t.Fatalf("notification survived rollback: %d %v", revision, err)
			}
		})
	}
}

func TestConfigurationRechecksPersistentWriter(t *testing.T) {
	for _, change := range []string{"revoked session", "expired session", "demoted user", "foreign user", "both credentials", "revoked key", "read-only key", "expired key"} {
		t.Run(change, func(t *testing.T) {
			core, identities, store, writer := configurationFixture(t)
			switch change {
			case "revoked session":
				if err := identities.RevokeSession(writer.SessionID, "test"); err != nil {
					t.Fatal(err)
				}
			case "expired session":
				if _, err := core.DB().ExecContext(t.Context(), "UPDATE sessions SET expires_at = 1"); err != nil {
					t.Fatal(err)
				}
			case "demoted user":
				if _, err := core.DB().ExecContext(t.Context(), "UPDATE users SET role = 'member'"); err != nil {
					t.Fatal(err)
				}
			case "foreign user":
				writer.UserID++
			case "both credentials":
				writer.APIKeyID = "other"
			default:
				scopes := []string{identity.ScopeWrite}
				if change == "read-only key" {
					scopes = []string{identity.ScopeRead}
				}
				credential, _, err := identities.CreateAPIKey(identity.NewAPIKeyOptions{Name: "service", UserID: writer.UserID, Scopes: scopes})
				if err != nil {
					t.Fatal(err)
				}
				writer.SessionID, writer.APIKeyID = "", credential.ID
				if change == "revoked key" {
					if _, err := core.DB().ExecContext(t.Context(), "UPDATE api_keys SET revoked_at = 1"); err != nil {
						t.Fatal(err)
					}
				}
				if change == "expired key" {
					if _, err := core.DB().ExecContext(t.Context(), "UPDATE api_keys SET expires_at = 1"); err != nil {
						t.Fatal(err)
					}
				}
			}
			_, err := store.Save(t.Context(), Policy, "{}", "initial", 0, writer)
			if !errors.Is(err, identity.ErrSessionRevoked) && !errors.Is(err, identity.ErrNetworkWriterForbidden) {
				t.Fatalf("stale writer accepted: %v", err)
			}
			if countRows(t, core.DB(), "network_documents") != 0 {
				t.Fatal("forbidden writer published a configuration")
			}
		})
	}
}

func TestAddressRecordCASProtectedNamesAndAuditRollback(t *testing.T) {
	core, _, store, writer := configurationFixture(t)
	created, err := store.PutRecord(t.Context(), Record{Name: "nas.xunara.test", Type: "A", Value: "100.64.0.10"}, 0, writer, "xunara.test")
	if err != nil || created.Revision != 1 {
		t.Fatalf("create: %+v %v", created, err)
	}
	if _, err := store.PutRecord(t.Context(), created, 0, writer, "xunara.test"); !errors.Is(err, ErrConflict) {
		t.Fatalf("missing revision accepted: %v", err)
	}
	updated, err := store.PutRecord(t.Context(), created, 1, writer, "xunara.test")
	if err != nil || updated.Revision != 2 || !updated.Created.Equal(created.Created) {
		t.Fatalf("edit: %+v %v", updated, err)
	}
	if err := store.DeleteRecord(t.Context(), created.ID, 1, writer); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale deletion: %v", err)
	}
	node := state.Node{Hostname: "Laptop Name", NodeKey: key.NewNode().Public()}
	if err := core.CreateNode(&node); err != nil {
		t.Fatal(err)
	}
	if _, err := store.PutRecord(t.Context(), Record{Name: "laptop-name.xunara.test", Type: "A", Value: "100.64.0.9"}, 0, writer, "xunara.test"); !errors.Is(err, ErrRecordProtected) {
		t.Fatalf("device-name collision: %v", err)
	}
	if err := core.ReplaceNodeServices(node.ID, []state.Service{{Name: "files", Protocol: "tcp", Port: 445}}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.PutRecord(t.Context(), Record{Name: "files.xunara.test", Type: "A", Value: "100.64.0.9"}, 0, writer, "xunara.test"); !errors.Is(err, ErrConflict) {
		t.Fatalf("service-name collision: %v", err)
	}
	for _, record := range []Record{{Name: "_acme-challenge.node.xunara.test", Type: "A"}, {Name: "node.xunara.test", Type: "TXT"}, {Name: "node.xunara.test", Type: "A", NodeID: 1}} {
		if _, err := store.PutRecord(t.Context(), record, 0, writer, "xunara.test"); !errors.Is(err, ErrRecordProtected) {
			t.Fatalf("protected record: %v", err)
		}
	}
	if _, err := core.DB().ExecContext(t.Context(), "CREATE TRIGGER reject_dns_audit BEFORE INSERT ON audit_events BEGIN SELECT RAISE(ABORT, 'injected failure'); END"); err != nil {
		t.Fatal(err)
	}
	if err := store.DeleteRecord(t.Context(), updated.ID, 2, writer); err == nil {
		t.Fatal("audit failure did not roll back deletion")
	}
	records, err := store.Records(t.Context())
	if err != nil || len(records) != 1 || records[0].Revision != 2 {
		t.Fatalf("rolled-back records: %+v %v", records, err)
	}
	if _, err := core.DB().ExecContext(t.Context(), "DROP TRIGGER reject_dns_audit"); err != nil {
		t.Fatal(err)
	}
	if err := store.DeleteRecord(t.Context(), updated.ID, 2, writer); err != nil {
		t.Fatal(err)
	}
}

func TestAddressRecordQuotaAcrossConnections(t *testing.T) {
	core, _, store, writer := configurationFixture(t)
	transaction, err := core.DB().BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for index := 1; index <= 511; index++ {
		if _, err := transaction.ExecContext(t.Context(), "INSERT INTO dns_records(id, name, type, value, node_id, created) VALUES (?, ?, 'A', '100.64.0.9', 0, 1)", index, fmt.Sprintf("host-%d.xunara.test", index)); err != nil {
			transaction.Rollback()
			t.Fatal(err)
		}
	}
	if err := transaction.Commit(); err != nil {
		t.Fatal(err)
	}
	var filename string
	if err := core.DB().QueryRowContext(t.Context(), "SELECT file FROM pragma_database_list WHERE name = 'main'").Scan(&filename); err != nil {
		t.Fatal(err)
	}
	second, err := state.OpenSQLite(t.Context(), filename)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { second.Close() })
	results := make(chan error, 2)
	var workers sync.WaitGroup
	for index, connection := range []*SQLiteStore{store, NewSQLiteStore(second.DB())} {
		workers.Go(func() {
			_, err := connection.PutRecord(t.Context(), Record{Name: fmt.Sprintf("new-%d.xunara.test", index), Type: "A", Value: "100.64.0.10"}, 0, writer, "xunara.test")
			results <- err
		})
	}
	workers.Wait()
	close(results)
	var successes, limits int
	for err := range results {
		if err == nil {
			successes++
		} else if errors.Is(err, ErrRecordLimit) {
			limits++
		} else {
			t.Fatal(err)
		}
	}
	if successes != 1 || limits != 1 || countRows(t, core.DB(), "dns_records") != 512 {
		t.Fatalf("quota: success=%d limited=%d", successes, limits)
	}
}

func TestConfigurationReadFailureIsNotAnEmptyNetwork(t *testing.T) {
	core, _, store, _ := configurationFixture(t)
	if err := core.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Get(context.Background(), Policy); err == nil {
		t.Fatal("closed store reported a default policy")
	}
	if _, err := store.Records(context.Background()); err == nil {
		t.Fatal("closed store reported an empty record list")
	}
}
