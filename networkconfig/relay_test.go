package networkconfig

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/xunara-net/xunara-server/identity"
	"github.com/xunara-net/xunara-server/state"
)

func relayConfigurationFixture(test *testing.T) (*state.SQLiteStore, *identity.SQLiteStore, *SQLiteStore, Writer, string) {
	test.Helper()
	core, identities, configuration, writer := configurationFixture(test)
	secret, err := state.NewRelayTokenSecret()
	if err != nil {
		test.Fatal(err)
	}
	if err := core.CreateRelay(state.Relay{ID: "relay-test", RegionName: "原始地区"}, secret); err != nil {
		test.Fatal(err)
	}
	return core, identities, configuration, writer, secret
}

func TestRelayConfigurationHistoryRestorePreservesIdentityAndTelemetry(test *testing.T) {
	core, _, store, writer, secret := relayConfigurationFixture(test)
	beforeAudit := countRows(test, core.DB(), "audit_events")
	limit, region := int64(2048), "更新地区"
	relay, err := store.SaveRelay(test.Context(), "relay-test", state.RelayConfigUpdate{ConfigVersion: 1, DesiredState: state.RelayStateMaintenance, BandwidthLimit: &limit, RegionName: &region}, nil, writer)
	if err != nil || relay.ConfigVersion != 2 {
		test.Fatalf("save: version=%d err=%v", relay.ConfigVersion, err)
	}
	if err := core.UpdateRelayHeartbeat("relay-test", state.RelayHeartbeat{Healthy: true, BytesIn: 99}); err != nil {
		test.Fatal(err)
	}
	previous := uint64(1)
	restored, err := store.SaveRelay(test.Context(), "relay-test", state.RelayConfigUpdate{ConfigVersion: 2}, &previous, writer)
	if err != nil || restored.ConfigVersion != 3 || restored.DesiredState != state.RelayStateOnline || restored.RegionName != "原始地区" || restored.BandwidthLimit != 0 || restored.BytesIn != 99 || !restored.Healthy {
		test.Fatalf("restore did not preserve telemetry: %v", err)
	}
	history, err := store.RelayHistory(test.Context(), "relay-test")
	if err != nil || len(history) != 3 || history[0].ConfigVersion != 3 || history[1].RegionName != region || history[2].Actor != "system:import" {
		test.Fatalf("history: %+v %v", history, err)
	}
	encoded, err := json.Marshal(history)
	if err != nil || strings.Contains(string(encoded), secret) || strings.Contains(string(encoded), "token") || strings.Contains(string(encoded), "bytes_in") {
		test.Fatal("configuration history exposed identity or telemetry")
	}
	if _, found := core.RelayByToken(secret); !found || countRows(test, core.DB(), "audit_events") != beforeAudit+2 {
		test.Fatal("restore changed identity or did not commit exactly one audit per operation")
	}
	_, _, other, _, _ := relayConfigurationFixture(test)
	foreign, err := other.RelayHistory(test.Context(), "relay-test")
	if err != nil || len(foreign) != 0 {
		test.Fatal("history crossed a tenant boundary")
	}
	if err := store.DeleteRelay(test.Context(), "relay-test", 2, writer); !errors.Is(err, state.ErrRelayConfigConflict) {
		test.Fatalf("stale deletion: %v", err)
	}
	if err := store.DeleteRelay(test.Context(), "relay-test", 3, writer); err != nil {
		test.Fatal(err)
	}
	if _, found := core.RelayByToken(secret); found || countRows(test, core.DB(), "network_document_history") != 0 {
		test.Fatal("deletion preserved credential or recoverable history")
	}
	if _, err := store.SaveRelay(test.Context(), "relay-test", state.RelayConfigUpdate{ConfigVersion: 3, DesiredState: state.RelayStateOnline}, nil, writer); !errors.Is(err, state.ErrRelayNotFound) {
		test.Fatalf("deleted relay was recreated: %v", err)
	}
}

func TestRelayConfigurationCASAcrossConnections(test *testing.T) {
	core, _, store, writer, _ := relayConfigurationFixture(test)
	var filename string
	if err := core.DB().QueryRowContext(test.Context(), "SELECT file FROM pragma_database_list WHERE name = 'main'").Scan(&filename); err != nil {
		test.Fatal(err)
	}
	second, err := state.OpenSQLite(test.Context(), filename)
	if err != nil {
		test.Fatal(err)
	}
	test.Cleanup(func() { second.Close() })
	start := make(chan struct{})
	results := make(chan error, 2)
	var workers sync.WaitGroup
	for _, connection := range []*SQLiteStore{store, NewSQLiteStore(second.DB())} {
		workers.Go(func() {
			<-start
			_, err := connection.SaveRelay(test.Context(), "relay-test", state.RelayConfigUpdate{ConfigVersion: 1, DesiredState: state.RelayStateDisabled}, nil, writer)
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
		} else if errors.Is(err, state.ErrRelayConfigConflict) {
			conflicts++
		} else {
			test.Fatal(err)
		}
	}
	if successes != 1 || conflicts != 1 || countRows(test, core.DB(), "network_document_history") != 2 {
		test.Fatalf("CAS: success=%d conflict=%d", successes, conflicts)
	}
}

func TestRelayConfigurationTransactionFailuresLeaveNoPartialChange(test *testing.T) {
	for _, deletion := range []bool{false, true} {
		for _, table := range []string{"network_document_history", "audit_events", "counters"} {
			test.Run(fmt.Sprintf("delete=%t/%s", deletion, table), func(test *testing.T) {
				core, _, store, writer, secret := relayConfigurationFixture(test)
				if _, err := store.SaveRelay(test.Context(), "relay-test", state.RelayConfigUpdate{ConfigVersion: 1, DesiredState: state.RelayStateOnline}, nil, writer); err != nil {
					test.Fatal(err)
				}
				beforeAudit, beforeHistory, beforeRevision := countRows(test, core.DB(), "audit_events"), countRows(test, core.DB(), "network_document_history"), core.ConfigRevision()
				operation := "INSERT"
				if deletion && table == "network_document_history" {
					operation = "DELETE"
				}
				if _, err := core.DB().ExecContext(test.Context(), "CREATE TRIGGER reject_relay_change BEFORE "+operation+" ON "+table+" BEGIN SELECT RAISE(ABORT, 'injected failure'); END"); err != nil {
					test.Fatal(err)
				}
				var err error
				if deletion {
					err = store.DeleteRelay(test.Context(), "relay-test", 2, writer)
				} else {
					_, err = store.SaveRelay(test.Context(), "relay-test", state.RelayConfigUpdate{ConfigVersion: 2, DesiredState: state.RelayStateDisabled}, nil, writer)
				}
				if err == nil {
					test.Fatal("injected failure succeeded")
				}
				relay, found := core.RelayByToken(secret)
				if !found || relay.ConfigVersion != 2 || relay.DesiredState != state.RelayStateOnline || countRows(test, core.DB(), "audit_events") != beforeAudit || countRows(test, core.DB(), "network_document_history") != beforeHistory || core.ConfigRevision() != beforeRevision {
					test.Fatal("failed transaction left partial changes")
				}
			})
		}
	}
}

func TestRelayConfigurationRechecksPersistentAuthorization(test *testing.T) {
	for _, reason := range []string{"revoked session", "expired session", "downgraded role", "revoked API key", "read-only API key"} {
		test.Run(reason, func(test *testing.T) {
			core, identities, store, writer, _ := relayConfigurationFixture(test)
			switch reason {
			case "revoked session":
				if err := identities.RevokeSession(writer.SessionID, "test"); err != nil {
					test.Fatal(err)
				}
			case "expired session":
				if _, err := core.DB().ExecContext(test.Context(), "UPDATE sessions SET expires_at = 1 WHERE id = ?", writer.SessionID); err != nil {
					test.Fatal(err)
				}
			case "downgraded role":
				if _, err := core.DB().ExecContext(test.Context(), "UPDATE users SET role = ? WHERE id = ?", identity.RoleMember, writer.UserID); err != nil {
					test.Fatal(err)
				}
			default:
				scope := identity.ScopeWrite
				if reason == "read-only API key" {
					scope = identity.ScopeRead
				}
				credential, _, err := identities.CreateAPIKey(identity.NewAPIKeyOptions{Name: "configuration", UserID: writer.UserID, Scopes: []string{scope}})
				if err != nil {
					test.Fatal(err)
				}
				writer.SessionID, writer.APIKeyID = "", credential.ID
				if reason == "revoked API key" {
					if _, err := core.DB().ExecContext(test.Context(), "UPDATE api_keys SET revoked_at = 1 WHERE id = ?", credential.ID); err != nil {
						test.Fatal(err)
					}
				}
			}
			if _, err := store.SaveRelay(test.Context(), "relay-test", state.RelayConfigUpdate{ConfigVersion: 1, DesiredState: state.RelayStateDisabled}, nil, writer); err == nil {
				test.Fatal("invalidated writer changed configuration")
			}
			if err := store.DeleteRelay(test.Context(), "relay-test", 1, writer); err == nil {
				test.Fatal("invalidated writer deleted identity")
			}
			if countRows(test, core.DB(), "relays") != 1 || countRows(test, core.DB(), "network_document_history") != 0 {
				test.Fatal("invalidated writer changed state")
			}
		})
	}
}

func TestRelayConfigurationRevocationCannotBeUndoneByRestore(test *testing.T) {
	_, _, store, writer, _ := relayConfigurationFixture(test)
	if _, err := store.SaveRelay(test.Context(), "relay-test", state.RelayConfigUpdate{ConfigVersion: 1, DesiredState: state.RelayStateRevoked}, nil, writer); err != nil {
		test.Fatal(err)
	}
	previous := uint64(1)
	if _, err := store.SaveRelay(test.Context(), "relay-test", state.RelayConfigUpdate{ConfigVersion: 2}, &previous, writer); !errors.Is(err, state.ErrRelayConfigRevoked) {
		test.Fatalf("revoked credential restored: %v", err)
	}
}

func TestRelayConfigurationDamagedHistoryAndCancellationFailClosed(test *testing.T) {
	core, _, store, writer, _ := relayConfigurationFixture(test)
	if _, err := store.SaveRelay(test.Context(), "relay-test", state.RelayConfigUpdate{ConfigVersion: 1, DesiredState: state.RelayStateMaintenance}, nil, writer); err != nil {
		test.Fatal(err)
	}
	previous := uint64(1)
	beforeAudit := countRows(test, core.DB(), "audit_events")
	for _, content := range []string{`{`, `{"config_version":1}`, `{"config_version":1,"desired_state":"unknown"}`, `{"config_version":1,"desired_state":"online","bandwidth_limit":-2}`, `{"config_version":1,"desired_state":"online","region_name":"bad\nname"}`} {
		if _, err := core.DB().ExecContext(test.Context(), "UPDATE network_document_history SET content = ? WHERE kind = ? AND revision = 1", content, state.RelayConfigurationKind("relay-test")); err != nil {
			test.Fatal(err)
		}
		if _, err := store.RelayHistory(test.Context(), "relay-test"); err == nil {
			test.Fatal("damaged history was rendered as valid configuration")
		}
		if _, err := store.SaveRelay(test.Context(), "relay-test", state.RelayConfigUpdate{ConfigVersion: 2}, &previous, writer); err == nil {
			test.Fatal("damaged history was restored with fabricated defaults")
		}
	}
	canceled, cancel := context.WithCancel(test.Context())
	cancel()
	if _, err := store.SaveRelay(canceled, "relay-test", state.RelayConfigUpdate{ConfigVersion: 2, DesiredState: state.RelayStateDisabled}, nil, writer); !errors.Is(err, context.Canceled) {
		test.Fatalf("cancelled write: %v", err)
	}
	if err := store.DeleteRelay(canceled, "relay-test", 2, writer); !errors.Is(err, context.Canceled) {
		test.Fatalf("cancelled deletion: %v", err)
	}
	relay, found := core.RelayByID("relay-test")
	if !found || relay.ConfigVersion != 2 || relay.DesiredState != state.RelayStateMaintenance || countRows(test, core.DB(), "audit_events") != beforeAudit {
		test.Fatal("failed operation left partial changes")
	}
}
