package state

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
)

func TestRelayExecutionStoreContract(test *testing.T) {
	for name, store := range relayTestStores(test) {
		test.Run(name, func(test *testing.T) {
			secret, err := NewRelayTokenSecret()
			if err != nil {
				test.Fatal(err)
			}
			if err := store.CreateRelay(Relay{ID: "runtime", Execution: RelayExecution{Status: "applied"}}, secret); err != nil {
				test.Fatal(err)
			}
			execution := RelayExecution{ConfigVersion: "1", AppliedVersion: "1", Status: "applied", State: "online", BandwidthLimit: 2048}
			heartbeat := RelayHeartbeat{Healthy: true, BytesIn: 123, Execution: &execution}
			first, err := store.RecordRelayHeartbeat(test.Context(), secret, heartbeat)
			if err != nil || first.Execution != execution || first.ExecutionReportedAt.IsZero() || first.ExecutionReportedAt != first.LastSeen {
				test.Fatalf("execution not recorded: %+v %v", first, err)
			}
			execution.Status = "tampered"
			persisted, _ := store.RelayByID("runtime")
			if persisted.Execution.Status != "applied" {
				test.Fatal("caller mutated a stored execution pointer")
			}
			invalid := first.Execution
			invalid.ConfigVersion, invalid.AppliedVersion = "2", "2"
			if _, err := store.RecordRelayHeartbeat(test.Context(), secret, RelayHeartbeat{BytesIn: 999, Execution: &invalid}); !errors.Is(err, ErrRelayExecutionInvalid) {
				test.Fatal("future execution version was accepted")
			}
			persisted, _ = store.RelayByID("runtime")
			if persisted.BytesIn != 123 || persisted.LastSeen != first.LastSeen {
				test.Fatal("invalid report partially wrote telemetry")
			}
			legacy, err := store.RecordRelayHeartbeat(test.Context(), secret, RelayHeartbeat{Healthy: true})
			if err != nil || !legacy.ExecutionReportedAt.IsZero() || legacy.Execution != (RelayExecution{}) {
				test.Fatal("legacy heartbeat reused another process's execution receipt")
			}
			cancelled, cancel := context.WithCancel(test.Context())
			cancel()
			if _, err := store.RecordRelayHeartbeat(cancelled, secret, heartbeat); !errors.Is(err, context.Canceled) {
				test.Fatalf("cancelled heartbeat: %v", err)
			}
			if _, err := store.RecordRelayHeartbeat(test.Context(), "unknown", RelayHeartbeat{}); !errors.Is(err, ErrRelayNotFound) {
				test.Fatalf("unknown credential: %v", err)
			}
			if _, err := store.UpdateRelayConfig("runtime", RelayConfigUpdate{ConfigVersion: 1, DesiredState: RelayStateRevoked}); err != nil {
				test.Fatal(err)
			}
			if _, err := store.RecordRelayHeartbeat(test.Context(), secret, RelayHeartbeat{}); !errors.Is(err, ErrRelayRevoked) {
				test.Fatalf("revoked credential: %v", err)
			}
		})
	}
}

func TestRelayExecutionValidation(test *testing.T) {
	relay := Relay{ConfigVersion: 4, DesiredState: RelayStateOnline, BandwidthLimit: 4096}
	base := RelayExecution{"4", "4", "applied", "online", 4096, ""}
	for _, change := range []func(*RelayExecution){
		func(report *RelayExecution) { report.ConfigVersion = "04" },
		func(report *RelayExecution) { report.ConfigVersion = "opaque" },
		func(report *RelayExecution) { report.ConfigVersion = "5" },
		func(report *RelayExecution) { report.AppliedVersion = "3" },
		func(report *RelayExecution) { report.Status = "received" },
		func(report *RelayExecution) { report.State = "pending" },
		func(report *RelayExecution) { report.State = "disabled" },
		func(report *RelayExecution) { report.BandwidthLimit = 0 },
		func(report *RelayExecution) { report.BandwidthLimit = -1 },
		func(report *RelayExecution) { report.BandwidthLimit = 1 << 53 },
		func(report *RelayExecution) { report.ErrorCode = "remote-secret" },
		func(report *RelayExecution) { report.Status = "failed"; report.ErrorCode = "remote-secret" },
	} {
		report := base
		change(&report)
		if err := validateRelayExecution(relay, report); !errors.Is(err, ErrRelayExecutionInvalid) {
			test.Fatalf("invalid report accepted: %+v", report)
		}
	}
	if err := validateRelayExecution(relay, base); err != nil {
		test.Fatal(err)
	}
	failed := RelayExecution{ConfigVersion: "4", Status: "failed", State: "pending", ErrorCode: "cache_write_failed"}
	if err := validateRelayExecution(relay, failed); err != nil {
		test.Fatal("fresh process execution failure rejected")
	}
	for _, raw := range []string{`{"config_version":"4","status":"applied","state":"online"}`, `{"config_version":null,"status":"applied","state":"online","bandwidth_limit":0}`} {
		var decoded RelayExecution
		if json.Unmarshal([]byte(raw), &decoded) == nil {
			test.Fatal("incomplete execution report gained invented zero bandwidth")
		}
	}
}

func TestSQLiteV21RelayExecutionMigrationAndRestart(test *testing.T) {
	filename := filepath.Join(test.TempDir(), "state.db")
	store := openTestSQLite(test, filename)
	secret, _ := NewRelayTokenSecret()
	if err := store.CreateRelay(Relay{ID: "pre-v22", RegionID: 40001, CertName: "stored-pin"}, secret); err != nil {
		test.Fatal(err)
	}
	for _, statement := range []string{"DROP TABLE dns_namespace", "DROP INDEX idx_nodes_dns_name_unique", "ALTER TABLE nodes DROP COLUMN dns_name", "DROP TABLE address_configuration", "DROP INDEX idx_nodes_ipv4_unique", "ALTER TABLE relays DROP COLUMN execution_report", "ALTER TABLE relays DROP COLUMN execution_reported_at", "PRAGMA user_version = 21"} {
		if _, err := store.DB().ExecContext(test.Context(), statement); err != nil {
			test.Fatal(err)
		}
	}
	store.Close()
	reopened := openTestSQLite(test, filename)
	relay, found := reopened.RelayByToken(secret)
	if !found || relay.RegionID != 40001 || relay.CertName != "stored-pin" || !relay.ExecutionReportedAt.IsZero() || relay.Execution != (RelayExecution{}) {
		test.Fatal("v21 migration lost identity or invented execution status")
	}
	execution := RelayExecution{"1", "1", "applied", "online", 0, ""}
	if _, err := reopened.RecordRelayHeartbeat(test.Context(), secret, RelayHeartbeat{Execution: &execution}); err != nil {
		test.Fatal(err)
	}
	reopened.Close()
	final := openTestSQLite(test, filename)
	persisted, found := final.RelayByToken(secret)
	if !found || persisted.Execution != execution || persisted.ExecutionReportedAt.IsZero() {
		test.Fatal("execution receipt did not survive a database restart")
	}
}
