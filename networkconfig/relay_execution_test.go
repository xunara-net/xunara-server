package networkconfig

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/xunara-net/xunara-server/state"
)

func TestRelayExecutionAuditAndTenantBoundary(test *testing.T) {
	core, _, store, _, secret := relayConfigurationFixture(test)
	before := countRows(test, core.DB(), "audit_events")
	report := state.RelayExecution{ConfigVersion: "1", AppliedVersion: "1", Status: "applied", State: "online"}
	heartbeat := state.RelayHeartbeat{Healthy: true, BytesIn: 10, Execution: &report}
	first, err := store.RecordRelayHeartbeat(test.Context(), secret, heartbeat)
	if err != nil || countRows(test, core.DB(), "audit_events") != before+1 {
		test.Fatalf("receipt audit not committed: %v", err)
	}
	var actor, action string
	if err := core.DB().QueryRowContext(test.Context(), "SELECT actor, action FROM audit_events ORDER BY id DESC LIMIT 1").Scan(&actor, &action); err != nil || actor != "relay:relay-test" || action != "relay.configuration_reported" {
		test.Fatal("service report was attributed to a human session")
	}
	heartbeat.BytesIn = 20
	second, err := store.RecordRelayHeartbeat(test.Context(), secret, heartbeat)
	if err != nil || second.BytesIn != 20 || second.ExecutionReportedAt.Before(first.ExecutionReportedAt) || countRows(test, core.DB(), "audit_events") != before+1 {
		test.Fatal("duplicate receipt created an audit storm or lost telemetry")
	}
	if _, err := store.RecordRelayHeartbeat(test.Context(), secret, state.RelayHeartbeat{}); err != nil || countRows(test, core.DB(), "audit_events") != before+2 {
		test.Fatal("legacy execution-unavailable transition was not audited")
	}
	_, _, foreign, _, _ := relayConfigurationFixture(test)
	if _, err := foreign.RecordRelayHeartbeat(test.Context(), secret, heartbeat); !errors.Is(err, state.ErrRelayNotFound) {
		test.Fatal("service heartbeat crossed a tenant boundary")
	}
}

func TestRelayExecutionTransactionFailures(test *testing.T) {
	for _, table := range []string{"audit_events", "counters"} {
		test.Run(table, func(test *testing.T) {
			core, _, store, _, secret := relayConfigurationFixture(test)
			before := countRows(test, core.DB(), "audit_events")
			if _, err := core.DB().ExecContext(test.Context(), "CREATE TRIGGER reject_execution BEFORE INSERT ON "+table+" BEGIN SELECT RAISE(ABORT, 'injected failure'); END"); err != nil {
				test.Fatal(err)
			}
			report := state.RelayExecution{ConfigVersion: "1", AppliedVersion: "1", Status: "applied", State: "online"}
			if _, err := store.RecordRelayHeartbeat(test.Context(), secret, state.RelayHeartbeat{Healthy: true, BytesIn: 99, Execution: &report}); err == nil {
				test.Fatal("audit failure accepted an execution report")
			}
			relay, found := core.RelayByToken(secret)
			if !found || !relay.LastSeen.IsZero() || !relay.ExecutionReportedAt.IsZero() || relay.BytesIn != 0 || countRows(test, core.DB(), "audit_events") != before {
				test.Fatal("failed report left partial telemetry or receipt")
			}
			cancelled, cancel := context.WithCancel(test.Context())
			cancel()
			if _, err := store.RecordRelayHeartbeat(cancelled, secret, state.RelayHeartbeat{}); !errors.Is(err, context.Canceled) {
				test.Fatalf("cancelled service transaction: %v", err)
			}
		})
	}
}

func TestRelayExecutionRevocationRaceAcrossConnections(test *testing.T) {
	core, _, store, writer, secret := relayConfigurationFixture(test)
	var filename string
	if err := core.DB().QueryRowContext(test.Context(), "SELECT file FROM pragma_database_list WHERE name = 'main'").Scan(&filename); err != nil {
		test.Fatal(err)
	}
	second, err := state.OpenSQLite(test.Context(), filename)
	if err != nil {
		test.Fatal(err)
	}
	defer second.Close()
	other := NewSQLiteStore(second.DB())
	start := make(chan struct{})
	var workers sync.WaitGroup
	workers.Go(func() {
		<-start
		if _, err := store.SaveRelay(test.Context(), "relay-test", state.RelayConfigUpdate{ConfigVersion: 1, DesiredState: state.RelayStateRevoked}, nil, writer); err != nil {
			test.Error(err)
		}
	})
	workers.Go(func() {
		<-start
		report := state.RelayExecution{ConfigVersion: "1", AppliedVersion: "1", Status: "applied", State: "online"}
		if _, err := other.RecordRelayHeartbeat(test.Context(), secret, state.RelayHeartbeat{Execution: &report}); err != nil && !errors.Is(err, state.ErrRelayRevoked) {
			test.Error(err)
		}
	})
	close(start)
	workers.Wait()
	if _, err := other.RecordRelayHeartbeat(test.Context(), secret, state.RelayHeartbeat{}); !errors.Is(err, state.ErrRelayRevoked) {
		test.Fatalf("post-revocation transaction accepted a service report: %v", err)
	}
	relay, found := core.RelayByToken(secret)
	if !found || relay.DesiredState != state.RelayStateRevoked || relay.ConfigVersion != 2 {
		test.Fatal("heartbeat raced a terminal revocation back to online")
	}
}
