package control

import (
	"net/http"
	"testing"

	"github.com/xunara-net/xunara-server/identity"
	"github.com/xunara-net/xunara-server/state"
)

func TestRelayExecutionHTTPContract(test *testing.T) {
	server := newTestServer(test)
	database := server.store.(*state.SQLiteStore).DB()
	secret := seedConfigurationRelay(test, server)
	_, apiKey := seedAPIKey(test, server, identity.ScopeRead, identity.ScopeWrite)
	host := newTestHTTPServer(test, server)
	report := state.RelayExecution{ConfigVersion: "1", AppliedVersion: "1", Status: "applied", State: "online", BandwidthLimit: 2048}
	response := apiRequest(test, host.Client(), http.MethodPost, host.URL+relayHeartbeatPath, secret, map[string]any{"healthy": true, "execution": report, "future_field": true})
	if response.StatusCode != http.StatusOK {
		test.Fatalf("receipt heartbeat status: %d", response.StatusCode)
	}
	var configuration relayRemoteConfig
	decodeTestBody(test, response, &configuration)
	response.Body.Close()
	if configuration.ConfigVersion != "1" || configuration.ConfigRevision != 1 {
		test.Fatal("opaque version or optional sequence not preserved")
	}
	response = apiRequest(test, host.Client(), http.MethodGet, host.URL+"/api/v2/relays/relay-history", apiKey, nil)
	var view relayView
	decodeTestBody(test, response, &view)
	response.Body.Close()
	if view.Execution == nil || *view.Execution != report || view.ExecutionReportedAt == "" {
		test.Fatal("console lost the service execution report")
	}
	report.ConfigVersion, report.AppliedVersion = "2", "2"
	response = apiRequest(test, host.Client(), http.MethodPost, host.URL+relayHeartbeatPath, secret, map[string]any{"execution": report})
	response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		test.Fatal("future execution report was accepted")
	}
	if _, err := database.ExecContext(test.Context(), "CREATE TRIGGER reject_heartbeat BEFORE UPDATE ON relays BEGIN SELECT RAISE(ABORT, 'injected failure'); END"); err != nil {
		test.Fatal(err)
	}
	response = apiRequest(test, host.Client(), http.MethodPost, host.URL+relayHeartbeatPath, secret, map[string]any{})
	var failure struct {
		Code string `json:"code"`
	}
	decodeTestBody(test, response, &failure)
	response.Body.Close()
	if response.StatusCode != http.StatusServiceUnavailable || failure.Code != "RELAY_INTERNAL" {
		test.Fatal("database failure masqueraded as identity revocation")
	}
	if _, err := database.ExecContext(test.Context(), "DROP TRIGGER reject_heartbeat"); err != nil {
		test.Fatal(err)
	}
	response = apiRequest(test, host.Client(), http.MethodPost, host.URL+relayHeartbeatPath, secret, map[string]any{"healthy": true})
	response.Body.Close()
	relay, _ := server.store.RelayByToken(secret)
	if response.StatusCode != http.StatusOK || !relay.ExecutionReportedAt.IsZero() {
		test.Fatal("legacy relay became incompatible or reused an old receipt")
	}
}
