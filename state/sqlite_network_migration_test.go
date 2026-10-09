package state

import (
	"path/filepath"
	"testing"
)

func TestSQLiteMigratesV19ToNetworkConfigurationV21(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "state.db")
	first := openTestSQLite(t, filename)
	record := DNSRecord{Name: "nas.xunara.test", Type: "A", Value: "100.64.0.20"}
	if err := first.UpsertDNSRecord(&record); err != nil {
		t.Fatal(err)
	}
	secret, err := NewRelayTokenSecret()
	if err != nil {
		t.Fatal(err)
	}
	if err := first.CreateRelay(Relay{ID: "relay-legacy", HostName: "relay.example.test", DesiredState: RelayStateOnline}, secret); err != nil {
		t.Fatal(err)
	}
	downgradeSQLiteTestVersion(t, first, 19)
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	reopened := openTestSQLite(t, filename)
	var version int
	if err := reopened.DB().QueryRowContext(t.Context(), "PRAGMA user_version").Scan(&version); err != nil || version != len(migrations) {
		t.Fatalf("schema: %d %v", version, err)
	}
	var revision int
	if err := reopened.DB().QueryRowContext(t.Context(), "SELECT revision FROM dns_records WHERE id = ?", record.ID).Scan(&revision); err != nil || revision != 1 {
		t.Fatalf("existing DNS record: %d %v", revision, err)
	}
	relay, found := reopened.RelayByToken(secret)
	if !found || relay.RegionID != 0 || relay.CertName != "" {
		t.Fatal("legacy relay lost its identity or fabricated certificate metadata")
	}
	if _, err := reopened.DB().ExecContext(t.Context(), "INSERT INTO network_documents VALUES ('policy', 1, '{}', 'test', 1)"); err != nil {
		t.Fatal(err)
	}
}
