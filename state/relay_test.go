package state

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

// relayStore returns a fresh store to run one relay test against. Both
// implementations must satisfy the same contract, so every test loops over
// them (see newTestStores).
func relayTestStores(t *testing.T) map[string]Store {
	t.Helper()
	return newTestStores(t)
}

func mustNewEnrollmentSecret(t *testing.T) string {
	t.Helper()
	secret, err := NewRelayEnrollmentTokenSecret()
	if err != nil {
		t.Fatalf("NewRelayEnrollmentTokenSecret: %v", err)
	}
	if !ValidRelayEnrollmentSecret(secret) {
		t.Fatalf("generated enrollment secret %q does not validate", secret)
	}
	return secret
}

func mustNewRelayToken(t *testing.T) string {
	t.Helper()
	token, err := NewRelayTokenSecret()
	if err != nil {
		t.Fatalf("NewRelayTokenSecret: %v", err)
	}
	if !ValidRelayToken(token) {
		t.Fatalf("generated relay token %q does not validate", token)
	}
	return token
}

func TestRelayEnrollmentTokenLifecycle(t *testing.T) {
	for name, s := range relayTestStores(t) {
		secret := mustNewEnrollmentSecret(t)
		id, err := NewRelayEnrollmentTokenID()
		if err != nil {
			t.Fatalf("%s NewRelayEnrollmentTokenID: %v", name, err)
		}
		tok := RelayEnrollmentToken{ID: id, Name: "hk-1", Visibility: RelayVisibilityPrivate, CreatedBy: "user:1"}
		if err := s.CreateRelayEnrollmentToken(tok, secret); err != nil {
			t.Fatalf("%s CreateRelayEnrollmentToken: %v", name, err)
		}

		got, ok := s.RelayEnrollmentTokenBySecret(secret)
		if !ok || got.ID != id || got.Name != "hk-1" {
			t.Fatalf("%s lookup by secret = (%+v, %v), want id %s", name, got, ok, id)
		}
		if byID, ok := s.RelayEnrollmentTokenByID(id); !ok || byID.ID != id {
			t.Fatalf("%s lookup by id = (%+v, %v)", name, byID, ok)
		}
		if list := s.ListRelayEnrollmentTokens(); len(list) != 1 || list[0].ID != id {
			t.Fatalf("%s list = %+v, want one token %s", name, list, id)
		}

		// A malformed or unknown secret never resolves.
		if _, ok := s.RelayEnrollmentTokenBySecret("xrelay-enroll-not-a-real-token"); ok {
			t.Fatalf("%s accepted a malformed secret", name)
		}
		elsewhere := mustNewEnrollmentSecret(t)
		if _, ok := s.RelayEnrollmentTokenBySecret(elsewhere); ok {
			t.Fatalf("%s resolved an unknown secret", name)
		}

		now := time.Now().UTC()
		consumed, err := s.ConsumeRelayEnrollmentToken(id, now)
		if err != nil {
			t.Fatalf("%s ConsumeRelayEnrollmentToken: %v", name, err)
		}
		if consumed.UsedAt.IsZero() {
			t.Fatalf("%s consumed token has no UsedAt", name)
		}
		if _, err := s.ConsumeRelayEnrollmentToken(id, now); !errors.Is(err, ErrRelayEnrollmentConsumed) {
			t.Fatalf("%s second consume = %v, want ErrRelayEnrollmentConsumed", name, err)
		}
		if _, err := s.ConsumeRelayEnrollmentToken("renr-missing", now); !errors.Is(err, ErrRelayNotFound) {
			t.Fatalf("%s unknown consume = %v, want ErrRelayNotFound", name, err)
		}

		if err := s.DeleteRelayEnrollmentToken(id); err != nil {
			t.Fatalf("%s DeleteRelayEnrollmentToken: %v", name, err)
		}
		if _, ok := s.RelayEnrollmentTokenByID(id); ok {
			t.Fatalf("%s token survived deletion", name)
		}
		// Deleting twice is a no-op, not an error.
		if err := s.DeleteRelayEnrollmentToken(id); err != nil {
			t.Fatalf("%s second delete: %v", name, err)
		}
	}
}

func TestRelayEnrollmentTokenExpiry(t *testing.T) {
	for name, s := range relayTestStores(t) {
		secret := mustNewEnrollmentSecret(t)
		id, _ := NewRelayEnrollmentTokenID()
		now := time.Now().UTC()
		tok := RelayEnrollmentToken{ID: id, Expiry: now.Add(-time.Minute)}
		if err := s.CreateRelayEnrollmentToken(tok, secret); err != nil {
			t.Fatalf("%s CreateRelayEnrollmentToken: %v", name, err)
		}
		if _, err := s.ConsumeRelayEnrollmentToken(id, now); !errors.Is(err, ErrRelayEnrollmentExpired) {
			t.Fatalf("%s consume of an expired token = %v, want ErrRelayEnrollmentExpired", name, err)
		}
		// An expired token stays expired: the failure must not consume it.
		if _, err := s.ConsumeRelayEnrollmentToken(id, now); !errors.Is(err, ErrRelayEnrollmentExpired) {
			t.Fatalf("%s second consume of an expired token = %v", name, err)
		}
	}
}

func TestRelayLifecycle(t *testing.T) {
	for name, s := range relayTestStores(t) {
		token := mustNewRelayToken(t)
		id, _ := NewRelayID()
		relay := Relay{
			ID: id, Name: "hk-1", HostName: "hk1.example.com",
			RegionCode: "hk", RegionName: "Hong Kong",
			NodeKey: "nodekey:" + id, Version: "0.1.0",
			DERPPort: 443, STUNPort: 3478,
			Visibility: RelayVisibilityOrganization, CreatedBy: "user:1",
		}
		if err := s.CreateRelay(relay, token); err != nil {
			t.Fatalf("%s CreateRelay: %v", name, err)
		}

		if got, ok := s.RelayByToken(token); !ok || got.ID != id {
			t.Fatalf("%s lookup by token = (%+v, %v)", name, got, ok)
		}
		if got, ok := s.RelayByID(id); !ok || got.DesiredState != RelayStateOnline || got.ConfigVersion == 0 {
			t.Fatalf("%s lookup by id = (%+v, %v); want online with a config version", name, got, ok)
		}
		if got, ok := s.RelayByNodeKey(relay.NodeKey); !ok || got.ID != id {
			t.Fatalf("%s lookup by node key = (%+v, %v)", name, got, ok)
		}
		if list := s.ListRelays(); len(list) != 1 || list[0].ID != id {
			t.Fatalf("%s list = %+v, want one relay", name, list)
		}

		// A second relay cannot reuse the same token.
		other, _ := NewRelayID()
		if err := s.CreateRelay(Relay{ID: other, Name: "dup"}, token); !errors.Is(err, ErrRelayTokenExists) {
			t.Fatalf("%s duplicate token = %v, want ErrRelayTokenExists", name, err)
		}
		// Nor can two relays share a node key.
		if err := s.CreateRelay(Relay{ID: other, NodeKey: relay.NodeKey}, mustNewRelayToken(t)); err == nil {
			t.Fatalf("%s accepted a duplicate node key", name)
		}

		if err := s.UpdateRelayHeartbeat(id, RelayHeartbeat{
			Version: "0.2.0", Healthy: true, UptimeSeconds: 3600,
			ConnectedClients: 12, BytesIn: 1000, BytesOut: 2000,
		}); err != nil {
			t.Fatalf("%s UpdateRelayHeartbeat: %v", name, err)
		}
		got, _ := s.RelayByID(id)
		if !got.Healthy || got.UptimeSeconds != 3600 || got.ConnectedClients != 12 ||
			got.BytesIn != 1000 || got.BytesOut != 2000 || got.Version != "0.2.0" || got.LastSeen.IsZero() {
			t.Fatalf("%s heartbeat not recorded: %+v", name, got)
		}

		limit := int64(10485760)
		region := "Hong Kong 2"
		updated, err := s.UpdateRelayConfig(id, RelayConfigUpdate{
			DesiredState: RelayStateMaintenance, BandwidthLimit: &limit, RegionName: &region,
		})
		if err != nil {
			t.Fatalf("%s UpdateRelayConfig: %v", name, err)
		}
		if updated.DesiredState != RelayStateMaintenance || updated.BandwidthLimit != limit || updated.RegionName != region {
			t.Fatalf("%s config update = %+v", name, updated)
		}
		if updated.ConfigVersion <= got.ConfigVersion {
			t.Fatalf("%s config version did not advance: %d -> %d", name, got.ConfigVersion, updated.ConfigVersion)
		}
		// A partial update keeps the other fields.
		again, err := s.UpdateRelayConfig(id, RelayConfigUpdate{DesiredState: RelayStateOnline})
		if err != nil {
			t.Fatalf("%s second UpdateRelayConfig: %v", name, err)
		}
		if again.BandwidthLimit != limit || again.RegionName != region {
			t.Fatalf("%s partial update reset fields: %+v", name, again)
		}
		if again.ConfigVersion <= updated.ConfigVersion {
			t.Fatalf("%s config version did not advance on the second change", name)
		}

		if _, err := s.UpdateRelayConfig("relay-missing", RelayConfigUpdate{DesiredState: RelayStateDisabled}); !errors.Is(err, ErrRelayNotFound) {
			t.Fatalf("%s config update of an unknown relay = %v", name, err)
		}
		if err := s.UpdateRelayHeartbeat("relay-missing", RelayHeartbeat{}); !errors.Is(err, ErrRelayNotFound) {
			t.Fatalf("%s heartbeat of an unknown relay = %v", name, err)
		}

		if err := s.DeleteRelay(id); err != nil {
			t.Fatalf("%s DeleteRelay: %v", name, err)
		}
		if _, ok := s.RelayByID(id); ok {
			t.Fatalf("%s relay survived deletion", name)
		}
		if _, ok := s.RelayByToken(token); ok {
			t.Fatalf("%s token still resolves after deletion", name)
		}
		if _, ok := s.RelayByNodeKey(relay.NodeKey); ok {
			t.Fatalf("%s node key still resolves after deletion", name)
		}
	}
}

func TestRelaySecretsAreStoredHashed(t *testing.T) {
	s := NewMemoryStore()
	secret := mustNewEnrollmentSecret(t)
	id, _ := NewRelayEnrollmentTokenID()
	if err := s.CreateRelayEnrollmentToken(RelayEnrollmentToken{ID: id}, secret); err != nil {
		t.Fatalf("CreateRelayEnrollmentToken: %v", err)
	}
	if _, ok := s.relay.secrets[RelaySecretHash(secret)]; !ok {
		t.Fatalf("token is not stored under its hash")
	}
	for _, stored := range s.relay.secrets {
		if stored == secret {
			t.Fatalf("plaintext secret leaked into storage")
		}
	}

	// A store refuses malformed secrets instead of persisting something that
	// could never authenticate.
	if err := s.CreateRelayEnrollmentToken(RelayEnrollmentToken{ID: "x"}, "short"); err == nil {
		t.Fatalf("store accepted a malformed enrollment secret")
	}
	if err := s.CreateRelay(Relay{ID: "relay-x"}, "short"); err == nil {
		t.Fatalf("store accepted a malformed relay token")
	}
}

func TestRelayStateSurvivesSQLiteReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	ctx := context.Background()

	store, err := OpenSQLite(ctx, path)
	if err != nil {
		t.Fatalf("OpenSQLite: %v", err)
	}
	token := mustNewRelayToken(t)
	id, _ := NewRelayID()
	if err := store.CreateRelay(Relay{
		ID: id, Name: "hk-1", HostName: "hk1.example.com",
		RegionCode: "hk", NodeKey: "nodekey:" + id, DERPPort: 443,
	}, token); err != nil {
		t.Fatalf("CreateRelay: %v", err)
	}
	limit := int64(2048)
	if _, err := store.UpdateRelayConfig(id, RelayConfigUpdate{DesiredState: RelayStateDisabled, BandwidthLimit: &limit}); err != nil {
		t.Fatalf("UpdateRelayConfig: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	reopened, err := OpenSQLite(ctx, path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	t.Cleanup(func() { reopened.Close() })

	got, ok := reopened.RelayByToken(token)
	if !ok {
		t.Fatalf("relay did not survive a reopen")
	}
	if got.DesiredState != RelayStateDisabled || got.BandwidthLimit != limit {
		t.Fatalf("relay config after reopen = %+v", got)
	}
	if _, ok := reopened.RelayByNodeKey("nodekey:" + id); !ok {
		t.Fatalf("node key lookup did not survive a reopen")
	}
}
