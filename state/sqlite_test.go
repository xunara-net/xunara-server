package state

import (
	"context"
	"fmt"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"tailscale.com/types/key"
)

// openTestSQLite opens a SQLite store in a temporary directory.
func openTestSQLite(t *testing.T, path string) *SQLiteStore {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	s, err := OpenSQLite(ctx, path)
	if err != nil {
		t.Fatalf("OpenSQLite: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// 历史测试使用当前库构造业务数据，再移除新增结构，不能仅倒改 user_version。
func downgradeSQLiteTestVersion(t *testing.T, store *SQLiteStore, version int) {
	t.Helper()
	if version < 24 {
		for _, statement := range []string{"DROP TABLE dns_namespace", "DROP INDEX idx_nodes_dns_name_unique", "ALTER TABLE nodes DROP COLUMN dns_name"} {
			if _, err := store.db.ExecContext(t.Context(), statement); err != nil {
				t.Fatal(err)
			}
		}
	}
	if version < 23 {
		for _, statement := range []string{"DROP TABLE address_configuration", "DROP INDEX idx_nodes_ipv4_unique"} {
			if _, err := store.db.ExecContext(t.Context(), statement); err != nil {
				t.Fatal(err)
			}
		}
	}
	if version < 22 {
		for _, statement := range []string{"ALTER TABLE relays DROP COLUMN execution_report", "ALTER TABLE relays DROP COLUMN execution_reported_at"} {
			if _, err := store.db.ExecContext(t.Context(), statement); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, statement := range []string{
		"DROP TABLE network_documents", "DROP TABLE network_document_history",
		"ALTER TABLE dns_records DROP COLUMN revision", "DROP INDEX idx_relays_region_id",
		"ALTER TABLE relays DROP COLUMN region_id", "ALTER TABLE relays DROP COLUMN cert_name",
	} {
		if _, err := store.db.ExecContext(t.Context(), statement); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.db.ExecContext(t.Context(), fmt.Sprintf("PRAGMA user_version = %d", version)); err != nil {
		t.Fatal(err)
	}
}

func TestSQLiteStoreConformance(t *testing.T) {
	runStoreConformance(t, func(t *testing.T) Store {
		return openTestSQLite(t, filepath.Join(t.TempDir(), "state.db"))
	})
}

func TestSQLitePreAuthKeyConformance(t *testing.T) {
	runPreAuthKeyConformance(t, func(t *testing.T) Store {
		return openTestSQLite(t, filepath.Join(t.TempDir(), "state.db"))
	})
}

func TestSQLiteDNSRecordConformance(t *testing.T) {
	runDNSRecordConformance(t, func(t *testing.T) Store {
		return openTestSQLite(t, filepath.Join(t.TempDir(), "state.db"))
	})
}

func TestSQLiteTKAConformance(t *testing.T) {
	runTKAConformance(t, func(t *testing.T) Store {
		return openTestSQLite(t, filepath.Join(t.TempDir(), "state.db"))
	})
}

// TestSQLiteTKAMetaPersistsAcrossReopen checks the tailnet-lock bookkeeping
// survives a restart, which multi-instance failover depends on.
func TestSQLiteTKAMetaPersistsAcrossReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")

	first, err := OpenSQLite(context.Background(), path)
	if err != nil {
		t.Fatalf("OpenSQLite: %v", err)
	}
	want := TKAMeta{EverEnabled: true, Enabled: true, DisablementSecretSealed: "v1:sealed"}
	if err := first.SetTKAMeta(want); err != nil {
		t.Fatalf("SetTKAMeta: %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	second, err := OpenSQLite(context.Background(), path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	t.Cleanup(func() { second.Close() })
	if got := second.TKAMeta(); got != want {
		t.Errorf("TKAMeta after reopen = %+v, want %+v", got, want)
	}
}

// TestSQLitePreAuthKeyPersistsAcrossReopen checks keys survive a restart and
// that the ID counter does not restart with them.
func TestSQLitePreAuthKeyPersistsAcrossReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	ctx := context.Background()

	first, err := OpenSQLite(ctx, path)
	if err != nil {
		t.Fatalf("OpenSQLite: %v", err)
	}
	k := PreAuthKey{Key: "tskey-auth-durable", Reusable: true}
	if err := first.CreatePreAuthKey(&k); err != nil {
		t.Fatalf("CreatePreAuthKey: %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	second, err := OpenSQLite(ctx, path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer second.Close()

	got, ok := second.GetPreAuthKey(k.Key)
	if !ok {
		t.Fatal("pre-auth key did not survive reopen")
	}
	if got.ID != k.ID || !got.Reusable {
		t.Errorf("key changed across reopen: %+v", got)
	}

	next := PreAuthKey{Key: "tskey-auth-next"}
	if err := second.CreatePreAuthKey(&next); err != nil {
		t.Fatalf("CreatePreAuthKey after reopen: %v", err)
	}
	if next.ID == k.ID {
		t.Error("pre-auth key ID counter restarted after reopen")
	}
}

// TestSQLiteStorePersistsAcrossReopen is the point of a durable store: node
// identity must survive a server restart, including the Noise-adjacent key
// material the Compatibility Core binds to.
func TestSQLiteStorePersistsAcrossReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")

	ctx := context.Background()
	first, err := OpenSQLite(ctx, path)
	if err != nil {
		t.Fatalf("OpenSQLite: %v", err)
	}

	n := Node{Hostname: "durable", NodeKey: key.NewNode().Public()}
	if err := first.CreateNode(&n); err != nil {
		t.Fatalf("CreateNode: %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	second, err := OpenSQLite(ctx, path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer second.Close()

	got, ok := second.GetNodeByNodeKey(n.NodeKey)
	if !ok {
		t.Fatal("node did not survive reopen")
	}
	if got.ID != n.ID || got.StableID != n.StableID {
		t.Errorf("identity changed: got id=%d stable=%q, want id=%d stable=%q",
			got.ID, got.StableID, n.ID, n.StableID)
	}
	if got.IPv4 != n.IPv4 || got.IPv6 != n.IPv6 {
		t.Errorf("addresses changed: got %v/%v, want %v/%v", got.IPv4, got.IPv6, n.IPv4, n.IPv6)
	}

	// A node created after reopen must not collide with the existing one.
	next := Node{Hostname: "next", NodeKey: key.NewNode().Public()}
	if err := second.CreateNode(&next); err != nil {
		t.Fatalf("CreateNode after reopen: %v", err)
	}
	if next.ID == n.ID {
		t.Error("ID counter restarted after reopen")
	}
	if next.IPv4 == n.IPv4 {
		t.Error("IPv4 counter restarted after reopen")
	}
}

// TestSQLiteMigratesV7ToV8 simulates a database written before the node's
// network-lock key was persisted: reopening it must apply the v8 migration
// instead of failing on the missing column.
func TestSQLiteMigratesV7ToV8(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")

	ctx := context.Background()
	first := openTestSQLite(t, path)
	n := Node{Hostname: "old", NodeKey: key.NewNode().Public()}
	if err := first.CreateNode(&n); err != nil {
		t.Fatalf("CreateNode: %v", err)
	}
	if _, err := first.db.ExecContext(ctx, "ALTER TABLE nodes DROP COLUMN nl_key"); err != nil {
		t.Fatalf("dropping nl_key: %v", err)
	}
	downgradeSQLiteTestVersion(t, first, 7)
	if err := first.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	second := openTestSQLite(t, path)
	got, ok := second.GetNodeByNodeKey(n.NodeKey)
	if !ok {
		t.Fatal("node did not survive the v7 -> v8 migration")
	}
	if !got.NLKey.IsZero() {
		t.Errorf("NLKey = %v, want the zero value for a pre-v8 node", got.NLKey)
	}

	got.NLKey = key.NewNLPrivate().Public()
	if err := second.UpdateNode(got); err != nil {
		t.Fatalf("UpdateNode after migration: %v", err)
	}
	again, ok := second.GetNodeByNodeKey(n.NodeKey)
	if !ok {
		t.Fatal("node disappeared after update")
	}
	if again.NLKey != got.NLKey {
		t.Errorf("NLKey after migration = %v, want %v", again.NLKey, got.NLKey)
	}
}

// TestSQLiteMigratesV8ToV9 simulates a database written before device posture
// attributes existed: reopening it must create the table (v9) and keep the
// node rows readable.
func TestSQLiteMigratesV8ToV9(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")

	ctx := context.Background()
	first := openTestSQLite(t, path)
	n := Node{Hostname: "old", NodeKey: key.NewNode().Public()}
	if err := first.CreateNode(&n); err != nil {
		t.Fatalf("CreateNode: %v", err)
	}
	if _, err := first.db.ExecContext(ctx, "DROP TABLE node_device_attrs"); err != nil {
		t.Fatalf("dropping node_device_attrs: %v", err)
	}
	downgradeSQLiteTestVersion(t, first, 8)
	if err := first.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	second := openTestSQLite(t, path)
	got, ok := second.GetNodeByNodeKey(n.NodeKey)
	if !ok {
		t.Fatal("node did not survive the v8 -> v9 migration")
	}
	if err := second.SetNodeDeviceAttrs(got.ID, map[string]any{"os_version": "15.2"}); err != nil {
		t.Fatalf("SetNodeDeviceAttrs after migration: %v", err)
	}
	attrs, err := second.NodeDeviceAttrs(got.ID)
	if err != nil {
		t.Fatalf("NodeDeviceAttrs after migration: %v", err)
	}
	if attrs["os_version"] != "15.2" {
		t.Errorf("attributes after migration = %#v", attrs)
	}
}

// TestSQLiteMigratesV9ToV10 simulates a database written before service
// discovery existed: reopening it must create the table (v10) and keep the
// node rows readable.
func TestSQLiteMigratesV9ToV10(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")

	ctx := context.Background()
	first := openTestSQLite(t, path)
	n := Node{Hostname: "old", NodeKey: key.NewNode().Public()}
	if err := first.CreateNode(&n); err != nil {
		t.Fatalf("CreateNode: %v", err)
	}
	if _, err := first.db.ExecContext(ctx, "DROP TABLE node_services"); err != nil {
		t.Fatalf("dropping node_services: %v", err)
	}
	downgradeSQLiteTestVersion(t, first, 9)
	if err := first.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	second := openTestSQLite(t, path)
	got, ok := second.GetNodeByNodeKey(n.NodeKey)
	if !ok {
		t.Fatal("node did not survive the v9 -> v10 migration")
	}
	if err := second.ReplaceNodeServices(got.ID, []Service{{Name: "api", Protocol: "tcp", Port: 8080}}); err != nil {
		t.Fatalf("ReplaceNodeServices after migration: %v", err)
	}
	if svc, ok := second.GetServiceByName("api"); !ok || svc.Port != 8080 {
		t.Errorf("service after migration = %+v, %v", svc, ok)
	}
}

// TestSQLiteMigratesV10ToV11 simulates a database written before Xunara Flux
// existed: reopening it must create the transfer table (v11) and keep the node
// rows readable.
func TestSQLiteMigratesV10ToV11(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")

	ctx := context.Background()
	first := openTestSQLite(t, path)
	sender := Node{Hostname: "old-sender", NodeKey: key.NewNode().Public()}
	recipient := Node{Hostname: "old-recipient", NodeKey: key.NewNode().Public()}
	for _, n := range []*Node{&sender, &recipient} {
		if err := first.CreateNode(n); err != nil {
			t.Fatalf("CreateNode: %v", err)
		}
	}
	if _, err := first.db.ExecContext(ctx, "DROP TABLE flux_transfers"); err != nil {
		t.Fatalf("dropping flux_transfers: %v", err)
	}
	downgradeSQLiteTestVersion(t, first, 10)
	if err := first.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	second := openTestSQLite(t, path)
	if _, ok := second.GetNodeByNodeKey(sender.NodeKey); !ok {
		t.Fatal("node did not survive the v10 -> v11 migration")
	}
	transfer := FluxTransfer{
		SenderNode:    sender.ID,
		RecipientNode: recipient.ID,
		Name:          "old.txt",
		Size:          4,
		SHA256:        "00",
		ExpiresAt:     time.Now().Add(time.Hour),
	}
	if err := second.CreateFluxTransfer(&transfer, FluxQuotas{}); err != nil {
		t.Fatalf("CreateFluxTransfer after migration: %v", err)
	}
	if got, ok := second.GetFluxTransfer(transfer.ID); !ok || got.State != FluxPending {
		t.Errorf("transfer after migration = %+v, %v", got, ok)
	}
}

// TestSQLiteMigratesV12ToV13 simulates a database written before the rate
// limiter existed: reopening it must create the bucket table.
func TestSQLiteMigratesV12ToV13(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")

	ctx := context.Background()
	first := openTestSQLite(t, path)
	node := Node{Hostname: "old", NodeKey: key.NewNode().Public()}
	if err := first.CreateNode(&node); err != nil {
		t.Fatalf("CreateNode: %v", err)
	}
	if _, err := first.db.ExecContext(ctx, "DROP TABLE rate_limits"); err != nil {
		t.Fatalf("dropping rate_limits: %v", err)
	}
	downgradeSQLiteTestVersion(t, first, 12)
	if err := first.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	second := openTestSQLite(t, path)
	if _, ok := second.GetNodeByNodeKey(node.NodeKey); !ok {
		t.Fatal("node did not survive the v12 -> v13 migration")
	}
	if allowed, _, err := second.AllowRate("migrated", 1, time.Minute, time.Now()); err != nil || !allowed {
		t.Fatalf("AllowRate after migration = %v/%v", allowed, err)
	}
}

// TestSQLiteMigratesV13ToV14 simulates a database written before Xunara Reach
// existed: reopening it must create the session and chunk tables.
func TestSQLiteMigratesV13ToV14(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")

	ctx := context.Background()
	first := openTestSQLite(t, path)
	node := Node{Hostname: "old", NodeKey: key.NewNode().Public()}
	target := Node{Hostname: "old-target", NodeKey: key.NewNode().Public()}
	for _, n := range []*Node{&node, &target} {
		if err := first.CreateNode(n); err != nil {
			t.Fatalf("CreateNode: %v", err)
		}
	}
	for _, table := range []string{"reach_chunks", "reach_sessions"} {
		if _, err := first.db.ExecContext(ctx, "DROP TABLE "+table); err != nil {
			t.Fatalf("dropping %s: %v", table, err)
		}
	}
	downgradeSQLiteTestVersion(t, first, 13)
	if err := first.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	second := openTestSQLite(t, path)
	if _, ok := second.GetNodeByNodeKey(node.NodeKey); !ok {
		t.Fatal("node did not survive the v13 -> v14 migration")
	}
	session := ReachSession{Sender: node.ID, Target: target.ID, Argv: []string{"true"}, Timeout: time.Minute}
	if err := second.CreateReachSession(&session, ReachQuotas{}); err != nil {
		t.Fatalf("CreateReachSession after migration: %v", err)
	}
}

// TestSQLiteMigratesV15ToV16 simulates a database written before Atlas service
// visibility existed: reopening it must add the column, keep the service rows
// readable and leave them discoverable by the whole organization.
func TestSQLiteMigratesV15ToV16(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")

	ctx := context.Background()
	first := openTestSQLite(t, path)
	node := Node{Hostname: "old", NodeKey: key.NewNode().Public()}
	if err := first.CreateNode(&node); err != nil {
		t.Fatalf("CreateNode: %v", err)
	}
	if err := first.ReplaceNodeServices(node.ID, []Service{
		{Name: "api", Protocol: "tcp", Port: 8080},
	}); err != nil {
		t.Fatalf("ReplaceNodeServices: %v", err)
	}
	if _, err := first.db.ExecContext(ctx, "DROP TABLE node_service_visibility"); err != nil {
		t.Fatalf("dropping node_service_visibility: %v", err)
	}
	downgradeSQLiteTestVersion(t, first, 15)
	if err := first.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	second := openTestSQLite(t, path)
	if _, ok := second.GetNodeByNodeKey(node.NodeKey); !ok {
		t.Fatal("node did not survive the v15 -> v16 migration")
	}
	svc, ok := second.GetServiceByName("api")
	if !ok || svc.Port != 8080 {
		t.Fatalf("service after migration = %+v, %v", svc, ok)
	}
	if len(svc.Visibility) != 0 {
		t.Errorf("service visibility after migration = %v, want the organization default", svc.Visibility)
	}
}

// TestSQLiteMigratesV16ToV17 simulates a database written before
// cross-organization service sharing existed: reopening it must add the
// column, read the old services back as not shared, and accept new writes
// that do set the flag.
func TestSQLiteMigratesV16ToV17(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")

	ctx := context.Background()
	first := openTestSQLite(t, path)
	node := Node{Hostname: "old", NodeKey: key.NewNode().Public()}
	if err := first.CreateNode(&node); err != nil {
		t.Fatalf("CreateNode: %v", err)
	}
	if err := first.ReplaceNodeServices(node.ID, []Service{
		{Name: "api", Protocol: "tcp", Port: 8080},
	}); err != nil {
		t.Fatalf("ReplaceNodeServices: %v", err)
	}
	if _, err := first.db.ExecContext(ctx, "DROP TABLE node_service_shared"); err != nil {
		t.Fatalf("dropping node_service_shared: %v", err)
	}
	downgradeSQLiteTestVersion(t, first, 16)
	if err := first.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	second := openTestSQLite(t, path)
	svc, ok := second.GetServiceByName("api")
	if !ok || svc.Port != 8080 {
		t.Fatalf("service after migration = %+v, %v", svc, ok)
	}
	if svc.Shared {
		t.Error("service after migration is shared, want the v2 default (not shared)")
	}

	if err := second.ReplaceNodeServices(node.ID, []Service{
		{Name: "api", Protocol: "tcp", Port: 8080, Shared: true},
	}); err != nil {
		t.Fatalf("ReplaceNodeServices(shared): %v", err)
	}
	if svc, ok := second.GetServiceByName("api"); !ok || !svc.Shared {
		t.Errorf("shared flag after migration = %+v, %v, want true", svc, ok)
	}
}

// TestSQLiteMigratesV17ToV18 simulates a database written before ACL-derived
// service visibility existed: reopening it must add the table, read the old
// services back as selector-visible, and accept new writes that derive
// visibility from the ACL.
func TestSQLiteMigratesV17ToV18(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")

	ctx := context.Background()
	first := openTestSQLite(t, path)
	node := Node{Hostname: "old", NodeKey: key.NewNode().Public()}
	if err := first.CreateNode(&node); err != nil {
		t.Fatalf("CreateNode: %v", err)
	}
	if err := first.ReplaceNodeServices(node.ID, []Service{
		{Name: "api", Protocol: "tcp", Port: 8080, Visibility: []string{"group:eng"}},
	}); err != nil {
		t.Fatalf("ReplaceNodeServices: %v", err)
	}
	if _, err := first.db.ExecContext(ctx, "DROP TABLE node_service_acl_visibility"); err != nil {
		t.Fatalf("dropping node_service_acl_visibility: %v", err)
	}
	downgradeSQLiteTestVersion(t, first, 17)
	if err := first.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	second := openTestSQLite(t, path)
	svc, ok := second.GetServiceByName("api")
	if !ok || svc.Port != 8080 {
		t.Fatalf("service after migration = %+v, %v", svc, ok)
	}
	if svc.VisibilityFromACL {
		t.Error("service after migration derives visibility from the ACL, want the stored selectors")
	}
	if !slices.Equal(svc.Visibility, []string{"group:eng"}) {
		t.Errorf("service visibility after migration = %v, want group:eng", svc.Visibility)
	}

	if err := second.ReplaceNodeServices(node.ID, []Service{
		{Name: "api", Protocol: "tcp", Port: 8080, VisibilityFromACL: true},
	}); err != nil {
		t.Fatalf("ReplaceNodeServices(acl): %v", err)
	}
	if svc, ok := second.GetServiceByName("api"); !ok || !svc.VisibilityFromACL {
		t.Errorf("ACL-derived flag after migration = %+v, %v, want true", svc, ok)
	}
}

func TestSQLiteStoreConcurrentAccess(t *testing.T) {
	s := openTestSQLite(t, filepath.Join(t.TempDir(), "state.db"))

	done := make(chan struct{})
	go func() {
		defer close(done)
		for range 16 {
			n := Node{NodeKey: key.NewNode().Public()}
			if err := s.CreateNode(&n); err != nil {
				t.Errorf("CreateNode: %v", err)
				return
			}
		}
	}()

	for range 16 {
		_ = s.ListNodes()
	}
	<-done

	if got := len(s.ListNodes()); got != 16 {
		t.Errorf("ListNodes len = %d, want 16", got)
	}
}
