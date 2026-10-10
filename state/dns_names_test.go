package state

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"tailscale.com/types/key"
	"tailscale.com/util/dnsname"
)

func dnsNameStoreFactories() map[string]storeFactory {
	return map[string]storeFactory{
		"memory": func(test *testing.T) Store { return NewMemoryStore() },
		"sqlite": func(test *testing.T) Store { return openTestSQLite(test, filepath.Join(test.TempDir(), "state.db")) },
	}
}

func createDNSNode(test *testing.T, store Store, hostname string) Node {
	test.Helper()
	node := Node{MachineKey: key.NewMachine().Public(), NodeKey: key.NewNode().Public(), Hostname: hostname, DNSName: "untrusted-input"}
	if err := store.CreateNode(&node); err != nil {
		test.Fatal(err)
	}
	return node
}

func TestDNSNameOwnershipLifecycle(test *testing.T) {
	for name, factory := range dnsNameStoreFactories() {
		test.Run(name, func(test *testing.T) {
			store := factory(test)
			if err := store.ConfigureDNSDomain(test.Context(), " XUNARA.TEST. "); err != nil {
				test.Fatal(err)
			}
			record := DNSRecord{Name: " NAS.XUNARA.TEST. ", Type: "a", Value: "100.64.0.10"}
			if err := store.UpsertDNSRecord(&record); err != nil {
				test.Fatal(err)
			}
			first := createDNSNode(test, store, "NAS")
			if first.Hostname != "NAS" || first.DNSName != fmt.Sprintf("nas-%d", first.ID) || first.FQDN("xunara.test") == record.FQDN() {
				test.Fatalf("record shadowed or machine hostname overwritten: %+v", first)
			}
			provider := createDNSNode(test, store, "provider")
			if err := store.ReplaceNodeServices(provider.ID, []Service{{Name: "files", Protocol: "tcp", Port: 445}}); err != nil {
				test.Fatal(err)
			}
			second := createDNSNode(test, store, "Files")
			if second.DNSName != fmt.Sprintf("files-%d", second.ID) {
				test.Fatalf("service shadowed: %+v", second)
			}
			third := createDNSNode(test, store, "provider")
			if third.DNSName == provider.DNSName {
				test.Fatal("duplicate device name")
			}
			shadow := DNSRecord{Name: third.FQDN("xunara.test"), Type: "AAAA", Value: "fd7a:115c:a1e0::9"}
			if err := store.UpsertDNSRecord(&shadow); !errors.Is(err, ErrDNSDeviceName) || shadow.ID != 0 {
				test.Fatalf("assigned device alias not protected: %v %+v", err, shadow)
			}
			if err := store.ReplaceNodeServices(provider.ID, []Service{{Name: third.DNSName, Protocol: "tcp", Port: 80}}); !errors.Is(err, ErrServiceNameTaken) {
				test.Fatalf("service shadowed device alias: %v", err)
			}
			if service, found := store.GetServiceByName("files"); !found || service.NodeID != provider.ID {
				test.Fatal("failed replacement removed an existing service")
			}
			shadow = DNSRecord{Name: "files.xunara.test", Type: "A", Value: "100.64.0.90"}
			if err := store.UpsertDNSRecord(&shadow); !errors.Is(err, ErrDNSNameConflict) {
				test.Fatalf("DNS record shadowed service: %v", err)
			}
			for _, name := range []string{"notes.nas.xunara.test", "_acme-challenge." + first.DNSName + ".xunara.test"} {
				challenge := DNSRecord{Name: name, Type: "TXT", Value: "test-value", NodeID: first.ID}
				if err := store.UpsertDNSRecord(&challenge); err != nil {
					test.Fatalf("non-conflicting subdomain or challenge: %v", err)
				}
			}
			stableName, stableIP, stableID := first.DNSName, first.IPv4, first.StableID
			first.Hostname, first.DNSName, first.NodeKey = "nas", "spoofed-alias", key.NewNode().Public()
			if err := store.UpdateNodeWithDNS(&first); err != nil {
				test.Fatal(err)
			}
			if first.DNSName != stableName || first.IPv4 != stableIP || first.StableID != stableID {
				test.Fatal("re-report or key rotation changed the assigned name/identity/IP")
			}
			first.Hostname = "files"
			if err := store.UpdateNodeWithDNS(&first); err != nil || first.DNSName != fmt.Sprintf("files-%d", first.ID) {
				test.Fatalf("rename did not protect service: %+v %v", first, err)
			}
			if err := store.UpdateNode(first); err != nil {
				test.Fatalf("generic update bypassed or failed naming policy: %v", err)
			}
			if err := store.DeleteDNSRecord(record.ID); err != nil {
				test.Fatal(err)
			}
			if fresh := createDNSNode(test, store, "nas"); fresh.DNSName != "nas" {
				test.Fatal("deleted record did not release its name")
			}
			if err := store.DeleteNode(third.ID); err != nil {
				test.Fatal(err)
			}
			if fresh := createDNSNode(test, store, third.DNSName); fresh.DNSName != third.DNSName {
				test.Fatal("deleted node did not release its alias")
			}
			if err := store.ConfigureDNSDomain(test.Context(), "another.test"); !errors.Is(err, ErrDNSDomainChange) {
				test.Fatalf("another instance changed the bound namespace: %v", err)
			}
			if err := store.ConfigureDNSDomain(test.Context(), ""); !errors.Is(err, ErrDNSDomainChange) {
				test.Fatalf("another instance disabled the bound namespace: %v", err)
			}
		})
	}
}

func TestDNSNameLengthAndFallback(test *testing.T) {
	for name, factory := range dnsNameStoreFactories() {
		test.Run(name, func(test *testing.T) {
			store := factory(test)
			domain := strings.Repeat("d", 63) + "." + strings.Repeat("e", 63) + "." + strings.Repeat("f", 63) + ".test"
			if err := store.ConfigureDNSDomain(test.Context(), domain); err != nil {
				test.Fatal(err)
			}
			first := createDNSNode(test, store, strings.Repeat("h", 100))
			second := createDNSNode(test, store, strings.Repeat("h", 100))
			for _, node := range []Node{first, second, createDNSNode(test, store, "玄序设备")} {
				if len(node.DNSName) > 63 || len(strings.TrimSuffix(node.FQDN(domain), ".")) > 253 || dnsname.ValidLabel(node.DNSName) != nil {
					test.Fatalf("invalid or oversized assigned name: %q", node.DNSName)
				}
			}
			if first.DNSName == second.DNSName {
				test.Fatal("truncated names collided")
			}
		})
	}
}

func legacyDNSDatabase(test *testing.T, path string, hostnames []string, recordName string) {
	test.Helper()
	database, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		test.Fatal(err)
	}
	defer database.Close()
	for _, migration := range migrations[:23] {
		if _, err := database.ExecContext(test.Context(), migration); err != nil {
			test.Fatal(err)
		}
	}
	if _, err := database.ExecContext(test.Context(), "PRAGMA user_version = 23"); err != nil {
		test.Fatal(err)
	}
	if _, err := database.ExecContext(test.Context(), "INSERT INTO counters (name, value) VALUES ('next_node_id', ?)", len(hostnames)+1); err != nil {
		test.Fatal(err)
	}
	for index, hostname := range hostnames {
		if _, err := database.ExecContext(test.Context(), `INSERT INTO nodes
			(id, stable_id, machine_key, node_key, disco_key, user_id, hostname, ipv4, created)
			VALUES (?, ?, ?, ?, '', 1, ?, ?, 1)`, index+1, fmt.Sprintf("legacy-%d", index),
			key.NewMachine().Public().String(), key.NewNode().Public().String(), hostname, fmt.Sprintf("100.64.0.%d", index+1)); err != nil {
			test.Fatal(err)
		}
	}
	if recordName != "" {
		if _, err := database.ExecContext(test.Context(), "INSERT INTO dns_records(id, name, type, value, node_id, created) VALUES (1, ?, 'A', '100.64.0.9', 0, 1)", recordName); err != nil {
			test.Fatal(err)
		}
	}
}

func TestDNSNameV23UpgradePreflightAndRestart(test *testing.T) {
	path := filepath.Join(test.TempDir(), "state.db")
	legacyDNSDatabase(test, path, []string{"Laptop Name", "NAS"}, "notes.xunara.test")
	before, err := os.ReadFile(path)
	if err != nil {
		test.Fatal(err)
	}
	if err := CheckDNSNamespace(test.Context(), path, "XUNARA.TEST."); err != nil {
		test.Fatal(err)
	}
	after, err := os.ReadFile(path)
	if err != nil || sha256.Sum256(before) != sha256.Sum256(after) {
		test.Fatal("preflight changed the old database")
	}
	store := openTestSQLite(test, path)
	if err := store.ConfigureDNSDomain(test.Context(), "xunara.test"); err != nil {
		test.Fatal(err)
	}
	first, found := store.GetNodeByID(1)
	if !found || first.DNSName != "laptop-name" || first.IPv4.String() != "100.64.0.1" || first.StableID != "legacy-0" || first.Hostname != "Laptop Name" {
		test.Fatalf("old identity/name/address altered: %+v", first)
	}
	if err := store.Close(); err != nil {
		test.Fatal(err)
	}
	restarted := openTestSQLite(test, path)
	if err := restarted.ConfigureDNSDomain(test.Context(), "xunara.test"); err != nil {
		test.Fatal(err)
	}
	if got, found := restarted.GetNodeByID(1); !found || !reflect.DeepEqual(got, first) {
		test.Fatal("restart lost existing device facts")
	}
	alias := createDNSNode(test, restarted, "laptop-name")
	if alias.DNSName == first.DNSName {
		test.Fatal("restart lost name ownership")
	}
	if err := CheckDNSNamespace(test.Context(), path, "xunara.test"); err != nil {
		test.Fatal(err)
	}
}

func TestDNSNameLegacyConflictsFailWithoutRenaming(test *testing.T) {
	for name, fixture := range map[string]struct {
		hostnames []string
		record    string
	}{"devices": {[]string{"Laptop Name", "laptop-name"}, ""}, "record": {[]string{"NAS"}, "NAS.XUNARA.TEST."}} {
		test.Run(name, func(test *testing.T) {
			path := filepath.Join(test.TempDir(), "state.db")
			legacyDNSDatabase(test, path, fixture.hostnames, fixture.record)
			if err := CheckDNSNamespace(test.Context(), path, "xunara.test"); !errors.Is(err, ErrDNSNameConflict) {
				test.Fatalf("preflight accepted old collision: %v", err)
			}
			store := openTestSQLite(test, path)
			if err := store.ConfigureDNSDomain(test.Context(), "xunara.test"); !errors.Is(err, ErrDNSNameConflict) {
				test.Fatalf("binding accepted old collision: %v", err)
			}
			var names, namespaces int
			if err := store.DB().QueryRowContext(test.Context(), "SELECT count(*) FROM nodes WHERE dns_name != ''").Scan(&names); err != nil {
				test.Fatal(err)
			}
			if err := store.DB().QueryRowContext(test.Context(), "SELECT count(*) FROM dns_namespace").Scan(&namespaces); err != nil || names != 0 || namespaces != 0 {
				test.Fatalf("failed binding partially persisted: %d %d %v", names, namespaces, err)
			}
			for index, hostname := range fixture.hostnames {
				if node, found := store.GetNodeByID(NodeID(index + 1)); !found || node.Hostname != hostname || node.DNSName != "" {
					test.Fatal("failed binding renamed an old device")
				}
			}
		})
	}
}

func TestDNSNameWriteFailureDoesNotPublishCandidate(test *testing.T) {
	store := openTestSQLite(test, filepath.Join(test.TempDir(), "state.db"))
	if err := store.ConfigureDNSDomain(test.Context(), "xunara.test"); err != nil {
		test.Fatal(err)
	}
	node := createDNSNode(test, store, "first")
	previous := node
	if _, err := store.DB().ExecContext(test.Context(), "CREATE TRIGGER reject_dns_node BEFORE UPDATE ON nodes BEGIN SELECT RAISE(ABORT, 'injected failure'); END"); err != nil {
		test.Fatal(err)
	}
	node.Hostname = "renamed"
	candidate := node
	if err := store.UpdateNodeWithDNS(&node); err == nil || !reflect.DeepEqual(candidate, node) {
		test.Fatal("failed commit changed the caller's candidate")
	}
	if stored, found := store.GetNodeByID(previous.ID); !found || !reflect.DeepEqual(stored, previous) {
		test.Fatal("failed commit changed stored node/name")
	}
	if _, err := store.DB().ExecContext(test.Context(), "DROP TRIGGER reject_dns_node; DROP TABLE dns_namespace"); err != nil {
		test.Fatal(err)
	}
	newNode := Node{NodeKey: key.NewNode().Public(), Hostname: "uncommitted"}
	if err := store.CreateNode(&newNode); err == nil || newNode.ID != 0 || newNode.DNSName != "" {
		test.Fatal("failed namespace read was treated as an available name")
	}
	if err := store.UpsertDNSRecord(&DNSRecord{Name: "available.xunara.test", Type: "A", Value: "100.64.0.9"}); err == nil {
		test.Fatal("record write ignored namespace read failure")
	}
	if err := store.ReplaceNodeServices(previous.ID, []Service{{Name: "available", Protocol: "tcp", Port: 80}}); err == nil {
		test.Fatal("service write ignored namespace read failure")
	}
}

func TestDNSNameConcurrentSQLiteWriters(test *testing.T) {
	path := filepath.Join(test.TempDir(), "state.db")
	first, second := openTestSQLite(test, path), openTestSQLite(test, path)
	for _, store := range []*SQLiteStore{first, second} {
		if err := store.ConfigureDNSDomain(test.Context(), "xunara.test"); err != nil {
			test.Fatal(err)
		}
	}
	var workers sync.WaitGroup
	results := make(chan Node, 24)
	failures := make(chan error, 24)
	for index := 0; index < 24; index++ {
		store := []*SQLiteStore{first, second}[index%2]
		node := Node{MachineKey: key.NewMachine().Public(), NodeKey: key.NewNode().Public(), Hostname: "laptop"}
		workers.Go(func() {
			if err := store.CreateNode(&node); err != nil {
				failures <- err
				return
			}
			results <- node
		})
	}
	workers.Wait()
	close(results)
	close(failures)
	for err := range failures {
		test.Fatal(err)
	}
	names := make(map[string]bool)
	for node := range results {
		if names[node.DNSName] {
			test.Fatalf("duplicate concurrent name: %s", node.DNSName)
		}
		names[node.DNSName] = true
	}
	if len(names) != 24 || CheckDNSNamespace(test.Context(), path, "xunara.test") != nil {
		test.Fatal("concurrent namespace is incomplete or conflicting")
	}
}

func TestDNSNameConcurrentNodeAndRecord(test *testing.T) {
	for iteration := 0; iteration < 12; iteration++ {
		path := filepath.Join(test.TempDir(), "state.db")
		first, second := openTestSQLite(test, path), openTestSQLite(test, path)
		if err := first.ConfigureDNSDomain(test.Context(), "xunara.test"); err != nil {
			test.Fatal(err)
		}
		ready := make(chan struct{})
		result := make(chan error, 1)
		record := DNSRecord{Name: "laptop.xunara.test", Type: "A", Value: "100.64.0.90"}
		go func() {
			<-ready
			result <- second.UpsertDNSRecord(&record)
		}()
		close(ready)
		node := createDNSNode(test, first, "laptop")
		err := <-result
		if node.DNSName == "laptop" {
			if !errors.Is(err, ErrDNSDeviceName) {
				test.Fatalf("record raced past device ownership: %v", err)
			}
		} else if err != nil || record.ID == 0 {
			test.Fatalf("winning record or device alias was lost: %v %+v", err, node)
		}
		if err := CheckDNSNamespace(test.Context(), path, "xunara.test"); err != nil {
			test.Fatal(err)
		}
	}
}

func TestDNSNameConcurrentRenameAndService(test *testing.T) {
	for iteration := 0; iteration < 12; iteration++ {
		path := filepath.Join(test.TempDir(), "state.db")
		first, second := openTestSQLite(test, path), openTestSQLite(test, path)
		if err := first.ConfigureDNSDomain(test.Context(), "xunara.test"); err != nil {
			test.Fatal(err)
		}
		node := createDNSNode(test, first, "laptop")
		provider := createDNSNode(test, first, "provider")
		ready := make(chan struct{})
		result := make(chan error, 1)
		go func() {
			<-ready
			result <- second.ReplaceNodeServices(provider.ID, []Service{{Name: "files", Protocol: "tcp", Port: 445}})
		}()
		close(ready)
		node.Hostname = "files"
		if err := first.UpdateNodeWithDNS(&node); err != nil {
			test.Fatal(err)
		}
		err := <-result
		if node.DNSName == "files" {
			if !errors.Is(err, ErrServiceNameTaken) {
				test.Fatalf("service raced past renamed device: %v", err)
			}
		} else if err != nil {
			test.Fatalf("winning service or assigned alias lost: %v", err)
		}
		if err := CheckDNSNamespace(test.Context(), path, "xunara.test"); err != nil {
			test.Fatal(err)
		}
	}
}

func TestDNSNameBindingFailureRollsBackLegacyNames(test *testing.T) {
	path := filepath.Join(test.TempDir(), "state.db")
	legacyDNSDatabase(test, path, []string{"laptop", "phone"}, "")
	store := openTestSQLite(test, path)
	if _, err := store.DB().ExecContext(test.Context(), "CREATE TRIGGER reject_binding BEFORE INSERT ON dns_namespace BEGIN SELECT RAISE(ABORT, 'injected failure'); END"); err != nil {
		test.Fatal(err)
	}
	if err := store.ConfigureDNSDomain(test.Context(), "xunara.test"); err == nil {
		test.Fatal("failed binding reported success")
	}
	var count int
	if err := store.DB().QueryRowContext(test.Context(), "SELECT count(*) FROM nodes WHERE dns_name != ''").Scan(&count); err != nil || count != 0 {
		test.Fatal("failed binding partially backfilled assigned labels")
	}
	if _, err := store.DB().ExecContext(test.Context(), "DROP TRIGGER reject_binding"); err != nil {
		test.Fatal(err)
	}
	if err := store.ConfigureDNSDomain(test.Context(), "xunara.test"); err != nil {
		test.Fatal(err)
	}
}

func TestDNSNameInvalidOrCancelledDomain(test *testing.T) {
	for name, factory := range dnsNameStoreFactories() {
		test.Run(name, func(test *testing.T) {
			store := factory(test)
			for _, domain := range []string{"https://xunara.test", "bad..test", "_invalid.test", strings.Repeat("a", 64) + ".test"} {
				if err := store.ConfigureDNSDomain(test.Context(), domain); err == nil {
					test.Fatalf("invalid domain accepted: %s", domain)
				}
			}
			ctx, cancel := context.WithCancel(test.Context())
			cancel()
			if err := store.ConfigureDNSDomain(ctx, "xunara.test"); !errors.Is(err, context.Canceled) {
				test.Fatalf("cancelled binding succeeded: %v", err)
			}
			if err := store.ConfigureDNSDomain(test.Context(), "xunara.test"); err != nil {
				test.Fatal("invalid/cancelled request changed binding")
			}
		})
	}
}
