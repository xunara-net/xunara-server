package state

import (
	"errors"
	"net/netip"
	"path/filepath"
	"sync"
	"testing"

	"tailscale.com/types/key"
)

func TestAddressConfigurationSurvivesRestartAndSerializesAllocation(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "state.db")
	first := openTestSQLite(t, filename)
	second := openTestSQLite(t, filename)
	old := addNode(t, first)
	prefix := netip.MustParsePrefix("100.101.50.0/24")
	if err := first.SetAddressPrefixes(prefix, netip.Prefix{}); err != nil {
		t.Fatal(err)
	}
	newNode := addNode(t, second)
	if !prefix.Contains(newNode.IPv4) || newNode.IPv4 == old.IPv4 {
		t.Fatal("second connection used a stale allocation cache")
	}
	first.Close()
	second.Close()
	reopened := openTestSQLite(t, filename)
	configuration, err := reopened.AddressConfiguration(t.Context())
	if err != nil || configuration.IPv4 != prefix {
		t.Fatalf("restart: %+v %v", configuration, err)
	}
	if actual, found := reopened.GetNodeByID(old.ID); !found || actual.IPv4 != old.IPv4 {
		t.Fatal("prefix change silently renumbered an existing device")
	}
}

func TestSingleHostPoolAllocationSerializesAcrossConnections(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	first := openTestSQLite(t, path)
	second := openTestSQLite(t, path)
	if err := first.SetAddressPrefixes(netip.MustParsePrefix("192.168.50.20/32"), netip.Prefix{}); err != nil {
		t.Fatal(err)
	}
	type result struct {
		node Node
		err  error
	}
	results := make(chan result, 2)
	start := make(chan struct{})
	var workers sync.WaitGroup
	for _, store := range []*SQLiteStore{first, second} {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			node := Node{NodeKey: key.NewNode().Public(), MachineKey: key.NewMachine().Public()}
			err := store.CreateNode(&node)
			results <- result{node: node, err: err}
		}()
	}
	close(start)
	workers.Wait()
	close(results)
	succeeded := 0
	for result := range results {
		if result.err == nil {
			succeeded++
			if result.node.IPv4.String() != "192.168.50.20" {
				t.Fatalf("single host allocated outside range: %s", result.node.IPv4)
			}
		}
	}
	if succeeded != 1 {
		t.Fatalf("successful single-host allocations = %d, want 1", succeeded)
	}
}

func TestDeviceIPv4CASAndStaleHeartbeat(t *testing.T) {
	store := openTestSQLite(t, filepath.Join(t.TempDir(), "state.db"))
	first := addNode(t, store)
	second := addNode(t, store)
	change := func(expected, next netip.Addr) error {
		transaction, err := store.DB().BeginTx(t.Context(), nil)
		if err != nil {
			return err
		}
		defer transaction.Rollback()
		if _, err := ChangeNodeIPv4Tx(t.Context(), transaction, first.ID, first.StableID, expected, next); err != nil {
			return err
		}
		return transaction.Commit()
	}
	if err := change(first.IPv4, second.IPv4); !errors.Is(err, ErrAddressInUse) {
		t.Fatalf("duplicate address: %v", err)
	}
	next := netip.MustParseAddr("100.64.0.20")
	if err := change(first.IPv4, next); err != nil {
		t.Fatal(err)
	}
	if err := change(first.IPv4, next); !errors.Is(err, ErrAddressConflict) {
		t.Fatalf("stale address: %v", err)
	}
	first.Hostname = "heartbeat-renamed"
	if err := store.UpdateNode(first); err != nil {
		t.Fatal(err)
	}
	actual, _ := store.GetNodeByID(first.ID)
	if actual.IPv4 != next || actual.Hostname != first.Hostname || actual.IPv6 != first.IPv6 || actual.NodeKey != first.NodeKey {
		t.Fatal("heartbeat restored the old IP or address update replaced other node facts")
	}
}

func TestAllocationRejectsStaleVersionsAndRollsBackCounter(t *testing.T) {
	store := openTestSQLite(t, filepath.Join(t.TempDir(), "state.db"))
	current, err := store.AddressConfiguration(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	apply := func(configuration AddressConfiguration) error {
		transaction, err := store.DB().BeginTx(t.Context(), nil)
		if err != nil {
			return err
		}
		defer transaction.Rollback()
		if _, err := ApplyAddressConfigurationTx(t.Context(), transaction, configuration); err != nil {
			return err
		}
		return transaction.Commit()
	}
	current.IPv4 = netip.MustParsePrefix("100.101.50.0/24")
	current.SourceRevision = 1
	if err := apply(current); err != nil {
		t.Fatal(err)
	}
	stale := current
	stale.IPv4 = netip.MustParsePrefix("100.101.51.0/24")
	if err := apply(stale); !errors.Is(err, ErrAddressConflict) {
		t.Fatalf("same version overwrite: %v", err)
	}
	stale.SourceRevision = 0
	if err := apply(stale); !errors.Is(err, ErrAddressConflict) {
		t.Fatalf("version rollback: %v", err)
	}
	if err := store.SetAddressPrefixes(stale.IPv4, netip.Prefix{}); !errors.Is(err, ErrAddressConflict) {
		t.Fatalf("legacy setter bypassed version: %v", err)
	}
}
