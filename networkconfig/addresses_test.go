package networkconfig

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"testing"

	"tailscale.com/types/key"

	"github.com/xunara-net/xunara-server/identity"
	"github.com/xunara-net/xunara-server/state"
)

func TestAddressChangesRollbackWithAuditAndPermission(t *testing.T) {
	core, identities, store, writer := configurationFixture(t)
	node := state.Node{NodeKey: key.NewNode().Public(), MachineKey: key.NewMachine().Public()}
	if err := core.CreateNode(&node); err != nil {
		t.Fatal(err)
	}
	if _, err := core.DB().ExecContext(t.Context(), "CREATE TRIGGER reject_address_audit BEFORE INSERT ON audit_events BEGIN SELECT RAISE(ABORT,'injected'); END"); err != nil {
		t.Fatal(err)
	}
	next := netip.MustParseAddr("100.64.0.20")
	beforeRevision := core.ConfigRevision()
	if _, err := store.SaveNodeIPv4(t.Context(), node.ID, node.StableID, node.IPv4, next, writer); err == nil {
		t.Fatal("audit failure reported success")
	}
	if actual, _ := core.GetNodeByID(node.ID); actual.IPv4 != node.IPv4 || core.ConfigRevision() != beforeRevision {
		t.Fatal("failed transaction changed address or notification")
	}
	if _, err := store.SaveAllocation(t.Context(), &writer, func(ctx context.Context, current state.AddressConfiguration) (AllocationUpdate, error) {
		current.IPv4 = netip.MustParsePrefix("100.101.50.0/24")
		current.SourceRevision++
		return AllocationUpdate{current, writer.Actor()}, nil
	}); err == nil {
		t.Fatal("prefix audit failure reported success")
	}
	if actual, err := core.AddressConfiguration(t.Context()); err != nil || actual.IPv4.String() != "100.64.0.0/10" || actual.SourceRevision != 0 {
		t.Fatal("prefix failure was not atomic")
	}
	if _, err := core.DB().ExecContext(t.Context(), "DROP TRIGGER reject_address_audit"); err != nil {
		t.Fatal(err)
	}
	user, found := identities.GetUser(writer.UserID)
	if !found {
		t.Fatal("missing writer")
	}
	user.Role = identity.RoleMember
	if err := identities.UpdateUser(user); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SaveNodeIPv4(t.Context(), node.ID, node.StableID, node.IPv4, next, writer); !errors.Is(err, identity.ErrNetworkWriterForbidden) {
		t.Fatalf("revoked role bypass: %v", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := store.SaveNodeIPv4(ctx, node.ID, node.StableID, node.IPv4, next, writer); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled write: %v", err)
	}
}

func TestAddressClaimCASAcrossDatabaseConnections(t *testing.T) {
	core, _, store, writer := configurationFixture(t)
	var filename string
	if err := core.DB().QueryRowContext(t.Context(), "SELECT file FROM pragma_database_list WHERE name='main'").Scan(&filename); err != nil {
		t.Fatal(err)
	}
	second, err := state.OpenSQLite(t.Context(), filename)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { second.Close() })
	nodes := make([]state.Node, 2)
	for index := range nodes {
		nodes[index] = state.Node{NodeKey: key.NewNode().Public(), MachineKey: key.NewMachine().Public()}
		if err := core.CreateNode(&nodes[index]); err != nil {
			t.Fatal(err)
		}
	}
	connections := []*SQLiteStore{store, NewSQLiteStore(second.DB())}
	start := make(chan struct{})
	results := make(chan error, 2)
	var workers sync.WaitGroup
	for index, connection := range connections {
		workers.Go(func() {
			<-start
			node := nodes[index]
			_, err := connection.SaveNodeIPv4(t.Context(), node.ID, node.StableID, node.IPv4, netip.MustParseAddr("100.64.0.20"), writer)
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
		} else if errors.Is(err, state.ErrAddressInUse) {
			conflicts++
		} else {
			t.Fatal(err)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("duplicate claims: successes=%d conflicts=%d", successes, conflicts)
	}
}
