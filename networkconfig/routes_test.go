package networkconfig

import (
	"errors"
	"net/netip"
	"reflect"
	"sync"
	"testing"

	"github.com/xunara-net/xunara-server/state"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

func routeFixtureNode(test *testing.T, core *state.SQLiteStore, writer Writer) state.Node {
	test.Helper()
	node := state.Node{UserID: writer.UserID, Hostname: "route-fixture", MachineKey: key.NewMachine().Public(), NodeKey: key.NewNode().Public(),
		Hostinfo: &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16"), netip.MustParsePrefix("192.168.50.0/24")}}}
	if err := core.CreateNode(&node); err != nil {
		test.Fatal(err)
	}
	return node
}

func TestRouteApprovalAtomicAuditAndConfigurationRevision(test *testing.T) {
	for _, failure := range []string{"RAISE(ABORT, 'fixture')", "RAISE(IGNORE)"} {
		test.Run(failure, func(test *testing.T) {
			core, _, configuration, writer := configurationFixture(test)
			node := routeFixtureNode(test, core, writer)
			route := node.AnnouncedRoutes()[0]
			if _, err := core.DB().ExecContext(test.Context(), "CREATE TRIGGER reject_route_audit BEFORE INSERT ON audit_events WHEN NEW.action = 'route.approved' BEGIN SELECT "+failure+"; END"); err != nil {
				test.Fatal(err)
			}
			_, err := configuration.SaveNodeRoutes(test.Context(), node.StableID, state.RouteApprovalUpdate{Revision: state.RouteApprovalRevision(node), Approve: []netip.Prefix{route}, RequireAnnounced: true}, writer, nil)
			if err == nil {
				test.Fatal("missing mandatory audit accepted")
			}
			stored, found := core.GetNodeByID(node.ID)
			if !found || !reflect.DeepEqual(stored.ApprovedRoutes, node.ApprovedRoutes) || core.ConfigRevision() != 0 {
				test.Fatal("failed audit left partial approval/revision")
			}
		})
	}
}

func TestRouteApprovalCounterFailureRollsBack(test *testing.T) {
	core, _, configuration, writer := configurationFixture(test)
	node := routeFixtureNode(test, core, writer)
	if err := core.BumpConfigRevision(); err != nil {
		test.Fatal(err)
	}
	before := countRows(test, core.DB(), "audit_events")
	if _, err := core.DB().ExecContext(test.Context(), "CREATE TRIGGER ignore_route_revision BEFORE UPDATE ON counters WHEN NEW.name = 'config_revision' AND NEW.value <> OLD.value BEGIN SELECT RAISE(IGNORE); END"); err != nil {
		test.Fatal(err)
	}
	_, err := configuration.SaveNodeRoutes(test.Context(), node.StableID, state.RouteApprovalUpdate{Approve: node.AnnouncedRoutes()}, writer, nil)
	if err == nil {
		test.Fatal("ignored configuration revision accepted")
	}
	stored, _ := core.GetNodeByID(node.ID)
	if len(stored.ApprovedRoutes) != 0 || core.ConfigRevision() != 1 || countRows(test, core.DB(), "audit_events") != before {
		test.Fatal("counter failure left partial state")
	}
}

func TestRouteApprovalAcrossConnectionsCASAndLegacyDeltas(test *testing.T) {
	core, _, first, writer := configurationFixture(test)
	node := routeFixtureNode(test, core, writer)
	var filename string
	if err := core.DB().QueryRowContext(test.Context(), "SELECT file FROM pragma_database_list WHERE name = 'main'").Scan(&filename); err != nil {
		test.Fatal(err)
	}
	other, err := state.OpenSQLite(test.Context(), filename)
	if err != nil {
		test.Fatal(err)
	}
	defer other.Close()
	second := NewSQLiteStore(other.DB())
	results := make(chan error, 2)
	start := make(chan struct{})
	var workers sync.WaitGroup
	for index, configuration := range []*SQLiteStore{first, second} {
		workers.Add(1)
		go func(configuration *SQLiteStore, route netip.Prefix) {
			defer workers.Done()
			<-start
			_, err := configuration.SaveNodeRoutes(test.Context(), node.StableID, state.RouteApprovalUpdate{Revision: state.RouteApprovalRevision(node), Approve: []netip.Prefix{route}, RequireAnnounced: true}, writer, nil)
			results <- err
		}(configuration, node.AnnouncedRoutes()[index])
	}
	close(start)
	workers.Wait()
	close(results)
	success, conflicts := 0, 0
	for err := range results {
		if err == nil {
			success++
		} else if errors.Is(err, state.ErrRouteConflict) {
			conflicts++
		} else {
			test.Fatal(err)
		}
	}
	if success != 1 || conflicts != 1 {
		test.Fatal("same version raced without one conflict")
	}
	for index, configuration := range []*SQLiteStore{first, second} {
		if _, err := configuration.SaveNodeRoutes(test.Context(), node.StableID, state.RouteApprovalUpdate{Approve: []netip.Prefix{node.AnnouncedRoutes()[index]}}, writer, nil); err != nil {
			test.Fatal(err)
		}
	}
	stored, _ := core.GetNodeByID(node.ID)
	if len(stored.ApprovedRoutes) != 2 {
		test.Fatal("legacy delta lost a concurrent approval")
	}
}

func TestRouteApprovalRechecksRevokedAndDemotedWriter(test *testing.T) {
	for _, mutation := range []string{"UPDATE sessions SET revoked_at = 1", "UPDATE users SET role = 'member'"} {
		core, _, configuration, writer := configurationFixture(test)
		node := routeFixtureNode(test, core, writer)
		if _, err := core.DB().ExecContext(test.Context(), mutation); err != nil {
			test.Fatal(err)
		}
		if _, err := configuration.SaveNodeRoutes(test.Context(), node.StableID, state.RouteApprovalUpdate{Approve: node.AnnouncedRoutes()}, writer, nil); err == nil {
			test.Fatal("stale administrator accepted")
		}
		stored, _ := core.GetNodeByID(node.ID)
		if len(stored.ApprovedRoutes) != 0 {
			test.Fatal("unauthorized mutation committed")
		}
	}
}
