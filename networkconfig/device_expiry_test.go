package networkconfig

import (
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/xunara-net/xunara-server/identity"
	"github.com/xunara-net/xunara-server/state"
)

func TestDeviceExpirySettingsPersistOnlyExpiry(test *testing.T) {
	core, _, configuration, writer := configurationFixture(test)
	original := routeFixtureNode(test, core, writer)
	seconds := int64(7 * 86400)
	before := time.Now().UTC()
	node, err := configuration.UpdateNodeExpiry(test.Context(), original.StableID, state.DeviceExpiryUpdate{
		Revision: state.NodeExpiryRevision(original), Mode: state.DeviceExpirySchedule, DurationSeconds: &seconds,
	}, writer)
	if err != nil || node.Expiry.Before(before.Add(7*24*time.Hour)) || node.Expiry.After(time.Now().Add(7*24*time.Hour)) {
		test.Fatalf("server relative expiry: %v %v", node.Expiry, err)
	}
	expected := original
	expected.Expiry = node.Expiry
	if !reflect.DeepEqual(node, expected) {
		test.Fatal("expiry overwrote other node facts")
	}
	other := secondEnrollmentConnection(test, core)
	readback, err := other.RouteNode(test.Context(), node.StableID)
	if err != nil || !reflect.DeepEqual(node, readback) {
		test.Fatal("second instance did not read durable expiry")
	}
	beforeAudit := countRows(test, core.DB(), "audit_events")
	update := state.DeviceExpiryUpdate{Revision: state.NodeExpiryRevision(node), Mode: state.DeviceExpirySchedule, ExpiresAt: &node.Expiry}
	if _, err := other.UpdateNodeExpiry(test.Context(), node.StableID, update, writer); err != nil || core.ConfigRevision() != 1 || countRows(test, core.DB(), "audit_events") != beforeAudit {
		test.Fatal("unchanged exact time added mutation")
	}
	node, err = other.UpdateNodeExpiry(test.Context(), node.StableID, state.DeviceExpiryUpdate{Revision: update.Revision, Mode: state.DeviceExpiryDisable}, writer)
	if err != nil || !node.Expiry.IsZero() {
		test.Fatalf("disable: %v", err)
	}
	var nullExpiry bool
	if err := core.DB().QueryRowContext(test.Context(), "SELECT expiry IS NULL FROM nodes WHERE id = ?", original.ID).Scan(&nullExpiry); err != nil || !nullExpiry {
		test.Fatal("disabled expiry was not stored as SQL NULL")
	}
	readback, err = configuration.RouteNode(test.Context(), node.StableID)
	if err != nil || !readback.Expiry.IsZero() || readback.NodeKey != original.NodeKey || core.ConfigRevision() != 2 {
		test.Fatal("disabled expiry did not survive reload")
	}
}

func TestDeviceExpiryExpiredRecoveryAndPassageOfTime(test *testing.T) {
	core, _, configuration, writer := configurationFixture(test)
	node := routeFixtureNode(test, core, writer)
	if _, err := configuration.UpdateNodeExpiry(test.Context(), node.StableID, state.DeviceExpiryUpdate{Revision: state.NodeExpiryRevision(node), Mode: state.DeviceExpiryExtend}, writer); !errors.Is(err, state.ErrDeviceNotExpired) {
		test.Fatal("active device was temporarily extended")
	}
	// 数据未改变也会自然到期，不能只凭未改变的 revision 放行永久恢复。
	node.Expiry = time.Now().Add(-time.Second)
	if err := core.UpdateNode(node); err != nil {
		test.Fatal(err)
	}
	seconds := int64(86400)
	for _, update := range []state.DeviceExpiryUpdate{
		{Mode: state.DeviceExpiryDisable}, {Mode: state.DeviceExpirySchedule, DurationSeconds: &seconds},
	} {
		update.Revision = state.NodeExpiryRevision(node)
		if _, err := configuration.UpdateNodeExpiry(test.Context(), node.StableID, update, writer); !errors.Is(err, state.ErrDeviceExpired) {
			test.Fatalf("expired device bypassed explicit recovery: %v", err)
		}
	}
	before := time.Now()
	updated, err := configuration.UpdateNodeExpiry(test.Context(), node.StableID, state.DeviceExpiryUpdate{Revision: state.NodeExpiryRevision(node), Mode: state.DeviceExpiryExtend}, writer)
	if err != nil || updated.Expiry.Before(before.Add(30*time.Minute)) || updated.Expiry.After(time.Now().Add(30*time.Minute)) {
		test.Fatalf("temporary extension: %v", err)
	}
	if _, err := configuration.ShortenNodeExpiry(test.Context(), node, updated.Expiry.Add(time.Hour)); !errors.Is(err, state.ErrExpiryNotEarlier) {
		test.Fatal("machine extended administrator window")
	}
	if _, err := configuration.UpdateNodeExpiry(test.Context(), node.StableID, state.DeviceExpiryUpdate{Revision: state.NodeExpiryRevision(updated), Mode: state.DeviceExpiryExtend}, writer); !errors.Is(err, state.ErrDeviceNotExpired) {
		test.Fatal("repeated extension accepted")
	}
	updated, err = configuration.UpdateNodeExpiry(test.Context(), node.StableID, state.DeviceExpiryUpdate{Revision: state.NodeExpiryRevision(updated), Mode: state.DeviceExpiryDisable}, writer)
	if err != nil || !updated.Expiry.IsZero() {
		test.Fatal("administrator could not disable within recovery window")
	}
}

func TestDeviceExpirySettingsMandatoryWritesAndRevocation(test *testing.T) {
	for _, mode := range []string{state.DeviceExpirySchedule, state.DeviceExpiryDisable, state.DeviceExpiryExtend} {
		for _, failure := range []string{"RAISE(ABORT, 'fixture')", "RAISE(IGNORE)", "node-ignore", "counter-ignore", "revoked-session", "demoted-user"} {
			test.Run(mode+failure, func(test *testing.T) {
				core, _, configuration, writer := configurationFixture(test)
				node := routeFixtureNode(test, core, writer)
				node.Expiry = time.Now().Add(time.Hour)
				if mode == state.DeviceExpiryExtend {
					node.Expiry = time.Now().Add(-time.Hour)
				}
				if err := core.UpdateNode(node); err != nil {
					test.Fatal(err)
				}
				node, _ = core.GetNodeByID(node.ID)
				sql := ""
				switch failure {
				case "node-ignore":
					sql = "CREATE TRIGGER reject_expiry BEFORE UPDATE OF expiry ON nodes BEGIN SELECT RAISE(IGNORE); END"
				case "counter-ignore":
					sql = "CREATE TRIGGER reject_counter BEFORE INSERT ON counters WHEN NEW.name = 'config_revision' BEGIN SELECT RAISE(IGNORE); END"
				case "revoked-session":
					sql = "UPDATE sessions SET revoked_at = 1"
				case "demoted-user":
					sql = "UPDATE users SET role = 'member'"
				default:
					action := map[string]string{state.DeviceExpirySchedule: identity.AuditNodeExpiryUpdated, state.DeviceExpiryDisable: identity.AuditNodeExpiryDisabled, state.DeviceExpiryExtend: identity.AuditNodeExpiryExtended}[mode]
					sql = "CREATE TRIGGER reject_expiry_audit BEFORE INSERT ON audit_events WHEN NEW.action = '" + action + "' BEGIN SELECT " + failure + "; END"
				}
				if _, err := core.DB().ExecContext(test.Context(), sql); err != nil {
					test.Fatal(err)
				}
				before := countRows(test, core.DB(), "audit_events")
				seconds := int64(86400)
				update := state.DeviceExpiryUpdate{Revision: state.NodeExpiryRevision(node), Mode: mode}
				if mode == state.DeviceExpirySchedule {
					update.DurationSeconds = &seconds
				}
				if _, err := configuration.UpdateNodeExpiry(test.Context(), node.StableID, update, writer); err == nil {
					test.Fatal("required check/write ignored")
				}
				stored, _ := core.GetNodeByID(node.ID)
				if !reflect.DeepEqual(stored, node) || core.ConfigRevision() != 0 || countRows(test, core.DB(), "audit_events") != before {
					test.Fatal("expiry failure left partial changes")
				}
			})
		}
	}
}

func TestDeviceExpirySettingsAcrossConnectionsCAS(test *testing.T) {
	core, _, first, writer := configurationFixture(test)
	node := routeFixtureNode(test, core, writer)
	second := secondEnrollmentConnection(test, core)
	start, results := make(chan struct{}), make(chan error, 2)
	var workers sync.WaitGroup
	for _, configuration := range []*SQLiteStore{first, second} {
		workers.Add(1)
		go func(configuration *SQLiteStore) {
			defer workers.Done()
			<-start
			seconds := int64(86400)
			_, err := configuration.UpdateNodeExpiry(test.Context(), node.StableID, state.DeviceExpiryUpdate{Revision: state.NodeExpiryRevision(node), Mode: state.DeviceExpirySchedule, DurationSeconds: &seconds}, writer)
			results <- err
		}(configuration)
	}
	close(start)
	workers.Wait()
	close(results)
	success, conflict := 0, 0
	for err := range results {
		if err == nil {
			success++
		} else if errors.Is(err, state.ErrDeviceChanged) {
			conflict++
		} else {
			test.Fatal(err)
		}
	}
	if success != 1 || conflict != 1 || core.ConfigRevision() != 1 || countRows(test, core.DB(), "audit_events") != 1 {
		test.Fatal("cross-instance expiry bypassed CAS")
	}
}
