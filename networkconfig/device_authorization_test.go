package networkconfig

import (
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/xunara-net/xunara-server/identity"
	"github.com/xunara-net/xunara-server/state"
	"tailscale.com/types/key"
)

func enrollmentFixtureKey(test *testing.T, core *state.SQLiteStore, writer Writer, reusable bool) state.PreAuthKey {
	test.Helper()
	secret, err := state.NewPreAuthKeySecret()
	if err != nil {
		test.Fatal(err)
	}
	authorization := state.PreAuthKey{Key: secret, UserID: writer.UserID, Reusable: reusable, Expiry: time.Now().Add(time.Hour)}
	if err := core.CreatePreAuthKey(&authorization); err != nil {
		test.Fatal(err)
	}
	return authorization
}

func enrollmentFixtureNode() state.Node {
	return state.Node{MachineKey: key.NewMachine().Public(), NodeKey: key.NewNode().Public(), Hostname: "enrollment-fixture"}
}

func secondEnrollmentConnection(test *testing.T, core *state.SQLiteStore) *SQLiteStore {
	test.Helper()
	var filename string
	if err := core.DB().QueryRowContext(test.Context(), "SELECT file FROM pragma_database_list WHERE name = 'main'").Scan(&filename); err != nil {
		test.Fatal(err)
	}
	other, err := state.OpenSQLite(test.Context(), filename)
	if err != nil {
		test.Fatal(err)
	}
	test.Cleanup(func() { other.Close() })
	return NewSQLiteStore(other.DB())
}

func TestDeviceExpiryPreservesFactsCASAndIdempotency(test *testing.T) {
	core, _, configuration, writer := configurationFixture(test)
	original := routeFixtureNode(test, core, writer)
	original.ApprovedRoutes = original.AnnouncedRoutes()
	if err := core.UpdateNode(original); err != nil {
		test.Fatal(err)
	}
	original, _ = core.GetNodeByID(original.ID)
	revision := state.NodeExpiryRevision(original)
	original.Hostname = "activity-does-not-conflict"
	if err := core.UpdateNode(original); err != nil {
		test.Fatal(err)
	}
	original, _ = core.GetNodeByID(original.ID)
	updated, err := configuration.ExpireNode(test.Context(), original.StableID, revision, writer)
	if err != nil || !updated.Expired(time.Now()) {
		test.Fatalf("expire: %v", err)
	}
	expected := original
	expected.Expiry = updated.Expiry
	if !reflect.DeepEqual(updated, expected) {
		test.Fatal("expiry changed unrelated device facts")
	}
	if core.ConfigRevision() != 1 {
		test.Fatal("expiry notification not durable")
	}
	if _, err := configuration.ExpireNode(test.Context(), original.StableID, revision, writer); !errors.Is(err, state.ErrDeviceChanged) {
		test.Fatal("stale expiry confirmation accepted")
	}
	before := countRows(test, core.DB(), "audit_events")
	if _, err := configuration.ExpireNode(test.Context(), original.StableID, state.NodeExpiryRevision(updated), writer); err != nil {
		test.Fatal(err)
	}
	if core.ConfigRevision() != 1 || countRows(test, core.DB(), "audit_events") != before {
		test.Fatal("already expired device added duplicate mutation")
	}
}

func TestDeviceExpiryCannotBeUndoneByStaleClientFacts(test *testing.T) {
	core, _, configuration, writer := configurationFixture(test)
	original := routeFixtureNode(test, core, writer)
	original.Expiry = time.Now().Add(24 * time.Hour)
	if err := core.UpdateNode(original); err != nil {
		test.Fatal(err)
	}
	expired, err := configuration.ExpireNode(test.Context(), original.StableID, state.NodeExpiryRevision(original), writer)
	if err != nil {
		test.Fatal(err)
	}
	if _, err := configuration.ShortenNodeExpiry(test.Context(), original, time.Now().Add(time.Hour)); !errors.Is(err, state.ErrExpiryNotEarlier) {
		test.Fatal("stale client expiry restored expired device")
	}
	updated, changed, err := configuration.RegistrationKeys(test.Context(), original.MachineKey, original.NodeKey, key.NewNLPrivate().Public(), nil)
	if err != nil || !changed || !updated.Expiry.Equal(expired.Expiry) {
		test.Fatal("registration public key update changed expiry")
	}
	if _, _, err := configuration.RegistrationKeys(test.Context(), key.NewMachine().Public(), original.NodeKey, key.NewNLPrivate().Public(), nil); !errors.Is(err, state.ErrDeviceChanged) {
		test.Fatal("public key confused machine identities")
	}
}

func TestDeviceAuthorizationMandatoryWritesRollback(test *testing.T) {
	for _, operation := range []string{"expire", "create", "enroll", "rotate", "revoke"} {
		for _, failure := range []string{"RAISE(ABORT, 'fixture')", "RAISE(IGNORE)"} {
			test.Run(operation+failure, func(test *testing.T) {
				core, _, configuration, writer := configurationFixture(test)
				authorization := enrollmentFixtureKey(test, core, writer, false)
				node := routeFixtureNode(test, core, writer)
				action := map[string]string{"expire": identity.AuditNodeExpired, "create": identity.AuditPreAuthKeyCreated,
					"enroll": identity.AuditNodeRegistered, "rotate": identity.AuditNodeKeyRotated, "revoke": identity.AuditPreAuthKeyDeleted}[operation]
				if _, err := core.DB().ExecContext(test.Context(), "CREATE TRIGGER reject_device_audit BEFORE INSERT ON audit_events WHEN NEW.action = '"+action+"' BEGIN SELECT "+failure+"; END"); err != nil {
					test.Fatal(err)
				}
				before := countRows(test, core.DB(), "audit_events")
				var err error
				switch operation {
				case "expire":
					_, err = configuration.ExpireNode(test.Context(), node.StableID, state.NodeExpiryRevision(node), writer)
				case "create":
					candidate := authorization
					candidate.Key += "-new"
					_, err = configuration.CreateAuthKey(test.Context(), candidate, 10, writer)
				case "revoke":
					err = configuration.DeleteAuthKey(test.Context(), authorization.ID, writer)
				default:
					want := enrollmentFixtureNode()
					if operation == "rotate" {
						want.MachineKey = node.MachineKey
					}
					_, err = configuration.EnrollAuthKey(test.Context(), authorization.Key, want, 10, nil)
				}
				if err == nil {
					test.Fatal("required audit failure accepted")
				}
				stored, _ := core.GetNodeByID(node.ID)
				storedKey, found := core.GetPreAuthKey(authorization.Key)
				if !reflect.DeepEqual(stored, node) || !found || storedKey.Used || countRows(test, core.DB(), "nodes") != 1 ||
					countRows(test, core.DB(), "preauthkeys") != 1 || countRows(test, core.DB(), "audit_events") != before || core.ConfigRevision() != 0 {
					test.Fatal("failed authorization left partial state")
				}
			})
		}
	}
}

func TestEnrollmentRequiredConsumptionAndCounterRollback(test *testing.T) {
	for _, trigger := range []string{
		"CREATE TRIGGER reject_use BEFORE UPDATE ON preauthkeys BEGIN SELECT RAISE(IGNORE); END",
		"CREATE TRIGGER reject_notify BEFORE INSERT ON counters WHEN NEW.name = 'config_revision' BEGIN SELECT RAISE(IGNORE); END",
		"CREATE TRIGGER reject_node BEFORE INSERT ON nodes BEGIN SELECT RAISE(IGNORE); END",
	} {
		core, _, configuration, writer := configurationFixture(test)
		authorization := enrollmentFixtureKey(test, core, writer, false)
		if _, err := core.DB().ExecContext(test.Context(), trigger); err != nil {
			test.Fatal(err)
		}
		if _, err := configuration.EnrollAuthKey(test.Context(), authorization.Key, enrollmentFixtureNode(), 10, nil); err == nil {
			test.Fatal("ignored required write accepted")
		}
		stored, _ := core.GetPreAuthKey(authorization.Key)
		if stored.Used || countRows(test, core.DB(), "nodes") != 0 || countRows(test, core.DB(), "audit_events") != 0 {
			test.Fatal("failure burned credential or left device/audit")
		}
	}
}

func TestEnrollmentAcrossConnectionsSingleUseAndDeviceLimit(test *testing.T) {
	for _, reusable := range []bool{false, true} {
		test.Run(map[bool]string{false: "single-use", true: "device-quota"}[reusable], func(test *testing.T) {
			core, _, first, writer := configurationFixture(test)
			authorization := enrollmentFixtureKey(test, core, writer, reusable)
			second := secondEnrollmentConnection(test, core)
			start := make(chan struct{})
			results := make(chan error, 8)
			var workers sync.WaitGroup
			for index := range 8 {
				configuration := []*SQLiteStore{first, second}[index%2]
				workers.Go(func() {
					<-start
					_, err := configuration.EnrollAuthKey(test.Context(), authorization.Key, enrollmentFixtureNode(), 1, nil)
					results <- err
				})
			}
			close(start)
			workers.Wait()
			close(results)
			success := 0
			for err := range results {
				if err == nil {
					success++
				} else if !errors.Is(err, state.ErrDeviceLimit) && !errors.Is(err, state.ErrPreAuthKeyNotUsable) {
					test.Fatal(err)
				}
			}
			if success != 1 || countRows(test, core.DB(), "nodes") != 1 {
				test.Fatal("concurrent enrollment bypassed one-use/quota")
			}
		})
	}
}

func TestAuthKeyIssuanceAcrossConnectionsQuotaAndPersistedAuthority(test *testing.T) {
	core, _, first, writer := configurationFixture(test)
	second := secondEnrollmentConnection(test, core)
	results := make(chan error, 2)
	start := make(chan struct{})
	var workers sync.WaitGroup
	for _, configuration := range []*SQLiteStore{first, second} {
		workers.Go(func() {
			<-start
			secret, err := state.NewPreAuthKeySecret()
			if err == nil {
				_, err = configuration.CreateAuthKey(test.Context(), state.PreAuthKey{Key: secret, UserID: writer.UserID}, 1, writer)
			}
			results <- err
		})
	}
	close(start)
	workers.Wait()
	close(results)
	success := 0
	for err := range results {
		if err == nil {
			success++
		} else if !errors.Is(err, state.ErrAuthKeyLimit) {
			test.Fatal(err)
		}
	}
	if success != 1 {
		test.Fatal("parallel issuance bypassed key quota")
	}
	for _, mutation := range []string{"UPDATE users SET role = 'member'", "UPDATE sessions SET revoked_at = 1"} {
		if _, err := core.DB().ExecContext(test.Context(), mutation); err != nil {
			test.Fatal(err)
		}
		if _, err := first.CreateAuthKey(test.Context(), state.PreAuthKey{Key: "uncommitted", UserID: writer.UserID}, -1, writer); err == nil {
			test.Fatal("stale writer accepted")
		}
	}
}

func TestEnrollmentRotationAtQuotaKeepsIdentityAndTags(test *testing.T) {
	core, _, configuration, writer := configurationFixture(test)
	authorization := enrollmentFixtureKey(test, core, writer, false)
	original := routeFixtureNode(test, core, writer)
	original.Tags = []string{"tag:server"}
	original.Expiry = time.Now().Add(-time.Hour)
	if err := core.UpdateNode(original); err != nil {
		test.Fatal(err)
	}
	original, _ = core.GetNodeByID(original.ID)
	want := enrollmentFixtureNode()
	want.MachineKey = original.MachineKey
	updated, err := configuration.EnrollAuthKey(test.Context(), authorization.Key, want, 1, nil)
	if err != nil {
		test.Fatal(err)
	}
	if updated.ID != original.ID || updated.StableID != original.StableID || updated.IPv4 != original.IPv4 || updated.IPv6 != original.IPv6 ||
		!reflect.DeepEqual(updated.Tags, original.Tags) || updated.UserID != original.UserID || updated.NodeKey != want.NodeKey || updated.Expired(time.Now()) {
		test.Fatal("reauthorization changed stable identity, tags or allocation")
	}
}
