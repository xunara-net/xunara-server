package networkconfig

import (
	"errors"
	"sync"
	"testing"

	"github.com/xunara-net/xunara-server/identity"
	"github.com/xunara-net/xunara-server/state"
)

func interactiveFixture(test *testing.T, identities *identity.SQLiteStore, writer Writer) (identity.DeviceAuthorization, DeviceDecision) {
	test.Helper()
	node := enrollmentFixtureNode()
	node.UserID = writer.UserID
	node.Method = state.RegisterMethodInteractive
	authorization, err := identities.CreateDeviceAuthorization(identity.NewDeviceAuthorizationOptions{
		MachineKey: node.MachineKey.String(), NodeKey: node.NodeKey.String(), RequestedAction: "register",
	})
	if err != nil {
		test.Fatal(err)
	}
	return authorization, DeviceDecision{UserID: writer.UserID, Actor: writer.Actor(), Writer: &writer, Node: node, Approve: true, DeviceLimit: 10}
}

func TestInteractiveDecisionMandatoryWritesRollback(test *testing.T) {
	for name, fault := range map[string]string{
		"decision":         `CREATE TRIGGER reject_decision BEFORE UPDATE ON device_authorizations BEGIN SELECT RAISE(ABORT, 'fixture'); END`,
		"ignored-decision": `CREATE TRIGGER reject_decision BEFORE UPDATE ON device_authorizations BEGIN SELECT RAISE(IGNORE); END`,
		"audit":            `CREATE TRIGGER reject_decision BEFORE INSERT ON audit_events WHEN NEW.action = 'node.approved' BEGIN SELECT RAISE(ABORT, 'fixture'); END`,
		"ignored-audit":    `CREATE TRIGGER reject_decision BEFORE INSERT ON audit_events WHEN NEW.action = 'node.approved' BEGIN SELECT RAISE(IGNORE); END`,
		"notification":     `CREATE TRIGGER reject_decision BEFORE INSERT ON counters WHEN NEW.name = 'config_revision' BEGIN SELECT RAISE(ABORT, 'fixture'); END`,
	} {
		test.Run(name, func(test *testing.T) {
			core, identities, configuration, writer := configurationFixture(test)
			authorization, decision := interactiveFixture(test, identities, writer)
			if _, err := core.DB().Exec(fault); err != nil {
				test.Fatal(err)
			}
			if _, _, err := configuration.DecideDevice(test.Context(), authorization, decision); err == nil {
				test.Fatal("required failure accepted")
			}
			current, err := identities.LookupDeviceAuthorization(test.Context(), authorization.ID)
			if err != nil || current.State != identity.DevicePending || len(core.ListNodes()) != 0 || core.ConfigRevision() != 0 {
				test.Fatal("partial authorization persisted")
			}
			if _, err := core.DB().Exec("DROP TRIGGER reject_decision"); err != nil {
				test.Fatal(err)
			}
			if _, _, err := configuration.DecideDevice(test.Context(), authorization, decision); err != nil {
				test.Fatal(err)
			}
			if _, _, err := configuration.DecideDevice(test.Context(), authorization, decision); err != nil {
				test.Fatal(err)
			}
			if len(core.ListNodes()) != 1 || core.ConfigRevision() != 1 {
				test.Fatal("retry duplicated node or audit")
			}
		})
	}
}

func TestInteractiveDecisionAcrossConnectionsApproveVersusDeny(test *testing.T) {
	core, identities, first, writer := configurationFixture(test)
	second := secondEnrollmentConnection(test, core)
	authorization, approval := interactiveFixture(test, identities, writer)
	denial := approval
	denial.Approve = false
	start := make(chan struct{})
	results := make(chan error, 2)
	var workers sync.WaitGroup
	workers.Go(func() {
		<-start
		_, _, err := first.DecideDevice(test.Context(), authorization, approval)
		results <- err
	})
	workers.Go(func() {
		<-start
		_, _, err := second.DecideDevice(test.Context(), authorization, denial)
		results <- err
	})
	close(start)
	workers.Wait()
	close(results)
	successes := 0
	for err := range results {
		if err == nil {
			successes++
		} else if !errors.Is(err, identity.ErrDeviceDecided) {
			test.Fatal(err)
		}
	}
	current, err := identities.LookupDeviceAuthorization(test.Context(), authorization.ID)
	if err != nil || successes != 1 || core.ConfigRevision() != 1 {
		test.Fatal("decisions did not serialize")
	}
	if current.State == identity.DeviceDenied && len(core.ListNodes()) != 0 || current.State == identity.DeviceApproved && len(core.ListNodes()) != 1 {
		test.Fatal("decision and node disagree")
	}
}

func TestInteractiveDecisionRevokedActorCannotApprove(test *testing.T) {
	core, identities, configuration, writer := configurationFixture(test)
	authorization, decision := interactiveFixture(test, identities, writer)
	if err := identities.RevokeSession(writer.SessionID, "fixture"); err != nil {
		test.Fatal(err)
	}
	if _, _, err := configuration.DecideDevice(test.Context(), authorization, decision); err == nil {
		test.Fatal("revoked actor approved")
	}
	if len(core.ListNodes()) != 0 {
		test.Fatal("revoked actor left node")
	}
}
