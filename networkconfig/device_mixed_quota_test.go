package networkconfig

import (
	"errors"
	"sync"
	"testing"

	"github.com/xunara-net/xunara-server/state"
)

func TestDeviceQuotaSerializesApprovalAndTokenAcrossConnections(test *testing.T) {
	core, _, authorizationStore, writer := configurationFixture(test)
	authorization := enrollmentFixtureKey(test, core, writer, true)
	var filename string
	if err := core.DB().QueryRowContext(test.Context(), "SELECT file FROM pragma_database_list WHERE name = 'main'").Scan(&filename); err != nil {
		test.Fatal(err)
	}
	approvalStore, err := state.OpenSQLite(test.Context(), filename)
	if err != nil {
		test.Fatal(err)
	}
	defer approvalStore.Close()
	start := make(chan struct{})
	results := make(chan error, 8)
	var workers sync.WaitGroup
	for index := range 8 {
		workers.Go(func() {
			<-start
			want := enrollmentFixtureNode()
			var err error
			if index%2 == 0 {
				err = approvalStore.CreateNodeLimited(test.Context(), &want, 1)
			} else {
				_, err = authorizationStore.EnrollAuthKey(test.Context(), authorization.Key, want, 1, nil)
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
		} else if !errors.Is(err, state.ErrDeviceLimit) {
			test.Fatal(err)
		}
	}
	if success != 1 || countRows(test, core.DB(), "nodes") != 1 {
		test.Fatal("mixed enrollment paths exceeded device quota")
	}
}
