package state

import (
	"net/netip"
	"testing"
	"time"

	"tailscale.com/types/key"
)

func TestRecordNodeLastSeenDoesNotOverwriteNewerFacts(test *testing.T) {
	for _, backend := range []string{"sqlite", "memory"} {
		test.Run(backend, func(test *testing.T) {
			var store Store
			if backend == "sqlite" {
				database, err := OpenSQLite(test.Context(), test.TempDir()+"/state.db")
				if err != nil {
					test.Fatal(err)
				}
				defer database.Close()
				store = database
			} else {
				store = NewMemoryStore()
			}
			node := Node{MachineKey: key.NewMachine().Public(), NodeKey: key.NewNode().Public(), UserID: DefaultUserID, Hostname: "old"}
			if err := store.CreateNode(&node); err != nil {
				test.Fatal(err)
			}
			current := node
			current.Hostname = "current"
			current.ApprovedRoutes = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
			if err := store.UpdateNode(current); err != nil {
				test.Fatal(err)
			}
			seen := time.Now().UTC()
			if err := store.RecordNodeLastSeen(node, seen); err != nil {
				test.Fatal(err)
			}
			if err := store.RecordNodeLastSeen(node, seen.Add(-time.Hour)); err != nil {
				test.Fatal(err)
			}
			stored, _ := store.GetNodeByID(node.ID)
			if stored.Hostname != "current" || len(stored.ApprovedRoutes) != 1 || stored.LastSeen == nil || !stored.LastSeen.Equal(seen) {
				test.Fatal("disconnect restored stale node facts or moved activity backwards")
			}
			stored.NodeKey = key.NewNode().Public()
			if err := store.UpdateNode(stored); err != nil {
				test.Fatal(err)
			}
			if err := store.RecordNodeLastSeen(node, seen.Add(time.Hour)); err == nil {
				test.Fatal("old connection changed activity of rotated node identity")
			}
		})
	}
}
