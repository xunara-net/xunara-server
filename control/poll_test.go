package control

import (
	"testing"

	"tailscale.com/tailcfg"
	"tailscale.com/types/key"

	"github.com/xunara-net/xunara-server/state"
)

// seedTestNode creates a bare node in the server's store so recordMapRequest
// and the mapper can be exercised without a full registration flow.
func seedTestNode(t *testing.T, s *Server) state.Node {
	t.Helper()

	node := state.Node{
		MachineKey: key.NewMachine().Public(),
		NodeKey:    key.NewNode().Public(),
		Method:     state.RegisterMethodInteractive,
	}
	if err := s.store.CreateNode(&node); err != nil {
		t.Fatalf("seeding node: %v", err)
	}
	return node
}

func TestRecordMapRequestAdoptsPreferredDERP(t *testing.T) {
	s := newServerWithConfig(t, Config{DERPMap: &tailcfg.DERPMap{
		Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{1: {}, 2: {}},
	}})
	node := seedTestNode(t, s)

	// The client measures DERP latency and reports its favourite; the server
	// adopts it as the node's home region.
	node = s.recordMapRequest(node, tailcfg.MapRequest{
		Hostinfo: &tailcfg.Hostinfo{NetInfo: &tailcfg.NetInfo{PreferredDERP: 2}},
	})
	if node.HomeDERP != 2 {
		t.Fatalf("HomeDERP = %d, want 2 after the client's report", node.HomeDERP)
	}

	// A region this server does not advertise is untrusted input: ignore it.
	node = s.recordMapRequest(node, tailcfg.MapRequest{
		Hostinfo: &tailcfg.Hostinfo{NetInfo: &tailcfg.NetInfo{PreferredDERP: 99}},
	})
	if node.HomeDERP != 2 {
		t.Fatalf("HomeDERP = %d, want the previous 2 for an unknown region", node.HomeDERP)
	}

	// A routine update without NetInfo keeps the adopted home.
	node = s.recordMapRequest(node, tailcfg.MapRequest{
		Hostinfo: &tailcfg.Hostinfo{Hostname: "node-a"},
	})
	if node.HomeDERP != 2 {
		t.Fatalf("HomeDERP = %d, want the adopted 2 to survive an update without NetInfo", node.HomeDERP)
	}
	if node.Hostname != "node-a" {
		t.Fatalf("Hostname = %q, want node-a", node.Hostname)
	}

	stored, ok := s.store.GetNodeByID(node.ID)
	if !ok {
		t.Fatal("node disappeared from the store")
	}
	if stored.HomeDERP != 2 {
		t.Errorf("stored HomeDERP = %d, want 2", stored.HomeDERP)
	}
}

func TestRecordMapRequestSingleDERPFallback(t *testing.T) {
	s := newServerWithConfig(t, Config{DERPMap: &tailcfg.DERPMap{
		Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{7: {}},
	}})
	node := seedTestNode(t, s)

	node = s.recordMapRequest(node, tailcfg.MapRequest{})
	if node.HomeDERP != 7 {
		t.Errorf("HomeDERP = %d, want the single configured region 7", node.HomeDERP)
	}
}

func TestClientVersionAdvisory(t *testing.T) {
	s := newServerWithConfig(t, Config{
		LatestClientVersion: "1.88.3",
		ClientVersionURL:    "https://example.com/update",
	})
	advisory := s.clientVersionFor()
	if advisory == nil {
		t.Fatal("clientVersionFor returned nil with the feature enabled")
	}

	t.Run("build suffix matches the short version", func(t *testing.T) {
		cv := advisory(state.Node{Hostinfo: &tailcfg.Hostinfo{IPNVersion: "1.88.3-t1234abcd"}})
		if cv == nil || !cv.RunningLatest {
			t.Fatalf("advisory = %+v, want RunningLatest", cv)
		}
		if cv.LatestVersion != "" || cv.Notify {
			t.Errorf("a running-latest advisory must not name a version or notify: %+v", cv)
		}
	})

	t.Run("older version is notified", func(t *testing.T) {
		cv := advisory(state.Node{Hostinfo: &tailcfg.Hostinfo{IPNVersion: "1.87.0"}})
		if cv == nil {
			t.Fatal("no advisory for an older version")
		}
		if cv.RunningLatest || cv.LatestVersion != "1.88.3" || !cv.Notify {
			t.Errorf("advisory = %+v, want latest 1.88.3 with Notify", cv)
		}
		if cv.NotifyURL != "https://example.com/update" || cv.NotifyText == "" {
			t.Errorf("advisory notification lacks url/text: %+v", cv)
		}
	})

	t.Run("unknown version is left alone", func(t *testing.T) {
		if cv := advisory(state.Node{}); cv != nil {
			t.Errorf("advisory = %+v, want nil for a node that never reported a version", cv)
		}
		if cv := advisory(state.Node{Hostinfo: &tailcfg.Hostinfo{IPNVersion: "  "}}); cv != nil {
			t.Errorf("advisory = %+v, want nil for a blank version", cv)
		}
	})

	t.Run("disabled without a configured version", func(t *testing.T) {
		off := newServerWithConfig(t, Config{}).clientVersionFor()
		if off != nil {
			t.Error("clientVersionFor returned a function with the feature disabled")
		}
	})
}

func TestFullMapCarriesClientVersionAdvisory(t *testing.T) {
	s := newServerWithConfig(t, Config{LatestClientVersion: "1.88.3"})
	node := seedTestNode(t, s)
	node.Hostname = "node-a"
	node.Hostinfo = &tailcfg.Hostinfo{Hostname: "node-a", IPNVersion: "1.87.0"}
	if err := s.store.UpdateNode(node); err != nil {
		t.Fatalf("updating node: %v", err)
	}

	full := s.fullMap(node, tailcfg.MapRequest{Version: tailcfg.CurrentCapabilityVersion})
	if full.ClientVersion == nil || full.ClientVersion.LatestVersion != "1.88.3" || !full.ClientVersion.Notify {
		t.Errorf("full map advisory = %+v, want 1.88.3 with Notify", full.ClientVersion)
	}

	update := s.updateMap(node)
	if update.ClientVersion == nil || update.ClientVersion.LatestVersion != "1.88.3" {
		t.Errorf("update advisory = %+v, want 1.88.3", update.ClientVersion)
	}
}
