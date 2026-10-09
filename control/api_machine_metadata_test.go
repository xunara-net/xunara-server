package control

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"tailscale.com/tailcfg"

	"github.com/xunara-net/xunara-server/state"
)

func TestAPIMachineMetadataIsReadOnlyAndMinimal(t *testing.T) {
	server := newTestServer(t)
	server.cfg.Domain = "devices.example.test"
	expires := time.Now().UTC().Add(time.Hour)
	node := state.Node{ID: 9, Hostname: "Laptop", Tags: []string{"tag:server"}, Expiry: expires,
		Hostinfo: &tailcfg.Hostinfo{OS: "linux", OSVersion: "6.12", IPNVersion: "1.104.0",
			FrontendLogID: "private-frontend", BackendLogID: "private-backend", PushDeviceToken: "private-push"}}
	view := server.apiMachineView(node)
	if view.OS != "linux" || view.OSVersion != "6.12" || view.ClientVersion != "1.104.0" || view.DNSName != "laptop.devices.example.test" || view.Expires == nil || !view.Expires.Equal(expires) {
		t.Fatalf("metadata = %+v", view)
	}
	view.Tags[0] = "tag:changed"
	if node.Tags[0] != "tag:server" {
		t.Fatal("view shares mutable tags with the stored node")
	}
	encoded, err := json.Marshal(view)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"private-", "machineKey", "nodeKey", "discoKey", "hostinfo", "connectionType", "latency"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("machine presentation exposes or invents %q", forbidden)
		}
	}
}

func TestAPIMachineMissingMetadataIsNotInvented(t *testing.T) {
	server := newTestServer(t)
	server.cfg.Domain = ""
	view := server.apiMachineView(state.Node{ID: 9})
	if view.OS != "" || view.ClientVersion != "" || view.DNSName != "" || view.Expires != nil || view.Tags == nil {
		t.Fatalf("missing metadata = %+v", view)
	}
}
