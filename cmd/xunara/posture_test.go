package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"tailscale.com/types/key"

	"github.com/xunara-net/xunara-server/state"
)

// seedPostureStore builds an in-memory store with two machines, one of which
// reported attributes.
func seedPostureStore(t *testing.T) (state.Store, state.Node) {
	t.Helper()

	store := state.NewMemoryStore()
	reporter := state.Node{Hostname: "reporter", NodeKey: key.NewNode().Public()}
	if err := store.CreateNode(&reporter); err != nil {
		t.Fatalf("CreateNode: %v", err)
	}
	quiet := state.Node{Hostname: "quiet", NodeKey: key.NewNode().Public()}
	if err := store.CreateNode(&quiet); err != nil {
		t.Fatalf("CreateNode: %v", err)
	}

	if err := store.SetNodeDeviceAttrs(reporter.ID, map[string]any{
		"os_version":   "15.2",
		"disk_encrypt": true,
	}); err != nil {
		t.Fatalf("SetNodeDeviceAttrs: %v", err)
	}
	return store, reporter
}

// TestWritePostureList covers the list view: only machines with attributes are
// shown, with names but not values.
func TestWritePostureList(t *testing.T) {
	store, _ := seedPostureStore(t)

	var buf bytes.Buffer
	if err := writePostureList(&buf, store); err != nil {
		t.Fatalf("writePostureList: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "reporter") {
		t.Errorf("list does not name the reporting machine:\n%s", out)
	}
	if !strings.Contains(out, "2 (") || !strings.Contains(out, "disk_encrypt") || !strings.Contains(out, "os_version") {
		t.Errorf("list does not summarise the attributes:\n%s", out)
	}
	if strings.Contains(out, "15.2") {
		t.Errorf("list leaked an attribute value:\n%s", out)
	}
	if strings.Contains(out, "quiet") {
		t.Errorf("list shows a machine without attributes:\n%s", out)
	}

	// An empty store explains itself instead of printing an empty table.
	var empty bytes.Buffer
	if err := writePostureList(&empty, state.NewMemoryStore()); err != nil {
		t.Fatalf("writePostureList (empty): %v", err)
	}
	if !strings.Contains(empty.String(), "No machine has reported device posture attributes") {
		t.Errorf("empty list output = %q", empty.String())
	}
}

// TestWritePostureShow covers the detail view and its node-reference handling.
func TestWritePostureShow(t *testing.T) {
	store, reporter := seedPostureStore(t)

	var buf bytes.Buffer
	if err := writePostureShow(&buf, store, reporter.StableID); err != nil {
		t.Fatalf("writePostureShow: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "HOSTNAME") || !strings.Contains(out, "reporter") {
		t.Errorf("show does not identify the machine:\n%s", out)
	}
	if !strings.Contains(out, "os_version") || !strings.Contains(out, "15.2") ||
		!strings.Contains(out, "disk_encrypt") || !strings.Contains(out, "true") {
		t.Errorf("show does not print the attributes:\n%s", out)
	}

	// A machine with no attributes is a normal answer, not an error.
	var quiet bytes.Buffer
	node := state.Node{Hostname: "quiet2", NodeKey: key.NewNode().Public()}
	if err := store.CreateNode(&node); err != nil {
		t.Fatalf("CreateNode: %v", err)
	}
	if err := writePostureShow(&quiet, store, node.StableID); err != nil {
		t.Fatalf("writePostureShow (no attributes): %v", err)
	}
	if !strings.Contains(quiet.String(), "has not reported any device posture attributes") {
		t.Errorf("output for a machine without attributes = %q", quiet.String())
	}

	// An unknown reference is distinguishable from a store failure.
	if err := writePostureShow(&bytes.Buffer{}, store, "nope"); !errors.Is(err, errNodeNotFound) {
		t.Errorf("unknown node error = %v, want errNodeNotFound", err)
	}
}
