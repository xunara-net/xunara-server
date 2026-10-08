package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"tailscale.com/types/key"

	"github.com/xunara-net/xunara-server/state"
)

// seedServiceStore builds an in-memory store with two nodes, one advertising
// two services.
func seedServiceStore(t *testing.T) (state.Store, state.Node) {
	t.Helper()

	store := state.NewMemoryStore()
	web := state.Node{Hostname: "web", NodeKey: key.NewNode().Public()}
	if err := store.CreateNode(&web); err != nil {
		t.Fatalf("CreateNode: %v", err)
	}
	quiet := state.Node{Hostname: "quiet", NodeKey: key.NewNode().Public()}
	if err := store.CreateNode(&quiet); err != nil {
		t.Fatalf("CreateNode: %v", err)
	}

	if err := store.ReplaceNodeServices(web.ID, []state.Service{
		{Name: "api", Protocol: "tcp", Port: 8080, Metadata: map[string]string{"version": "2"}},
		{Name: "metrics", Protocol: "tcp", Port: 9090},
		{Name: "db", Protocol: "tcp", Port: 5432, Health: true},
		{Name: "cache", Protocol: "tcp", Port: 6379, Health: true, Visibility: []string{"group:eng"}, Shared: true},
		{Name: "admin", Protocol: "tcp", Port: 9000, VisibilityFromACL: true},
	}); err != nil {
		t.Fatalf("ReplaceNodeServices: %v", err)
	}
	if _, err := store.ReportServiceHealth(web.ID, []state.ServiceHealthReport{{Name: "db", Ready: true}}, time.Minute); err != nil {
		t.Fatalf("ReportServiceHealth: %v", err)
	}
	return store, web
}

// TestWriteServicesList covers the list view: every service with its
// publisher.
func TestWriteServicesList(t *testing.T) {
	store, web := seedServiceStore(t)

	var buf bytes.Buffer
	if err := writeServicesList(&buf, store); err != nil {
		t.Fatalf("writeServicesList: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"api", "metrics", "tcp", "8080", "9090", "web", web.StableID, "healthy", "unhealthy", "group:eng", "yes"} {
		if !strings.Contains(out, want) {
			t.Errorf("list output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "quiet") {
		t.Errorf("list shows a node without services:\n%s", out)
	}

	// The visibility column says "*" for the organization default, the shared
	// column says "-" for services that are not projected, and the health
	// column says "-" for services that never opted in.
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) > 5 && fields[0] == "api" && (fields[3] != "*" || fields[4] != "-" || fields[5] != "-") {
			t.Errorf("api row = %v, want visibility *, shared - and health -:\n%s", fields, out)
		}
		if len(fields) > 5 && fields[0] == "cache" && (fields[3] != "group:eng" || fields[4] != "yes") {
			t.Errorf("cache row = %v, want visibility group:eng and shared yes:\n%s", fields, out)
		}
		if len(fields) > 5 && fields[0] == "admin" && fields[3] != "acl" {
			t.Errorf("admin visibility = %q, want acl:\n%s", fields[3], out)
		}
	}

	var empty bytes.Buffer
	if err := writeServicesList(&empty, state.NewMemoryStore()); err != nil {
		t.Fatalf("writeServicesList (empty): %v", err)
	}
	if !strings.Contains(empty.String(), "No services have been advertised") {
		t.Errorf("empty list output = %q", empty.String())
	}
}

// TestWriteServicesShow covers the detail view, metadata and the unknown-name
// error.
func TestWriteServicesShow(t *testing.T) {
	store, web := seedServiceStore(t)

	var buf bytes.Buffer
	if err := writeServicesShow(&buf, store, "api"); err != nil {
		t.Fatalf("writeServicesShow: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"api", "tcp", "8080", "web", web.StableID, "version", "2"} {
		if !strings.Contains(out, want) {
			t.Errorf("show output lacks %q:\n%s", want, out)
		}
	}
	if !strings.Contains(out, "SHARED") {
		t.Errorf("show output lacks the shared line:\n%s", out)
	}

	if err := writeServicesShow(&bytes.Buffer{}, store, "nope"); !errors.Is(err, errServiceNotFound) {
		t.Errorf("unknown service error = %v, want errServiceNotFound", err)
	}
}

// TestWriteServicesShowHealth covers the readiness lines: a tracked service
// reports its effective health and when readiness was last seen, and an
// untracked service has no health block at all.
func TestWriteServicesShowHealth(t *testing.T) {
	store, _ := seedServiceStore(t)

	var buf bytes.Buffer
	if err := writeServicesShow(&buf, store, "db"); err != nil {
		t.Fatalf("writeServicesShow(db): %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "HEALTH") || !strings.Contains(out, "healthy") {
		t.Errorf("tracked service lacks its health:\n%s", out)
	}
	if !strings.Contains(out, "HEALTH REPORTED") {
		t.Errorf("tracked service lacks the report time:\n%s", out)
	}

	buf.Reset()
	if err := writeServicesShow(&buf, store, "cache"); err != nil {
		t.Fatalf("writeServicesShow(cache): %v", err)
	}
	if out := buf.String(); !strings.Contains(out, "unhealthy") {
		t.Errorf("never-reported service is not unhealthy:\n%s", out)
	}

	buf.Reset()
	if err := writeServicesShow(&buf, store, "api"); err != nil {
		t.Fatalf("writeServicesShow(api): %v", err)
	}
	if out := buf.String(); strings.Contains(out, "HEALTH") {
		t.Errorf("untracked service shows a health block:\n%s", out)
	}
}
