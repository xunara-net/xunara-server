package control

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/xunara-net/xunara-server/identity"
)

// platformAuditResponse mirrors the export payload.
type platformAuditResponse struct {
	Events  []PlatformAuditEvent `json:"events"`
	Cursors map[string]uint64    `json:"cursors"`
	HasMore bool                 `json:"has_more"`
}

// platformAuditRequest performs one platform audit export request.
func platformAuditRequest(t *testing.T, hs *httptest.Server, token, query string) *http.Response {
	t.Helper()

	req, err := http.NewRequest(http.MethodGet, hs.URL+"/api/platform/v1/audit"+query, nil)
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	req.Host = "login.acme.example.com"
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := hs.Client().Do(req)
	if err != nil {
		t.Fatalf("GET platform audit: %v", err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

// decodePlatformAudit decodes a successful export response.
func decodePlatformAudit(t *testing.T, resp *http.Response) platformAuditResponse {
	t.Helper()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var out platformAuditResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decoding export: %v", err)
	}
	return out
}

// seedAudit appends one event and returns its assigned ID.
func seedAudit(t *testing.T, s *Server, action, target string) uint64 {
	t.Helper()

	event := identity.AuditEvent{Actor: "user:1", Action: action, Target: target}
	if err := s.Identity().AppendAudit(&event); err != nil {
		t.Fatalf("append audit: %v", err)
	}
	return event.ID
}

// TestPlatformAuditExport covers the cross-organization export: merged order,
// per-organization cursors, resumability and filters.
func TestPlatformAuditExport(t *testing.T) {
	acme := newServerWithConfig(t, Config{Domain: "acme.example.com"})
	globex := newServerWithConfig(t, Config{})
	router := newTestRouter(t, RouterConfig{
		Orgs: []OrgSite{
			{ID: "acme", Name: "Acme", Domains: []string{"login.acme.example.com"}, Server: acme},
			{ID: "globex", Name: "Globex", Domains: []string{"*.globex.example.com"}, Server: globex},
		},
		PlatformAdminToken: "platform-secret",
	})
	hs := httptest.NewServer(router.Handler())
	t.Cleanup(hs.Close)

	const token = "platform-secret"

	// The export needs the platform token, not an organization credential.
	if resp := platformAuditRequest(t, hs, "", ""); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("tokenless export status = %d, want 401", resp.StatusCode)
	}

	// Both organizations already recorded their built-in local user, so the
	// delta is measured from the baseline export's cursors.
	baseResp := platformAuditRequest(t, hs, token, "")
	if cc := baseResp.Header.Get("Cache-Control"); cc != "no-store" {
		t.Errorf("export Cache-Control = %q, want no-store", cc)
	}
	base := decodePlatformAudit(t, baseResp)
	if len(base.Events) == 0 {
		t.Fatal("baseline export is empty; expected the built-in user event")
	}
	fromBase := "?cursor=acme:" + itoa64(base.Cursors["acme"]) +
		"&cursor=globex:" + itoa64(base.Cursors["globex"])

	acmeOne := seedAudit(t, acme, identity.AuditNodeRegistered, "node:1")
	globexOne := seedAudit(t, globex, identity.AuditUserCreated, "user:1")
	seedAudit(t, acme, identity.AuditNodeApproved, "node:1")
	globexTwo := seedAudit(t, globex, identity.AuditNodeRegistered, "node:2")
	acmeThree := seedAudit(t, acme, identity.AuditDNSRecordSet, "dns:1")

	page := decodePlatformAudit(t, platformAuditRequest(t, hs, token, fromBase))
	if len(page.Events) != 5 {
		t.Fatalf("events = %d, want 5", len(page.Events))
	}
	if page.HasMore {
		t.Error("has_more = true for a complete page")
	}
	if page.Cursors["acme"] != acmeThree || page.Cursors["globex"] != globexTwo {
		t.Errorf("cursors = %v, want acme:%d globex:%d", page.Cursors, acmeThree, globexTwo)
	}
	for i := 1; i < len(page.Events); i++ {
		if page.Events[i].Time.Before(page.Events[i-1].Time) {
			t.Fatalf("events are not ordered by time: %+v", page.Events)
		}
	}
	for _, event := range page.Events {
		if event.Org != "acme" && event.Org != "globex" {
			t.Errorf("event %+v has no organization", event)
		}
		if event.ID == 0 || event.Actor == "" || event.Action == "" {
			t.Errorf("event %+v is incomplete", event)
		}
	}

	// Resuming from the returned cursors yields nothing new.
	done := decodePlatformAudit(t, platformAuditRequest(t, hs, token,
		"?cursor=acme:"+itoa64(acmeThree)+"&cursor=globex:"+itoa64(globexTwo)))
	if len(done.Events) != 0 {
		t.Fatalf("resumed export = %+v, want no events", done.Events)
	}
	if done.Cursors["acme"] != acmeThree || done.Cursors["globex"] != globexTwo {
		t.Errorf("resumed cursors = %v, want them unchanged", done.Cursors)
	}

	// One organization filter, and the cursor map follows it.
	onlyGlobex := decodePlatformAudit(t, platformAuditRequest(t, hs, token,
		"?org=globex&cursor=globex:"+itoa64(base.Cursors["globex"])))
	if len(onlyGlobex.Events) != 2 {
		t.Fatalf("globex-only events = %d, want 2", len(onlyGlobex.Events))
	}
	for _, event := range onlyGlobex.Events {
		if event.Org != "globex" {
			t.Errorf("org filter leaked %+v", event)
		}
	}
	if len(onlyGlobex.Cursors) != 1 || onlyGlobex.Cursors["globex"] != globexTwo {
		t.Errorf("globex-only cursors = %v", onlyGlobex.Cursors)
	}

	// Action filters use the webhook glob syntax, and a filtered-out event
	// still advances the cursor: it must not be offered again.
	acmeFour := seedAudit(t, acme, identity.AuditUserCreated, "user:9")
	acmeFive := seedAudit(t, acme, identity.AuditNodeRegistered, "node:9")
	filtered := decodePlatformAudit(t, platformAuditRequest(t, hs, token,
		"?org=acme&action=node.*&cursor=acme:"+itoa64(acmeThree)))
	if len(filtered.Events) != 1 || filtered.Events[0].ID != acmeFive {
		t.Fatalf("filtered export = %+v, want only the node.registered event %d", filtered.Events, acmeFive)
	}
	if filtered.Cursors["acme"] != acmeFive {
		t.Errorf("cursor = %d, want %d (past the filtered user.created)", filtered.Cursors["acme"], acmeFive)
	}
	if acmeFour == 0 {
		t.Error("seeded event has no ID")
	}

	// A small page bound scans that many raw events per organization and asks
	// the caller to continue.
	fresh := decodePlatformAudit(t, platformAuditRequest(t, hs, token, "?limit=1"))
	if len(fresh.Events) != 2 {
		t.Fatalf("limit=1 events = %+v, want one per organization", fresh.Events)
	}
	if !fresh.HasMore {
		t.Error("has_more = false for a bounded scan that hit its limit")
	}
	// Both organizations' first event is their built-in user, ID 1.
	if fresh.Cursors["acme"] != 1 || fresh.Cursors["globex"] != 1 {
		t.Errorf("limit=1 cursors = %v, want acme:1 globex:1", fresh.Cursors)
	}
	if acmeOne == 0 || globexOne == 0 {
		t.Error("seeded events have no IDs")
	}
}

// TestPlatformAuditExportRejections pins the query validation.
func TestPlatformAuditExportRejections(t *testing.T) {
	acme := newServerWithConfig(t, Config{Domain: "acme.example.com"})
	router := newTestRouter(t, RouterConfig{
		Orgs:               []OrgSite{{ID: "acme", Name: "Acme", Domains: []string{"login.acme.example.com"}, Server: acme}},
		PlatformAdminToken: "platform-secret",
	})
	hs := httptest.NewServer(router.Handler())
	t.Cleanup(hs.Close)

	for _, tc := range []struct {
		name  string
		query string
	}{
		{"unknown org", "?org=globex"},
		{"cursor without an id", "?cursor=acme"},
		{"cursor with a bad id", "?cursor=acme:soon"},
		{"cursor with an empty org", "?cursor=:1"},
		{"unsupported glob", "?action=node.?"},
		{"zero limit", "?limit=0"},
		{"non-numeric limit", "?limit=lots"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp := platformAuditRequest(t, hs, "platform-secret", tc.query)
			if resp.StatusCode != http.StatusBadRequest {
				t.Errorf("status = %d, want 400", resp.StatusCode)
			}
		})
	}

	// A cursor for another organization is accepted: it is simply unused, and
	// cursors are documented to be handed back verbatim.
	resp := platformAuditRequest(t, hs, "platform-secret", "?org=acme&cursor=globex:7")
	if resp.StatusCode != http.StatusOK {
		t.Errorf("foreign cursor status = %d, want 200", resp.StatusCode)
	}
}

// Seed a fresh organization's audit log and check the exported timestamps are
// usable as a watermark.
func TestPlatformAuditExportTimestamps(t *testing.T) {
	acme := newServerWithConfig(t, Config{Domain: "acme.example.com"})
	router := newTestRouter(t, RouterConfig{
		Orgs:               []OrgSite{{ID: "acme", Name: "Acme", Domains: []string{"login.acme.example.com"}, Server: acme}},
		PlatformAdminToken: "platform-secret",
	})
	hs := httptest.NewServer(router.Handler())
	t.Cleanup(hs.Close)

	before := time.Now().UTC().Add(-time.Second)
	seedAudit(t, acme, identity.AuditNodeRegistered, "node:1")

	page := decodePlatformAudit(t, platformAuditRequest(t, hs, "platform-secret", "?action=node.registered"))
	if len(page.Events) != 1 {
		t.Fatalf("events = %+v, want one", page.Events)
	}
	if got := page.Events[0].Time; got.Before(before) || got.After(time.Now().UTC().Add(time.Second)) {
		t.Errorf("event time = %v, want a real UTC timestamp", got)
	}
	if page.Events[0].Time.Location() != time.UTC {
		t.Errorf("event time location = %v, want UTC", page.Events[0].Time.Location())
	}
}
