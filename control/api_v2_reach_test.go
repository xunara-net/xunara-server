package control

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	xunarav2 "github.com/xunara-net/xunara-server/api/gen/xunara/v2"
	"github.com/xunara-net/xunara-server/identity"
	"github.com/xunara-net/xunara-server/state"
)

// reachAdminPage decodes one management listing.
func reachAdminPage(t *testing.T, resp *http.Response) ([]reachAdminSession, string) {
	t.Helper()

	var page struct {
		Items      []reachAdminSession `json:"items"`
		NextCursor string              `json:"nextCursor"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&page); err != nil {
		t.Fatalf("decoding the reach listing: %v", err)
	}
	return page.Items, page.NextCursor
}

// TestAPIV2ReachManagement drives the read-only management surface: list with
// filters and cursors, detail with argv, and the bounded output read.
func TestAPIV2ReachManagement(t *testing.T) {
	s, hs, sender, target, _ := startReach(t)
	_, readToken := seedAPIKey(t, s, identity.ScopeRead)
	_, writeToken := seedAPIKey(t, s, identity.ScopeWrite)
	client := noRedirectClient()

	// One session that ran and printed on both streams.
	session := offerReach(t, hs, sender, target, []string{"df", "-h"})
	target.doReach(t, hs.Client(), http.MethodPost, reachURL(hs, session.ID, "accept"), nil)
	target.doReach(t, hs.Client(), http.MethodPost, reachURL(hs, session.ID, "start"), nil)
	for _, chunk := range []struct {
		stream string
		data   string
	}{
		{"stdout", "Filesystem\n"},
		{"stderr", "warn\n"},
	} {
		if _, status := target.doReach(t, hs.Client(), http.MethodPost, reachURL(hs, session.ID, "chunks"),
			map[string]any{"stream": chunk.stream, "seq": 0, "data": []byte(chunk.data)}); status != http.StatusNoContent {
			t.Fatalf("chunk %s = %d", chunk.stream, status)
		}
	}
	target.doReach(t, hs.Client(), http.MethodPost, reachURL(hs, session.ID, "finish"), map[string]any{"exitCode": 0})

	// A second session that was refused.
	denied := offerReach(t, hs, sender, target, []string{"rm", "-rf", "/"})
	target.doReach(t, hs.Client(), http.MethodPost, reachURL(hs, denied.ID, "deny"), nil)

	base := hs.URL + "/api/v2/reach/sessions"
	if resp := apiRequest(t, client, http.MethodGet, base, "", nil); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("anonymous list = %d, want 401", resp.StatusCode)
	}
	if resp := apiRequest(t, client, http.MethodGet, base, writeToken, nil); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("write-only list = %d, want 403", resp.StatusCode)
	}

	resp := apiRequest(t, client, http.MethodGet, base, readToken, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list = %d, want 200", resp.StatusCode)
	}
	if cc := resp.Header.Get("Cache-Control"); cc != "no-store" {
		t.Errorf("list Cache-Control = %q, want no-store", cc)
	}
	items, _ := reachAdminPage(t, resp)
	if len(items) != 2 {
		t.Fatalf("list = %+v", items)
	}
	byID := map[string]reachAdminSession{}
	for _, item := range items {
		byID[item.ID] = item
	}
	ran, ok := byID[session.ID]
	if !ok {
		t.Fatalf("finished session missing from %+v", items)
	}
	if ran.State != string(state.ReachSucceeded) || ran.ExitCode == nil || *ran.ExitCode != 0 {
		t.Errorf("finished session = %+v", ran)
	}
	if len(ran.Argv) != 2 || ran.Argv[0] != "df" || ran.Sender.StableID != sender.node.StableID {
		t.Errorf("finished session argv/participants = %+v", ran)
	}
	if ran.OutputBytes.Stdout != int64(len("Filesystem\n")) || ran.OutputBytes.Stderr != int64(len("warn\n")) {
		t.Errorf("output bytes = %+v", ran.OutputBytes)
	}
	if refused, ok := byID[denied.ID]; !ok || refused.State != string(state.ReachDenied) {
		t.Errorf("denied session = %+v", byID[denied.ID])
	}

	// Filters are fail-closed.
	resp = apiRequest(t, client, http.MethodGet, base+"?state=denied", readToken, nil)
	if items, _ := reachAdminPage(t, resp); len(items) != 1 || items[0].ID != denied.ID {
		t.Errorf("state filter = %+v", items)
	}
	if resp := apiRequest(t, client, http.MethodGet, base+"?state=nonsense", readToken, nil); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("unknown state = %d, want 400", resp.StatusCode)
	}
	resp = apiRequest(t, client, http.MethodGet, base+"?node="+target.node.StableID, readToken, nil)
	if items, _ := reachAdminPage(t, resp); len(items) != 2 {
		t.Errorf("node filter = %+v", items)
	}
	resp = apiRequest(t, client, http.MethodGet, base+"?node=n0000000000000000", readToken, nil)
	if items, _ := reachAdminPage(t, resp); len(items) != 0 {
		t.Errorf("unknown node filter returned %+v", items)
	}
	// "0" is not a node ID: it must match nothing, never mean "no filter".
	resp = apiRequest(t, client, http.MethodGet, base+"?node=0", readToken, nil)
	if items, _ := reachAdminPage(t, resp); len(items) != 0 {
		t.Errorf("node=0 returned %+v, want nothing", items)
	}
	if resp := apiRequest(t, client, http.MethodGet, base+"?limit=bogus", readToken, nil); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("bad limit = %d, want 400", resp.StatusCode)
	}
	// "YWJj" decodes to the wrong cursor kind: refused rather than ignored.
	if resp := apiRequest(t, client, http.MethodGet, base+"?cursor=YWJj", readToken, nil); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("bad cursor = %d, want 400", resp.StatusCode)
	}

	// The cursor walks the whole list exactly once.
	seen := map[string]bool{}
	cursor := ""
	for page := 0; page < 5; page++ {
		url := base + "?limit=1"
		if cursor != "" {
			url += "&cursor=" + cursor
		}
		resp := apiRequest(t, client, http.MethodGet, url, readToken, nil)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("page %d = %d", page, resp.StatusCode)
		}
		items, next := reachAdminPage(t, resp)
		for _, item := range items {
			if seen[item.ID] {
				t.Fatalf("session %s appeared twice", item.ID)
			}
			seen[item.ID] = true
		}
		if next == "" {
			break
		}
		cursor = next
	}
	if len(seen) != 2 {
		t.Errorf("cursor walk saw %v, want both sessions", seen)
	}

	// The detail carries argv; the output needs the chunks endpoint.
	resp = apiRequest(t, client, http.MethodGet, base+"/"+session.ID, readToken, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("detail = %d, want 200", resp.StatusCode)
	}
	var detail reachAdminSession
	if err := json.NewDecoder(resp.Body).Decode(&detail); err != nil {
		t.Fatalf("decoding the detail: %v", err)
	}
	if len(detail.Argv) != 2 || detail.OutputBytes.Stdout != int64(len("Filesystem\n")) {
		t.Errorf("detail = %+v", detail)
	}
	if resp := apiRequest(t, client, http.MethodGet, base+"/does-not-exist", readToken, nil); resp.StatusCode != http.StatusNotFound {
		t.Errorf("unknown session = %d, want 404", resp.StatusCode)
	}

	resp = apiRequest(t, client, http.MethodGet, base+"/"+session.ID+"/chunks", readToken, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("chunks = %d, want 200", resp.StatusCode)
	}
	var chunks reachChunksResponse
	if err := json.NewDecoder(resp.Body).Decode(&chunks); err != nil {
		t.Fatalf("decoding the chunks: %v", err)
	}
	if len(chunks.Out) != 1 || string(chunks.Out[0].Data) != "Filesystem\n" || len(chunks.Err) != 1 {
		t.Errorf("chunks = %+v", chunks)
	}
	if chunks.NextOut != 0 || chunks.NextErr != 0 {
		t.Errorf("cursor = %d/%d, want 0/0", chunks.NextOut, chunks.NextErr)
	}
	resp = apiRequest(t, client, http.MethodGet, base+"/"+session.ID+"/chunks?out=0&err=0", readToken, nil)
	if chunks := decodeReachChunks(t, readBody(t, resp)); len(chunks.Out) != 0 || len(chunks.Err) != 0 {
		t.Errorf("read after cursor = %+v", chunks)
	}
	if resp := apiRequest(t, client, http.MethodGet, base+"/"+session.ID+"/chunks?out=x", readToken, nil); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("bad cursor = %d, want 400", resp.StatusCode)
	}
	if resp := apiRequest(t, client, http.MethodGet, base+"/does-not-exist/chunks", readToken, nil); resp.StatusCode != http.StatusNotFound {
		t.Errorf("chunks of an unknown session = %d, want 404", resp.StatusCode)
	}
}

// TestAPIV2ReachDisabled checks that a deployment without Reach keeps the
// feature unprobeable: every management endpoint is a 404.
func TestAPIV2ReachDisabled(t *testing.T) {
	s := newTestServer(t)
	hs := newTestHTTPServer(t, s)
	_, token := seedAPIKey(t, s, identity.ScopeRead)
	client := noRedirectClient()

	base := hs.URL + "/api/v2/reach/sessions"
	for _, path := range []string{base, base + "/abc", base + "/abc/chunks"} {
		if resp := apiRequest(t, client, http.MethodGet, path, token, nil); resp.StatusCode != http.StatusNotFound {
			t.Errorf("GET %s with reach disabled = %d, want 404", path, resp.StatusCode)
		}
	}
}

// TestPlatformGRPCReachSessions checks the typed mirror: same sessions, same
// filters, same cursor and the same NOT_FOUND for an unknown session or a
// deployment without Reach.
func TestPlatformGRPCReachSessions(t *testing.T) {
	s, hs, sender, target, _ := startReach(t)
	_, readToken := seedAPIKey(t, s, identity.ScopeRead)
	_, writeToken := seedAPIKey(t, s, identity.ScopeWrite)
	client := startGRPCTestServer(t, s.RegisterPlatformGRPC)

	ran := offerReach(t, hs, sender, target, []string{"df", "-h"})
	target.doReach(t, hs.Client(), http.MethodPost, reachURL(hs, ran.ID, "accept"), nil)
	target.doReach(t, hs.Client(), http.MethodPost, reachURL(hs, ran.ID, "start"), nil)
	target.doReach(t, hs.Client(), http.MethodPost, reachURL(hs, ran.ID, "chunks"),
		map[string]any{"stream": "stdout", "seq": 0, "data": []byte("Filesystem\n")})
	target.doReach(t, hs.Client(), http.MethodPost, reachURL(hs, ran.ID, "finish"), map[string]any{"exitCode": 0})
	refused := offerReach(t, hs, sender, target, []string{"rm", "-rf", "/"})
	target.doReach(t, hs.Client(), http.MethodPost, reachURL(hs, refused.ID, "deny"), nil)

	if _, err := client.ListReachSessions(context.Background(), &xunarav2.ListReachSessionsRequest{}); status.Code(err) != codes.Unauthenticated {
		t.Errorf("anonymous error = %v, want Unauthenticated", err)
	}
	if _, err := client.ListReachSessions(grpcCtx(writeToken), &xunarav2.ListReachSessionsRequest{}); status.Code(err) != codes.PermissionDenied {
		t.Errorf("write-only error = %v, want PermissionDenied", err)
	}

	list, err := client.ListReachSessions(grpcCtx(readToken), &xunarav2.ListReachSessionsRequest{})
	if err != nil {
		t.Fatalf("ListReachSessions: %v", err)
	}
	if len(list.GetSessions()) != 2 {
		t.Fatalf("sessions = %+v", list.GetSessions())
	}
	byID := map[string]*xunarav2.ReachSession{}
	for _, session := range list.GetSessions() {
		byID[session.GetId()] = session
	}
	entry := byID[ran.ID]
	if entry == nil {
		t.Fatalf("finished session missing from %+v", list.GetSessions())
	}
	if entry.GetState() != string(state.ReachSucceeded) || entry.GetExitCode() != 0 {
		t.Errorf("finished session = %+v", entry)
	}
	if got := entry.GetArgv(); len(got) != 2 || got[0] != "df" {
		t.Errorf("argv = %v", got)
	}
	if entry.GetSender().GetStableId() != sender.node.StableID || entry.GetTarget().GetStableId() != target.node.StableID {
		t.Errorf("participants = %+v / %+v", entry.GetSender(), entry.GetTarget())
	}
	if entry.GetOutputBytes().GetStdout() != int64(len("Filesystem\n")) {
		t.Errorf("output bytes = %+v", entry.GetOutputBytes())
	}
	if got := byID[refused.ID].GetState(); got != string(state.ReachDenied) {
		t.Errorf("denied session state = %s", got)
	}

	// Filters and pagination follow the HTTP rules.
	filtered, err := client.ListReachSessions(grpcCtx(readToken), &xunarav2.ListReachSessionsRequest{State: "denied"})
	if err != nil || len(filtered.GetSessions()) != 1 || filtered.GetSessions()[0].GetId() != refused.ID {
		t.Errorf("state filter = %+v (%v)", filtered.GetSessions(), err)
	}
	if _, err := client.ListReachSessions(grpcCtx(readToken), &xunarav2.ListReachSessionsRequest{State: "nonsense"}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("unknown state error = %v, want InvalidArgument", err)
	}
	unknownNode, err := client.ListReachSessions(grpcCtx(readToken), &xunarav2.ListReachSessionsRequest{Node: "n0000000000000000"})
	if err != nil || len(unknownNode.GetSessions()) != 0 {
		t.Errorf("unknown node = %+v (%v)", unknownNode.GetSessions(), err)
	}
	zeroNode, err := client.ListReachSessions(grpcCtx(readToken), &xunarav2.ListReachSessionsRequest{Node: "0"})
	if err != nil || len(zeroNode.GetSessions()) != 0 {
		t.Errorf("node=0 = %+v (%v), want nothing", zeroNode.GetSessions(), err)
	}
	if _, err := client.ListReachSessions(grpcCtx(readToken), &xunarav2.ListReachSessionsRequest{PageToken: "YWJj"}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("bad page token error = %v, want InvalidArgument", err)
	}

	seen := map[string]bool{}
	token := ""
	for page := 0; page < 5; page++ {
		pageResp, err := client.ListReachSessions(grpcCtx(readToken), &xunarav2.ListReachSessionsRequest{PageSize: 1, PageToken: token})
		if err != nil {
			t.Fatalf("page %d: %v", page, err)
		}
		for _, session := range pageResp.GetSessions() {
			if seen[session.GetId()] {
				t.Fatalf("session %s appeared twice", session.GetId())
			}
			seen[session.GetId()] = true
		}
		token = pageResp.GetNextPageToken()
		if token == "" {
			break
		}
	}
	if len(seen) != 2 {
		t.Errorf("cursor walk saw %v, want both sessions", seen)
	}

	// Detail and error mapping.
	detail, err := client.GetReachSession(grpcCtx(readToken), &xunarav2.GetReachSessionRequest{Id: ran.ID})
	if err != nil {
		t.Fatalf("GetReachSession: %v", err)
	}
	if detail.GetId() != ran.ID || len(detail.GetArgv()) != 2 {
		t.Errorf("detail = %+v", detail)
	}
	if _, err := client.GetReachSession(grpcCtx(readToken), &xunarav2.GetReachSessionRequest{Id: "does-not-exist"}); status.Code(err) != codes.NotFound {
		t.Errorf("unknown session error = %v, want NotFound", err)
	}
}

// TestPlatformGRPCReachDisabled checks that a deployment without Reach keeps
// the endpoints unprobeable over gRPC too.
func TestPlatformGRPCReachDisabled(t *testing.T) {
	s := newTestServer(t)
	_, readToken := seedAPIKey(t, s, identity.ScopeRead)
	client := startGRPCTestServer(t, s.RegisterPlatformGRPC)

	if _, err := client.ListReachSessions(grpcCtx(readToken), &xunarav2.ListReachSessionsRequest{}); status.Code(err) != codes.NotFound {
		t.Errorf("list with reach disabled = %v, want NotFound", err)
	}
	if _, err := client.GetReachSession(grpcCtx(readToken), &xunarav2.GetReachSessionRequest{Id: "abc"}); status.Code(err) != codes.NotFound {
		t.Errorf("get with reach disabled = %v, want NotFound", err)
	}
}
