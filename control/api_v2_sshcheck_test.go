package control

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	xunarav2 "github.com/xunara-net/xunara-server/api/gen/xunara/v2"
	"github.com/xunara-net/xunara-server/identity"
	"github.com/xunara-net/xunara-server/state"
)

// seedSSHCheck creates one durable SSH check session bound to (src, dst).
func seedSSHCheck(t *testing.T, s *Server, id string, src, dst state.Node, localUser string, ttl time.Duration) identity.SSHCheckSession {
	t.Helper()
	sess, err := s.Identity().CreateSSHCheckSession(identity.NewSSHCheckOptions{
		ID:        id,
		SrcNodeID: int64(src.ID),
		DstNodeID: int64(dst.ID),
		LocalUser: localUser,
		TTL:       ttl,
	})
	if err != nil {
		t.Fatalf("CreateSSHCheckSession: %v", err)
	}
	return sess
}

// decodeSSHCheckPage reads one GET /api/v2/ssh-check/sessions response.
func decodeSSHCheckPage(t *testing.T, raw []byte) ([]sshCheckAdminSession, string) {
	t.Helper()
	var page struct {
		Items      []sshCheckAdminSession `json:"items"`
		NextCursor string                 `json:"nextCursor"`
	}
	if err := json.Unmarshal(raw, &page); err != nil {
		t.Fatalf("decoding the ssh check page: %v (%s)", err, raw)
	}
	return page.Items, page.NextCursor
}

// sshCheckTestServer seeds one session per lifecycle state, newest last:
// expired (rejected semantics aside), consumed, accepted, then pending.
func sshCheckTestServer(t *testing.T) (*Server, *httptest.Server, state.Node, state.Node) {
	t.Helper()
	s := newTestServer(t)
	hs := newTestHTTPServer(t, s)
	src := seedAPIMachine(t, s, "ssh-src", nil)
	dst := seedAPIMachine(t, s, "ssh-dst", nil)

	seedSSHCheck(t, s, "check-pending", src, dst, "root", 0)
	time.Sleep(2 * time.Millisecond)
	accepted := seedSSHCheck(t, s, "check-accepted", src, dst, "deploy", 0)
	if _, err := s.Identity().DecideSSHCheckSession(accepted.ID, identity.SSHCheckAccepted, state.DefaultUserID, time.Now().UTC()); err != nil {
		t.Fatalf("deciding the accepted session: %v", err)
	}
	time.Sleep(2 * time.Millisecond)
	consumed := seedSSHCheck(t, s, "check-consumed", src, dst, "", 0)
	if _, err := s.Identity().DecideSSHCheckSession(consumed.ID, identity.SSHCheckRejected, state.DefaultUserID, time.Now().UTC()); err != nil {
		t.Fatalf("deciding the consumed session: %v", err)
	}
	if _, err := s.Identity().ConsumeSSHCheckVerdict(consumed.ID, time.Now().UTC()); err != nil {
		t.Fatalf("consuming the verdict: %v", err)
	}
	time.Sleep(2 * time.Millisecond)
	// A TTL that has already passed: the janitor is not running in tests, so
	// the row is still there and the surface must report it as expired, not
	// pending.
	seedSSHCheck(t, s, "check-expired", src, dst, "root", time.Millisecond)
	time.Sleep(5 * time.Millisecond)
	return s, hs, src, dst
}

// TestAPIV2SSHCheckSessions drives GET /api/v2/ssh-check/sessions: derived
// states, peer details, filters (fail-closed), and cursor paging.
func TestAPIV2SSHCheckSessions(t *testing.T) {
	s, hs, src, dst := sshCheckTestServer(t)
	client := noRedirectClient()
	_, readToken := seedAPIKey(t, s, identity.ScopeRead)
	_, writeToken := seedAPIKey(t, s, identity.ScopeWrite)

	base := hs.URL + "/api/v2/ssh-check/sessions"
	if resp := apiRequest(t, client, http.MethodGet, base, "", nil); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("anonymous status = %d, want 401", resp.StatusCode)
	}
	if resp := apiRequest(t, client, http.MethodGet, base, writeToken, nil); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("write-only status = %d, want 403", resp.StatusCode)
	}

	resp := apiRequest(t, client, http.MethodGet, base, readToken, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if cc := resp.Header.Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", cc)
	}
	items, next := decodeSSHCheckPage(t, readBody(t, resp))
	if next != "" {
		t.Errorf("nextCursor = %q, want empty", next)
	}
	if len(items) != 4 {
		t.Fatalf("items = %d, want 4: %+v", len(items), items)
	}
	wantIDs := []string{"check-expired", "check-consumed", "check-accepted", "check-pending"}
	wantStates := []string{"expired", "consumed", "accepted", "pending"}
	wantVerdicts := []string{"pending", "reject", "accept", "pending"}
	for i := range wantIDs {
		if items[i].ID != wantIDs[i] || items[i].State != wantStates[i] || items[i].Verdict != wantVerdicts[i] {
			t.Errorf("items[%d] = %s/%s/%s, want %s/%s/%s", i,
				items[i].ID, items[i].State, items[i].Verdict, wantIDs[i], wantStates[i], wantVerdicts[i])
		}
	}

	pending := items[3]
	if pending.LocalUser != "root" || pending.Src.NodeID != int64(src.ID) || pending.Dst.NodeID != int64(dst.ID) {
		t.Errorf("pending session = %+v", pending)
	}
	if pending.Src.Hostname != "ssh-src" || pending.Src.StableID == "" ||
		pending.Dst.Hostname != "ssh-dst" || pending.Dst.StableID == "" {
		t.Errorf("pending peers = %+v -> %+v", pending.Src, pending.Dst)
	}
	if pending.DecidedAt != nil || pending.DecidedBy != nil || pending.ConsumedAt != nil {
		t.Errorf("pending session has decision fields: %+v", pending)
	}

	accepted := items[2]
	if accepted.DecidedAt == nil || accepted.DecidedBy == nil ||
		accepted.DecidedBy.LoginName != state.DefaultLoginName || accepted.ConsumedAt != nil {
		t.Errorf("accepted session = %+v", accepted)
	}
	consumed := items[1]
	if consumed.ConsumedAt == nil || consumed.DecidedAt == nil {
		t.Errorf("consumed session = %+v", consumed)
	}
	if items[0].ConsumedAt != nil || items[0].DecidedAt != nil {
		t.Errorf("expired session has decision fields: %+v", items[0])
	}

	// Filters are fail-closed: an unknown state is a 400 (the raw verdict
	// "accept" is not a state), and an unknown node matches nothing instead
	// of widening the result.
	for _, path := range []string{
		base + "?state=accept",
		base + "?state=PENDING",
		base + "?cursor=%%%",
		base + "?limit=0",
		base + "?limit=nope",
	} {
		if resp := apiRequest(t, client, http.MethodGet, path, readToken, nil); resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%s status = %d, want 400", path, resp.StatusCode)
		}
	}
	for _, path := range []string{base + "?node=0", base + "?node=nope", base + "?node=999999"} {
		items, _ := decodeSSHCheckPage(t, readBody(t, apiRequest(t, client, http.MethodGet, path, readToken, nil)))
		if len(items) != 0 {
			t.Errorf("%s returned %d sessions, want none", path, len(items))
		}
	}
	for _, path := range []string{
		base + "?node=" + url.QueryEscape(src.StableID),
		base + "?node=" + url.QueryEscape(dst.StableID),
	} {
		items, _ := decodeSSHCheckPage(t, readBody(t, apiRequest(t, client, http.MethodGet, path, readToken, nil)))
		if len(items) != 4 {
			t.Errorf("%s returned %d sessions, want 4", path, len(items))
		}
	}

	items, _ = decodeSSHCheckPage(t, readBody(t, apiRequest(t, client,
		http.MethodGet, base+"?state=pending", readToken, nil)))
	if len(items) != 1 || items[0].ID != "check-pending" {
		t.Errorf("state=pending = %+v", items)
	}
	items, _ = decodeSSHCheckPage(t, readBody(t, apiRequest(t, client,
		http.MethodGet, base+"?state=consumed", readToken, nil)))
	if len(items) != 1 || items[0].ID != "check-consumed" {
		t.Errorf("state=consumed = %+v", items)
	}

	// Cursor paging: limit=3 walks the list in (createdAt, id) order.
	first, cursor := decodeSSHCheckPage(t, readBody(t, apiRequest(t, client,
		http.MethodGet, base+"?limit=3", readToken, nil)))
	if len(first) != 3 || cursor == "" {
		t.Fatalf("first page = %d items, cursor %q", len(first), cursor)
	}
	second, cursor2 := decodeSSHCheckPage(t, readBody(t, apiRequest(t, client,
		http.MethodGet, base+"?limit=3&cursor="+url.QueryEscape(cursor), readToken, nil)))
	if len(second) != 1 || second[0].ID != "check-pending" || cursor2 != "" {
		t.Fatalf("second page = %+v, cursor %q", second, cursor2)
	}
}

// TestListSSHCheckSessionsGRPC checks the gRPC mirror: credentials, filters,
// paging and error mapping.
func TestListSSHCheckSessionsGRPC(t *testing.T) {
	s, _, _, _ := sshCheckTestServer(t)
	client := startGRPCTestServer(t, s.RegisterPlatformGRPC)

	if _, err := client.ListSSHCheckSessions(context.Background(), &xunarav2.ListSSHCheckSessionsRequest{}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("anonymous error = %v, want UNAUTHENTICATED", err)
	}
	_, writeToken := seedAPIKey(t, s, identity.ScopeWrite)
	if _, err := client.ListSSHCheckSessions(grpcCtx(writeToken), &xunarav2.ListSSHCheckSessionsRequest{}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("write-only error = %v, want PERMISSION_DENIED", err)
	}
	_, readToken := seedAPIKey(t, s, identity.ScopeRead)

	out, err := client.ListSSHCheckSessions(grpcCtx(readToken), &xunarav2.ListSSHCheckSessionsRequest{})
	if err != nil {
		t.Fatalf("ListSSHCheckSessions: %v", err)
	}
	if len(out.GetSessions()) != 4 {
		t.Fatalf("sessions = %d, want 4", len(out.GetSessions()))
	}
	first := out.GetSessions()[0]
	if first.GetId() != "check-expired" || first.GetState() != "expired" || first.GetVerdict() != "pending" {
		t.Errorf("first session = %+v", first)
	}
	if first.GetSrc().GetHostname() != "ssh-src" || first.GetDst().GetHostname() != "ssh-dst" {
		t.Errorf("peers = %+v -> %+v", first.GetSrc(), first.GetDst())
	}
	accepted := out.GetSessions()[2]
	if accepted.GetState() != "accepted" || accepted.GetDecidedBy().GetLoginName() != state.DefaultLoginName ||
		accepted.GetDecidedAt() == nil || accepted.GetConsumedAt() != nil {
		t.Errorf("accepted session = %+v", accepted)
	}
	if out.GetSessions()[1].GetConsumedAt() == nil {
		t.Errorf("consumed session lacks consumed_at: %+v", out.GetSessions()[1])
	}

	byState, err := client.ListSSHCheckSessions(grpcCtx(readToken), &xunarav2.ListSSHCheckSessionsRequest{State: "pending"})
	if err != nil {
		t.Fatalf("filtered ListSSHCheckSessions: %v", err)
	}
	if len(byState.GetSessions()) != 1 || byState.GetSessions()[0].GetId() != "check-pending" {
		t.Errorf("state=pending = %+v", byState.GetSessions())
	}
	if _, err := client.ListSSHCheckSessions(grpcCtx(readToken), &xunarav2.ListSSHCheckSessionsRequest{State: "accept"}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("invalid state error = %v, want INVALID_ARGUMENT", err)
	}
	if _, err := client.ListSSHCheckSessions(grpcCtx(readToken), &xunarav2.ListSSHCheckSessionsRequest{PageToken: "%%%"}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("invalid cursor error = %v, want INVALID_ARGUMENT", err)
	}

	page, err := client.ListSSHCheckSessions(grpcCtx(readToken), &xunarav2.ListSSHCheckSessionsRequest{PageSize: 3})
	if err != nil {
		t.Fatalf("paged ListSSHCheckSessions: %v", err)
	}
	if len(page.GetSessions()) != 3 || page.GetNextPageToken() == "" {
		t.Fatalf("page = %d sessions, token %q", len(page.GetSessions()), page.GetNextPageToken())
	}
	page2, err := client.ListSSHCheckSessions(grpcCtx(readToken),
		&xunarav2.ListSSHCheckSessionsRequest{PageSize: 3, PageToken: page.GetNextPageToken()})
	if err != nil {
		t.Fatalf("second ListSSHCheckSessions: %v", err)
	}
	if len(page2.GetSessions()) != 1 || page2.GetSessions()[0].GetId() != "check-pending" || page2.GetNextPageToken() != "" {
		t.Errorf("second page = %+v", page2.GetSessions())
	}
}
