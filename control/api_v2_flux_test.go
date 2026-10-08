package control

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	xunarav2 "github.com/xunara-net/xunara-server/api/gen/xunara/v2"
	"github.com/xunara-net/xunara-server/identity"
	"github.com/xunara-net/xunara-server/state"
)

// fluxAdminPage decodes one management listing.
func fluxAdminPage(t *testing.T, resp *http.Response) ([]fluxAdminTransfer, string) {
	t.Helper()

	var page struct {
		Items      []fluxAdminTransfer `json:"items"`
		NextCursor string              `json:"nextCursor"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&page); err != nil {
		t.Fatalf("decoding the flux listing: %v", err)
	}
	return page.Items, page.NextCursor
}

// offerFlux stores one pending transfer through the agent API and returns its
// ID and the ciphertext the sender would upload.
func offerFlux(t *testing.T, hs *httptest.Server, sender, recipient enrolledServiceAgent, name string, plaintext []byte) (string, []byte) {
	t.Helper()
	sum := sha256.Sum256(plaintext)
	raw, status := sender.doFlux(t, hs.Client(), http.MethodPost, hs.URL+"/api/agent/v1/flux/transfers",
		mustJSON(t, map[string]any{
			"recipient": recipient.node.StableID,
			"name":      name,
			"size":      len(plaintext),
			"sha256":    hex.EncodeToString(sum[:]),
		}), "application/json")
	if status != http.StatusCreated {
		t.Fatalf("creating a flux offer = %d (%s)", status, brief(raw))
	}
	ciphertext := make([]byte, len(plaintext)+60)
	if _, err := rand.Read(ciphertext); err != nil {
		t.Fatalf("generating ciphertext: %v", err)
	}
	return decodeJSON[fluxTransferView](t, raw).ID, ciphertext
}

// TestAPIV2FluxManagement drives the read-only Flux management surface: list
// with filters and cursors, detail, and the guarantee that neither content
// nor key material appears anywhere.
func TestAPIV2FluxManagement(t *testing.T) {
	s := newServerWithConfig(t, Config{Flux: &FluxConfig{}})
	hs := newTestHTTPServer(t, s)
	client := noRedirectClient()
	_, readToken := seedAPIKey(t, s, identity.ScopeRead)
	_, writeToken := seedAPIKey(t, s, identity.ScopeWrite)

	sender := enrollServiceAgent(t, s, hs, "flux-sender")
	recipient := enrollServiceAgent(t, s, hs, "flux-recipient")
	bystander := enrollServiceAgent(t, s, hs, "flux-bystander")

	// One transfer runs all the way to "uploaded"; a bystander cannot read
	// its content through the agent API, and the management plane never can.
	uploadedID, ciphertext := offerFlux(t, hs, sender, recipient, "notes.txt", []byte("flux payload"))
	if _, status := recipient.doFlux(t, hs.Client(), http.MethodPost,
		hs.URL+"/api/agent/v1/flux/transfers/"+uploadedID+"/accept",
		mustJSON(t, map[string]any{"publicKey": base64.StdEncoding.EncodeToString(make([]byte, 32))}),
		"application/json"); status != http.StatusOK {
		t.Fatalf("accept = %d", status)
	}
	if _, status := sender.doFlux(t, hs.Client(), http.MethodPut,
		hs.URL+"/api/agent/v1/flux/transfers/"+uploadedID+"/content", ciphertext, "application/octet-stream"); status != http.StatusOK {
		t.Fatalf("upload = %d", status)
	}

	// A second transfer is refused with a static reason.
	deniedID, _ := offerFlux(t, hs, bystander, recipient, "private.bin", []byte("nope"))
	if _, status := recipient.doFlux(t, hs.Client(), http.MethodPost,
		hs.URL+"/api/agent/v1/flux/transfers/"+deniedID+"/deny",
		mustJSON(t, map[string]any{"reason": "not expected"}), "application/json"); status != http.StatusOK {
		t.Fatalf("deny = %d", status)
	}

	base := hs.URL + "/api/v2/flux/transfers"
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
	raw := readBody(t, resp)
	var page struct {
		Items      []fluxAdminTransfer `json:"items"`
		NextCursor string              `json:"nextCursor"`
	}
	if err := json.Unmarshal(raw, &page); err != nil {
		t.Fatalf("decoding the flux listing: %v (%s)", err, raw)
	}
	items := page.Items
	if len(items) != 2 {
		t.Fatalf("list = %+v", items)
	}
	byID := map[string]fluxAdminTransfer{}
	for _, item := range items {
		byID[item.ID] = item
	}
	uploaded, ok := byID[uploadedID]
	if !ok {
		t.Fatalf("uploaded transfer missing from %+v", items)
	}
	if uploaded.State != string(state.FluxUploaded) || uploaded.Name != "notes.txt" || uploaded.Size != int64(len("flux payload")) {
		t.Errorf("uploaded transfer = %+v", uploaded)
	}
	if uploaded.Sender.StableID != sender.node.StableID || uploaded.Recipient.StableID != recipient.node.StableID {
		t.Errorf("participants = %+v / %+v", uploaded.Sender, uploaded.Recipient)
	}
	payloadSum := sha256.Sum256([]byte("flux payload"))
	if uploaded.SHA256 != hex.EncodeToString(payloadSum[:]) {
		t.Errorf("sha256 = %q", uploaded.SHA256)
	}
	if refused := byID[deniedID]; refused.State != string(state.FluxDenied) || refused.Reason != "not expected" {
		t.Errorf("denied transfer = %+v", refused)
	}

	// The management body never carries the ciphertext, the recipient's key
	// or a content path; the recipient key is base64 in the agent view, so a
	// base64 hit would be a leak.
	for _, secret := range []string{"recipientKey", base64.StdEncoding.EncodeToString(ciphertext), "flux/"} {
		if strings.Contains(string(raw), secret) {
			t.Errorf("management listing leaks %q:\n%s", secret, raw)
		}
	}
	// There is no content endpoint on the management surface at all.
	if resp := apiRequest(t, client, http.MethodGet, base+"/"+uploadedID+"/content", readToken, nil); resp.StatusCode != http.StatusNotFound {
		t.Errorf("management content endpoint = %d, want 404", resp.StatusCode)
	}

	// Filters are fail-closed.
	resp = apiRequest(t, client, http.MethodGet, base+"?state=denied", readToken, nil)
	if items, _ := fluxAdminPage(t, resp); len(items) != 1 || items[0].ID != deniedID {
		t.Errorf("state filter = %+v", items)
	}
	if resp := apiRequest(t, client, http.MethodGet, base+"?state=nonsense", readToken, nil); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("unknown state = %d, want 400", resp.StatusCode)
	}
	resp = apiRequest(t, client, http.MethodGet, base+"?node="+sender.node.StableID, readToken, nil)
	if items, _ := fluxAdminPage(t, resp); len(items) != 1 || items[0].ID != uploadedID {
		t.Errorf("node filter = %+v", items)
	}
	resp = apiRequest(t, client, http.MethodGet, base+"?node=n0000000000000000", readToken, nil)
	if items, _ := fluxAdminPage(t, resp); len(items) != 0 {
		t.Errorf("unknown node filter returned %+v", items)
	}
	// "0" is not a node ID: it must match nothing, never mean "no filter".
	resp = apiRequest(t, client, http.MethodGet, base+"?node=0", readToken, nil)
	if items, _ := fluxAdminPage(t, resp); len(items) != 0 {
		t.Errorf("node=0 returned %+v, want nothing", items)
	}
	if resp := apiRequest(t, client, http.MethodGet, base+"?limit=bogus", readToken, nil); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("bad limit = %d, want 400", resp.StatusCode)
	}
	if resp := apiRequest(t, client, http.MethodGet, base+"?cursor=YWJj", readToken, nil); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("wrong-kind cursor = %d, want 400", resp.StatusCode)
	}

	// Cursor pagination neither drops nor repeats rows.
	first, cursor := fluxAdminPage(t, apiRequest(t, client, http.MethodGet, base+"?limit=1", readToken, nil))
	if len(first) != 1 || cursor == "" {
		t.Fatalf("first page = %+v (cursor %q)", first, cursor)
	}
	second, _ := fluxAdminPage(t, apiRequest(t, client, http.MethodGet, base+"?limit=1&cursor="+cursor, readToken, nil))
	if len(second) != 1 || second[0].ID == first[0].ID {
		t.Fatalf("second page = %+v after %+v", second, first)
	}

	// Detail resolves one transfer; unknown IDs are 404.
	detail := apiRequest(t, client, http.MethodGet, base+"/"+uploadedID, readToken, nil)
	if detail.StatusCode != http.StatusOK {
		t.Fatalf("detail = %d, want 200", detail.StatusCode)
	}
	if view := decodeJSON[fluxAdminTransfer](t, readBody(t, detail)); view.ID != uploadedID || view.State != string(state.FluxUploaded) {
		t.Errorf("detail = %+v", view)
	}
	if resp := apiRequest(t, client, http.MethodGet, base+"/nosuchtransfer", readToken, nil); resp.StatusCode != http.StatusNotFound {
		t.Errorf("unknown transfer = %d, want 404", resp.StatusCode)
	}
}

// TestAPIV2FluxDisabled checks that a deployment without Flux hides the whole
// surface behind 404, like the agent endpoints.
func TestAPIV2FluxDisabled(t *testing.T) {
	s := newTestServer(t)
	hs := newTestHTTPServer(t, s)
	client := noRedirectClient()
	_, readToken := seedAPIKey(t, s, identity.ScopeRead)

	for _, path := range []string{"/api/v2/flux/transfers", "/api/v2/flux/transfers/fx_abc"} {
		if resp := apiRequest(t, client, http.MethodGet, hs.URL+path, readToken, nil); resp.StatusCode != http.StatusNotFound {
			t.Errorf("GET %s with flux disabled = %d, want 404", path, resp.StatusCode)
		}
	}
}

// TestPlatformGRPCFluxTransfers mirrors the HTTP surface on the typed API.
func TestPlatformGRPCFluxTransfers(t *testing.T) {
	s := newServerWithConfig(t, Config{Flux: &FluxConfig{}})
	hs := newTestHTTPServer(t, s)
	_, readToken := seedAPIKey(t, s, identity.ScopeRead)
	_, writeToken := seedAPIKey(t, s, identity.ScopeWrite)
	client := startGRPCTestServer(t, s.RegisterPlatformGRPC)

	sender := enrollServiceAgent(t, s, hs, "flux-sender")
	recipient := enrollServiceAgent(t, s, hs, "flux-recipient")
	uploadedID, ciphertext := offerFlux(t, hs, sender, recipient, "report.bin", []byte("payload"))
	if _, status := recipient.doFlux(t, hs.Client(), http.MethodPost,
		hs.URL+"/api/agent/v1/flux/transfers/"+uploadedID+"/accept",
		mustJSON(t, map[string]any{"publicKey": base64.StdEncoding.EncodeToString(make([]byte, 32))}),
		"application/json"); status != http.StatusOK {
		t.Fatalf("accept = %d", status)
	}
	if _, status := sender.doFlux(t, hs.Client(), http.MethodPut,
		hs.URL+"/api/agent/v1/flux/transfers/"+uploadedID+"/content", ciphertext, "application/octet-stream"); status != http.StatusOK {
		t.Fatalf("upload = %d", status)
	}
	deniedID, _ := offerFlux(t, hs, sender, recipient, "drop.bin", []byte("x"))
	if _, status := recipient.doFlux(t, hs.Client(), http.MethodPost,
		hs.URL+"/api/agent/v1/flux/transfers/"+deniedID+"/deny",
		mustJSON(t, map[string]any{"reason": "no space"}), "application/json"); status != http.StatusOK {
		t.Fatalf("deny = %d", status)
	}

	if _, err := client.ListFluxTransfers(context.Background(), &xunarav2.ListFluxTransfersRequest{}); status.Code(err) != codes.Unauthenticated {
		t.Errorf("anonymous error = %v, want Unauthenticated", err)
	}
	if _, err := client.ListFluxTransfers(grpcCtx(writeToken), &xunarav2.ListFluxTransfersRequest{}); status.Code(err) != codes.PermissionDenied {
		t.Errorf("write-only error = %v, want PermissionDenied", err)
	}

	list, err := client.ListFluxTransfers(grpcCtx(readToken), &xunarav2.ListFluxTransfersRequest{})
	if err != nil {
		t.Fatalf("ListFluxTransfers: %v", err)
	}
	if len(list.GetTransfers()) != 2 {
		t.Fatalf("transfers = %+v", list.GetTransfers())
	}
	byID := map[string]*xunarav2.FluxTransfer{}
	for _, transfer := range list.GetTransfers() {
		byID[transfer.GetId()] = transfer
	}
	uploaded := byID[uploadedID]
	if uploaded == nil {
		t.Fatalf("uploaded transfer missing from %+v", list.GetTransfers())
	}
	if uploaded.GetState() != string(state.FluxUploaded) || uploaded.GetName() != "report.bin" ||
		uploaded.GetSize() != int64(len("payload")) ||
		uploaded.GetSender().GetStableId() != sender.node.StableID ||
		uploaded.GetRecipient().GetStableId() != recipient.node.StableID {
		t.Errorf("uploaded transfer = %+v", uploaded)
	}
	if refused := byID[deniedID]; refused.GetState() != string(state.FluxDenied) || refused.GetReason() != "no space" {
		t.Errorf("denied transfer = %+v", refused)
	}

	// Filters and pagination follow the HTTP rules.
	filtered, err := client.ListFluxTransfers(grpcCtx(readToken), &xunarav2.ListFluxTransfersRequest{State: "denied"})
	if err != nil || len(filtered.GetTransfers()) != 1 || filtered.GetTransfers()[0].GetId() != deniedID {
		t.Errorf("state filter = %+v (%v)", filtered.GetTransfers(), err)
	}
	if _, err := client.ListFluxTransfers(grpcCtx(readToken), &xunarav2.ListFluxTransfersRequest{State: "nonsense"}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("unknown state error = %v, want InvalidArgument", err)
	}
	zeroNode, err := client.ListFluxTransfers(grpcCtx(readToken), &xunarav2.ListFluxTransfersRequest{Node: "0"})
	if err != nil || len(zeroNode.GetTransfers()) != 0 {
		t.Errorf("node=0 = %+v (%v), want nothing", zeroNode.GetTransfers(), err)
	}
	first, err := client.ListFluxTransfers(grpcCtx(readToken), &xunarav2.ListFluxTransfersRequest{PageSize: 1})
	if err != nil || len(first.GetTransfers()) != 1 || first.GetNextPageToken() == "" {
		t.Fatalf("first page = %+v (%v)", first.GetTransfers(), err)
	}
	second, err := client.ListFluxTransfers(grpcCtx(readToken), &xunarav2.ListFluxTransfersRequest{PageSize: 1, PageToken: first.GetNextPageToken()})
	if err != nil || len(second.GetTransfers()) != 1 || second.GetTransfers()[0].GetId() == first.GetTransfers()[0].GetId() {
		t.Errorf("second page = %+v (%v)", second.GetTransfers(), err)
	}
	if _, err := client.ListFluxTransfers(grpcCtx(readToken), &xunarav2.ListFluxTransfersRequest{PageToken: "not-a-cursor"}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("bad page token error = %v, want InvalidArgument", err)
	}

	// Detail, and the disabled case answers NOT_FOUND.
	detail, err := client.GetFluxTransfer(grpcCtx(readToken), &xunarav2.GetFluxTransferRequest{Id: uploadedID})
	if err != nil || detail.GetId() != uploadedID {
		t.Fatalf("GetFluxTransfer = %+v (%v)", detail, err)
	}
	if _, err := client.GetFluxTransfer(grpcCtx(readToken), &xunarav2.GetFluxTransferRequest{Id: "nosuch"}); status.Code(err) != codes.NotFound {
		t.Errorf("unknown transfer error = %v, want NotFound", err)
	}

	off := newTestServer(t)
	_, offToken := seedAPIKey(t, off, identity.ScopeRead)
	offClient := startGRPCTestServer(t, off.RegisterPlatformGRPC)
	if _, err := offClient.ListFluxTransfers(grpcCtx(offToken), &xunarav2.ListFluxTransfersRequest{}); status.Code(err) != codes.NotFound {
		t.Errorf("disabled list error = %v, want NotFound", err)
	}
	if _, err := offClient.GetFluxTransfer(grpcCtx(offToken), &xunarav2.GetFluxTransferRequest{Id: uploadedID}); status.Code(err) != codes.NotFound {
		t.Errorf("disabled get error = %v, want NotFound", err)
	}
}
