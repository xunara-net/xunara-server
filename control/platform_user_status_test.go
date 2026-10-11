package control

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	xunarav2 "github.com/xunara-net/xunara-server/api/gen/xunara/v2"
	"github.com/xunara-net/xunara-server/identity"
	"github.com/xunara-net/xunara-server/state"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"tailscale.com/types/key"
)

func statusAPIRequest(test *testing.T, handler http.Handler, path, token string, body any, cookie *http.Cookie) *httptest.ResponseRecorder {
	test.Helper()
	data, err := json.Marshal(body)
	if err != nil {
		test.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPatch, "http://platform.test"+path, bytes.NewReader(data))
	request.Header.Set("Content-Type", "application/json")
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	if cookie != nil {
		request.AddCookie(cookie)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func statusBody(user identity.User, disabled bool) map[string]any {
	return map[string]any{"disabled": disabled, "reason": "平台核对账号", "expected_updated_at": user.UpdatedAt}
}

func TestPlatformUserStatusAuthorizationCASAndLastOwner(test *testing.T) {
	router, _, platformToken := newAdminTestRouter(test)
	server := router.serverFor("acme")
	memberID := seedRoleUser(test, server, "member", identity.RoleMember)
	member, _ := server.identity.GetUser(memberID)
	owner, _ := server.identity.GetUser(state.DefaultUserID)
	ownerCookie, _ := seedUserSession(test, server, owner.ID)
	serviceToken := seedAPIKeyForUser(test, server, owner.ID)
	path := "/api/platform/v1/organizations/acme/users/" + strconv.FormatUint(uint64(memberID), 10) + "/status"
	for _, credential := range []struct {
		token  string
		cookie *http.Cookie
	}{{}, {cookie: ownerCookie}, {token: serviceToken}} {
		response := statusAPIRequest(test, router.Handler(), path, credential.token, statusBody(member, true), credential.cookie)
		if response.Code != http.StatusUnauthorized {
			test.Fatalf("non-platform credentials changed user status: %d", response.Code)
		}
	}
	for _, scenario := range []struct {
		body     any
		expected int
	}{
		{map[string]any{"disabled": true, "reason": "missing version"}, http.StatusPreconditionRequired},
		{map[string]any{"reason": "missing flag", "expected_updated_at": member.UpdatedAt}, http.StatusBadRequest},
		{map[string]any{"disabled": true, "reason": "", "expected_updated_at": member.UpdatedAt}, http.StatusBadRequest},
		{map[string]any{"disabled": true, "reason": "stale", "expected_updated_at": member.UpdatedAt.Add(time.Nanosecond)}, http.StatusConflict},
		{map[string]any{"disabled": true, "reason": "valid", "expected_updated_at": member.UpdatedAt, "role": "owner"}, http.StatusBadRequest},
	} {
		if response := statusAPIRequest(test, router.Handler(), path, platformToken, scenario.body, nil); response.Code != scenario.expected {
			test.Fatalf("invalid status request: %d, want %d", response.Code, scenario.expected)
		}
	}
	ownerPath := "/api/platform/v1/organizations/acme/users/1/status"
	response := statusAPIRequest(test, router.Handler(), ownerPath, platformToken, statusBody(owner, true), nil)
	if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), "LAST_ACTIVE_OWNER") {
		test.Fatal("last enabled owner could be disabled")
	}
	response = statusAPIRequest(test, router.Handler(), path, platformToken, statusBody(member, true), nil)
	if response.Code != http.StatusOK || response.Header().Get("Cache-Control") != "no-store" {
		test.Fatalf("valid status update: %d", response.Code)
	}
	if response := statusAPIRequest(test, router.Handler(), path, platformToken, statusBody(member, false), nil); response.Code != http.StatusConflict {
		test.Fatal("stale enable overwrote the disable")
	}
	listing := platformAPIRequest(test, router.Handler(), http.MethodGet, "/api/platform/v1/users", platformToken)
	var payload struct {
		Users []platformUser `json:"users"`
	}
	if err := json.Unmarshal(listing.Body.Bytes(), &payload); err != nil || len(payload.Users) != 2 {
		test.Fatal("could not read platform account states")
	}
	if row := payload.Users[1]; !row.Disabled || row.DisabledAt == nil || row.DisabledReason != "平台核对账号" || !row.UpdatedAt.After(member.UpdatedAt) {
		test.Fatal("platform list lost status or CAS revision")
	}
	members := accountRequest(test, server, http.MethodGet, "/api/v1/users", nil, ownerCookie, nil)
	var tenantPayload struct {
		Users []apiUser `json:"users"`
	}
	if err := json.Unmarshal(members.Body.Bytes(), &tenantPayload); err != nil || len(tenantPayload.Users) != 2 || !tenantPayload.Users[1].Disabled || tenantPayload.Users[1].DisabledAt == nil {
		test.Fatal("tenant members lost the read-only disabled status")
	}
	if strings.Contains(members.Body.String(), "平台核对账号") || strings.Contains(members.Body.String(), "disabledReason") {
		test.Fatal("platform status reason leaked into the tenant member API")
	}
}

func TestPlatformUserStatusBlocksHumanAndDelegatedAuthorization(test *testing.T) {
	server := newServerWithConfig(test, Config{AllowLocalLogin: true})
	memberID := seedRoleUser(test, server, "member", identity.RoleAdmin)
	member, _ := server.identity.GetUser(memberID)
	credential, err := server.identity.LookupLocalCredential(test.Context(), state.DefaultUserID)
	if err != nil {
		test.Fatal(err)
	}
	if err := server.identity.SetLocalCredential(&identity.LocalCredential{UserID: memberID, PasswordHash: credential.PasswordHash}); err != nil {
		test.Fatal(err)
	}
	cookie, sessionToken := seedUserSession(test, server, memberID)
	serviceToken := seedAPIKeyForUser(test, server, memberID)
	grpcClient := startGRPCTestServer(test, server.RegisterPlatformGRPC)
	if _, err := grpcClient.GetMeta(grpcCtx(serviceToken), &xunarav2.GetMetaRequest{}); err != nil {
		test.Fatal("active account service key did not work")
	}
	node := state.Node{UserID: memberID, MachineKey: key.NewMachine().Public(), NodeKey: key.NewNode().Public(), Method: state.RegisterMethodInteractive}
	if err := server.store.CreateNode(&node); err != nil {
		test.Fatal(err)
	}
	before := server.store.ListNodes()
	if _, err := server.identity.SetUserStatusByPlatform(test.Context(), memberID, identity.UserStatusChange{Disabled: true, Reason: "测试停用", ExpectedUpdatedAt: member.UpdatedAt}); err != nil {
		test.Fatal(err)
	}
	for _, token := range []string{sessionToken, serviceToken} {
		if _, err := grpcClient.GetMeta(grpcCtx(token), &xunarav2.GetMetaRequest{}); status.Code(err) != codes.Unauthenticated {
			test.Fatal("disabled account retained gRPC authorization")
		}
		request := httptest.NewRequest(http.MethodGet, "/api/v1/users", nil)
		request.Header.Set("Authorization", "Bearer "+token)
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, request)
		if response.Code != http.StatusUnauthorized {
			test.Fatalf("disabled bearer still authorized: %d", response.Code)
		}
	}
	request := httptest.NewRequest(http.MethodGet, "/console", nil)
	request.AddCookie(cookie)
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusFound || !strings.HasPrefix(response.Header().Get("Location"), "/login") {
		test.Fatal("disabled cookie reached the HTML console")
	}
	login := accountRequest(test, server, http.MethodPost, "/api/v1/auth/login", apiLoginRequest{Login: member.LoginName, Password: testLocalPassword}, nil, nil)
	if login.Code != http.StatusUnauthorized || strings.Contains(strings.ToLower(login.Body.String()), "disabled") || len(login.Result().Cookies()) != 0 {
		test.Fatal("disabled password login exposed status or issued a cookie")
	}
	if !reflect.DeepEqual(before, server.store.ListNodes()) {
		test.Fatal("disabling a human changed machine identity")
	}
	if persisted, err := server.identity.GetAPIKeyByToken(serviceToken); err != nil || !persisted.RevokedAt.IsZero() {
		test.Fatal("human status implicitly revoked independent service credentials")
	}
	disabled, _ := server.identity.GetUser(memberID)
	if _, err := server.identity.SetUserStatusByPlatform(test.Context(), memberID, identity.UserStatusChange{Reason: "重新启用", ExpectedUpdatedAt: disabled.UpdatedAt}); err != nil {
		test.Fatal(err)
	}
	if _, err := grpcClient.GetMeta(grpcCtx(sessionToken), &xunarav2.GetMetaRequest{}); status.Code(err) != codes.Unauthenticated {
		test.Fatal("re-enable restored an old session")
	}
	if _, err := grpcClient.GetMeta(grpcCtx(serviceToken), &xunarav2.GetMetaRequest{}); err != nil {
		test.Fatal("re-enabled account could not use a still-valid delegated service key")
	}
	login = accountRequest(test, server, http.MethodPost, "/api/v1/auth/login", apiLoginRequest{Login: member.LoginName, Password: testLocalPassword}, nil, nil)
	if login.Code != http.StatusOK || len(login.Result().Cookies()) != 1 {
		test.Fatal("re-enabled account could not sign in afresh")
	}
}

func TestPlatformUserStatusTenantBoundaryAndStorageFailure(test *testing.T) {
	router, _, token := newAdminTestRouter(test)
	first := router.serverFor("acme")
	firstID := seedRoleUser(test, first, "member", identity.RoleMember)
	member, _ := first.identity.GetUser(firstID)
	other, err := router.CreateManagedOrg(test.Context(), ManagedOrg{ID: "other", Name: "Other", Domains: []string{"other.test"}, ServerURL: "http://other.test"})
	if err != nil {
		test.Fatal(err)
	}
	secondID := seedRoleUser(test, other.Server, "member", identity.RoleMember)
	if firstID != secondID {
		test.Fatal("fixture needs matching local IDs in distinct tenants")
	}
	path := "/api/platform/v1/organizations/acme/users/" + strconv.FormatUint(uint64(firstID), 10) + "/status"
	if response := statusAPIRequest(test, router.Handler(), path, token, statusBody(member, true), nil); response.Code != http.StatusOK {
		test.Fatal("could not disable target tenant member")
	}
	peer, _ := other.Server.identity.GetUser(secondID)
	if !peer.DisabledAt.IsZero() {
		test.Fatal("account status crossed the tenant boundary")
	}
	database := first.store.(*state.SQLiteStore).DB()
	if _, err := database.Exec("ALTER TABLE users RENAME TO unavailable_status_users"); err != nil {
		test.Fatal(err)
	}
	response := platformAPIRequest(test, router.Handler(), http.MethodGet, "/api/platform/v1/users", token)
	if response.Code != http.StatusServiceUnavailable || strings.Contains(response.Body.String(), "unavailable_status_users") {
		test.Fatal("unreadable accounts appeared as an empty or enabled list")
	}
	if response := statusAPIRequest(test, router.Handler(), path, token, statusBody(member, false), nil); response.Code != http.StatusServiceUnavailable {
		test.Fatal("unreadable status did not fail closed")
	}
}
