package control

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xunara-net/xunara-server/identity"
)

func authenticationSettingsRequest(test *testing.T, server *Server, method, path string, body any, token string) *httptest.ResponseRecorder {
	test.Helper()
	return accountRequest(test, server, method, path, body, nil, map[string]string{"Authorization": "Bearer " + token, "X-CSRF-Token": csrfTokenFor(token), "If-Match": "3"})
}

func TestRuntimeAuthenticationProviderPersistenceRotationAndArchive(test *testing.T) {
	server := newServerWithConfig(test, Config{ServerURL: "https://app.example.test"})
	token := inviteOwnerToken(test, server)
	endpoint := "/api/v1/authentication/providers"
	body := map[string]any{"revision": 0, "id": "github-main", "type": "github", "display_name": "GitHub 账号", "client_id": "app-client-id", "client_secret": "client-secret-never-return", "enabled": true}
	created := authenticationSettingsRequest(test, server, http.MethodPost, endpoint, body, token)
	if created.Code != http.StatusCreated || strings.Contains(created.Body.String(), "client-secret-never-return") || strings.Contains(created.Body.String(), "sealed_secret") || !strings.Contains(created.Body.String(), "secret_configured") {
		test.Fatalf("provider creation: %d %s", created.Code, created.Body.String())
	}
	saved, err := server.identity.ReadAuthenticationConfig(test.Context())
	if err != nil || saved.Revision != 1 || strings.Contains(string(saved.Payload), "client-secret-never-return") || !strings.Contains(string(saved.Payload), "v1:") {
		test.Fatal("client secret was not encrypted at rest")
	}
	key, err := os.Stat(filepath.Join(server.cfg.StateDir, "authentication_secret.key"))
	if err != nil || key.Mode().Perm() != 0o600 {
		test.Fatal("provider sealing key is not private")
	}
	peer, err := New(server.cfg)
	if err != nil {
		test.Fatal(err)
	}
	defer peer.Close()
	if _, exists := peer.identityProviders().Get("github-main"); !exists || peer.providerRedirect("github-main") != "https://app.example.test/oauth2/callback/github-main" {
		test.Fatal("restart lost the runtime provider or callback")
	}
	changed := authenticationSettingsRequest(test, server, http.MethodPatch, endpoint+"/github-main", map[string]any{"revision": 1, "client_secret": "rotated-secret-never-return"}, token)
	if changed.Code != http.StatusOK || strings.Contains(changed.Body.String(), "rotated-secret-never-return") {
		test.Fatal("secret rotation failed or leaked its value")
	}
	if response := authenticationSettingsRequest(test, server, http.MethodPatch, endpoint+"/github-main", map[string]any{"revision": 1, "enabled": false}, token); response.Code != http.StatusConflict {
		test.Fatal("stale configuration overwrote the provider")
	}
	if response := authenticationSettingsRequest(test, server, http.MethodPatch, endpoint+"/github-main", map[string]any{"revision": 2, "client_id": "other-realm"}, token); response.Code != http.StatusBadRequest {
		test.Fatal("provider identity realm was changed")
	}
	if response := authenticationSettingsRequest(test, server, http.MethodPatch, endpoint+"/github-main", map[string]any{"revision": 2, "enabled": false}, token); response.Code != http.StatusOK {
		test.Fatal("provider disable failed")
	}
	listed := authenticationSettingsRequest(test, peer, http.MethodGet, "/api/v1/authentication/settings", nil, token)
	if listed.Code != http.StatusOK || peer.authenticationRevision() != 3 {
		test.Fatal("second instance did not refresh its configuration")
	}
	if _, exists := peer.identityProviders().Get("github-main"); exists {
		test.Fatal("disabled provider remained usable on a second instance")
	}
	if response := authenticationSettingsRequest(test, server, http.MethodDelete, endpoint+"/github-main", nil, token); response.Code != http.StatusOK {
		test.Fatalf("provider archive: %d %s", response.Code, response.Body.String())
	}
	body["revision"] = 4
	if response := authenticationSettingsRequest(test, server, http.MethodPost, endpoint, body, token); response.Code != http.StatusConflict {
		test.Fatal("archived provider ID was reused for a different identity realm")
	}
	for _, event := range server.identity.ListAudit(0) {
		if strings.Contains(event.Detail, "secret-never-return") {
			test.Fatal("secret leaked into the audit log")
		}
	}
}

func TestRuntimeAuthenticationPolicyInvitationsAndOwnerBoundary(test *testing.T) {
	server := newServerWithConfig(test, Config{Registration: RegistrationClosed})
	token := inviteOwnerToken(test, server)
	endpoint := "/api/v1/authentication/settings"
	if denied := accountRequest(test, server, http.MethodPatch, endpoint, map[string]any{"revision": 0, "registration": "invite"}, nil, map[string]string{"Authorization": "Bearer " + token}); denied.Code != http.StatusForbidden {
		test.Fatal("authentication policy changed without CSRF")
	}
	response := authenticationSettingsRequest(test, server, http.MethodPatch, endpoint, map[string]any{"revision": 0, "registration": "invite"}, token)
	if response.Code != http.StatusOK {
		test.Fatalf("policy change: %d %s", response.Code, response.Body.String())
	}
	invite := authenticationSettingsRequest(test, server, http.MethodPost, "/api/v1/member-invitations", memberInviteRequest{Role: "member", TTLHours: 1}, token)
	if invite.Code != http.StatusCreated {
		test.Fatalf("enabled invitations: %d %s", invite.Code, invite.Body.String())
	}
	if response := authenticationSettingsRequest(test, server, http.MethodPatch, endpoint, map[string]any{"revision": 1, "registration": "closed"}, token); response.Code != http.StatusOK {
		test.Fatal("policy close failed")
	}
	listed := authenticationSettingsRequest(test, server, http.MethodGet, "/api/v1/member-invitations", nil, token)
	if listed.Code != http.StatusOK || !strings.Contains(listed.Body.String(), `"enabled":false`) || len(server.identity.ListRegistrationInvites()) != 1 {
		test.Fatal("closing invitations lost their history")
	}
	memberID := seedRoleUser(test, server, "administrator", identity.RoleAdmin)
	_, memberToken := seedUserSession(test, server, memberID)
	if response := authenticationSettingsRequest(test, server, http.MethodGet, endpoint, nil, memberToken); response.Code != http.StatusForbidden {
		test.Fatal("non-owner read privileged authentication configuration")
	}
	if response := authenticationSettingsRequest(test, server, http.MethodPatch, endpoint, map[string]any{"revision": 2, "public_signup_enabled": false}, token); response.Code != http.StatusForbidden {
		test.Fatal("tenant owner changed the platform signup policy")
	}
}

func TestRuntimeOIDCPublicClientConfiguration(test *testing.T) {
	server := newServerWithConfig(test, Config{ServerURL: "https://app.example.test"})
	token := inviteOwnerToken(test, server)
	endpoint := "/api/v1/authentication/providers"
	body := map[string]any{"revision": 0, "id": "public-oidc", "type": "oidc", "display_name": "OIDC 公共客户端", "client_id": "public-client", "issuer": "https://issuer.example.test", "enabled": true}
	created := authenticationSettingsRequest(test, server, http.MethodPost, endpoint, body, token)
	if created.Code != http.StatusCreated {
		test.Fatalf("public client creation: %d %s", created.Code, created.Body.String())
	}
	var payload struct {
		Providers []struct {
			SecretConfigured bool `json:"secret_configured"`
		} `json:"providers"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &payload); err != nil || len(payload.Providers) != 1 || payload.Providers[0].SecretConfigured {
		test.Fatal("public client falsely reports a stored secret")
	}
	if _, err := os.Stat(filepath.Join(server.cfg.StateDir, "authentication_secret.key")); !os.IsNotExist(err) {
		test.Fatal("public client created an unnecessary sealing key")
	}
	peer, err := New(server.cfg)
	if err != nil {
		test.Fatal(err)
	}
	defer peer.Close()
	if _, exists := peer.identityProviders().Get("public-oidc"); !exists {
		test.Fatal("public client did not survive restart without a secret")
	}
	for _, change := range []struct {
		revision uint64
		secret   string
	}{{1, "confidential-oidc-secret"}, {2, ""}} {
		response := authenticationSettingsRequest(test, server, http.MethodPatch, endpoint+"/public-oidc", map[string]any{"revision": change.revision, "client_secret": change.secret}, token)
		if response.Code != http.StatusOK {
			test.Fatal("OIDC client secret configuration transition failed")
		}
	}
	saved, err := server.identity.ReadAuthenticationConfig(test.Context())
	var config authenticationConfiguration
	if err != nil || json.Unmarshal(saved.Payload, &config) != nil || config.Providers[0].SealedSecret != "" {
		test.Fatal("public client retained the removed confidential secret")
	}
	denied := authenticationSettingsRequest(test, server, http.MethodPost, endpoint, map[string]any{"revision": 3, "id": "github-without-secret", "type": "github", "client_id": "client", "enabled": false}, token)
	if denied.Code != http.StatusBadRequest {
		test.Fatal("OAuth2 application silently accepted missing server credentials")
	}
}

func TestRuntimeAuthenticationRejectsUnsafeProviderConfiguration(test *testing.T) {
	server := newServerWithConfig(test, Config{ServerURL: "https://app.example.test"})
	token := inviteOwnerToken(test, server)
	for _, issuer := range []string{"http://issuer.example.com", "https://127.0.0.1", "https://169.254.169.254", "https://user:secret@issuer.example.com", "https://issuer.example.com?client_secret=unsafe"} {
		response := authenticationSettingsRequest(test, server, http.MethodPost, "/api/v1/authentication/providers", map[string]any{"revision": 0, "id": "oidc-main", "type": "oidc", "client_id": "client", "issuer": issuer, "enabled": true}, token)
		if response.Code != http.StatusBadRequest {
			test.Fatalf("unsafe issuer accepted: %d", response.Code)
		}
	}
	for _, body := range []map[string]any{
		{"revision": 0, "id": "local", "type": "oidc", "client_id": "client", "issuer": "https://issuer.example.com"},
		{"revision": 0, "id": "oidc-main", "type": "oidc", "client_id": "client", "issuer": "https://issuer.example.com", "client_secret_file": "/etc/passwd"},
	} {
		response := authenticationSettingsRequest(test, server, http.MethodPost, "/api/v1/authentication/providers", body, token)
		if response.Code != http.StatusBadRequest && response.Code != http.StatusConflict {
			test.Fatal("reserved provider ID or server file reference accepted")
		}
	}
}

func TestRuntimeAuthenticationSignupDeskPolicyIsIndependent(test *testing.T) {
	router, _ := selfServiceRouter(test, &SelfServiceConfig{DomainSuffix: "xunara.test", CookieDomain: "xunara.test"})
	server := router.serverFor("portal")
	token := inviteOwnerToken(test, server)
	response := authenticationSettingsRequest(test, server, http.MethodPatch, "/api/v1/authentication/settings", map[string]any{"revision": 0, "registration": "invite"}, token)
	if response.Code != http.StatusOK || server.registrationMode() != RegistrationOpen {
		test.Fatalf("member invite policy closed public signup: %d %s", response.Code, response.Body.String())
	}
	if response := authenticationSettingsRequest(test, server, http.MethodPatch, "/api/v1/authentication/settings", map[string]any{"revision": 1, "registration": "open"}, token); response.Code != http.StatusBadRequest {
		test.Fatal("signup desk allowed anonymous shared-network membership")
	}
	request := httptest.NewRequest(http.MethodPatch, "http://app.xunara.test/api/platform/v1/organizations/portal/authentication/settings", strings.NewReader(`{"revision":1,"public_signup_enabled":false}`))
	request.Header.Set("Authorization", "Bearer self-service-platform-token")
	request.Header.Set("Content-Type", "application/json")
	closed := httptest.NewRecorder()
	router.Handler().ServeHTTP(closed, request)
	if closed.Code != http.StatusOK {
		test.Fatalf("platform signup switch: %d %s", closed.Code, closed.Body.String())
	}
	created := postJSONAtHost(test, router.Handler(), "app.xunara.test", selfServiceSignupPath, selfServiceRequest{Login: "not-created", Password: "fixture-password-safe"})
	if created.Code != http.StatusForbidden || len(router.orgSnapshot()) != 2 {
		test.Fatal("closed public signup created a tenant")
	}
	methods := accountRequest(test, server, http.MethodGet, "/api/v1/auth/providers", nil, nil, nil)
	var payload struct {
		Registration       string `json:"registration"`
		MemberRegistration string `json:"member_registration"`
	}
	if err := json.Unmarshal(methods.Body.Bytes(), &payload); err != nil || payload.Registration != "closed" || payload.MemberRegistration != "invite" {
		test.Fatal("public provider payload merged member and tenant registration policies")
	}
}
