package main

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOAuth2ConfigSecretReferences(test *testing.T) {
	test.Setenv("XUNARA_TEST_OAUTH2_SECRET", "private-fixture-secret")
	path := writeOrgConfig(test, `[{"id":"github","type":"github","client_id":"fixture","client_secret_env":"XUNARA_TEST_OAUTH2_SECRET"}]`)
	providers, err := loadOAuth2ConfigFile(path)
	if err != nil || len(providers) != 1 || providers[0].ClientSecret != "private-fixture-secret" {
		test.Fatalf("environment reference: %v", err)
	}
	secretFile := filepath.Join(test.TempDir(), "oauth-secret")
	if err := os.WriteFile(secretFile, []byte("private-file-secret\n"), 0o600); err != nil {
		test.Fatal(err)
	}
	secret, err := oauth2ClientSecret(oauth2ProviderConfig{ClientSecretFile: secretFile})
	if err != nil || secret != "private-file-secret" {
		test.Fatalf("private file reference: %v", err)
	}
	for _, config := range []oauth2ProviderConfig{
		{}, {ClientSecretEnv: "MISSING_OAUTH2_ENV"}, {ClientSecretFile: "relative"},
		{ClientSecretEnv: "XUNARA_TEST_OAUTH2_SECRET", ClientSecretFile: secretFile},
	} {
		if _, err := oauth2ClientSecret(config); err == nil || strings.Contains(err.Error(), "private-file-secret") || strings.Contains(err.Error(), "private-fixture-secret") {
			test.Fatal("invalid secret reference accepted or leaked")
		}
	}
	link := filepath.Join(test.TempDir(), "symlink")
	if err := os.Symlink(secretFile, link); err != nil {
		test.Fatal(err)
	}
	if _, err := oauth2ClientSecret(oauth2ProviderConfig{ClientSecretFile: link}); err == nil {
		test.Fatal("secret symlink accepted")
	}
	if err := os.Chmod(secretFile, 0o644); err != nil {
		test.Fatal(err)
	}
	if _, err := oauth2ClientSecret(oauth2ProviderConfig{ClientSecretFile: secretFile}); err == nil {
		test.Fatal("world-readable secret accepted")
	}
}

func TestOAuth2ConfigRejectsMalformedPlaintextAndExcess(test *testing.T) {
	for _, doc := range []string{`null`, `[]`, `{}`, `[{`, `[{"client_secret":"do-not-print-this"}]`, `[{}] {}`, strings.Repeat(" ", (1<<20)+1)} {
		if _, err := loadOAuth2ConfigFile(writeOrgConfig(test, doc)); err == nil || strings.Contains(err.Error(), "do-not-print-this") {
			test.Fatal("unsafe configuration accepted or secret printed")
		}
	}
	if _, err := buildOAuth2Configs(make([]oauth2ProviderConfig, 17)); err == nil {
		test.Fatal("unbounded provider list accepted")
	}
	if err := checkOrgScopedFlags([]string{"oauth2-config"}); err == nil {
		test.Fatal("single-tenant OAuth2 flag accepted in org-config mode")
	}
}

func TestOAuth2OrgConfigIsTenantScoped(test *testing.T) {
	test.Setenv("XUNARA_TEST_OAUTH2_SECRET", "private-fixture-secret")
	config := orgConfig{ID: "acme", ServerURL: "https://acme.example", StateDir: test.TempDir(), AllowLocalLogin: true,
		OAuth2: []oauth2ProviderConfig{{ID: "github", Type: "github", ClientID: "fixture", ClientSecretEnv: "XUNARA_TEST_OAUTH2_SECRET"}}}
	encoded, err := json.Marshal(config)
	if err != nil || strings.Contains(string(encoded), "private-fixture-secret") {
		test.Fatal("serialized org config leaked secret")
	}
	sites, err := loadOrgSites(writeOrgConfig(test, `{"organizations":[`+string(encoded)+`]}`), slog.Default())
	if err != nil {
		test.Fatal(err)
	}
	defer sites[0].Server.Close()
	response := httptest.NewRecorder()
	sites[0].Server.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/v1/auth/providers", nil))
	if len(sites) != 1 || response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"id":"github"`) || strings.Contains(response.Body.String(), "private-fixture-secret") {
		test.Fatal("org OAuth2 provider not safely advertised")
	}
}
