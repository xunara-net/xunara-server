package control

import (
	"slices"
	"strings"
	"testing"

	"github.com/xunara-net/xunara-server/identity"
)

func nativeOAuth2Settings() identity.OAuth2Config {
	return identity.OAuth2Config{ID: "github", Type: "github", ClientID: "fixture", ClientSecret: "private-fixture"}
}

func TestOAuth2ProviderConfigurationAndCapabilities(test *testing.T) {
	settings := nativeOAuth2Settings()
	config := Config{ServerURL: "https://console.example", OAuth2Providers: []identity.OAuth2Config{settings}}
	_, redirects, local, err := configureIdentityProviders(config)
	if err != nil || local || redirects["github"] != "https://console.example/oauth2/callback/github" {
		test.Fatalf("OAuth2 configuration: %v", err)
	}
	server := newServerWithConfig(test, config)
	capabilities := server.apiCapabilities()
	if !slices.Contains(capabilities, "auth.oauth2") || !slices.Contains(capabilities, "account.identity_binding") || slices.Contains(capabilities, "auth.oidc") || slices.Contains(capabilities, "auth.password") {
		test.Fatal("OAuth2-only capabilities must not claim OIDC/password")
	}
	config.AllowLocalLogin = true
	config.OIDCProviders = []identity.OIDCConfig{{ID: "corp", Issuer: "https://idp.example", ClientID: "client"}}
	registry, _, local, err := configureIdentityProviders(config)
	if err != nil || !local {
		test.Fatalf("coexisting providers: %v", err)
	}
	server.providers, server.localLogin = registry, local
	for _, capability := range []string{"auth.oauth2", "auth.oidc", "auth.password", "auth.external"} {
		if !slices.Contains(server.apiCapabilities(), capability) {
			test.Fatalf("coexisting providers lack %s", capability)
		}
	}
}

func TestOAuth2ProviderConfigurationRejectsIdentityConfusion(test *testing.T) {
	settings := nativeOAuth2Settings()
	for _, config := range []Config{
		{OAuth2Providers: []identity.OAuth2Config{settings, settings}},
		{OAuth2Providers: []identity.OAuth2Config{settings}, OIDCProviders: []identity.OIDCConfig{{ID: "github", Issuer: "https://idp.example", ClientID: "client"}}},
		{OAuth2Providers: []identity.OAuth2Config{settings}, Providers: []identity.IdentityProvider{&fakeProvider{id: "github"}}},
		{Providers: []identity.IdentityProvider{&fakeProvider{id: identity.LocalProviderID}}},
		{Providers: []identity.IdentityProvider{nil}},
	} {
		config.ServerURL = "https://console.example"
		if _, _, _, err := configureIdentityProviders(config); err == nil {
			test.Fatal("duplicate/reserved/nil provider accepted")
		}
	}
	settings.RedirectURL = "https://other-tenant.example/oauth2/callback/github"
	if _, _, _, err := configureIdentityProviders(Config{ServerURL: "https://console.example", OAuth2Providers: []identity.OAuth2Config{settings}}); err == nil || !strings.Contains(err.Error(), "fixed callback") {
		test.Fatal("cross-tenant callback accepted")
	}
}
