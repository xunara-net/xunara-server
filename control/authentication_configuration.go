package control

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"path/filepath"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/xunara-net/xunara-server/identity"
)

type runtimeIdentityProvider struct {
	ID            string   `json:"id"`
	Type          string   `json:"type"`
	DisplayName   string   `json:"display_name"`
	ClientID      string   `json:"client_id"`
	SealedSecret  string   `json:"sealed_secret,omitempty"`
	Issuer        string   `json:"issuer,omitempty"`
	BaseURL       string   `json:"base_url,omitempty"`
	AuthURL       string   `json:"auth_url,omitempty"`
	TokenURL      string   `json:"token_url,omitempty"`
	UserInfoURL   string   `json:"userinfo_url,omitempty"`
	SubjectField  string   `json:"subject_field,omitempty"`
	NameField     string   `json:"name_field,omitempty"`
	UsernameField string   `json:"username_field,omitempty"`
	EmailField    string   `json:"email_field,omitempty"`
	AuthStyle     string   `json:"auth_style,omitempty"`
	Scopes        []string `json:"scopes"`
	Enabled       bool     `json:"enabled"`
	Archived      bool     `json:"archived,omitempty"`
}

type authenticationConfiguration struct {
	MemberRegistration          RegistrationMode          `json:"member_registration"`
	PublicSignupEnabled         *bool                     `json:"public_signup_enabled,omitempty"`
	Providers                   []runtimeIdentityProvider `json:"providers"`
	DisabledDeploymentProviders []string                  `json:"disabled_deployment_providers"`
}

type authenticationRuntime struct {
	Revision  uint64
	Config    authenticationConfiguration
	Providers *identity.Registry
	Redirects map[string]string
}

func (server *Server) identityProviders() *identity.Registry {
	if runtime := server.authentication.Load(); runtime != nil {
		return runtime.Providers
	}
	return server.providers
}

func (server *Server) providerRedirect(providerID string) string {
	if runtime := server.authentication.Load(); runtime != nil {
		return runtime.Redirects[providerID]
	}
	return server.providerRedirects[providerID]
}

func (server *Server) authenticationRevision() uint64 {
	if runtime := server.authentication.Load(); runtime != nil {
		return runtime.Revision
	}
	return 0
}

func (server *Server) memberRegistrationMode() RegistrationMode {
	if runtime := server.authentication.Load(); runtime != nil {
		return runtime.Config.MemberRegistration
	}
	if server.selfServiceInfo() != nil {
		return RegistrationClosed
	}
	return server.registration
}

// 平台开户是独立网络的创建；所有者改成员准入不能关闭它或将访客加进共享网络。
func (server *Server) registrationMode() RegistrationMode {
	if server.selfServiceInfo() != nil {
		if runtime := server.authentication.Load(); runtime != nil && runtime.Config.PublicSignupEnabled != nil && !*runtime.Config.PublicSignupEnabled {
			return RegistrationClosed
		}
		return RegistrationOpen
	}
	return server.memberRegistrationMode()
}

func (server *Server) authenticationConfig() authenticationConfiguration {
	if runtime := server.authentication.Load(); runtime != nil {
		return runtime.Config
	}
	return server.defaultAuthenticationConfig()
}

func (server *Server) defaultAuthenticationConfig() authenticationConfiguration {
	mode := server.registration
	if server.selfServiceInfo() != nil {
		mode = RegistrationClosed
	}
	return authenticationConfiguration{
		MemberRegistration: mode, Providers: []runtimeIdentityProvider{}, DisabledDeploymentProviders: []string{},
	}
}

func (server *Server) refreshAuthentication(ctx context.Context) error {
	server.authenticationMu.Lock()
	defer server.authenticationMu.Unlock()
	saved, err := server.identity.ReadAuthenticationConfig(ctx)
	if err != nil {
		return err
	}
	if saved.Revision == 0 {
		if server.authentication.Load() != nil {
			return errors.New("control: persisted authentication configuration is missing")
		}
		return nil
	}
	if current := server.authentication.Load(); current != nil && current.Revision == saved.Revision {
		return nil
	}
	var config authenticationConfiguration
	if err := json.Unmarshal(saved.Payload, &config); err != nil {
		return errors.New("control: authentication configuration cannot be decoded")
	}
	runtime, err := server.buildAuthenticationRuntime(config)
	if err != nil {
		return err
	}
	runtime.Revision = saved.Revision
	server.authentication.Store(runtime)
	return nil
}

func (server *Server) authenticationMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		path := request.URL.Path
		if strings.HasPrefix(path, "/api/v1/") || strings.HasPrefix(path, "/api/v2/") || strings.HasPrefix(path, "/console") ||
			strings.HasPrefix(path, "/oidc/") || strings.HasPrefix(path, "/oauth2/") || path == "/login" || path == "/signup" || path == "/setup" {
			if err := server.refreshAuthentication(request.Context()); err != nil {
				writer.Header().Set("Cache-Control", "no-store")
				writeAPIError(writer, http.StatusServiceUnavailable, "AUTH_CONFIG_UNAVAILABLE: could not read authentication configuration")
				return
			}
		}
		next.ServeHTTP(writer, request)
	})
}

func (server *Server) buildAuthenticationRuntime(config authenticationConfiguration) (*authenticationRuntime, error) {
	if config.MemberRegistration != RegistrationClosed && config.MemberRegistration != RegistrationInvite && config.MemberRegistration != RegistrationOpen || len(config.Providers) > 16 {
		return nil, errors.New("control: invalid authentication configuration")
	}
	registry := identity.NewRegistry()
	redirects := make(map[string]string)
	for _, providerID := range server.providers.IDs() {
		if slices.Contains(config.DisabledDeploymentProviders, providerID) && providerID != identity.LocalProviderID {
			continue
		}
		provider, _ := server.providers.Get(providerID)
		registry.Register(provider)
		redirects[providerID] = server.providerRedirects[providerID]
	}
	for _, settings := range config.Providers {
		if _, exists := server.providers.Get(settings.ID); exists {
			return nil, errors.New("control: provider ID belongs to deployment configuration")
		}
		if settings.Archived || !settings.Enabled {
			continue
		}
		provider, err := server.runtimeIdentityProvider(settings)
		if err != nil {
			return nil, err
		}
		registry.Register(provider)
		redirects[settings.ID] = provider.RedirectURL()
	}
	return &authenticationRuntime{Config: config, Providers: registry, Redirects: redirects}, nil
}

func (server *Server) runtimeIdentityProvider(settings runtimeIdentityProvider) (*managedIdentityProvider, error) {
	if err := validateRuntimeIdentitySettings(settings); err != nil {
		return nil, err
	}
	secret := ""
	if settings.SealedSecret != "" {
		key, err := loadOrCreateSealingKey(filepath.Join(server.cfg.StateDir, "authentication_secret.key"))
		if err != nil {
			return nil, errors.New("control: authentication secret storage is unavailable")
		}
		secret, err = openSecret(key, settings.SealedSecret)
		if err != nil {
			return nil, errors.New("control: authentication secret cannot be opened")
		}
	}
	callbackPath := "/oauth2/callback/"
	if settings.Type == "oidc" {
		callbackPath = "/oidc/callback/"
	}
	callback := strings.TrimRight(server.cfg.ServerURL, "/") + callbackPath + settings.ID
	if err := identity.ValidatePublicIdentityEndpoint(callback); err != nil {
		return nil, errors.New("control: runtime providers need a public HTTPS control URL")
	}
	var provider identity.IdentityProvider
	var err error
	if settings.Type == "oidc" {
		provider, err = identity.NewOIDCProvider(identity.OIDCConfig{
			ID: settings.ID, DisplayName: settings.DisplayName, Issuer: settings.Issuer,
			ClientID: settings.ClientID, ClientSecret: secret, RedirectURL: callback, Scopes: settings.Scopes,
		})
	} else {
		provider, err = identity.NewOAuth2Provider(identity.OAuth2Config{
			ID: settings.ID, Type: settings.Type, DisplayName: settings.DisplayName, ClientID: settings.ClientID,
			ClientSecret: secret, RedirectURL: callback, BaseURL: settings.BaseURL, AuthURL: settings.AuthURL,
			TokenURL: settings.TokenURL, UserInfoURL: settings.UserInfoURL, SubjectField: settings.SubjectField,
			NameField: settings.NameField, UsernameField: settings.UsernameField, EmailField: settings.EmailField,
			AuthStyle: settings.AuthStyle, Scopes: settings.Scopes,
		})
	}
	if err != nil {
		return nil, errors.New("control: invalid provider configuration or missing client credentials")
	}
	return &managedIdentityProvider{IdentityProvider: provider, client: identity.NewPublicIdentityHTTPClient(), name: settings.DisplayName, callback: callback, providerType: settings.Type}, nil
}

func validateRuntimeIdentitySettings(settings runtimeIdentityProvider) error {
	if len(settings.ID) < 1 || len(settings.ID) > 64 || settings.ID == identity.LocalProviderID ||
		!authenticationText(settings.DisplayName, 100, false) || !authenticationText(settings.ClientID, 512, true) ||
		len(settings.Scopes) > 16 {
		return errors.New("control: invalid provider name or client ID")
	}
	for index, character := range settings.ID {
		if !(character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || index > 0 && (character == '-' || character == '_')) {
			return errors.New("control: invalid provider ID")
		}
	}
	for _, scope := range settings.Scopes {
		if !authenticationText(scope, 100, true) || strings.ContainsAny(scope, " \t") {
			return errors.New("control: invalid provider scope")
		}
	}
	for _, endpoint := range []string{settings.Issuer, settings.BaseURL, settings.AuthURL, settings.TokenURL, settings.UserInfoURL} {
		if endpoint == "" {
			continue
		}
		parsed, err := url.Parse(endpoint)
		if len(endpoint) > 2048 || err != nil || parsed.RawQuery != "" || parsed.ForceQuery || identity.ValidatePublicIdentityEndpoint(endpoint) != nil {
			return errors.New("control: endpoints must be public HTTPS without credentials, query or fragment")
		}
	}
	switch settings.Type {
	case "oidc":
		if settings.Issuer == "" || settings.BaseURL != "" || settings.AuthURL != "" || settings.TokenURL != "" || settings.UserInfoURL != "" || settings.SubjectField != "" || settings.AuthStyle != "" {
			return errors.New("control: OIDC needs only its issuer and standard claims")
		}
	case "github", "gitlab", "gitea", "generic":
		if settings.Issuer != "" {
			return errors.New("control: OAuth2 cannot use an OIDC issuer")
		}
	default:
		return errors.New("control: unsupported provider type")
	}
	return nil
}

func authenticationText(value string, limit int, required bool) bool {
	return (!required || strings.TrimSpace(value) != "") && utf8.ValidString(value) && utf8.RuneCountInString(value) <= limit && !strings.ContainsFunc(value, unicode.IsControl)
}

// 只给运行时配置注入安全出站客户端，不改变已有受信部署文件或官方客户端协议。
type managedIdentityProvider struct {
	identity.IdentityProvider
	client       *http.Client
	name         string
	callback     string
	providerType string
}

func (provider *managedIdentityProvider) DisplayName() string { return provider.name }
func (provider *managedIdentityProvider) RedirectURL() string { return provider.callback }
func (provider *managedIdentityProvider) Protocol() string {
	if provider.providerType == "oidc" {
		return "oidc"
	}
	return "oauth2"
}

func (provider *managedIdentityProvider) Begin(ctx context.Context, transaction *identity.AuthTransaction) (*identity.AuthorizationRequest, error) {
	result, err := provider.IdentityProvider.Begin(oidc.ClientContext(ctx, provider.client), transaction)
	if err != nil {
		return nil, err
	}
	if result == nil || identity.ValidatePublicIdentityURL(ctx, result.URL) != nil {
		return nil, identity.ErrIdentityEndpointBlocked
	}
	return result, nil
}

func (provider *managedIdentityProvider) Callback(ctx context.Context, transaction *identity.AuthTransaction, request *identity.CallbackRequest) (*identity.IdentityResult, error) {
	return provider.IdentityProvider.Callback(oidc.ClientContext(ctx, provider.client), transaction, request)
}
