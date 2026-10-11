package control

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/xunara-net/xunara-server/identity"
)

type authenticationPolicyRequest struct {
	Revision            *uint64           `json:"revision"`
	Registration        *RegistrationMode `json:"registration"`
	PublicSignupEnabled *bool             `json:"public_signup_enabled"`
}

type authenticationProviderRequest struct {
	Revision      *uint64  `json:"revision"`
	ID            string   `json:"id"`
	Type          string   `json:"type"`
	DisplayName   string   `json:"display_name"`
	ClientID      string   `json:"client_id"`
	ClientSecret  string   `json:"client_secret"`
	Issuer        string   `json:"issuer"`
	BaseURL       string   `json:"base_url"`
	AuthURL       string   `json:"auth_url"`
	TokenURL      string   `json:"token_url"`
	UserInfoURL   string   `json:"userinfo_url"`
	SubjectField  string   `json:"subject_field"`
	NameField     string   `json:"name_field"`
	UsernameField string   `json:"username_field"`
	EmailField    string   `json:"email_field"`
	AuthStyle     string   `json:"auth_style"`
	Scopes        []string `json:"scopes"`
	Enabled       bool     `json:"enabled"`
}

type authenticationProviderPatch struct {
	Revision     *uint64 `json:"revision"`
	DisplayName  *string `json:"display_name"`
	Enabled      *bool   `json:"enabled"`
	ClientSecret *string `json:"client_secret"`
}

func (server *Server) handleAPIAuthenticationSettings(writer http.ResponseWriter, request *http.Request) {
	principal, ok := server.requireInviteOwner(writer, request, request.Method != http.MethodGet)
	if !ok {
		return
	}
	server.manageAuthenticationSettings(writer, request, identity.AuthenticationConfigWrite{UserID: principal.UserID, SessionID: principal.Session.ID})
}

func (router *Router) handlePlatformAuthenticationSettings(writer http.ResponseWriter, request *http.Request) {
	server := router.serverFor(chi.URLParam(request, "orgID"))
	if server == nil {
		writeAPIError(writer, http.StatusNotFound, "ORGANIZATION_NOT_FOUND: this network does not exist")
		return
	}
	if err := server.refreshAuthentication(request.Context()); err != nil {
		server.writeAuthenticationConfigError(writer, err)
		return
	}
	server.manageAuthenticationSettings(writer, request, identity.AuthenticationConfigWrite{Platform: true})
}

func (server *Server) authenticationSettingsPayload(request *http.Request, platform bool) map[string]any {
	config := server.defaultAuthenticationConfig()
	revision := uint64(0)
	if runtime := server.authentication.Load(); runtime != nil {
		config, revision = runtime.Config, runtime.Revision
	}
	publicSignup := server.selfServiceInfo() != nil && (config.PublicSignupEnabled == nil || *config.PublicSignupEnabled)
	providers := make([]map[string]any, 0)
	for _, settings := range server.cfg.OIDCProviders {
		providerID := settings.ID
		if providerID == "" {
			providerID = "oidc"
		}
		view := server.authenticationProviderView(runtimeIdentityProvider{ID: providerID, Type: "oidc", DisplayName: settings.DisplayName,
			Issuer: settings.Issuer, ClientID: settings.ClientID, Scopes: settings.Scopes, Enabled: !slices.Contains(config.DisabledDeploymentProviders, providerID)}, "deployment", settings.ClientSecret != "")
		providers = append(providers, view)
	}
	for _, settings := range server.cfg.OAuth2Providers {
		providerID := settings.ID
		if providerID == "" {
			providerID = settings.Type
		}
		providers = append(providers, server.authenticationProviderView(runtimeIdentityProvider{ID: providerID, Type: settings.Type, DisplayName: settings.DisplayName,
			ClientID: settings.ClientID, BaseURL: settings.BaseURL, AuthURL: settings.AuthURL, TokenURL: settings.TokenURL, UserInfoURL: settings.UserInfoURL,
			SubjectField: settings.SubjectField, NameField: settings.NameField, UsernameField: settings.UsernameField, EmailField: settings.EmailField,
			AuthStyle: settings.AuthStyle, Scopes: settings.Scopes, Enabled: !slices.Contains(config.DisabledDeploymentProviders, providerID)}, "deployment", settings.ClientSecret != ""))
	}
	for _, settings := range config.Providers {
		providers = append(providers, server.authenticationProviderView(settings, "runtime", settings.SealedSecret != ""))
	}
	for _, provider := range server.cfg.Providers {
		providers = append(providers, server.authenticationProviderView(runtimeIdentityProvider{ID: provider.ID(), Type: "external", DisplayName: server.providerName(provider.ID()), Enabled: !slices.Contains(config.DisabledDeploymentProviders, provider.ID())}, "deployment", false))
	}
	payload := map[string]any{
		"control_url": server.cfg.ServerURL,
		"revision":    revision, "registration": config.MemberRegistration.String(),
		"self_service": server.selfServiceInfo() != nil, "public_signup_enabled": publicSignup,
		"can_manage_public_signup": platform && server.selfServiceInfo() != nil, "local_login": server.localLogin,
		"providers": providers,
	}
	if !platform {
		payload["csrf_token"] = csrfTokenFor(server.accountSessionToken(request))
	}
	return payload
}

// 显式白名单响应，不能序列化带 SealedSecret 的内部配置或返回部署环境中的凭据。
func (server *Server) authenticationProviderView(settings runtimeIdentityProvider, source string, hasSecret bool) map[string]any {
	callback := "/oauth2/callback/"
	protocol := "oauth2"
	if settings.Type == "oidc" {
		callback, protocol = "/oidc/callback/", "oidc"
	}
	callbackURL := strings.TrimRight(server.cfg.ServerURL, "/") + callback + settings.ID
	if source == "deployment" && server.providerRedirects[settings.ID] != "" {
		callbackURL = server.providerRedirects[settings.ID]
	}
	return map[string]any{
		"id": settings.ID, "type": settings.Type, "protocol": protocol, "display_name": settings.DisplayName,
		"client_id": settings.ClientID, "issuer": settings.Issuer, "base_url": settings.BaseURL,
		"auth_url": settings.AuthURL, "token_url": settings.TokenURL, "userinfo_url": settings.UserInfoURL,
		"subject_field": settings.SubjectField, "name_field": settings.NameField, "username_field": settings.UsernameField,
		"email_field": settings.EmailField, "auth_style": settings.AuthStyle, "scopes": settings.Scopes,
		"enabled": settings.Enabled, "archived": settings.Archived, "source": source, "secret_configured": hasSecret,
		"callback_url": callbackURL,
	}
}

func (server *Server) authenticationDraft(expected *uint64) (authenticationConfiguration, error) {
	if expected == nil {
		return authenticationConfiguration{}, NewHTTPError(http.StatusBadRequest, "AUTH_CONFIG_VERSION_REQUIRED: reload settings before saving", nil)
	}
	current := server.authentication.Load()
	config := server.defaultAuthenticationConfig()
	if current != nil {
		if current.Revision != *expected {
			return authenticationConfiguration{}, identity.ErrAuthenticationConfigChanged
		}
		config = current.Config
	} else if *expected != 0 {
		return authenticationConfiguration{}, identity.ErrAuthenticationConfigChanged
	}
	encoded, err := json.Marshal(config)
	if err != nil {
		return authenticationConfiguration{}, err
	}
	var draft authenticationConfiguration
	err = json.Unmarshal(encoded, &draft)
	return draft, err
}

func (server *Server) manageAuthenticationSettings(writer http.ResponseWriter, request *http.Request, actor identity.AuthenticationConfigWrite) {
	writer.Header().Set("Cache-Control", "no-store")
	if request.Method == http.MethodGet {
		writeJSON(writer, http.StatusOK, server.authenticationSettingsPayload(request, actor.Platform))
		return
	}
	providerID := chi.URLParam(request, "providerID")
	var revision *uint64
	var policy authenticationPolicyRequest
	var creation authenticationProviderRequest
	var patch authenticationProviderPatch
	switch {
	case request.Method == http.MethodPost:
		if !decodeAccountBodyLimit(writer, request, &creation, 32<<10) {
			return
		}
		revision = creation.Revision
	case request.Method == http.MethodDelete:
		expected, err := strconv.ParseUint(request.Header.Get("If-Match"), 10, 64)
		if err != nil {
			server.writeAuthenticationConfigError(writer, NewHTTPError(http.StatusBadRequest, "AUTH_CONFIG_VERSION_REQUIRED: send an If-Match revision", nil))
			return
		}
		revision = &expected
	case providerID != "":
		if !decodeAccountBody(writer, request, &patch) {
			return
		}
		revision = patch.Revision
	default:
		if !decodeAccountBody(writer, request, &policy) {
			return
		}
		revision = policy.Revision
	}
	draft, err := server.authenticationDraft(revision)
	if err == nil {
		switch {
		case request.Method == http.MethodPost:
			err = server.addAuthenticationProvider(&draft, creation)
			actor.Detail = "provider created"
		case providerID != "":
			err = server.patchAuthenticationProvider(&draft, providerID, patch, request.Method == http.MethodDelete)
			actor.Detail = "provider updated; pending external authorizations cancelled"
		default:
			err = server.patchAuthenticationPolicy(&draft, policy, actor.Platform)
			actor.Detail = "registration policy updated; pending external authorizations cancelled"
		}
	}
	if err == nil {
		err = server.saveAuthenticationConfiguration(request.Context(), draft, *revision, actor)
	}
	if err != nil {
		server.writeAuthenticationConfigError(writer, err)
		return
	}
	status := http.StatusOK
	if request.Method == http.MethodPost {
		status = http.StatusCreated
	}
	writeJSON(writer, status, server.authenticationSettingsPayload(request, actor.Platform))
}

func (server *Server) patchAuthenticationPolicy(draft *authenticationConfiguration, patch authenticationPolicyRequest, platform bool) error {
	if patch.Registration == nil && patch.PublicSignupEnabled == nil {
		return NewHTTPError(http.StatusBadRequest, "AUTH_CONFIG_INVALID: choose a setting to change", nil)
	}
	if patch.Registration != nil {
		if *patch.Registration != RegistrationClosed && *patch.Registration != RegistrationInvite && *patch.Registration != RegistrationOpen || server.selfServiceInfo() != nil && *patch.Registration == RegistrationOpen {
			return NewHTTPError(http.StatusBadRequest, "AUTH_CONFIG_INVALID: the signup desk cannot allow anonymous members in its shared network", nil)
		}
		draft.MemberRegistration = *patch.Registration
	}
	if patch.PublicSignupEnabled != nil {
		if !platform || server.selfServiceInfo() == nil {
			return NewHTTPError(http.StatusForbidden, "PLATFORM_REQUIRED: only the platform operator may change public tenant signup", nil)
		}
		draft.PublicSignupEnabled = patch.PublicSignupEnabled
	}
	return nil
}

func (server *Server) sealAuthenticationSecret(secret string) (string, error) {
	if len(secret) > 4096 || strings.ContainsAny(secret, "\x00\r\n") {
		return "", NewHTTPError(http.StatusBadRequest, "AUTH_CONFIG_INVALID: invalid client secret", nil)
	}
	key, err := loadOrCreateSealingKey(filepath.Join(server.cfg.StateDir, "authentication_secret.key"))
	if err != nil {
		return "", err
	}
	return sealSecret(key, secret)
}

func (server *Server) addAuthenticationProvider(draft *authenticationConfiguration, body authenticationProviderRequest) error {
	if len(draft.Providers) >= 16 {
		return NewHTTPError(http.StatusBadRequest, "AUTH_CONFIG_INVALID: at most 16 runtime providers are supported", nil)
	}
	if _, exists := server.providers.Get(body.ID); exists || slices.ContainsFunc(draft.Providers, func(settings runtimeIdentityProvider) bool { return settings.ID == body.ID }) {
		return NewHTTPError(http.StatusConflict, "PROVIDER_ID_RESERVED: choose a new identity provider ID", nil)
	}
	settings := runtimeIdentityProvider{
		ID: body.ID, Type: body.Type, DisplayName: body.DisplayName, ClientID: body.ClientID,
		Issuer: body.Issuer, BaseURL: body.BaseURL, AuthURL: body.AuthURL, TokenURL: body.TokenURL,
		UserInfoURL: body.UserInfoURL, SubjectField: body.SubjectField, NameField: body.NameField,
		UsernameField: body.UsernameField, EmailField: body.EmailField, AuthStyle: body.AuthStyle,
		Scopes: body.Scopes, Enabled: body.Enabled,
	}
	if settings.DisplayName == "" {
		settings.DisplayName = settings.ID
	}
	if err := validateRuntimeIdentitySettings(settings); err != nil {
		return NewHTTPError(http.StatusBadRequest, "AUTH_CONFIG_INVALID: check provider fields and public HTTPS endpoints", err)
	}
	var err error
	settings.SealedSecret, err = server.sealAuthenticationSecret(body.ClientSecret)
	if err != nil {
		return err
	}
	if _, err := server.runtimeIdentityProvider(settings); err != nil {
		return NewHTTPError(http.StatusBadRequest, "AUTH_CONFIG_INVALID: check provider fields, client credentials and HTTPS callback address", err)
	}
	draft.Providers = append(draft.Providers, settings)
	return nil
}

func (server *Server) patchAuthenticationProvider(draft *authenticationConfiguration, providerID string, patch authenticationProviderPatch, archive bool) error {
	for index, settings := range draft.Providers {
		if settings.ID != providerID {
			continue
		}
		if settings.Archived {
			return NewHTTPError(http.StatusConflict, "PROVIDER_ARCHIVED: use a new provider ID", nil)
		}
		if patch.DisplayName == nil && patch.Enabled == nil && patch.ClientSecret == nil && !archive {
			return NewHTTPError(http.StatusBadRequest, "AUTH_CONFIG_INVALID: choose a provider setting to change", nil)
		}
		if patch.DisplayName != nil {
			settings.DisplayName = *patch.DisplayName
		}
		if patch.Enabled != nil {
			settings.Enabled = *patch.Enabled
		}
		if patch.ClientSecret != nil {
			var err error
			settings.SealedSecret, err = server.sealAuthenticationSecret(*patch.ClientSecret)
			if err != nil {
				return err
			}
		}
		if archive {
			settings.Enabled, settings.Archived = false, true
			settings.SealedSecret = ""
		} else if _, err := server.runtimeIdentityProvider(settings); err != nil {
			return NewHTTPError(http.StatusBadRequest, "AUTH_CONFIG_INVALID: check the provider name and client secret", err)
		}
		draft.Providers[index] = settings
		return nil
	}
	if _, exists := server.providers.Get(providerID); exists && providerID != identity.LocalProviderID {
		if patch.DisplayName != nil || patch.ClientSecret != nil || archive || patch.Enabled == nil {
			return NewHTTPError(http.StatusBadRequest, "DEPLOYMENT_PROVIDER: only the enabled switch is managed here for deployment providers", nil)
		}
		draft.DisabledDeploymentProviders = slices.DeleteFunc(draft.DisabledDeploymentProviders, func(provider string) bool { return provider == providerID })
		if !*patch.Enabled {
			draft.DisabledDeploymentProviders = append(draft.DisabledDeploymentProviders, providerID)
		}
		return nil
	}
	return NewHTTPError(http.StatusNotFound, "PROVIDER_NOT_FOUND: this provider does not exist", nil)
}

func (server *Server) saveAuthenticationConfiguration(ctx context.Context, config authenticationConfiguration, expected uint64, writer identity.AuthenticationConfigWrite) error {
	runtime, err := server.buildAuthenticationRuntime(config)
	if err != nil {
		return err
	}
	writer.Methods = identity.LoginMethods{Providers: runtime.Providers.IDs(), Local: server.localLogin, Passkeys: server.passkeys != nil}
	for _, providerID := range server.identityProviders().IDs() {
		if _, exists := runtime.Providers.Get(providerID); !exists {
			writer.Removed = append(writer.Removed, providerID)
		}
	}
	payload, err := json.Marshal(config)
	if err != nil {
		return err
	}
	if _, err := server.identity.SaveAuthenticationConfig(ctx, identity.AuthenticationConfig{Revision: expected, Payload: payload}, writer); err != nil {
		return err
	}
	return server.refreshAuthentication(ctx)
}

func (server *Server) writeAuthenticationConfigError(writer http.ResponseWriter, err error) {
	var structured HTTPError
	switch {
	case errors.As(err, &structured):
		writeAPIError(writer, structured.Code, structured.Msg)
	case errors.Is(err, identity.ErrAuthenticationConfigChanged):
		writeAPIError(writer, http.StatusConflict, "AUTH_CONFIG_CHANGED: settings were changed; reload before saving")
	case errors.Is(err, identity.ErrLastLoginMethod):
		writeAPIError(writer, http.StatusConflict, "LAST_LOGIN_METHOD: some accounts would lose their only usable login method")
	case errors.Is(err, identity.ErrInviteOwnerRequired):
		writeAPIError(writer, http.StatusForbidden, "OWNER_REQUIRED: only the network owner may manage authentication")
	case errors.Is(err, identity.ErrSessionRevoked):
		writeAPIError(writer, http.StatusUnauthorized, "SESSION_REVOKED: sign in again")
	default:
		writeAPIError(writer, http.StatusServiceUnavailable, "AUTH_CONFIG_UNAVAILABLE: could not read or save authentication configuration")
	}
}
