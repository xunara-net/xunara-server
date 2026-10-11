package control

import (
	"fmt"
	"strings"

	"github.com/xunara-net/xunara-server/identity"
)

func configureIdentityProviders(config Config) (*identity.Registry, map[string]string, bool, error) {
	registry := identity.NewRegistry()
	redirects := make(map[string]string)
	localLogin := len(config.OIDCProviders) == 0 && len(config.OAuth2Providers) == 0 && len(config.Providers) == 0 || config.AllowLocalLogin
	if localLogin {
		registry.Register(identity.LocalLogin{})
	}
	register := func(provider identity.IdentityProvider) error {
		if provider == nil || provider.ID() == "" || provider.ID() == identity.LocalProviderID {
			return fmt.Errorf("control: external identity provider must have a non-reserved ID")
		}
		if _, exists := registry.Get(provider.ID()); exists {
			return fmt.Errorf("control: duplicate identity provider ID")
		}
		registry.Register(provider)
		if redirect, ok := provider.(interface{ RedirectURL() string }); ok {
			redirects[provider.ID()] = redirect.RedirectURL()
		}
		return nil
	}
	for _, provider := range config.Providers {
		if err := register(provider); err != nil {
			return nil, nil, false, err
		}
	}
	for _, settings := range config.OIDCProviders {
		if settings.ID == "" {
			settings.ID = "oidc"
		}
		if settings.RedirectURL == "" && config.ServerURL != "" {
			settings.RedirectURL = strings.TrimRight(config.ServerURL, "/") + "/oidc/callback/" + settings.ID
		}
		provider, err := identity.NewOIDCProvider(settings)
		if err != nil {
			return nil, nil, false, fmt.Errorf("control: %w", err)
		}
		if err := register(provider); err != nil {
			return nil, nil, false, err
		}
	}
	for _, settings := range config.OAuth2Providers {
		if settings.ID == "" {
			settings.ID = settings.Type
		}
		// 回调属于当前租户的固定公共地址，不接受调用方提供的地址或另一租户的 host。
		allowed := strings.TrimRight(config.ServerURL, "/") + "/oauth2/callback/" + settings.ID
		if settings.RedirectURL == "" {
			settings.RedirectURL = allowed
		} else if settings.RedirectURL != allowed {
			return nil, nil, false, fmt.Errorf("control: OAuth2 redirect URL must equal this tenant's fixed callback URL")
		}
		provider, err := identity.NewOAuth2Provider(settings)
		if err != nil {
			return nil, nil, false, fmt.Errorf("control: %w", err)
		}
		if err := register(provider); err != nil {
			return nil, nil, false, err
		}
	}
	return registry, redirects, localLogin, nil
}
