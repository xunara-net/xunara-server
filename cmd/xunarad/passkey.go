package main

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/xunara-net/xunara-server/identity"
)

// buildPasskeyConfig resolves passkey (WebAuthn) sign-in configuration.
//
// Explicit configuration fails closed: an unusable relying party that an
// operator asked for is a startup error, not a disabled feature. Implicit
// derivation from -server-url is different: a deployment that cannot be a
// relying party (no external URL, plain http outside loopback, an IP address)
// simply has no passkey sign-in, and startup continues.
func buildPasskeyConfig(enabled bool, serverURL, rpID, displayName string, origins []string) (*identity.PasskeyConfig, error) {
	if !enabled {
		return nil, nil
	}

	explicit := rpID != "" || displayName != "" || len(origins) > 0
	if !explicit {
		return derivePasskeyConfig(serverURL), nil
	}

	cfg := &identity.PasskeyConfig{RPID: rpID, Origins: origins, DisplayName: displayName}
	if cfg.RPID != "" && len(cfg.Origins) == 0 {
		// An operator naming only the RP ID still gets the same server URL as
		// origin, as long as it really belongs to that RP ID.
		if derived := derivePasskeyConfig(serverURL); derived != nil && hostUnderRPID(derived.RPID, cfg.RPID) {
			cfg.Origins = derived.Origins
		}
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid passkey configuration: %w", err)
	}
	return cfg, nil
}

// derivePasskeyConfig infers the relying party from the externally reachable
// server URL: RP ID = host, origin = scheme://host. It returns nil when the
// URL cannot serve WebAuthn (missing URL, plain http outside loopback, an IP
// address).
func derivePasskeyConfig(serverURL string) *identity.PasskeyConfig {
	u, err := url.Parse(strings.TrimSpace(serverURL))
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" ||
		(u.Path != "" && u.Path != "/") {
		return nil
	}
	cfg := &identity.PasskeyConfig{
		RPID:    u.Hostname(),
		Origins: []string{u.Scheme + "://" + u.Host},
	}
	if err := cfg.Validate(); err != nil {
		return nil
	}
	return cfg
}

// hostUnderRPID reports whether host is rpID or a subdomain of it.
func hostUnderRPID(host, rpID string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	rpID = strings.ToLower(strings.TrimSuffix(rpID, "."))
	return host == rpID || strings.HasSuffix(host, "."+rpID)
}
