package main

import (
	"log/slog"
	"strings"

	"github.com/xunara-net/xunara-server/control"
	"tailscale.com/tailcfg"
)

func managedServerConfig(org control.ManagedOrg, stateDir string, opts routerOptions, sharedDERPMap *tailcfg.DERPMap, logger *slog.Logger) control.Config {
	config := control.Config{
		ServerURL:       org.ServerURL,
		Domain:          org.Domain,
		StateDir:        stateDir,
		ConsoleTimezone: opts.consoleTimezone,
		TrustedProxy:    opts.trustedProxy,
		DERPMap:         sharedDERPMap.Clone(),
		Logger:          logger,
	}
	if opts.consoleBaseURL != "" {
		base := strings.TrimRight(opts.consoleBaseURL, "/")
		config.ConsoleURL = base + "/t/" + org.ID
		config.Passkeys = derivePasskeyConfig(base)
		if config.Passkeys != nil {
			// 多个租户和平台管理员共享 RP 时，不能让 UID=1 的居民凭据互相覆盖。
			config.Passkeys.UserHandleNamespace = "xunara:tenant:" + org.ID
		}
	}
	return config
}
