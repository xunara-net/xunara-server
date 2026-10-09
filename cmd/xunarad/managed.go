package main

import (
	"log/slog"

	"github.com/xunara-net/xunara-server/control"
	"tailscale.com/tailcfg"
)

func managedServerConfig(org control.ManagedOrg, stateDir string, opts routerOptions, sharedDERPMap *tailcfg.DERPMap, logger *slog.Logger) control.Config {
	return control.Config{
		ServerURL:       org.ServerURL,
		Domain:          org.Domain,
		StateDir:        stateDir,
		ConsoleTimezone: opts.consoleTimezone,
		TrustedProxy:    opts.trustedProxy,
		DERPMap:         sharedDERPMap.Clone(),
		Logger:          logger,
	}
}
