package control

import (
	"context"
	"net/http"

	"tailscale.com/types/key"
)

type noiseDispatch struct {
	Handler func(*noiseServer) http.Handler
}
type deviceScopeCheck struct {
	Check func(context.Context, key.MachinePublic, key.NodePublic) error
}
type nativeEndpoints struct {
	ClientURL  string
	ConsoleURL string
}

func (server *Server) clientLoginURL() string {
	if endpoints := server.nativeEndpoints.Load(); endpoints != nil {
		return endpoints.ClientURL
	}
	return server.cfg.ServerURL
}
