package control

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/xunara-net/xunara-server/state"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

// 共享入口只决定请求进入哪个 Core；身份、策略和机器授权仍由各租户独立验证。
type nativeGateway struct {
	router   *Router
	registry *OrgRegistry
	front    *Server
	frontID  string
	origin   string
}

func (router *Router) enableNativeGatewayLocked() error {
	desk := router.selfService.Load()
	if desk == nil || desk.cfg.ConsoleURL == "" || router.cfg.Registry == nil {
		return errors.New("native gateway requires a shared console and organization registry")
	}
	origin, err := url.Parse(desk.cfg.ConsoleURL)
	if err != nil || (origin.Scheme != "https" && origin.Hostname() != "localhost" && origin.Hostname() != "127.0.0.1" && origin.Hostname() != "::1") {
		return errors.New("native gateway requires HTTPS outside loopback")
	}
	gateway := &nativeGateway{router: router, registry: router.cfg.Registry, front: desk.site.site.Server,
		frontID: desk.site.site.ID, origin: desk.cfg.ConsoleURL}
	// 已有设备只补录原归属，绝不按主机名或用户 ID 搬迁历史授权。
	for _, org := range router.orgs {
		nodes, err := org.site.Server.networkNodes(context.Background())
		if err != nil {
			return err
		}
		for _, node := range nodes {
			if node.MachineKey.IsZero() || node.NodeKey.IsZero() {
				return errors.New("cannot route an existing device without both keys")
			}
			if err := gateway.registry.bindNative(context.Background(), node.MachineKey.String(), node.NodeKey.String(), org.site.ID, org.site.Server.noiseKey.Public().String()); err != nil {
				return err
			}
		}
		if err := gateway.attach(org); err != nil {
			return err
		}
	}
	// NewRouter 已持路由锁；回调仅在开始服务后读取路由表，避免初始化自锁。
	router.nativeGateway = gateway
	gateway.front.noiseDispatch.Store(&noiseDispatch{Handler: gateway.noiseHandler})
	return nil
}

func (gateway *nativeGateway) attach(org *routerOrg) error {
	server := org.site.Server
	consoleURL := server.consoleURL()
	if org.managed {
		consoleURL = gateway.origin + tenantConsolePrefix(org.site.ID)
	} else if org.site.ID == gateway.frontID {
		consoleURL = gateway.origin
	}
	server.nativeEndpoints.Store(&nativeEndpoints{ClientURL: gateway.origin, ConsoleURL: consoleURL})
	orgID, generation := org.site.ID, server.noiseKey.Public().String()
	server.deviceScope.Store(&deviceScopeCheck{Check: func(ctx context.Context, machine key.MachinePublic, node key.NodePublic) error {
		if machine.IsZero() || node.IsZero() {
			return errNativeScope
		}
		if orgID != gateway.frontID {
			return gateway.registry.bindNative(ctx, machine.String(), node.String(), orgID, generation)
		}
		// 未经过统一登录选择账户的旧入口申请，不能继续被默认管理员批准。
		binding, found, err := gateway.registry.nativeBinding(ctx, machine.String(), node.String())
		if err != nil {
			return err
		}
		if !found || binding.Organization != orgID || binding.NoiseKey != generation {
			return errNativeScope
		}
		return nil
	}})
	return server.loadPolicy()
}

func (gateway *nativeGateway) boundOrg(ctx context.Context, machine key.MachinePublic, node key.NodePublic) (*routerOrg, bool, error) {
	binding, found, err := gateway.registry.nativeBinding(ctx, machine.String(), node.String())
	if err != nil || !found {
		return nil, found, err
	}
	org := gateway.router.orgByID(binding.Organization)
	if org == nil || org.site.Server.noiseKey.Public().String() != binding.NoiseKey {
		return nil, true, errNativeScope
	}
	return org, true, nil
}

func nativeHintsMatch(request *http.Request, allowed ...key.NodePublic) bool {
	for _, value := range request.Header.Values(tailcfg.LBHeader) {
		for _, hint := range strings.Split(value, ",") {
			var hinted key.NodePublic
			if err := hinted.UnmarshalText([]byte(strings.TrimSpace(hint))); err != nil || hinted.IsZero() {
				return false
			}
			matched := false
			for _, node := range allowed {
				matched = matched || hinted == node
			}
			if !matched {
				return false
			}
		}
	}
	return true
}

func (gateway *nativeGateway) noiseHandler(connection *noiseServer) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, err := io.ReadAll(http.MaxBytesReader(writer, request.Body, noiseBodyLimit))
		if err != nil {
			http.Error(writer, "invalid request body", http.StatusBadRequest)
			return
		}
		request.Body = io.NopCloser(bytes.NewReader(body))
		if request.URL.Path == "/machine/register" && request.Method == http.MethodPost {
			gateway.register(connection, writer, request, body)
			return
		}
		var payload struct{ NodeKey key.NodePublic }
		if len(body) > 0 && json.Unmarshal(body, &payload) != nil {
			http.Error(writer, "invalid request body", http.StatusBadRequest)
			return
		}
		nodeKey := payload.NodeKey
		if nodeKey.IsZero() {
			for _, value := range request.Header.Values(tailcfg.LBHeader) {
				var hint key.NodePublic
				if hint.UnmarshalText([]byte(strings.TrimSpace(value))) != nil || (!nodeKey.IsZero() && hint != nodeKey) {
					http.Error(writer, "invalid routing hint", http.StatusUnauthorized)
					return
				}
				nodeKey = hint
			}
		}
		if !nativeHintsMatch(request, nodeKey) {
			http.Error(writer, "routing hint does not match node", http.StatusUnauthorized)
			return
		}
		org, err := gateway.machineOrg(request.Context(), connection.machineKey, nodeKey)
		if err != nil {
			http.Error(writer, "device network unavailable", http.StatusUnauthorized)
			return
		}
		// 每个 HTTP/2 请求使用独立副本，不能改变连接字段而引入并行串网。
		scoped := *connection
		scoped.server = org.site.Server
		scoped.router().ServeHTTP(writer, request)
	})
}

func (gateway *nativeGateway) machineOrg(ctx context.Context, machine key.MachinePublic, node key.NodePublic) (*routerOrg, error) {
	if !node.IsZero() {
		org, found, err := gateway.boundOrg(ctx, machine, node)
		if err != nil || !found {
			return nil, errNativeScope
		}
		actual, err := org.site.Server.networkConfig.NodeByKey(ctx, node)
		if err != nil || actual.MachineKey != machine {
			return nil, errNativeScope
		}
		return org, nil
	}
	bindings, err := gateway.registry.nativeBindingsForMachine(ctx, machine.String())
	if err != nil {
		return nil, err
	}
	var target *routerOrg
	for _, binding := range bindings {
		org := gateway.router.orgByID(binding.Organization)
		if org == nil || org.site.Server.noiseKey.Public().String() != binding.NoiseKey {
			continue
		}
		var nodeKey key.NodePublic
		if err := nodeKey.UnmarshalText([]byte(binding.NodeKey)); err != nil {
			return nil, err
		}
		actual, err := org.site.Server.networkConfig.NodeByKey(ctx, nodeKey)
		if errors.Is(err, state.ErrRouteNodeNotFound) {
			continue
		}
		if err != nil || actual.MachineKey != machine {
			return nil, errNativeScope
		}
		if target != nil && target != org {
			return nil, errNativeScope
		}
		target = org
	}
	if target == nil {
		return nil, errNativeScope
	}
	return target, nil
}

func (gateway *nativeGateway) register(connection *noiseServer, writer http.ResponseWriter, request *http.Request, body []byte) {
	reject := func(message string) { writeJSON(writer, http.StatusOK, tailcfg.RegisterResponse{Error: message}) }
	var registration tailcfg.RegisterRequest
	if json.Unmarshal(body, &registration) != nil || registration.NodeKey.IsZero() {
		reject("invalid registration")
		return
	}
	if connection.rejectUnsupported(writer, registration.Version, registration.NodeKey) {
		return
	}
	if !nativeHintsMatch(request, registration.NodeKey, registration.OldNodeKey) {
		reject("routing hint does not match registration")
		return
	}
	ctx := request.Context()
	org, bound, err := gateway.boundOrg(ctx, connection.machineKey, registration.NodeKey)
	if err != nil {
		reject("device network unavailable")
		return
	}
	if registration.Auth != nil && registration.Auth.AuthKey != "" {
		var keyed *routerOrg
		for _, candidate := range gateway.router.orgSnapshot() {
			usable, err := candidate.site.Server.networkConfig.AcceptsRegistrationKey(ctx, registration.Auth.AuthKey, connection.machineKey, registration.NodeKey)
			if err != nil {
				reject("registration unavailable")
				return
			}
			if usable {
				if keyed != nil {
					reject("invalid authentication key")
					return
				}
				keyed = candidate
			}
		}
		if keyed == nil || (bound && org != keyed) {
			reject("invalid authentication key")
			return
		}
		org = keyed
	}
	if org == nil && !registration.OldNodeKey.IsZero() && len(registration.NodeKeySignature) > 0 {
		// 已签名的静默轮换留在原租户，且仍由原 Core 验证签名。
		// 无签名的重新登录走人类账户确认，不因旧键提示自动选择默认管理员。
		org, err = gateway.machineOrg(ctx, connection.machineKey, registration.OldNodeKey)
		if err != nil {
			reject("previous device network unavailable")
			return
		}
	}
	if org != nil {
		if err := gateway.registry.bindNative(ctx, connection.machineKey.String(), registration.NodeKey.String(), org.site.ID, org.site.Server.noiseKey.Public().String()); err != nil {
			reject("device network unavailable")
			return
		}
		scoped := *connection
		scoped.server = org.site.Server
		scoped.handleRegister(writer, request)
		return
	}
	flow, err := gateway.registry.nativeFlowByKeys(ctx, connection.machineKey.String(), registration.NodeKey.String())
	if errors.Is(err, errNativeFlow) {
		allowed, _, admissionErr := gateway.front.store.AllowRate("native-enrollment-ip:"+connection.clientIP, 20, 10*time.Minute, time.Now())
		if admissionErr != nil || !allowed {
			reject("too many registration attempts; try again later")
			return
		}
		flow, err = gateway.registry.createNativeFlow(ctx, connection.machineKey, registration)
	}
	if err != nil {
		reject("device enrollment unavailable")
		return
	}
	writeJSON(writer, http.StatusOK, tailcfg.RegisterResponse{AuthURL: gateway.origin + "/device/" + flow.ID})
}
