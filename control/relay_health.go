package control

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"tailscale.com/net/tlsdial"

	"github.com/xunara-net/xunara-server/identity"
	"github.com/xunara-net/xunara-server/state"
)

type relayHealthResult struct {
	RelayID             string    `json:"relayId"`
	ConfigVersion       uint64    `json:"configVersion"`
	CheckedAt           time.Time `json:"checkedAt"`
	Status              string    `json:"status"`
	Code                string    `json:"code"`
	TLSVerified         bool      `json:"tlsVerified"`
	HTTPStatus          int       `json:"httpStatus"`
	LatencyMilliseconds *float64  `json:"latencyMilliseconds"`
	Perspective         string    `json:"perspective"`
}

// 这是控制面到登记节点的 TLS/HTTP 探测，不能覆盖心跳、准入或客户端真实数据路径。
func probeManagedRelay(ctx context.Context, relay state.Relay, dial func(context.Context, string, string) (net.Conn, error)) relayHealthResult {
	result := relayHealthResult{RelayID: relay.ID, ConfigVersion: relay.ConfigVersion, CheckedAt: time.Now().UTC(),
		Status: "unreachable", Code: "CONNECT_OR_TLS_FAILED", Perspective: "control-plane"}
	if relay.HostName == "" || relay.DERPPort <= 0 || relay.DERPPort > 65535 {
		result.Status, result.Code = "blocked", "TARGET_CONFIGURATION_INVALID"
		return result
	}
	endpoint := &url.URL{Scheme: "https", Host: net.JoinHostPort(relay.HostName, strconv.Itoa(relay.DERPPort)), Path: "/derp/probe"}
	if identity.ValidatePublicIdentityEndpoint(endpoint.String()) != nil {
		result.Status, result.Code = "blocked", "PROBE_ADDRESS_BLOCKED"
		return result
	}
	configuration := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: relay.HostName}
	if pin, present := strings.CutPrefix(relay.CertName, "sha256-raw:"); present {
		if len(pin) != 64 || strings.Trim(pin, "0123456789abcdef") != "" {
			result.Status, result.Code = "blocked", "TLS_PIN_INVALID"
			return result
		}
		tlsdial.SetConfigExpectedCertHash(configuration, pin)
	} else if relay.CertName != "" {
		tlsdial.SetConfigExpectedCert(configuration, relay.CertName)
	}
	transport := &http.Transport{Proxy: nil, DialContext: dial, TLSClientConfig: configuration,
		TLSHandshakeTimeout: 4 * time.Second, ResponseHeaderTimeout: 4 * time.Second, MaxResponseHeaderBytes: 16 << 10,
		DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 8 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	bounded, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(bounded, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return result
	}
	request.Header.Set("User-Agent", "Xunara-Relay-Health/1")
	started := time.Now()
	response, err := client.Do(request)
	if err != nil {
		if errors.Is(err, identity.ErrIdentityEndpointBlocked) {
			result.Status, result.Code = "blocked", "PROBE_ADDRESS_BLOCKED"
		}
		return result
	}
	defer response.Body.Close()
	result.HTTPStatus = response.StatusCode
	result.TLSVerified = response.TLS != nil && response.TLS.HandshakeComplete
	if _, err := io.Copy(io.Discard, io.LimitReader(response.Body, 4096)); err != nil {
		result.Code = "PROBE_RESPONSE_FAILED"
		return result
	}
	if response.StatusCode != http.StatusOK || !result.TLSVerified {
		result.Code = "PROBE_HTTP_UNEXPECTED"
		return result
	}
	elapsed := float64(time.Since(started).Microseconds()) / 1000
	result.Status, result.Code, result.LatencyMilliseconds = "reachable", "OK", &elapsed
	return result
}

func (server *Server) handleAPIV2RelayHealth(writer http.ResponseWriter, request *http.Request) {
	principal, allowed := server.requireNetworkWriter(writer, request)
	if !allowed {
		return
	}
	var body struct{}
	if !decodeAPIBody(writer, request, &body) {
		return
	}
	relay, err := server.lookupManagedRelay(request.Context(), chi.URLParam(request, "id"))
	if err != nil {
		server.writeRelayManagementError(writer, err)
		return
	}
	if relay.DesiredState == state.RelayStateRevoked {
		writeAPIError(writer, http.StatusConflict, "RELAY_REVOKED: revoked relay cannot be probed")
		return
	}
	allowed, retryAfter, err := server.store.AllowRate("relay-health:user:"+strconv.FormatUint(uint64(principal.UserID), 10), 12, time.Minute, time.Now().UTC())
	if err != nil {
		server.writeNetworkError(writer, err)
		return
	}
	if !allowed {
		writer.Header().Set("Retry-After", strconv.Itoa(max(1, int(retryAfter.Seconds()))))
		writeAPIError(writer, http.StatusTooManyRequests, "RELAY_PROBE_RATE_LIMITED: wait before checking again")
		return
	}
	result := probeManagedRelay(request.Context(), relay, identity.PublicEndpointDialer())
	event := identity.AuditEvent{Actor: principal.actor(), Action: "relay.health_checked", Target: "relay:" + relay.ID,
		Detail: fmt.Sprintf("control-plane TLS probe: %s/%s", result.Status, result.Code)}
	if err := server.identity.AppendAudit(&event); err != nil {
		writeAPIError(writer, http.StatusServiceUnavailable, "RELAY_PROBE_AUDIT_FAILED: check could not be recorded")
		return
	}
	writeJSON(writer, http.StatusOK, result)
}
