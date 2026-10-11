package identity

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

var ErrIdentityEndpointBlocked = errors.New("identity: endpoint must use public HTTPS")

var identityReservedNetworks = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"), netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("64:ff9b::/96"), netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("2001::/32"), netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"),
}

func publicIdentityAddress(address netip.Addr) bool {
	address = address.Unmap()
	if !address.IsValid() || !address.IsGlobalUnicast() || address.IsPrivate() || address.IsLoopback() || address.IsLinkLocalUnicast() || address.Zone() != "" {
		return false
	}
	if address.Is6() && !netip.MustParsePrefix("2000::/3").Contains(address) {
		return false
	}
	for _, reserved := range identityReservedNetworks {
		if reserved.Contains(address) {
			return false
		}
	}
	return true
}

// 浏览器配置不得指向本机、内网或带凭据的 URL；DNS 地址还会在实际连接前重新校验。
func ValidatePublicIdentityEndpoint(raw string) error {
	endpoint, err := url.Parse(raw)
	if err != nil || endpoint.Scheme != "https" || endpoint.Hostname() == "" || endpoint.User != nil || endpoint.Opaque != "" || endpoint.Fragment != "" || strings.Contains(endpoint.Hostname(), "%") {
		return ErrIdentityEndpointBlocked
	}
	host := strings.ToLower(strings.TrimSuffix(endpoint.Hostname(), "."))
	if host == "localhost" || strings.HasSuffix(host, ".localhost") || strings.HasSuffix(host, ".local") || strings.HasSuffix(host, ".internal") {
		return ErrIdentityEndpointBlocked
	}
	if address, err := netip.ParseAddr(host); err == nil && !publicIdentityAddress(address) {
		return ErrIdentityEndpointBlocked
	}
	return nil
}

type identityResolver func(context.Context, string) ([]netip.Addr, error)

func resolveIdentityAddresses(ctx context.Context, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

func publicIdentityAddresses(ctx context.Context, host string, resolve identityResolver) ([]netip.Addr, error) {
	addresses, err := resolve(ctx, host)
	if err != nil || len(addresses) == 0 {
		return nil, ErrIdentityEndpointBlocked
	}
	for _, address := range addresses {
		if !publicIdentityAddress(address) {
			return nil, ErrIdentityEndpointBlocked
		}
	}
	return addresses, nil
}

func ValidatePublicIdentityURL(ctx context.Context, raw string) error {
	if err := ValidatePublicIdentityEndpoint(raw); err != nil {
		return err
	}
	endpoint, _ := url.Parse(raw)
	_, err := publicIdentityAddresses(ctx, endpoint.Hostname(), resolveIdentityAddresses)
	return err
}

type publicIdentityTransport struct{ transport *http.Transport }

func (transport *publicIdentityTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if err := ValidatePublicIdentityEndpoint(request.URL.String()); err != nil {
		return nil, err
	}
	response, err := transport.transport.RoundTrip(request)
	if err == nil {
		response.Body = http.MaxBytesReader(nil, response.Body, 1<<20)
	}
	return response, err
}

// 禁用环境代理；TLS 仍验证原始主机名，TCP 只连接刚刚校验的 IP，避免 DNS 重绑定。
func identityPublicDialer(resolve identityResolver, dial func(context.Context, string, string) (net.Conn, error)) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, target string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(target)
		if err != nil {
			return nil, ErrIdentityEndpointBlocked
		}
		addresses, err := publicIdentityAddresses(ctx, host, resolve)
		if err != nil {
			return nil, err
		}
		for _, address := range addresses {
			connection, err := dial(ctx, network, net.JoinHostPort(address.String(), port))
			if err == nil {
				return connection, nil
			}
		}
		return nil, errors.New("identity: public endpoint unavailable")
	}
}

func NewPublicIdentityHTTPClient() *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	transport.DialContext = identityPublicDialer(resolveIdentityAddresses, dialer.DialContext)
	transport.TLSHandshakeTimeout = 10 * time.Second
	transport.ResponseHeaderTimeout = 10 * time.Second
	transport.MaxResponseHeaderBytes = 64 << 10
	return &http.Client{
		Transport: &publicIdentityTransport{transport}, Timeout: 15 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}
