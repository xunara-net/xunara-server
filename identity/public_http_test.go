package identity

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"testing"
)

func TestPublicIdentityEndpointsRejectPrivateAndCredentialURLs(test *testing.T) {
	for _, endpoint := range []string{
		"http://accounts.example.com", "https://user:password@accounts.example.com", "https://localhost", "https://LOCALHOST.",
		"https://service.local", "https://service.internal", "https://127.0.0.1", "https://10.0.0.1", "https://169.254.169.254",
		"https://100.100.1.1", "https://198.18.0.1", "https://[::1]", "https://[fc00::1]", "https://[::ffff:127.0.0.1]",
		"https://[2002:7f00:1::]", "https://[64:ff9b::7f00:1]", "https://accounts.example.com/#fragment",
	} {
		if err := ValidatePublicIdentityEndpoint(endpoint); !errors.Is(err, ErrIdentityEndpointBlocked) {
			test.Errorf("accepted unsafe endpoint: %s", endpoint)
		}
	}
	for _, endpoint := range []string{"https://github.com", "https://login.example.com:8443/oidc", "https://[2606:4700:4700::1111]"} {
		if err := ValidatePublicIdentityEndpoint(endpoint); err != nil {
			test.Errorf("valid endpoint rejected: %s", endpoint)
		}
	}
	client := NewPublicIdentityHTTPClient()
	if client.Timeout == 0 || client.Transport.(*publicIdentityTransport).transport.Proxy != nil || client.CheckRedirect(&http.Request{}, nil) != http.ErrUseLastResponse {
		test.Fatal("public identity client has no timeout, uses an environment proxy or follows redirects")
	}
}

func TestPublicIdentityDialPinsValidatedAddressAndRejectsRebinding(test *testing.T) {
	sequence := 0
	resolve := func(context.Context, string) ([]netip.Addr, error) {
		sequence++
		if sequence == 1 {
			return []netip.Addr{netip.MustParseAddr("1.1.1.1")}, nil
		}
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	}
	connections := 0
	dial := identityPublicDialer(resolve, func(_ context.Context, _, target string) (net.Conn, error) {
		connections++
		if target != "1.1.1.1:443" {
			test.Fatal("dialer resolved the hostname again instead of using its validated IP")
		}
		return nil, nil
	})
	if _, err := dial(test.Context(), "tcp", "provider.example:443"); err != nil {
		test.Fatal(err)
	}
	if _, err := dial(test.Context(), "tcp", "provider.example:443"); !errors.Is(err, ErrIdentityEndpointBlocked) || connections != 1 {
		test.Fatal("DNS rebind reached a private address")
	}
	resolve = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("10.0.0.1")}, nil
	}
	if _, err := publicIdentityAddresses(test.Context(), "provider.example", resolve); !errors.Is(err, ErrIdentityEndpointBlocked) {
		test.Fatal("mixed public/private DNS response accepted")
	}
}
