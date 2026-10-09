package control

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// TestClientIPIgnoresForwardedHeaders checks the default posture: an anonymous
// caller cannot choose the address its rate limit is keyed on.
func TestClientIPIgnoresForwardedHeaders(t *testing.T) {
	s := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	req.RemoteAddr = "10.0.0.9:44321"
	req.Header.Set("X-Forwarded-For", "203.0.113.7")
	if got := s.clientIP(req); got != "10.0.0.9" {
		t.Fatalf("clientIP = %q, want the peer address 10.0.0.9", got)
	}
}

// TestClientIPUsesTheLastHopBehindATrustedProxy checks the proxied posture:
// the rightmost X-Forwarded-For hop is this deployment's own proxy, while
// anything the caller supplied sits to its left.
func TestClientIPUsesTheLastHopBehindATrustedProxy(t *testing.T) {
	s := newServerWithConfig(t, Config{StateDir: t.TempDir(), TrustedProxy: true})

	cases := []struct {
		name    string
		forward string
		peer    string
		want    string
	}{
		{"single hop", "203.0.113.7", "127.0.0.1:51515", "203.0.113.7"},
		{"caller-supplied prefix is ignored", "1.2.3.4, 203.0.113.7", "127.0.0.1:51515", "203.0.113.7"},
		{"garbage falls back to the peer", "not-an-address", "127.0.0.1:51515", "127.0.0.1"},
		{"no header falls back to the peer", "", "127.0.0.1:51515", "127.0.0.1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/login", nil)
			req.RemoteAddr = tc.peer
			if tc.forward != "" {
				req.Header.Set("X-Forwarded-For", tc.forward)
			}
			if got := s.clientIP(req); got != tc.want {
				t.Fatalf("clientIP = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestTrustedProxySeparatesRateLimitBuckets is the reason the option exists: a
// deployment behind nginx would otherwise key every caller on 127.0.0.1, so
// one busy client would exhaust the limit for everyone.
func TestTrustedProxySeparatesRateLimitBuckets(t *testing.T) {
	untrusted := newUnconfiguredServer(t)
	trusted := newServerWithConfig(t, Config{StateDir: t.TempDir(), TrustedProxy: true})

	attempt := func(s *Server, forwarded string) int {
		t.Helper()
		hs := newTestHTTPServer(t, s)
		client := noRedirectClient()
		var last *http.Response
		for i := 0; i < setupRateLimit+1; i++ {
			req, err := http.NewRequest(http.MethodPost, hs.URL+"/setup", strings.NewReader(url.Values{
				"_csrf":    {"not-a-token"},
				"token":    {"guess"},
				"login":    {"admin"},
				"password": {"correct horse battery"},
				"confirm":  {"correct horse battery"},
			}.Encode()))
			if err != nil {
				t.Fatalf("building the request: %v", err)
			}
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.Header.Set("X-Forwarded-For", forwarded)
			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("posting /setup: %v", err)
			}
			resp.Body.Close()
			if i == setupRateLimit-1 {
				last = resp
			}
		}
		return last.StatusCode
	}

	// Without the option the header is ignored, so both addresses share one
	// bucket: the second address is already exhausted.
	if status := attempt(untrusted, "203.0.113.7"); status == http.StatusTooManyRequests {
		t.Fatalf("first address on the untrusted server = %d, want it to pass", status)
	}
	if status := attempt(untrusted, "198.51.100.8"); status != http.StatusTooManyRequests {
		t.Fatalf("second address on the untrusted server = %d, want 429 (shared bucket)", status)
	}

	// With the option each address has its own bucket.
	if status := attempt(trusted, "203.0.113.7"); status == http.StatusTooManyRequests {
		t.Fatalf("first address on the trusted server = %d, want it to pass", status)
	}
	if status := attempt(trusted, "198.51.100.8"); status == http.StatusTooManyRequests {
		t.Fatalf("second address on the trusted server = %d, want its own bucket", status)
	}
}
