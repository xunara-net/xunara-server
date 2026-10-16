package control

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

// newUnconfiguredServer builds a server the way a fresh deployment starts:
// the built-in account exists, but it has no password and setup is pending.
func newUnconfiguredServer(t *testing.T) *Server {
	t.Helper()

	s, err := New(Config{ServerURL: "http://login.test", StateDir: t.TempDir()})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	ctx, cancel := context.WithCancel(context.Background())
	s.Start(ctx)
	t.Cleanup(cancel)
	return s
}

func (server *Server) readSetupToken() string {
	token, _ := server.loadSetupToken()
	return token
}

// getHTML performs a GET that asks for HTML, the way a browser does.
func getHTML(t *testing.T, client *http.Client, rawURL string, cookies ...*http.Cookie) *http.Response {
	t.Helper()

	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	req.Header.Set("Accept", "text/html,application/xhtml+xml")
	for _, cookie := range cookies {
		if cookie != nil {
			req.AddCookie(cookie)
		}
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", rawURL, err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func TestRootKeepsJSONForClients(t *testing.T) {
	s := newTestServer(t)
	hs := newTestHTTPServer(t, s)

	resp := getRequest(t, noRedirectClient(), hs.URL+"/", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET / status = %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("GET / content type = %q, want JSON", ct)
	}
	body := bodyString(t, resp)
	for _, want := range []string{`"name":"Xunara"`, `"console":"/dashboard"`, `"version"`} {
		if !strings.Contains(body, want) {
			t.Errorf("root JSON lacks %q: %s", want, body)
		}
	}
}
