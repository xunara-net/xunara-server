package control

import (
	"strings"
	"testing"

)


// TestLoginPageSharesDesignTokens checks the sign-in flow uses the console's
// palette instead of a separate look.
func TestLoginPageSharesDesignTokens(t *testing.T) {
	s := newServerWithConfig(t, Config{ServerURL: testPasskeyOrigin, Passkeys: testPasskeyConfig()})
	hs := newTestHTTPServer(t, s)

	resp := getRequest(t, noRedirectClient(), hs.URL+"/login", nil)
	if resp.StatusCode != 200 {
		t.Fatalf("GET /login status = %d, want 200", resp.StatusCode)
	}
	body := bodyString(t, resp)
	for _, want := range []string{"--accent:", "prefers-color-scheme: dark", "var(--surface)"} {
		if !strings.Contains(body, want) {
			t.Errorf("login page does not contain %q", want)
		}
	}
	if strings.Contains(body, "src=\"http") || strings.Contains(body, "@import") {
		t.Error("login page references an external asset")
	}
}
