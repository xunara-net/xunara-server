package control

import (
	"regexp"
	"strings"
	"testing"

	"github.com/xunara-net/xunara-server/identity"
)

// TestConsoleUIShell checks the modernization contract of the console shell
// (spec section 50): shared design tokens with a dark palette, skip link and
// labelled landmarks, aria-current on the active section, and
// progressive-enhancement controls that stay hidden without JavaScript.
func TestConsoleUIShell(t *testing.T) {
	s := newTestServer(t)
	hs := newTestHTTPServer(t, s)
	client := noRedirectClient()
	memberID := seedRoleUser(t, s, "viewer@example.com", identity.RoleMember)
	cookie, _ := seedUserSession(t, s, memberID)

	resp := getRequest(t, client, hs.URL+"/console/machines", cookie)
	if resp.StatusCode != 200 {
		t.Fatalf("GET /console/machines status = %d", resp.StatusCode)
	}
	body := bodyString(t, resp)

	for _, want := range []string{
		`<a class="skip" href="#main">`,
		`<main id="main" tabindex="-1">`,
		`aria-label="Console sections"`,
		`aria-current="page"`,
		`prefers-color-scheme: dark`,
		`:root[data-theme="dark"]`,
		`localStorage`,
		`<button class="nav-toggle" type="button" aria-expanded="false" aria-controls="console-nav" hidden>`,
		`<button class="theme-toggle" type="button" hidden`,
		// Short Chinese labels must not break between characters in the top
		// bar; the chips stay on one line and the bar wraps instead.
		`.brand, .nav-toggle, .who-name, .topbar .tag, .prefs summary, .theme-toggle, .topbar button { white-space: nowrap; }`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("console shell does not contain %q", want)
		}
	}

	// The modernization keeps the console free of external assets. Links are
	// fine (the footer points at the project pages), but nothing may be
	// loaded from another origin.
	linked := regexp.MustCompile(`<a\b[^>]*>`).ReplaceAllString(body, "")
	for _, banned := range []string{`href="http`, `src="http`, "@import", "url(http"} {
		if strings.Contains(linked, banned) {
			t.Errorf("console shell references an external asset (%q)", banned)
		}
	}

	// Every column header is announced with an explicit scope.
	if got, want := strings.Count(body, `<th scope="col">`), strings.Count(body, "</th>"); got != want {
		t.Errorf("column headers with scope = %d of %d", got, want)
	}
}

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
