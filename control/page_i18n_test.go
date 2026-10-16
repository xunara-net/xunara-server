package control

import (
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// getRequestWithLanguage performs a GET carrying an Accept-Language header, so
// a test can act like a browser that has not chosen a console language yet.
func getRequestWithLanguage(t *testing.T, client *http.Client, rawURL string, language string, cookies ...*http.Cookie) *http.Response {
	t.Helper()

	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	for _, cookie := range cookies {
		if cookie != nil {
			req.AddCookie(cookie)
		}
	}
	if language != "" {
		req.Header.Set("Accept-Language", language)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", rawURL, err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

// TestLocalizeHTML covers the render-time translation rules: text nodes and
// visible attributes translate, code samples, scripts and secrets do not, and
// English output is untouched.
func TestLocalizeHTML(t *testing.T) {
	dict := consoleDict{
		text: map[string]string{
			"Cancel":         "取消",
			"Sign out":       "退出",
			"Tailnet & lock": "网络锁",
		},
		block: map[string]string{
			"Say <code>hi</code> now.": "现在说 <code>hi</code>。",
		},
	}
	page := strings.Join([]string{
		`<p>Say <code>hi</code> now.</p>`,
		`<p>Untranslated prose stays as it is.</p>`,
		`<td>Cancel</td>`,
		`<pre>Cancel</pre>`,
		`<code>Cancel</code>`,
		`<td><span translate="no">Cancel</span></td>`,
		`<span class="who-name" translate="no">Sign out</span>`,
		`<script>var label = "Cancel";</script>`,
		`<style>.a { content: "Cancel" }</style>`,
		`<button placeholder="Cancel" aria-label="Sign out" title="Cancel">Sign out</button>`,
		`<span>Tailnet &amp; lock</span>`,
	}, "")

	got := localizeHTML(dict, page)
	for _, want := range []string{
		"现在说 <code>hi</code>。",
		"<td>取消</td>",
		"<pre>Cancel</pre>",
		"<code>Cancel</code>",
		`<span translate="no">Cancel</span>`,
		`<span class="who-name" translate="no">Sign out</span>`,
		`<script>var label = "Cancel";</script>`,
		`placeholder="取消"`,
		`aria-label="退出"`,
		`title="取消"`,
		">退出</button>",
		"网络锁",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("localized page does not contain %q:\n%s", want, got)
		}
	}
	for _, absent := range []string{`<td>Cancel</td>`, `>Sign out</button>`} {
		if strings.Contains(got, absent) {
			t.Errorf("localized page still contains %q:\n%s", absent, got)
		}
	}
	if !strings.Contains(got, "Untranslated prose stays as it is.") {
		t.Error("an untranslated paragraph was dropped or altered")
	}

	// Prefix rules translate a sentence built around a runtime value, and
	// T formats the counts the templates pass in.
	pref := consoleDict{text: map[string]string{}, prefix: map[string]string{"Fix the file:": "请修复文件："}}
	got = localizeHTML(pref, `<p>Fix the file: /etc/policy.hujson</p>`)
	if !strings.Contains(got, "请修复文件：/etc/policy.hujson") {
		t.Errorf("prefix rule did not apply:\n%s", got)
	}
	if got := translator("zh")("%d rules", 3); got != "3 条规则" {
		t.Errorf("T with arguments = %q, want 3 条规则", got)
	}
	if got := translator("en")("%d rules", 3); got != "3 rules" {
		t.Errorf("T with arguments (en) = %q, want 3 rules", got)
	}

	// English is a pass-through: the same bytes come back.
	dictEN := consoleTranslations[consoleDefaultLang]
	if dictEN.text != nil || dictEN.block != nil {
		t.Skip("English dictionary is unexpectedly populated")
	}
	if got := translateHTML("en", page); got != page {
		t.Errorf("English page changed:\n%s", got)
	}
}

// TestConsoleTimezone checks the console prints local time when the operator
// configured a zone, and UTC for an unknown one.
func TestConsoleTimezone(t *testing.T) {
	loc, err := loadConsoleTimezone("Asia/Shanghai")
	if err != nil {
		t.Skipf("zone database unavailable: %v", err)
	}
	moment := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	if got, want := consoleTimeIn(moment, loc), "2026-10-08 20:00 CST"; got != want {
		t.Errorf("Shanghai time = %q, want %q", got, want)
	}

	fallback, err := loadConsoleTimezone("Nowhere/Elsewhere")
	if err == nil {
		t.Error("an unknown zone name was accepted")
	}
	if fallback != time.UTC {
		t.Errorf("unknown zone fell back to %v, want UTC", fallback)
	}
	if got := consoleTimeIn(time.Time{}, loc); got != "never" {
		t.Errorf("zero time = %q, want never", got)
	}
	if got := consoleTimeIn(moment, nil); got != "2026-10-08 12:00 UTC" {
		t.Errorf("nil location = %q, want UTC", got)
	}

	s := newServerWithConfig(t, Config{ConsoleTimezone: "UTC"})
	if got := s.consoleTime(moment); got != "2026-10-08 12:00 UTC" {
		t.Errorf("configured console time = %q, want UTC format", got)
	}
}

// TestErrorPageLocalized checks the standalone pages (errors, sign-in) follow
// the same language as the console.
func TestErrorPageLocalized(t *testing.T) {
	s := newServerWithConfig(t, Config{ServerURL: testPasskeyOrigin, Passkeys: testPasskeyConfig()})
	hs := newTestHTTPServer(t, s)

	body := bodyString(t, getRequestWithLanguage(t, noRedirectClient(), hs.URL+"/login", "zh-CN,zh;q=0.9"))
	for _, want := range []string{"<h1>登录</h1>", "登录控制台以管理此网络。", "密码", `<html lang="zh"`} {
		if !strings.Contains(body, want) {
			t.Errorf("Chinese sign-in page does not contain %q:\n%s", want, body)
		}
	}

	// An error page follows the same preference, including its tab title.
	body = bodyString(t, getRequestWithLanguage(t, noRedirectClient(), hs.URL+"/register/unknown-link", "zh-CN,zh;q=0.9"))
	if !strings.Contains(body, `<html lang="zh"`) || !strings.Contains(body, "<title>未知登录链接") {
		t.Errorf("error page is not localized:\n%.600s", body)
	}
	if !strings.Contains(body, "返回登录") {
		t.Errorf("error page lacks the localized sign-in link:\n%.600s", body)
	}
}

// TestNotFoundPage checks the handler for unmatched paths: a browser that
// asked for HTML gets the localized page, while the API and the client
// binaries keep the plain-text reply they parse today.
func TestNotFoundPage(t *testing.T) {
	s := newServerWithConfig(t, Config{ServerURL: testPasskeyOrigin, Passkeys: testPasskeyConfig()})
	hs := newTestHTTPServer(t, s)

	request := func(target, accept, language string) *http.Response {
		t.Helper()
		req, err := http.NewRequest(http.MethodGet, hs.URL+target, nil)
		if err != nil {
			t.Fatalf("building request: %v", err)
		}
		if accept != "" {
			req.Header.Set("Accept", accept)
		}
		if language != "" {
			req.Header.Set("Accept-Language", language)
		}
		resp, err := noRedirectClient().Do(req)
		if err != nil {
			t.Fatalf("GET %s: %v", target, err)
		}
		t.Cleanup(func() { resp.Body.Close() })
		return resp
	}

	browser := request("/no-such-page", "text/html,application/xhtml+xml", "zh-CN,zh;q=0.9")
	if browser.StatusCode != http.StatusNotFound {
		t.Errorf("browser status = %d, want 404", browser.StatusCode)
	}
	body := bodyString(t, browser)
	for _, want := range []string{`<html lang="zh"`, "未找到页面", "你访问的页面不存在。"} {
		if !strings.Contains(body, want) {
			t.Errorf("Chinese 404 page does not contain %q:\n%.400s", want, body)
		}
	}

	english := bodyString(t, request("/no-such-page", "text/html", "en-US,en;q=0.9"))
	if !strings.Contains(english, "Page not found") || !strings.Contains(english, "The page you asked for does not exist.") {
		t.Errorf("English 404 page is wrong:\n%.400s", english)
	}

	// Everything that is not a browser keeps the plain-text reply, including
	// an HTML-accepting path under /api/.
	for _, tc := range []struct{ name, target, accept string }{
		{"api client", "/no-such-page", "application/json"},
		{"no accept header", "/no-such-page", ""},
		{"unmatched api path", "/api/v2/no-such-endpoint", "text/html"},
		{"unmatched retired console path", "/console/no-such-page", "application/json"},
	} {
		req, err := http.NewRequest(http.MethodGet, hs.URL+tc.target, nil)
		if err != nil {
			t.Fatalf("building request: %v", err)
		}
		if tc.accept != "" {
			req.Header.Set("Accept", tc.accept)
		}
		resp, err := noRedirectClient().Do(req)
		if err != nil {
			t.Fatalf("GET %s: %v", tc.target, err)
		}
		raw, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			t.Fatalf("reading body: %v", err)
		}
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("%s status = %d, want 404", tc.name, resp.StatusCode)
		}
		if got := string(raw); got != "404 page not found\n" {
			t.Errorf("%s body = %q, want a plain-text 404", tc.name, got)
		}
		if ct := resp.Header.Get("Content-Type"); strings.Contains(ct, "text/html") {
			t.Errorf("%s content type = %q, want a non-HTML reply", tc.name, ct)
		}
	}

}

// TestLoginScriptLocalized checks the same for the passkey sign-in script on
// the standalone sign-in page.
func TestLoginScriptLocalized(t *testing.T) {
	s := newServerWithConfig(t, Config{ServerURL: testPasskeyOrigin, Passkeys: testPasskeyConfig()})
	hs := newTestHTTPServer(t, s)

	body := bodyString(t, getRequestWithLanguage(t, noRedirectClient(), hs.URL+"/login", "zh-CN,zh;q=0.9"))
	if !strings.Contains(body, `err.message || "通行密钥登录失败。"`) {
		t.Errorf("Chinese passkey script keeps the English fallback:\n%.400s", body)
	}
	body = bodyString(t, getRequestWithLanguage(t, noRedirectClient(), hs.URL+"/login", "en-US,en;q=0.9"))
	if !strings.Contains(body, `err.message || "Passkey sign-in failed."`) {
		t.Errorf("English passkey script changed:\n%.400s", body)
	}
}
