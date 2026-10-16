package control

import (
	"strings"
	"time"
)

// 授权、初始化和错误页共用样式；完整用户中心由独立 Web 应用提供。
const siteTokens = `
:root {
  color-scheme: light dark;
  --bg: #f4f6f8; --surface: #ffffff; --surface-2: #f1f3f6;
  --fg: #15181e; --muted: #59606d;
  --border: #e2e6ec; --border-2: #c9d1dc;
  --accent: #1f5fd8; --accent-fg: #ffffff; --accent-soft: #e8f0fe;
  --ok: #1a7f37; --ok-bg: #e6f4ea;
  --warn: #b42318; --warn-bg: #fdecec;
  --shadow: 0 1px 2px rgba(16, 24, 40, .05), 0 2px 6px rgba(16, 24, 40, .06);
  --radius: 10px; --radius-sm: 7px;
  --font: system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial, "Noto Sans", sans-serif;
  --mono: ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace;
  --wrap: 76rem;
  --chrome: #1b2422; --chrome-fg: #eef3f1; --chrome-muted: #9db0aa;
}
@media (prefers-color-scheme: dark) {
  :root:not([data-theme="light"]) {
    --bg: #101318; --surface: #171b22; --surface-2: #1e232c;
    --fg: #e8eaf0; --muted: #9aa4b2;
    --border: #272d38; --border-2: #38414f;
    --accent: #7aa2ff; --accent-fg: #0d1117; --accent-soft: #1a2333;
    --ok: #6bd08a; --ok-bg: #12291c;
    --warn: #ff9a90; --warn-bg: #31181a;
    --shadow: 0 1px 2px rgba(0, 0, 0, .35), 0 2px 8px rgba(0, 0, 0, .3);
    --chrome: #0f1614; --chrome-fg: #eef3f1; --chrome-muted: #8fa39d;
  }
}
:root[data-theme="dark"] {
  --bg: #101318; --surface: #171b22; --surface-2: #1e232c;
  --fg: #e8eaf0; --muted: #9aa4b2;
  --border: #272d38; --border-2: #38414f;
  --accent: #7aa2ff; --accent-fg: #0d1117; --accent-soft: #1a2333;
  --ok: #6bd08a; --ok-bg: #12291c;
  --warn: #ff9a90; --warn-bg: #31181a;
  --shadow: 0 1px 2px rgba(0, 0, 0, .35), 0 2px 8px rgba(0, 0, 0, .3);
  --chrome: #0f1614; --chrome-fg: #eef3f1; --chrome-muted: #8fa39d;
}
/* Accent palettes: blue is the default, teal matches the warmer
   Chinese-admin look. Both keep the same contrast in light and dark. */
:root[data-accent="teal"] {
  --accent: #0f766e; --accent-fg: #ffffff; --accent-soft: #e5f3f1;
}
@media (prefers-color-scheme: dark) {
  :root[data-accent="teal"]:not([data-theme="light"]) {
    --accent: #5eead4; --accent-fg: #062a26; --accent-soft: #12312c;
  }
}
:root[data-accent="teal"][data-theme="dark"] {
  --accent: #5eead4; --accent-fg: #062a26; --accent-soft: #12312c;
}
* { box-sizing: border-box; }
`

func consoleTimeIn(t time.Time, loc *time.Location) string {
	if t.IsZero() {
		return "never"
	}
	if loc == nil {
		loc = time.UTC
	}
	return t.In(loc).Format("2006-01-02 15:04 MST")
}

// consoleTime formats one timestamp for this server's console.
func (s *Server) consoleTime(t time.Time) string {
	return consoleTimeIn(t, s.consoleLoc)
}

// loadConsoleTimezone resolves the configured console timezone. An empty name
// means UTC, which is the CLI's format too; an unknown name is reported so the
// deployment can fix it instead of silently printing a different zone.
func loadConsoleTimezone(name string) (*time.Location, error) {
	if strings.TrimSpace(name) == "" {
		return time.UTC, nil
	}
	loc, err := time.LoadLocation(name)
	if err != nil {
		return time.UTC, err
	}
	return loc, nil
}
