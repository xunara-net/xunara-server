package control

import (
	"bytes"
	"html/template"
	"io"
	"net/http"
	"strings"
	"time"
)

// The console shares the sign-in pages' rules: no external assets, no scripts,
// a strict referrer policy. Every value is rendered through html/template, so
// operator-entered text (hostnames, user names, DNS values) is escaped.
// Secrets are never rendered except where a handler explicitly passes a
// one-time value such as a freshly created pre-auth key.

// siteTokens is the shared design system of the web surface: one palette with
// light and dark values, system fonts only, and no external assets. Both the
// console shell and the sign-in pages build on it so the whole flow looks the
// same; page-specific rules follow the token block in each page's <style>.
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

const consoleHead = `<!doctype html>
<html lang="{{.Lang}}" data-accent="{{.Accent}}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>{{T .Title}} — Xunara console</title>
<style>` + siteTokens + `
body { font-family: var(--font); margin: 0; background: var(--bg); color: var(--fg);
       line-height: 1.6; -webkit-text-size-adjust: 100%; }
.skip { position: absolute; left: -999px; top: 0; z-index: 100; background: var(--surface);
        color: var(--fg); padding: .6rem .9rem; border-radius: 0 0 var(--radius-sm) 0; }
.skip:focus { left: 0; }

/* Top bar: dark chrome with the brand, preferences and the account block. */
.topbar { position: sticky; top: 0; z-index: 50; display: flex; align-items: center; gap: .8rem;
          flex-wrap: wrap; row-gap: .4rem;
          padding: .62rem 1.4rem; background: var(--chrome); color: var(--chrome-fg); }
.brand { display: flex; align-items: baseline; gap: .45rem; font-size: 1rem; font-weight: 700; letter-spacing: .01em; }
.brand span { color: var(--chrome-muted); font-weight: 500; }
.who { margin-left: auto; display: flex; align-items: center; gap: .5rem; flex-wrap: wrap;
       justify-content: flex-end; font-size: .84rem; color: var(--chrome-muted); }
/* Chinese labels are short enough to break between two characters, which reads
   as vertical text in a squeezed flex row; keep every chip on one line and let
   the bar wrap instead. */
.brand, .nav-toggle, .who-name, .topbar .tag, .prefs summary, .theme-toggle, .topbar button { white-space: nowrap; }
.who form { margin: 0; }
.who-name { font-weight: 600; color: var(--chrome-fg); }
.topbar .tag { background: rgba(255, 255, 255, .09); color: var(--chrome-muted); border-color: transparent; }
.topbar button { font-size: .82rem; }
button.ghost { background: transparent; color: var(--chrome-muted); border-color: rgba(255, 255, 255, .22); }
button.ghost:hover { color: var(--chrome-fg); background: rgba(255, 255, 255, .08); }
.nav-toggle, .theme-toggle { display: none; }
html.js .theme-toggle { display: inline-flex; align-items: center; background: transparent; color: var(--chrome-muted);
  border: 1px solid rgba(255, 255, 255, .22); padding: .3rem .5rem; }

/* Preferences: a plain <details>, so language and accent work without JS. */
.prefs { position: relative; }
.prefs summary { list-style: none; cursor: pointer; padding: .3rem .55rem; border: 1px solid rgba(255, 255, 255, .22);
  border-radius: var(--radius-sm); color: var(--chrome-muted); }
.prefs summary::-webkit-details-marker { display: none; }
.prefs[open] summary, .prefs summary:hover { color: var(--chrome-fg); background: rgba(255, 255, 255, .08); }
.prefs-menu { position: absolute; right: 0; top: calc(100% + .45rem); z-index: 60; min-width: 11rem;
  background: var(--surface); color: var(--fg); border: 1px solid var(--border); border-radius: var(--radius);
  box-shadow: var(--shadow); padding: .45rem; display: flex; flex-direction: column; }
.prefs-menu a { color: var(--fg); text-decoration: none; padding: .35rem .5rem; border-radius: var(--radius-sm); font-size: .86rem; }
.prefs-menu a:hover { background: var(--surface-2); }
.prefs-menu a.active { background: var(--accent-soft); color: var(--accent); font-weight: 600; }
.prefs-label { margin: .35rem .5rem .15rem; font-size: .72rem; font-weight: 700; letter-spacing: .06em;
  text-transform: uppercase; color: var(--muted); }

/* Shell: sidebar plus content, the familiar Chinese admin layout. */
.shell { display: grid; grid-template-columns: 15.5rem minmax(0, 1fr); gap: 0 1.6rem;
         max-width: var(--wrap); margin: 0 auto; padding: 0 1.4rem; align-items: start; }
.sidebar { position: sticky; top: 3.6rem; max-height: calc(100vh - 4.4rem); overflow-y: auto;
           padding: 1.1rem 0 2rem; }
.sidebar nav { display: flex; flex-direction: column; gap: .08rem; }
.nav-group { margin: 1rem .6rem .3rem; font-size: .72rem; font-weight: 700; letter-spacing: .07em;
             text-transform: uppercase; color: var(--muted); }
.sidebar a { display: block; padding: .42rem .65rem; border-radius: var(--radius-sm); color: var(--fg);
             text-decoration: none; font-size: .9rem; border-left: 3px solid transparent; }
.sidebar a:hover { background: var(--surface-2); }
.sidebar a.active { background: var(--accent-soft); color: var(--accent); font-weight: 600; border-left-color: var(--accent); }
main { min-width: 0; padding: 1.3rem 0 3rem; }
main:focus { outline: none; }
.page-head { margin: 0 0 1rem; }
.page-head h1 { font-size: 1.4rem; margin: 0 0 .25rem; letter-spacing: -.01em; }
.page-head .lede { margin: 0; color: var(--muted); }
h2 { font-size: 1.15rem; margin: 1.7rem 0 .5rem; }
h3 { font-size: 1rem; margin: 1.2rem 0 .4rem; }
h2:first-child, h3:first-child { margin-top: .4rem; }
p { margin: .5rem 0; }
a { color: var(--accent); }

/* Cards, tables and status badges. */
.cards { display: grid; grid-template-columns: repeat(auto-fill, minmax(10rem, 1fr)); gap: .7rem; margin: 1rem 0 1.4rem; }
.card { display: block; background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius);
        padding: .85rem 1rem; color: inherit; text-decoration: none; }
.card .num { display: block; font-size: 1.5rem; font-weight: 650; letter-spacing: -.01em; }
.card span:last-child { color: var(--muted); font-size: .84rem; }
.table-wrap { overflow-x: auto; margin: .6rem 0 1rem; background: var(--surface); border: 1px solid var(--border);
              border-radius: var(--radius); }
table { width: 100%; border-collapse: collapse; font-size: .88rem; }
th, td { text-align: left; padding: .55rem .8rem; border-bottom: 1px solid var(--border); vertical-align: top;
         overflow-wrap: anywhere; }
th { background: var(--surface-2); color: var(--muted); font-weight: 600; font-size: .8rem; white-space: nowrap; }
tbody tr:hover td { background: var(--surface-2); }
tr:last-child td { border-bottom: 0; }
td.actions, th.actions { text-align: right; white-space: nowrap; }
/* Identifiers in tables read as one token; the row scrolls, so they must not
   be split mid-word (prose keeps normal wrapping). */
td code, th code { white-space: nowrap; }
.table-filter { display: block; width: 100%; max-width: 20rem; margin: .7rem 0 0; font: inherit;
                padding: .42rem .6rem; border: 1px solid var(--border-2); border-radius: var(--radius-sm);
                background: var(--surface); color: var(--fg); }
.badge { display: inline-flex; align-items: center; gap: .35rem; padding: .05rem .5rem; border-radius: 999px;
         border: 1px solid var(--border); background: var(--surface-2); color: var(--muted);
         font-size: .78rem; font-weight: 600; white-space: nowrap; }
.badge::before { content: ""; width: .42rem; height: .42rem; border-radius: 50%; background: currentColor; }
.badge.ok { color: var(--ok); background: var(--ok-bg); border-color: currentColor; }
.badge.warn { color: var(--warn); background: var(--warn-bg); border-color: currentColor; }
.ok { color: var(--ok); font-weight: 600; }
.off { color: var(--muted); }
.warn { color: var(--warn); font-weight: 600; }
.tag { display: inline-block; background: var(--surface-2); color: var(--muted); border: 1px solid var(--border);
       border-radius: 999px; padding: .05rem .45rem; font-size: .73rem; font-weight: 600; }
.notice { background: var(--accent-soft); border: 1px solid var(--border); border-radius: var(--radius-sm);
          padding: .6rem .9rem; margin: .6rem 0; }
.notice.warn { background: var(--warn-bg); border-color: var(--warn); }
.empty { border: 1px dashed var(--border-2); border-radius: var(--radius); background: var(--surface);
         padding: 2rem 1rem; text-align: center; color: var(--muted); margin: .8rem 0 1rem; }

/* Forms. */
input:not([type="hidden"]):not([type="checkbox"]) { font: inherit; padding: .42rem .55rem;
  border: 1px solid var(--border-2); border-radius: var(--radius-sm); background: var(--surface); color: var(--fg); }
input::placeholder { color: var(--muted); }
a:focus-visible, input:focus-visible, button:focus-visible, summary:focus-visible { outline: 2px solid var(--accent);
  outline-offset: 2px; }
button { font: inherit; font-size: .85rem; font-weight: 600; padding: .38rem .72rem; border: 1px solid transparent;
         border-radius: var(--radius-sm); cursor: pointer; background: var(--accent); color: var(--accent-fg); }
button:hover { filter: brightness(1.06); }
button.danger { background: transparent; color: var(--warn); border-color: var(--warn); }
button + button { margin-left: .3rem; }
code { font-family: var(--mono); font-size: .82em; background: var(--surface-2); border: 1px solid var(--border);
       padding: .05rem .3rem; border-radius: 5px; }
pre { background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius-sm);
      padding: .75rem; overflow-x: auto; font-size: .82rem; }
dl { display: grid; grid-template-columns: max-content 1fr; gap: .35rem 1.1rem; margin: .6rem 0 1rem; }
dt { color: var(--muted); }
dd { margin: 0; }
.field { display: flex; gap: .6rem; align-items: center; margin: .55rem 0; flex-wrap: wrap; }
.field label { color: var(--muted); font-size: .86rem; }
.sr-only { position: absolute; width: 1px; height: 1px; margin: -1px; padding: 0; overflow: hidden;
           clip: rect(0 0 0 0); white-space: nowrap; border: 0; }
footer.console-foot { border-top: 1px solid var(--border); margin-top: 1rem; padding: 1.2rem 1.4rem 2rem;
  text-align: center; color: var(--muted); font-size: .8rem; }
footer.console-foot a { color: var(--muted); }

@media (max-width: 900px) {
  .topbar { padding: .6rem .9rem; }
  html.js .nav-toggle { display: inline-flex; align-items: center; background: transparent; color: var(--chrome-muted);
    border: 1px solid rgba(255, 255, 255, .22); padding: .3rem .6rem; }
  .shell { grid-template-columns: minmax(0, 1fr); padding: 0 .9rem; }
  .sidebar { position: static; max-height: none; padding: .8rem 0 .2rem; }
  html.js .sidebar { display: none; }
  html.js body.nav-open .sidebar { display: block; }
  main { padding: .9rem 0 2rem; }
  dl { grid-template-columns: 1fr; gap: .1rem; }
  dt { margin-top: .5rem; }
  /* Phone widths have no room for nine columns: keep each cell wide enough
     for a word or two and let the table scroll inside .table-wrap instead of
     squeezing values into one character per line. */
  th, td { min-width: 6.5rem; }
  .page-head h1 { font-size: 1.2rem; }
  .cards { grid-template-columns: repeat(2, minmax(0, 1fr)); }
}
</style>
</head>
<body>
<a class="skip" href="#main">{{T "Skip to content"}}</a>
<header class="topbar">
<span class="brand">Xunara <span>console</span></span>
<button class="nav-toggle" type="button" aria-expanded="false" aria-controls="console-nav" hidden>{{T "Menu"}}</button>
<div class="who">
<details class="prefs">
<summary aria-label="{{T "Appearance"}}" title="{{T "Appearance"}}">⚙</summary>
<div class="prefs-menu">
<p class="prefs-label">{{T "Language"}}</p>
<a href="/console/prefs?lang=zh&return_to={{.Path}}"{{if eq .Lang "zh"}} class="active"{{end}}>中文</a>
<a href="/console/prefs?lang=en&return_to={{.Path}}"{{if eq .Lang "en"}} class="active"{{end}}>English</a>
<p class="prefs-label">{{T "Accent color"}}</p>
<a href="/console/prefs?accent=blue&return_to={{.Path}}"{{if eq .Accent "blue"}} class="active"{{end}}>{{T "Blue"}}</a>
<a href="/console/prefs?accent=teal&return_to={{.Path}}"{{if eq .Accent "teal"}} class="active"{{end}}>{{T "Teal"}}</a>
</div>
</details>
<button class="theme-toggle" type="button" hidden aria-label="{{T "Switch color theme"}}">◐</button>
<span class="who-name" translate="no">{{.User}}</span> <span class="tag">{{T .Role}}</span>
<form method="post" action="/logout"><input type="hidden" name="csrf" value="{{.CSRF}}"><button class="ghost" type="submit">{{T "Sign out"}}</button></form>
</div>
</header>
<div class="shell">
<aside class="sidebar" id="console-nav">
<nav aria-label="{{T "Console sections"}}">
{{range .NavGroups}}{{if .Label}}<p class="nav-group">{{T .Label}}</p>{{end}}{{range .Items}}<a href="{{.Href}}"{{if .Active}} class="active" aria-current="page"{{end}}>{{T .Title}}</a>
{{end}}{{end}}
</nav>
</aside>
<main id="main" tabindex="-1">
<header class="page-head">
<h1>{{T .Title}}</h1>
{{if .Lede}}<p class="lede">{{T .Lede}}</p>{{end}}
</header>
{{if not .CanWrite}}<p class="notice">{{T "Your role is read-only; controls that change the tailnet are hidden."}}</p>{{end}}
{{if .Notice}}<p class="notice" role="status">{{.Notice}}</p>{{end}}
`

const consoleFoot = `</main>
</div>
<footer class="console-foot">Xunara {{T "console"}} · v{{.Version}} ·
<a href="https://github.com/xunara-net/xunara">GitHub</a> ·
<a href="https://github.com/xunara-net/xunara/issues">{{T "Feedback"}}</a> ·
<a href="https://github.com/xunara-net/xunara/blob/master/Xunara_AI_Development_Docs_2026-10-05/PROJECT_SPEC.md">{{T "Documentation"}}</a></footer>
<script>` + consoleJS + `</script>
</body></html>`

// consoleJS is the console's progressive enhancement: the pages work without
// JavaScript, and this adds a persisted dark-mode toggle, a collapsible mobile
// nav, scrollable tables with a row filter, and a confirmation for destructive
// submissions. It is inline like the passkey ceremony, so the console keeps
// its no-external-assets rule, and it never receives server data.
const consoleJS = `
(function () {
  var root = document.documentElement;
  root.classList.add("js");

  function preferredTheme() {
    var stored = null;
    try { stored = localStorage.getItem("xunara-theme"); } catch (err) { stored = null; }
    if (stored === "dark" || stored === "light") return stored;
    return window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  }
  var themeButton = document.querySelector(".theme-toggle");
  if (themeButton) {
    themeButton.hidden = false;
    /* The label names the theme the button switches *to*; both are template
       message ids so the hint follows the console language. */
    var themeLabels = { dark: {{T "Switch to dark theme"}}, light: {{T "Switch to light theme"}} };
    var label = function () {
      var next = preferredTheme() === "dark" ? "light" : "dark";
      themeButton.textContent = next === "dark" ? "\u263e" : "\u2600";
      themeButton.setAttribute("aria-label", themeLabels[next]);
      themeButton.title = themeLabels[next];
    };
    label();
    themeButton.addEventListener("click", function () {
      var next = preferredTheme() === "dark" ? "light" : "dark";
      root.setAttribute("data-theme", next);
      try { localStorage.setItem("xunara-theme", next); } catch (err) {}
      label();
    });
  }

  var navToggle = document.querySelector(".nav-toggle");
  if (navToggle) {
    navToggle.hidden = false;
    navToggle.addEventListener("click", function () {
      var open = document.body.classList.toggle("nav-open");
      navToggle.setAttribute("aria-expanded", open ? "true" : "false");
    });
  }

  Array.prototype.forEach.call(document.querySelectorAll("main table"), function (table) {
    if (table.parentElement && table.parentElement.className === "table-wrap") return;
    var wrap = document.createElement("div");
    wrap.className = "table-wrap";
    table.parentNode.insertBefore(wrap, table);
    wrap.appendChild(table);
    if (!table.tBodies.length || table.tBodies[0].rows.length < 6) return;
    var box = document.createElement("input");
    box.type = "search";
    box.className = "table-filter";
    box.placeholder = {{T "Filter rows…"}};
    box.setAttribute("aria-label", {{T "Filter table rows"}});
    wrap.parentNode.insertBefore(box, wrap);
    box.addEventListener("input", function () {
      var needle = box.value.toLowerCase();
      Array.prototype.forEach.call(table.tBodies, function (body) {
        Array.prototype.forEach.call(body.rows, function (row) {
          row.hidden = needle !== "" && row.textContent.toLowerCase().indexOf(needle) < 0;
        });
      });
    });
  });

  document.addEventListener("submit", function (event) {
    var form = event.target;
    if (!form || form.dataset.confirm === "skip") return;
    var danger = form.querySelector("button.danger");
    if (!danger) return;
    var verb = danger.textContent.trim() || {{T "Confirm"}};
    if (!window.confirm({{T "Please confirm: %s"}}.replace("%s", verb))) event.preventDefault();
  });
})();
`

// consoleTitles label each section; the nav identifier doubles as the key so a
// handler cannot forget to set a page title.
var consoleTitles = map[string]string{
	"plan":       "Plan and network",
	"overview":   "Overview",
	"machines":   "Machines",
	"exit-nodes": "Exit nodes",
	"services":   "Services",
	"relays":     "Relays",
	"serve":      "Serve",
	"devices":    "Devices",
	"users":      "Users",
	"passkeys":   "Passkeys",
	"dns":        "DNS",
	"derp":       "DERP",
	"auth-keys":  "Auth keys",
	"agents":     "Agents",
	"api-keys":   "API keys",
	"shares":     "Shares",
	"reach":      "Reach",
	"flux":       "Flux",
	"ssh-check":  "SSH checks",
	"webhooks":   "Webhooks",
	"policy":     "Policy",
	"security":   "Security",
	"audit":      "Audit",
}

// consolePage assembles a console template from the shared shell and a body.
func consolePage(name, body string) *template.Template {
	tmpl := template.New(name).Funcs(template.FuncMap{
		"fmtTime":  consoleTime,
		"argvLine": consoleArgvLine,
		"join":     func(values []string) string { return strings.Join(values, ", ") },
		"T":        translator("en"),
	})
	return template.Must(tmpl.Parse(consoleHead + body + consoleFoot))
}

// consoleArgvPreviewLimit bounds the one-line argv preview on the Reach list.
const consoleArgvPreviewLimit = 120

// consoleArgvLine renders a one-line command preview: the same argv the agent
// executed, joined with spaces and cut on a rune boundary. The session page
// shows every argument on its own.
func consoleArgvLine(argv []string) string {
	line := strings.Join(argv, " ")
	runes := []rune(line)
	if len(runes) > consoleArgvPreviewLimit {
		return string(runes[:consoleArgvPreviewLimit]) + "…"
	}
	return line
}

// consoleTime formats a timestamp in UTC. It is the parse-time binding of the
// console's fmtTime helper; each request renders through the server's own
// formatter, which uses the configured console timezone.
func consoleTime(t time.Time) string {
	return consoleTimeIn(t, time.UTC)
}

// consoleTimeIn formats a timestamp for the web console: the operator reads
// local time with the zone name, and the zero time reads as "never".
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

var (
	consoleOverviewTemplate = consolePage("overview", `
<h2>Overview</h2>
<div class="cards">
<div class="card"><span class="num">{{.MachinesOnline}}</span><span>machines online</span></div>
<div class="card"><span class="num">{{.MachinesTotal}}</span><span>machines total</span></div>
<div class="card"><span class="num">{{.Users}}</span><span>users</span></div>
<div class="card"><span class="num">{{.PendingDevices}}</span><span>pending devices</span></div>
<div class="card"><span class="num">{{.DNSRecords}}</span><span>DNS records</span></div>
<div class="card"><span class="num">{{.AuthKeys}}</span><span>auth keys</span></div>
<div class="card"><span class="num">{{.Agents}}</span><span>agent credentials</span></div>
</div>
<h2>Access control</h2>
<p>{{if .PolicyDocument}}{{T "%d rules" .PolicyRules}}{{else}}{{T "allow-all (no policy document)"}}{{end}}</p>
<h2>Tailnet lock</h2>
{{if .TailnetLock.Enabled}}
<p><span class="ok">enabled</span> — chain head <code>{{.TailnetLock.Head}}</code>;
{{.TailnetLock.Nodes.Signed}} of {{.TailnetLock.Nodes.Total}} nodes carry a node-key
signature, so peers verify every node key without trusting this control plane.</p>
{{else if .TailnetLock.Disabled}}
<p><span class="warn">disabled</span> — the chain is kept, so a node that still
enforces tailnet lock locally can fetch the disablement secret and clear its
state. Node keys are no longer verified by peers.</p>
{{else}}
<p>Not enabled. Node keys are not verified by peers; an administrator turns it on
with <code>tailscale lock init</code> from a trusted machine.</p>
{{end}}
<h2>Workload identity</h2>
{{if .IDTokenError}}
<p><span class="warn">unavailable</span> — {{.IDTokenError}}</p>
{{else if .IDToken.Enabled}}
<p><span class="ok">issuer enabled</span> — nodes fetch identity tokens at
<code>{{.IDToken.Issuer}}</code>/machine/id-token; relying parties verify them with the
public keys at <code>{{.IDToken.JWKSURL}}</code>.</p>
<p>{{T "%d signing key(s) published; the active key is" (len .IDToken.Keys)}}
<code>{{.IDToken.ActiveKeyID}}</code>{{T ". Issued tokens are valid for %d seconds and name the requesting node, never another one." .IDToken.TokenTTLSeconds}}
{{T "Rotate the key with"}} <code>xunara id-token rotate</code>.</p>
{{else}}
<p>Not enabled: this deployment has no externally reachable <code>-server-url</code>,
so it has no issuer URL to be a trust anchor for, and nodes receive 501 from
<code>/machine/id-token</code>.</p>
{{end}}
`)

	consoleMachinesTemplate = consolePage("machines", `
<h2>Machines</h2>
<table>
<thead><tr><th scope="col">Machine</th><th scope="col">Status</th><th scope="col">Owner</th><th scope="col">Method</th><th scope="col">Addresses</th><th scope="col">Routes</th><th scope="col">Posture</th><th scope="col">Services</th><th scope="col">Actions</th></tr></thead>
<tbody>
{{range .Machines}}
<tr>
<td>{{.Hostname}}
{{if .Ephemeral}} <span class="tag">ephemeral</span>{{end}}
{{if .ExitNode}} <span class="tag">exit node</span>{{end}}
{{if .Expired}} <span class="tag warn">expired</span>{{end}}</td>
<td>{{if .Online}}<span class="ok">online</span>{{else}}<span class="off">offline</span>{{end}}</td>
<td>{{.UserLoginName}}</td>
<td>{{.Method}}</td>
<td>{{if .IPv4}}<code>{{.IPv4}}</code>{{end}}{{if .IPv6}}<br><code>{{.IPv6}}</code>{{end}}</td>
<td>
{{if .ApprovedRoutes}}approved: {{range .ApprovedRoutes}}<code>{{.}}</code> {{end}}<br>{{end}}
{{if .AnnouncedRoutes}}announced: {{range .AnnouncedRoutes}}<code>{{.}}</code> {{end}}{{else}}announced: none{{end}}
</td>
<td>{{if .DeviceAttrCount}}{{.DeviceAttrCount}} attr{{if ne .DeviceAttrCount 1}}s{{end}}{{else}}—{{end}}</td>
<td>{{if .ServiceCount}}{{.ServiceCount}}{{else}}—{{end}}</td>
<td>
{{if $.CanWrite}}
<form method="post" action="/console/machines/{{.ID}}/routes">
<input type="hidden" name="csrf" value="{{$.CSRF}}">
<button name="action" value="approve-all" type="submit">Approve routes</button>
<button name="action" value="unapprove-all" type="submit">Withdraw</button>
</form>
<form method="post" action="/console/machines/{{.ID}}/delete">
<input type="hidden" name="csrf" value="{{$.CSRF}}">
<button class="danger" type="submit">Delete</button>
</form>
{{else}}—{{end}}
</td>
</tr>
{{else}}
<tr><td colspan="9">No machines have registered yet.</td></tr>
{{end}}
</tbody>
</table>
`)

	consoleDevicesTemplate = consolePage("devices", `
<h2>Pending devices</h2>
<p>Approving a device authorizes the machine keys below; it does not make the
device a human identity.</p>
{{if .Devices}}
<table>
<thead><tr><th scope="col">Device</th><th scope="col">Operating system</th><th scope="col">Requested</th><th scope="col">Expires</th><th scope="col">Actions</th></tr></thead>
<tbody>
{{range .Devices}}
<tr>
<td>{{.Hostname}}</td>
<td>{{.OS}}</td>
<td>{{fmtTime .Created}}</td>
<td>{{fmtTime .Expires}}</td>
<td>
{{if $.CanWrite}}
<form method="post" action="/console/devices/{{.ID}}/approve">
<input type="hidden" name="csrf" value="{{$.CSRF}}">
<button type="submit">Approve</button>
</form>
<form method="post" action="/console/devices/{{.ID}}/deny">
<input type="hidden" name="csrf" value="{{$.CSRF}}">
<button class="danger" type="submit">Deny</button>
</form>
{{else}}—{{end}}
</td>
</tr>
{{end}}
</tbody>
</table>
{{else}}
<p>No devices are waiting for approval.</p>
{{end}}
`)

	consoleUsersTemplate = consolePage("users", `
<h2>Users</h2>
<table>
<thead><tr><th scope="col">Login name</th><th scope="col">Display name</th><th scope="col">Role</th><th scope="col">Email</th><th scope="col">Created</th><th scope="col">Identities</th></tr></thead>
<tbody>
{{range .Users}}
<tr>
<td><span translate="no">{{.LoginName}}</span></td>
<td><span translate="no">{{.DisplayName}}</span></td>
<td>{{.Role}}</td>
<td>{{if .Email}}<span translate="no">{{.Email}}</span>{{else}}—{{end}}</td>
<td>{{fmtTime .CreatedAt}}</td>
<td>{{range .Identities}}<code>{{.ProviderID}}</code> {{.Subject}}<br>{{else}}—{{end}}</td>
</tr>
{{end}}
</tbody>
</table>
<h2>Edit a user</h2>
<p>Email is an attribute, never an identity key: links follow
(provider, subject) only.{{if not .IsOwner}} Only an owner may change roles.{{end}}</p>
{{range .Users}}
{{if $.CanWrite}}
<form method="post" action="/console/users/{{.ID}}">
<h3><span translate="no">{{.LoginName}}</span></h3>
<input type="hidden" name="csrf" value="{{$.CSRF}}">
<div class="field">
<label>Display name <input name="displayName" value="{{.DisplayName}}"></label>
<label>Email <input name="email" value="{{.Email}}"></label>
{{if $.IsOwner}}
<label>Role <select name="role">
<option value="member"{{if eq .Role "member"}} selected{{end}}>member</option>
<option value="admin"{{if eq .Role "admin"}} selected{{end}}>admin</option>
<option value="owner"{{if eq .Role "owner"}} selected{{end}}>owner</option>
</select></label>
{{end}}
<button type="submit">Save</button>
</div>
</form>
{{end}}
{{end}}
<h2>Invitations</h2>
<p>Registration is by invitation only: an invitation works once, carries the role it grants, and is stored hashed. The link below is shown once, when it is created; the server cannot show it again.</p>
{{if .NewInviteLink}}<p class="notice" role="status">Invitation created. Share this link:</p>
<p><code>{{.NewInviteLink}}</code></p>{{end}}
{{if .Invites}}
<table>
<thead><tr><th scope="col">Role</th><th scope="col">Note</th><th scope="col">Created</th><th scope="col">Expires</th><th scope="col">Status</th><th scope="col"></th></tr></thead>
<tbody>
{{range .Invites}}
<tr>
<td>{{.Role}}</td>
<td>{{if .Note}}{{.Note}}{{else}}—{{end}}</td>
<td>{{fmtTime .Created}}</td>
<td>{{fmtTime .Expires}}</td>
<td>{{if .Redeemed}}<span>redeemed</span> <span translate="no">{{.UsedBy}}</span>{{else if .Expired}}expired{{else}}open{{end}}</td>
<td>
{{if and $.CanWrite .Open}}
<form method="post" action="/console/invites/{{.ID}}/delete">
<input type="hidden" name="csrf" value="{{$.CSRF}}">
<button class="danger" type="submit">Revoke</button>
</form>
{{end}}
</td>
</tr>
{{end}}
</tbody>
</table>
{{else}}
<p>No invitations yet.</p>
{{end}}
{{if .CanWrite}}
<form method="post" action="/console/invites">
<h3>Create an invitation</h3>
<input type="hidden" name="csrf" value="{{.CSRF}}">
<div class="field">
<label>Role <select name="role">
<option value="member">member</option>
<option value="admin">admin</option>
</select></label>
<label>Note <input name="note" placeholder="who is it for"></label>
<label>Valid for <select name="ttl">
<option value="24">24 hours</option>
<option value="168" selected>7 days</option>
<option value="720">30 days</option>
<option value="0">no expiry</option>
</select></label>
<button type="submit">Create invitation</button>
</div>
</form>
{{end}}
`)

	consoleDNSTemplate = consolePage("dns", `
<h2>DNS records</h2>
<p>Extra records served to clients alongside MagicDNS.</p>
{{if .Records}}
<table>
<thead><tr><th scope="col">Name</th><th scope="col">Type</th><th scope="col">Value</th><th scope="col">Created</th><th scope="col"></th></tr></thead>
<tbody>
{{range .Records}}
<tr>
<td><code>{{.Name}}</code></td>
<td>{{.Type}}</td>
<td>{{.Value}}</td>
<td>{{fmtTime .Created}}</td>
<td>
{{if $.CanWrite}}
<form method="post" action="/console/dns/{{.ID}}/delete">
<input type="hidden" name="csrf" value="{{$.CSRF}}">
<button class="danger" type="submit">Delete</button>
</form>
{{else}}—{{end}}
</td>
</tr>
{{end}}
</tbody>
</table>
{{else}}
<p>No extra DNS records.</p>
{{end}}
`)

	consoleAuthKeysTemplate = consolePage("auth-keys", `
<h2>Auth keys</h2>
<p>Pre-authentication keys let a machine register without a browser. The secret
is shown once, at creation time, and never again.</p>
{{if .CreatedKey}}
<p class="notice">New key (copy it now): <code>{{.CreatedKey}}</code></p>
{{end}}
{{if .CanWrite}}
<form method="post" action="/console/auth-keys">
<input type="hidden" name="csrf" value="{{.CSRF}}">
<div class="field">
<label>Lifetime <input name="ttl" placeholder="24h (empty: never)"></label>
<label>Tags <input name="tags" placeholder="tag:server, tag:prod"></label>
<label><input type="checkbox" name="reusable"> Reusable</label>
<label><input type="checkbox" name="ephemeral"> Ephemeral</label>
<button type="submit">Create key</button>
</div>
</form>
{{end}}
{{if .AuthKeys}}
<table>
<thead><tr><th scope="col">ID</th><th scope="col">Owner</th><th scope="col">Tags</th><th scope="col">Reusable</th><th scope="col">Ephemeral</th><th scope="col">Used</th><th scope="col">Expires</th><th scope="col">Created</th><th scope="col"></th></tr></thead>
<tbody>
{{range .AuthKeys}}
<tr>
<td>{{.ID}}</td>
<td><span translate="no">{{.Owner}}</span></td>
<td>{{if .Tags}}{{range .Tags}}<code>{{.}}</code> {{end}}{{else}}—{{end}}</td>
<td>{{if .Reusable}}yes{{else}}no{{end}}</td>
<td>{{if .Ephemeral}}yes{{else}}no{{end}}</td>
<td>{{if .Used}}yes{{else}}no{{end}}</td>
<td>{{fmtTime .Expiry}}</td>
<td>{{fmtTime .Created}}</td>
<td>
{{if $.CanWrite}}
<form method="post" action="/console/auth-keys/{{.ID}}/delete">
<input type="hidden" name="csrf" value="{{$.CSRF}}">
<button class="danger" type="submit">Revoke</button>
</form>
{{else}}—{{end}}
</td>
</tr>
{{end}}
</tbody>
</table>
{{else}}
<p>No auth keys.</p>
{{end}}
`)

	consoleAgentsTemplate = consolePage("agents", `
<h2>Agents</h2>
<p>Xunara Agent credentials (native clients). Revoking one signs that agent out
immediately; the device keeps its node identity and can enroll again.</p>
{{if .Tokens}}
<table>
<thead><tr><th scope="col">ID</th><th scope="col">Node</th><th scope="col">Hostname</th><th scope="col">Live</th><th scope="col">Created</th><th scope="col">Expires</th><th scope="col">Last used</th><th scope="col">Revoked</th><th scope="col"></th></tr></thead>
<tbody>
{{range .Tokens}}
<tr>
<td><code>{{.ID}}</code></td>
<td>{{.NodeID}}</td>
<td>{{if .NodeHostname}}{{.NodeHostname}}{{else}}<em>deleted</em>{{end}}</td>
<td>{{if .Live}}yes{{else}}no{{end}}</td>
<td>{{fmtTime .CreatedAt}}</td>
<td>{{if .ExpiresAt}}{{fmtTime .ExpiresAt}}{{else}}never{{end}}</td>
<td>{{if .LastUsedAt}}{{fmtTime .LastUsedAt}}{{else}}never{{end}}</td>
<td>{{if .RevokedAt}}{{fmtTime .RevokedAt}}{{else}}—{{end}}</td>
<td>
{{if and $.CanWrite (not .RevokedAt)}}
<form method="post" action="/console/agents/{{.ID}}/revoke">
<input type="hidden" name="csrf" value="{{$.CSRF}}">
<button class="danger" type="submit">Revoke</button>
</form>
{{else}}—{{end}}
</td>
</tr>
{{end}}
</tbody>
</table>
{{else}}
<p>No agent credentials. A device creates one when it enrolls with
<code>/api/agent/v1/enroll</code>.</p>
{{end}}
`)

	consoleServicesTemplate = consolePage("services", `
<h2>Services</h2>
<p>Services nodes advertise about themselves. Publishing happens on the node
(<code>/api/agent/v1/services</code>); this page is read-only. A service name
resolves in MagicDNS to the advertising node, and reachability is still decided
by the ACL rules — discovery is not authorization. Services with health
reporting enabled are withdrawn from MagicDNS while they are unhealthy, and
<em>visibility</em> narrows which nodes can resolve the name (<code>*</code> is
the whole organization). <em>Shared</em> services are also projected into the
organizations that accepted a share of the advertising machine, under
<code>&lt;name&gt;-&lt;org&gt;</code> (discovery only: the ACL rules of both
organizations still decide who may connect). A service whose
<em>visibility</em> comes <em>from the ACL</em> is discoverable exactly by the
nodes that may already connect to it.</p>
{{if .Services}}
<table>
<thead><tr><th scope="col">Name</th><th scope="col">Protocol</th><th scope="col">Port</th><th scope="col">DNS name</th><th scope="col">Visibility</th><th scope="col">Shared</th><th scope="col">Health</th><th scope="col">Node</th><th scope="col">Updated</th><th scope="col">Metadata</th></tr></thead>
<tbody>
{{range .Services}}
<tr>
<td><code>{{.Name}}</code></td>
<td>{{.Protocol}}</td>
<td>{{.Port}}</td>
<td>{{if .DNSName}}<code>{{.DNSName}}</code>{{else}}—{{end}}</td>
<td>{{if .VisibilityFromACL}}acl{{else}}{{join .Visibility}}{{end}}</td>
<td>{{if .Shared}}yes{{else}}—{{end}}</td>
<td>{{if .Health}}{{.Health}}{{else}}—{{end}}</td>
<td>{{.Hostname}} <code>{{.StableID}}</code></td>
<td>{{fmtTime .Updated}}</td>
<td>{{if .Metadata}}{{range $k, $v := .Metadata}}<code>{{$k}}={{$v}}</code> {{end}}{{else}}—{{end}}</td>
</tr>
{{end}}
</tbody>
</table>
{{else}}
<p>No services have been advertised. An agent publishes them with
<code>xunara-agent</code> / <code>/api/agent/v1/services</code>.</p>
{{end}}
`)

	consoleAPIKeysTemplate = consolePage("api-keys", `
<h2>API keys</h2>
<p>Service identity credentials for automation: the <code>xunara_…</code> tokens
<code>/api/v1</code> and <code>/api/v2</code> accept. A key carries the scopes
it was granted, but never more than its owner's role allows; only the token's
hash is stored, and this page never shows it again. OAuth/OIDC login providers
are server configuration and are not managed here.</p>
{{if .CreatedToken}}
<p class="notice">New API key created. Copy the token now — it cannot be shown
again:</p>
<pre>{{.CreatedToken}}</pre>
{{end}}
{{if .CanWrite}}
<h3>Create a key</h3>
<form method="post" action="/console/api-keys">
<input type="hidden" name="csrf" value="{{.CSRF}}">
<div class="field">
<label for="api-key-name">Name</label>
<input id="api-key-name" name="name" required placeholder="ci-deploy">
<label><input type="checkbox" name="scope_read" value="1" checked> read</label>
<label><input type="checkbox" name="scope_write" value="1"> write</label>
<label for="api-key-ttl">Lifetime</label>
<input id="api-key-ttl" name="ttl" placeholder="720h (empty = no expiry)">
<button type="submit">Create key</button>
</div>
</form>
{{end}}
{{if .Keys}}
<table>
<thead><tr><th scope="col">Name</th><th scope="col">Owner</th><th scope="col">Scopes</th><th scope="col">Created</th><th scope="col">Expires</th><th scope="col">Last used</th><th scope="col">State</th>{{if .CanWrite}}<th scope="col"></th>{{end}}</tr></thead>
<tbody>
{{range .Keys}}
<tr>
<td>{{.Name}}<br><code>{{.ID}}</code></td>
<td><span translate="no">{{.Owner}}</span></td>
<td>{{range .Scopes}}<span class="tag">{{.}}</span> {{end}}</td>
<td>{{fmtTime .Created}}</td>
<td>{{if .Expires}}{{fmtTime .Expires}}{{else}}never{{end}}</td>
<td>{{if .LastUsed}}{{fmtTime .LastUsed}}{{else}}never{{end}}</td>
<td>{{if .Revoked}}<span class="warn">{{T "revoked"}} {{fmtTime .Revoked}}</span>{{else}}<span class="ok">live</span>{{end}}</td>
{{if $.CanWrite}}<td>{{if not .Revoked}}<form method="post" action="/console/api-keys/{{.ID}}/revoke"><input type="hidden" name="csrf" value="{{$.CSRF}}"><button class="danger" type="submit">Revoke</button></form>{{end}}</td>{{end}}
</tr>
{{end}}
</tbody>
</table>
{{else}}
<p>No API keys yet.</p>
{{end}}
`)

	consoleWebhooksTemplate = consolePage("webhooks", `
<h2>Webhooks</h2>
<p>Audit events are POSTed to these receivers. The signing secret is stored
sealed and is never shown again after creation.</p>
{{if .Webhooks}}
<table>
<thead><tr><th scope="col">ID</th><th scope="col">URL</th><th scope="col">Events</th><th scope="col">State</th><th scope="col">Source</th><th scope="col">Created</th><th scope="col"></th></tr></thead>
<tbody>
{{range .Webhooks}}
<tr>
<td><code>{{.ID}}</code></td>
<td>{{.URL}}</td>
<td>{{if .Events}}{{range .Events}}<span class="tag">{{.}}</span> {{end}}{{else}}all{{end}}</td>
<td>{{if .Enabled}}<span class="ok">enabled</span>{{else}}<span class="off">paused</span>{{end}}</td>
<td>{{.Source}}</td>
<td>{{if .Created}}{{fmtTime .Created}}{{else}}—{{end}}</td>
<td>
{{if and $.CanWrite (eq .Source "managed")}}
<form method="post" action="/console/webhooks/{{.ID}}/delete">
<input type="hidden" name="csrf" value="{{$.CSRF}}">
<button class="danger" type="submit">Delete</button>
</form>
{{else if eq .Source "config"}}from startup config{{else}}—{{end}}
</td>
</tr>
{{end}}
</tbody>
</table>
{{else}}
<p>No webhook receivers are configured.</p>
{{end}}
{{if .CanWrite}}
<h3>Add a receiver</h3>
<form method="post" action="/console/webhooks">
<input type="hidden" name="csrf" value="{{$.CSRF}}">
<div class="field"><label for="webhook-id">ID</label>
<input id="webhook-id" name="id" required></div>
<div class="field"><label for="webhook-url">URL</label>
<input id="webhook-url" name="url" size="48" placeholder="https://example.com/hooks/xunara" required></div>
<div class="field"><label for="webhook-secret">Secret</label>
<input id="webhook-secret" name="secret" type="password" required></div>
<div class="field"><label for="webhook-events">Events</label>
<input id="webhook-events" name="events" placeholder="* (all)"></div>
<button type="submit">Create webhook</button>
</form>
{{end}}
`)

	consoleFluxTemplate = consolePage("flux", `
<h2>Flux</h2>
<p>Xunara Flux file transfers between agents. The control plane relays
ciphertext only: file content and keys are end-to-end encrypted and are not
visible here or anywhere else on the server. The recipient must accept a
transfer before anything is uploaded; this page is read-only.</p>
{{if not .Enabled}}
<p>Flux is not enabled on this deployment, so there are no transfers to show.
An operator enables it with <code>-flux</code> (single organization) or
<code>flux_enabled</code> (organization table).</p>
{{else}}
<form method="get" action="/console/flux">
<div class="field"><label for="flux-state">State</label>
<select id="flux-state" name="state">
<option value="">all</option>
{{range .States}}<option value="{{.}}"{{if eq . $.StateFilter}} selected{{end}}>{{.}}</option>{{end}}
</select>
<button type="submit">Filter</button></div>
</form>
{{if .Transfers}}
<table>
<thead><tr><th scope="col">Created</th><th scope="col">State</th><th scope="col">File</th><th scope="col">Size</th><th scope="col">Sender</th><th scope="col">Recipient</th><th scope="col">Note</th></tr></thead>
<tbody>
{{range .Transfers}}
<tr>
<td><a href="/console/flux/{{.ID}}">{{fmtTime .CreatedAt}}</a></td>
<td>{{.State}}</td>
<td><code>{{.Name}}</code></td>
<td>{{.Size}} B</td>
<td>{{.Sender.Hostname}}<br><code>{{.Sender.StableID}}</code></td>
<td>{{.Recipient.Hostname}}<br><code>{{.Recipient.StableID}}</code></td>
<td>{{if .Reason}}{{.Reason}}{{else}}—{{end}}</td>
</tr>
{{end}}
</tbody>
</table>
{{if .More}}<p>{{T "Only the newest %d transfers are shown; filter by state or use the API to page through the rest." (len .Transfers)}}</p>{{end}}
{{else}}
<p>No Flux transfers match.</p>
{{end}}
{{end}}
`)

	consoleFluxTransferTemplate = consolePage("flux", `
<h2>Flux transfer</h2>
{{if not .Enabled}}
<p>Flux is not enabled on this deployment, so there are no transfers to show.</p>
{{else}}{{with .Transfer}}
<dl>
<dt>ID</dt><dd><code>{{.ID}}</code></dd>
<dt>State</dt><dd>{{.State}}</dd>
<dt>File</dt><dd><code>{{.Name}}</code> ({{.Size}} bytes)</dd>
<dt>Sender</dt><dd>{{.Sender.Hostname}} <code>{{.Sender.StableID}}</code></dd>
<dt>Recipient</dt><dd>{{.Recipient.Hostname}} <code>{{.Recipient.StableID}}</code></dd>
<dt>SHA-256</dt><dd><code>{{.SHA256}}</code></dd>
{{if .Reason}}<dt>Note</dt><dd class="warn">{{.Reason}}</dd>{{end}}
<dt>Created</dt><dd>{{fmtTime .CreatedAt}}</dd>
<dt>Updated</dt><dd>{{fmtTime .UpdatedAt}}</dd>
<dt>Expires</dt><dd>{{fmtTime .ExpiresAt}}</dd>
</dl>
<p>The file itself is end-to-end encrypted between the two agents: the control
plane stores only ciphertext while a transfer is in flight, deletes it when
the transfer completes or fails, and no console page can show the content.</p>
{{else}}
<p>No Flux transfer has that ID.</p>
{{end}}{{end}}
`)

	consoleReachTemplate = consolePage("reach", `
<h2>Reach</h2>
<p>Xunara Reach sessions between nodes: who offered which command to which
node, how it ended, and how much output it produced. A command runs on the
target only after that node approves the offer, and only the two participants
can drive a session; this page is read-only. The audit log records the
decisions, never the command line or the output.</p>
{{if not .Enabled}}
<p>Reach is not enabled on this deployment, so no sessions can exist. An
operator enables it per organization (<code>reach_enabled</code>) and runs
<code>xunarad -reach</code>.</p>
{{else}}
<form method="get" action="/console/reach">
<div class="field"><label for="reach-state">State</label>
<select id="reach-state" name="state">
<option value="">all</option>
{{range .States}}<option value="{{.}}"{{if eq . $.StateFilter}} selected{{end}}>{{.}}</option>{{end}}
</select>
<button type="submit">Filter</button></div>
</form>
{{if .Sessions}}
<table>
<thead><tr><th scope="col">Created</th><th scope="col">State</th><th scope="col">Sender</th><th scope="col">Target</th><th scope="col">Command</th><th scope="col">stdout / stderr</th><th scope="col">Exit</th></tr></thead>
<tbody>
{{range .Sessions}}
<tr>
<td><a href="/console/reach/{{.ID}}">{{fmtTime .CreatedAt}}</a></td>
<td>{{.State}}</td>
<td>{{.Sender.Hostname}}<br><code>{{.Sender.StableID}}</code></td>
<td>{{.Target.Hostname}}<br><code>{{.Target.StableID}}</code></td>
<td><code>{{argvLine .Argv}}</code></td>
<td>{{.OutputBytes.Stdout}} B / {{.OutputBytes.Stderr}} B</td>
<td>{{if .ExitCode}}{{.ExitCode}}{{else}}—{{end}}</td>
</tr>
{{end}}
</tbody>
</table>
{{if .More}}<p>{{T "Only the newest %d sessions are shown; filter by state or use the API to page through the rest." (len .Sessions)}}</p>{{end}}
{{else}}
<p>No Reach sessions match.</p>
{{end}}
{{end}}
`)

	consoleReachSessionTemplate = consolePage("reach", `
<h2>Reach session</h2>
{{if not .Enabled}}
<p>Reach is not enabled on this deployment, so there are no sessions to show.</p>
{{else}}{{with .Session}}
<dl>
<dt>ID</dt><dd><code>{{.ID}}</code></dd>
<dt>State</dt><dd>{{.State}}</dd>
<dt>Sender</dt><dd>{{.Sender.Hostname}} <code>{{.Sender.StableID}}</code></dd>
<dt>Target</dt><dd>{{.Target.Hostname}} <code>{{.Target.StableID}}</code></dd>
<dt>Command</dt><dd>{{range .Argv}}<code>{{.}}</code> {{end}}</dd>
<dt>Timeout</dt><dd>{{.TimeoutSec}}s</dd>
<dt>Exit code</dt><dd>{{if .ExitCode}}{{.ExitCode}}{{else}}—{{end}}</dd>
{{if .Error}}<dt>Error</dt><dd class="warn">{{.Error}}</dd>{{end}}
<dt>Created</dt><dd>{{fmtTime .CreatedAt}}</dd>
<dt>Updated</dt><dd>{{fmtTime .UpdatedAt}}</dd>
<dt>Expires</dt><dd>{{fmtTime .ExpiresAt}}</dd>
<dt>Output</dt><dd>{{T "%d bytes on stdout, %d bytes on stderr" .OutputBytes.Stdout .OutputBytes.Stderr}}</dd>
</dl>
<p>The output is retained with the session (one hour after the last update)
and may contain sensitive data; it never enters the audit log.</p>
<h3>stdout</h3>
{{if $.TruncatedOut}}<p class="warn">{{T "Showing the first %d bytes; more output was written." $.OutputLimit}}</p>{{end}}
{{if $.Stdout}}<pre>{{$.Stdout}}</pre>{{else}}<p>No stdout output.</p>{{end}}
<h3>stderr</h3>
{{if $.TruncatedErr}}<p class="warn">{{T "Showing the first %d bytes; more output was written." $.OutputLimit}}</p>{{end}}
{{if $.Stderr}}<pre>{{$.Stderr}}</pre>{{else}}<p>No stderr output.</p>{{end}}
{{else}}
<p>No Reach session has that ID.</p>
{{end}}{{end}}
`)

	consoleDERPTemplate = consolePage("derp", `
<h2>DERP</h2>
<p>Which DERP regions this organization serves its clients, and where the
machines are homed. The policy comes from the deployment's
<code>-derp-policy</code> / organization table; this page is read-only.
Serving a filtered map is advisory - the admission controller is the
enforceable half, and it only covers the relay Xunara runs.</p>
<dl>
<dt>Policy</dt><dd><code>{{.Status.PolicyMode}}</code>{{if eq .Status.PolicyMode "inherit"}} — the configured map is served unchanged{{end}}{{if eq .Status.PolicyMode "none"}} — clients are told this organization has no DERP{{end}}</dd>
{{if .Status.PolicyRegions}}<dt>Allowed regions</dt><dd>{{range .Status.PolicyRegions}}<code>{{.}}</code> {{end}}</dd>{{end}}
<dt>Map</dt><dd>{{if .Status.MapConfigured}}configured{{else}}not configured — clients keep their built-in default regions{{end}}</dd>
<dt>Regions served</dt><dd>{{.Status.RegionsServed}}</dd>
<dt>Machines</dt><dd>{{T "%d total; %d without a home region; %d homed to a region no longer served" (len .Nodes) .Status.NodesWithoutHome .Status.NodesWithUnservedHome}}</dd>
</dl>
{{if .Status.Regions}}
<table>
<thead><tr><th scope="col">ID</th><th scope="col">Code</th><th scope="col">Name</th><th scope="col">Relays</th><th scope="col">Machines</th></tr></thead>
<tbody>
{{range .Status.Regions}}
<tr>
<td>{{.ID}}</td>
<td>{{if .Code}}<code>{{.Code}}</code>{{else}}—{{end}}</td>
<td>{{if .Name}}{{.Name}}{{else}}—{{end}}</td>
<td>{{if .Hosts}}{{range .Hosts}}<code>{{.}}</code> {{end}}{{else}}—{{end}}</td>
<td>{{.NodeCount}}</td>
</tr>
{{end}}
</tbody>
</table>
{{else if .Status.MapConfigured}}
<p>No regions are served: the policy tells clients this organization has no
DERP at all.</p>
{{else}}
<p>No DERP map is configured, so clients keep their built-in default regions
until one is.</p>
{{end}}
<h3>Machine placement</h3>
{{if .Nodes}}
<table>
<thead><tr><th scope="col">Machine</th><th scope="col">Status</th><th scope="col">Home region</th></tr></thead>
<tbody>
{{range .Nodes}}
<tr>
<td>{{.Hostname}}<br><code>{{.StableID}}</code></td>
<td>{{if .Online}}<span class="ok">online</span>{{else}}<span class="off">offline</span>{{end}}</td>
<td>{{if .Unserved}}<span class="warn">region {{.Home}} (no longer served)</span>{{else if .Home}}{{.Home}}{{else}}<span class="off">none chosen yet</span>{{end}}</td>
</tr>
{{end}}
</tbody>
</table>
{{else}}
<p>No machines yet.</p>
{{end}}
`)

	consolePolicyTemplate = consolePage("policy", `
<h2>Policy</h2>
{{with .View}}
{{if not .Configured}}
<p>No policy document is configured: every machine may reach every other
machine, the same behaviour as an official tailnet without a policy.</p>
{{else}}
<p>Read-only view (Xunara Warden) of the ACL document in force. It is loaded
from disk and reloaded when the file changes; there is no editor here.</p>
<dl>
<dt>Document</dt><dd><code>{{.Path}}</code></dd>
<dt>Compiled rules</dt><dd>{{.RuleCount}}</dd>
</dl>
{{if .LoadError}}<p class="warn">The file on disk no longer parses, so the previous policy is still in force: {{.LoadError}}</p>{{end}}
{{if .Warnings}}<h3>Warnings</h3><ul>{{range .Warnings}}<li>{{.}}</li>{{end}}</ul>{{end}}
{{if .Unsupported}}<h3>Unsupported fields</h3>
<p>These top-level fields are understood but not enforced by this build;
ignoring them can only tighten the policy, never widen it.</p>
<ul>{{range .Unsupported}}<li><code>{{.}}</code></li>{{end}}</ul>{{end}}

<h3>Traffic rules</h3>
{{if .ACLs}}
<table>
<thead><tr><th scope="col">Action</th><th scope="col">Proto</th><th scope="col">Source</th><th scope="col">Destination</th></tr></thead>
<tbody>
{{range .ACLs}}<tr>
<td>{{.Action}}</td>
<td>{{if .Proto}}{{.Proto}}{{else}}default set{{end}}</td>
<td>{{join .Src}}{{if .Users}}{{join .Users}}{{end}}</td>
<td>{{join .Dst}}{{if .Ports}}{{join .Ports}}{{end}}</td>
</tr>{{end}}
</tbody>
</table>
{{else}}<p>No ACL rules in the document.</p>{{end}}

<h3>Grants</h3>
{{if .Grants}}
<table>
<thead><tr><th scope="col">Source</th><th scope="col">Destination</th><th scope="col">Protocols / ports</th><th scope="col">App capabilities</th></tr></thead>
<tbody>
{{range .Grants}}<tr>
<td>{{join .Src}}</td>
<td>{{join .Dst}}</td>
<td>{{join .IP}}</td>
<td>{{range $cap, $values := .App}}<code>{{$cap}}</code> {{end}}</td>
</tr>{{end}}
</tbody>
</table>
{{else}}<p>No grants in the document.</p>{{end}}

<h3>Groups</h3>
{{if .Groups}}
<table>
<thead><tr><th scope="col">Group</th><th scope="col">Members</th></tr></thead>
<tbody>
{{range $name, $members := .Groups}}<tr><td><code>{{$name}}</code></td><td>{{join $members}}</td></tr>{{end}}
</tbody>
</table>
{{else}}<p>No groups defined.</p>{{end}}

<h3>Hosts</h3>
{{if .Hosts}}
<table>
<thead><tr><th scope="col">Alias</th><th scope="col">Value</th></tr></thead>
<tbody>
{{range $alias, $value := .Hosts}}<tr><td><code>{{$alias}}</code></td><td><code>{{$value}}</code></td></tr>{{end}}
</tbody>
</table>
{{else}}<p>No hosts defined.</p>{{end}}

<h3>Tag owners</h3>
{{if .TagOwners}}
<table>
<thead><tr><th scope="col">Tag</th><th scope="col">Owners</th></tr></thead>
<tbody>
{{range $tag, $owners := .TagOwners}}<tr><td><code>{{$tag}}</code></td><td>{{join $owners}}</td></tr>{{end}}
</tbody>
</table>
{{else}}<p>No tag owners defined.</p>{{end}}

<h3>SSH rules</h3>
{{if .SSH}}
<table>
<thead><tr><th scope="col">Action</th><th scope="col">Source</th><th scope="col">Destination</th><th scope="col">Users</th><th scope="col">Environment</th><th scope="col">Check period</th></tr></thead>
<tbody>
{{range .SSH}}<tr>
<td>{{.Action}}</td>
<td>{{join .Src}}</td>
<td>{{join .Dst}}</td>
<td>{{join .Users}}</td>
<td>{{if .AcceptEnv}}{{join .AcceptEnv}}{{else}}—{{end}}</td>
<td>{{if .CheckPeriod}}{{.CheckPeriod}}{{else}}12h default{{end}}</td>
</tr>{{end}}
</tbody>
</table>
{{else}}<p>No SSH rules in the document.</p>{{end}}

<h3>Node attributes</h3>
{{if .NodeAttrs}}
<table>
<thead><tr><th scope="col">Target</th><th scope="col">Attributes</th></tr></thead>
<tbody>
{{range .NodeAttrs}}<tr><td>{{join .Target}}</td><td>{{join .Attr}}</td></tr>{{end}}
</tbody>
</table>
{{else}}<p>No nodeAttrs in the document.</p>{{end}}

<h3>Policy tests</h3>
{{if .Tests.Results}}
<table>
<thead><tr><th scope="col">#</th><th scope="col">Source</th><th scope="col">Proto</th><th scope="col">Result</th></tr></thead>
<tbody>
{{range .Tests.Results}}<tr>
<td>{{.Index}}</td>
<td><code>{{.Src}}</code></td>
<td>{{if .Proto}}{{.Proto}}{{else}}default set{{end}}</td>
<td>{{if .Pass}}<span class="ok">pass</span>{{else}}<span class="warn">fail</span><ul>{{range .Failures}}<li>{{.}}</li>{{end}}</ul>{{end}}</td>
</tr>{{end}}
</tbody>
</table>
{{else}}<p>Not run ({{.Tests.Total}} in the document){{if .Tests.Reason}}: {{.Tests.Reason}}{{end}}.</p>{{end}}
{{end}}
{{end}}
`)

	consoleSSHCheckTemplate = consolePage("ssh-check", `
<h2>SSH checks</h2>
<p>Tailscale SSH "check" mode: connections held until a human decides. This
page is read-only. A verdict is handed to exactly one follow-up request, so
"consumed" means the connection that asked for it already took the verdict;
"expired" is a pending check whose TTL passed before the janitor removed it.</p>
<form method="get" action="/console/ssh-check">
<div class="field"><label for="ssh-check-state">State</label>
<select id="ssh-check-state" name="state">
<option value="">all</option>
{{range .States}}<option value="{{.}}"{{if eq . $.StateFilter}} selected{{end}}>{{.}}</option>{{end}}
</select>
<button type="submit">Filter</button></div>
</form>
{{if .Sessions}}
<table>
<thead><tr><th scope="col">Check</th><th scope="col">State</th><th scope="col">Source</th><th scope="col">Destination</th><th scope="col">Local user</th><th scope="col">Created</th><th scope="col">Expires</th><th scope="col">Verdict</th></tr></thead>
<tbody>
{{range .Sessions}}
<tr>
<td><a href="/ssh/check/{{.ID}}"><code>{{.ID}}</code></a></td>
<td>{{if eq .State "pending"}}<span class="ok">pending</span>{{else}}{{.State}}{{end}}</td>
<td>{{if .Src.Hostname}}{{.Src.Hostname}}<br>{{end}}<code>node {{.Src.NodeID}}</code>{{if .Src.StableID}} <code>{{.Src.StableID}}</code>{{end}}</td>
<td>{{if .Dst.Hostname}}{{.Dst.Hostname}}<br>{{end}}<code>node {{.Dst.NodeID}}</code>{{if .Dst.StableID}} <code>{{.Dst.StableID}}</code>{{end}}</td>
<td>{{if .LocalUser}}<code>{{.LocalUser}}</code>{{else}}—{{end}}</td>
<td>{{fmtTime .CreatedAt}}</td>
<td>{{fmtTime .ExpiresAt}}</td>
<td>{{.Verdict}}{{if .DecidedBy}} by {{.DecidedBy.LoginName}}{{end}}{{if .ConsumedAt}}<br>consumed {{fmtTime .ConsumedAt}}{{end}}</td>
</tr>
{{end}}
</tbody>
</table>
{{if .More}}<p>{{T "Only the newest %d sessions are shown; filter by state or use the API to page through the rest." (len .Sessions)}}</p>{{end}}
{{else}}
<p>No SSH checks match.</p>
{{end}}
`)

	consoleAuditTemplate = consolePage("audit", `
<h2>Audit</h2>
<p>The most recent events first, at most 200.</p>
{{if .Events}}
<table>
<thead><tr><th scope="col">Time</th><th scope="col">Actor</th><th scope="col">Action</th><th scope="col">Target</th><th scope="col">Detail</th></tr></thead>
<tbody>
{{range .Events}}
<tr>
<td>{{fmtTime .Time}}</td>
<td>{{.Actor}}</td>
<td><code>{{.Action}}</code></td>
<td>{{.Target}}</td>
<td>{{.Detail}}</td>
</tr>
{{end}}
</tbody>
</table>
{{else}}
<p>No audit events yet.</p>
{{end}}
`)
)

// renderConsole writes a console page. Console output is per-session state and
// must never be cached by shared caches. The template is cloned per request so
// the T function is bound to the operator's language without touching the
// shared parsed template.
func (s *Server) renderConsole(w http.ResponseWriter, tmpl *template.Template, data map[string]any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	lang, _ := data["Lang"].(string)
	localized, err := tmpl.Clone()
	if err != nil {
		s.log.Error("cloning console template", "template", tmpl.Name(), "err", err)
		return
	}
	localized.Funcs(template.FuncMap{"T": translator(lang), "fmtTime": s.consoleTime})
	var buf bytes.Buffer
	if err := localized.Execute(&buf, data); err != nil {
		s.log.Error("rendering console page", "template", tmpl.Name(), "err", err)
		return
	}
	io.WriteString(w, translateHTML(lang, buf.String()))
}
