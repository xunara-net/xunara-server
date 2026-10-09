package control

import (
	"html/template"
	"net/http"
)

// The public surface: landing page, sign in, first-run setup, registration and
// the standalone action pages (device approval, SSH check). They share one
// shell so the product looks like one thing before and after sign-in, and they
// carry no external assets.

const publicCSS = `
body { font-family: var(--font); margin: 0; background: var(--bg); color: var(--fg); line-height: 1.6;
       -webkit-text-size-adjust: 100%; display: flex; flex-direction: column; min-height: 100vh; }
.skip { position: absolute; left: -999px; top: 0; z-index: 100; background: var(--surface); color: var(--fg);
        padding: .6rem .9rem; border-radius: 0 0 var(--radius-sm) 0; }
.skip:focus { left: 0; }

.pbar { position: sticky; top: 0; z-index: 20; display: flex; align-items: center; gap: 1rem; flex-wrap: wrap;
        padding: .7rem 1.4rem; background: var(--chrome); color: var(--chrome-fg); }
.pbrand { display: flex; align-items: baseline; gap: .45rem; font-weight: 700; letter-spacing: .01em;
          color: var(--chrome-fg); text-decoration: none; white-space: nowrap; }
.pbrand span { color: var(--chrome-muted); font-weight: 500; font-size: .85rem; }
.pnav { margin-left: auto; display: flex; align-items: center; gap: .9rem; flex-wrap: wrap; font-size: .85rem; }
.pnav a { color: var(--chrome-muted); text-decoration: none; white-space: nowrap; }
.pnav a:hover { color: var(--chrome-fg); }
.pnav .pwho { color: var(--chrome-fg); font-weight: 600; }
.plang { display: inline-flex; border: 1px solid rgba(255,255,255,.22); border-radius: 999px; overflow: hidden; }
.plang a { padding: .1rem .55rem; font-size: .78rem; }
.plang a.on { background: rgba(255,255,255,.14); color: var(--chrome-fg); }

main { flex: 1; width: 100%; max-width: 68rem; margin: 0 auto; padding: 2.2rem 1.4rem 3rem; }
main.narrow { max-width: 30rem; padding-top: 3rem; }
.pfoot { border-top: 1px solid var(--border); color: var(--muted); font-size: .8rem; text-align: center;
         padding: 1.2rem 1.4rem 1.6rem; }
.pfoot a { color: var(--muted); }

h1 { font-size: 1.9rem; line-height: 1.25; margin: 0 0 .6rem; letter-spacing: -.02em; }
h2 { font-size: 1.1rem; margin: 0 0 .6rem; }
h3 { font-size: .98rem; margin: 0 0 .35rem; }
p { margin: .5rem 0; }
a { color: var(--accent); }

.hero { display: grid; grid-template-columns: minmax(0, 1.25fr) minmax(0, 1fr); gap: 2rem; align-items: start; }
.eyebrow { text-transform: uppercase; letter-spacing: .12em; font-size: .72rem; font-weight: 700;
           color: var(--muted); margin: 0 0 .6rem; }
.lede { color: var(--muted); font-size: 1.02rem; }
.cta { display: flex; gap: .7rem; flex-wrap: wrap; margin: 1.4rem 0 1rem; }
.chips { list-style: none; display: flex; flex-wrap: wrap; gap: .45rem; padding: 0; margin: .8rem 0 0; }
.chips li { background: var(--surface-2); border: 1px solid var(--border); color: var(--muted);
            border-radius: 999px; padding: .16rem .7rem; font-size: .8rem; }
.panel { background: var(--surface); border: 1px solid var(--border); border-radius: calc(var(--radius) + 4px);
         box-shadow: var(--shadow); padding: 1.3rem 1.4rem; }
.panel pre { margin: .6rem 0 1rem; background: var(--surface-2); border: 1px solid var(--border);
             border-radius: var(--radius-sm); padding: .7rem .8rem; overflow-x: auto; }
.panel code { font-family: var(--mono); font-size: .84rem; white-space: nowrap; }
.panel pre code { white-space: pre-wrap; overflow-wrap: anywhere; }
.meta { display: grid; grid-template-columns: max-content 1fr; gap: .3rem .9rem; margin: 0; font-size: .88rem; }
.meta dt { color: var(--muted); }
.meta dd { margin: 0; overflow-wrap: anywhere; }
.fine { color: var(--muted); font-size: .82rem; margin-top: .9rem; }

.features { display: grid; grid-template-columns: repeat(auto-fit, minmax(14rem, 1fr)); gap: .8rem; margin-top: 2.4rem; }
.fcard { background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius); padding: 1rem 1.1rem; }
.fcard p { color: var(--muted); font-size: .88rem; margin: .3rem 0 0; }

.card { background: var(--surface); border: 1px solid var(--border); border-radius: calc(var(--radius) + 4px);
        box-shadow: var(--shadow); padding: 1.6rem 1.6rem 1.8rem; }
.card h1 { font-size: 1.35rem; }
.card .sub { color: var(--muted); font-size: .9rem; margin: 0 0 1.1rem; }

label { display: block; font-size: .84rem; font-weight: 600; margin: 1rem 0 .3rem; }
input[type=text], input[type=password], input[type=email], input[type=search] {
        width: 100%; font: inherit; padding: .58rem .7rem; border: 1px solid var(--border-2);
        border-radius: var(--radius-sm); background: var(--surface); color: var(--fg); }
input:focus-visible, button:focus-visible, a:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
.hint { color: var(--muted); font-size: .8rem; margin: .3rem 0 0; }
.pbtn, button { font: inherit; font-weight: 600; padding: .6rem 1.05rem; border-radius: var(--radius-sm);
        border: 1px solid transparent; cursor: pointer; background: var(--accent); color: var(--accent-fg);
        text-decoration: none; display: inline-block; text-align: center; }
.pbtn.ghost, button.ghost { background: transparent; color: var(--fg); border-color: var(--border-2); }
.pbtn.small { padding: .3rem .7rem; font-size: .8rem; }
.pbtn.ghost.on-dark { color: var(--chrome-fg); border-color: rgba(255,255,255,.24); }
.pbtn.wide { width: 100%; margin-top: 1.3rem; }
.provider { display: block; margin: .5rem 0; padding: .6rem 1rem; background: var(--surface-2);
            border: 1px solid var(--border-2); color: var(--fg); text-decoration: none;
            border-radius: var(--radius-sm); text-align: center; font-weight: 600; }
.provider:hover { border-color: var(--accent); color: var(--accent); }
.divider { display: flex; align-items: center; gap: .7rem; color: var(--muted); font-size: .78rem;
           margin: 1.3rem 0 .3rem; }
.divider::before, .divider::after { content: ""; height: 1px; background: var(--border); flex: 1; }
.notice { border: 1px solid var(--border-2); background: var(--surface-2); border-radius: var(--radius-sm);
          padding: .7rem .85rem; font-size: .85rem; color: var(--muted); margin: 1rem 0 0; }
.notice strong { color: var(--fg); }
dl { display: grid; grid-template-columns: max-content 1fr; gap: .4rem 1rem; }
dt { color: var(--muted); }
dd { margin: 0; }
.actions { margin-top: 1.4rem; display: flex; gap: .75rem; flex-wrap: wrap; }
.approve { background: var(--ok); color: var(--accent-fg); }
.deny { background: transparent; color: var(--warn); border-color: var(--warn); }
code { font-family: var(--mono); font-size: .85em; background: var(--surface-2); border: 1px solid var(--border);
       padding: .05rem .3rem; border-radius: 5px; }
.status { min-height: 1.2em; color: var(--muted); font-size: .85rem; }
.foot-links { margin-top: 1.4rem; font-size: .85rem; color: var(--muted); }

@media (max-width: 820px) {
  .hero { grid-template-columns: minmax(0, 1fr); gap: 1.4rem; }
  h1 { font-size: 1.55rem; }
  main { padding: 1.6rem 1rem 2.4rem; }
  .pbar { padding: .6rem .9rem; }
}
`

// publicHead opens the public shell: brand bar, content region.
const publicHead = `<!doctype html>
<html lang="{{.Lang}}" data-accent="{{.Accent}}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>{{.Title}} — Xunara</title>
<style>` + siteTokens + publicCSS + `</style>
</head>
<body>
<a class="skip" href="#main">{{T "Skip to content"}}</a>
<header class="pbar">
<a class="pbrand" href="/">Xunara <span>{{T "control plane"}}</span></a>
<nav class="pnav">
<a href="https://github.com/xunara-net/xunara/blob/master/Xunara_AI_Development_Docs_2026-10-05/PROJECT_SPEC.md">{{T "Documentation"}}</a>
<a href="https://github.com/xunara-net/xunara">GitHub</a>
<span class="plang"><a href="/console/prefs?lang=zh&return_to={{.Path}}"{{if eq .Lang "zh"}} class="on"{{end}}>中文</a><a href="/console/prefs?lang=en&return_to={{.Path}}"{{if eq .Lang "en"}} class="on"{{end}}>English</a></span>
{{if .User}}<span class="pwho">{{.User}}</span><a class="pbtn small ghost on-dark" href="/console/">{{T "Open console"}}</a>
{{else if not .Setup}}<a class="pbtn small ghost on-dark" href="/login?return_to=%2Fconsole%2F">{{T "Sign in"}}</a>{{end}}
</nav>
</header>
`

const publicFoot = `
<footer class="pfoot">Xunara {{.Version}} · <a href="/version">/version</a> · <a href="/health">/health</a></footer>
</body></html>`

// renderPublicPage renders one of the pages outside the console, filling in
// the shell's shared state (current path, signed-in user, whether the
// deployment still needs its administrator).
func (s *Server) renderPublicPage(w http.ResponseWriter, r *http.Request, tmpl *template.Template, data map[string]any) {
	if _, ok := data["Path"]; !ok {
		data["Path"] = r.URL.RequestURI()
	}
	if _, ok := data["User"]; !ok {
		if session, ok := s.currentSession(r); ok {
			data["User"] = s.UserProfile(session.UserID).LoginName
		}
	}
	if _, ok := data["Setup"]; !ok {
		required, ok := s.setupStateForPage(w, r)
		if !ok {
			return
		}
		data["Setup"] = required
	}
	s.renderPage(w, r, tmpl, data)
}

var (
	// landingPageTemplate is what a visitor sees first: what this is, how to
	// get in, and how to point a client at it.
	landingPageTemplate = pageTemplate("landing", publicHead+`<main id="main">
<section class="hero">
<div class="hero-text">
<p class="eyebrow">Xunara · 玄序</p>
<h1>Self-hosted Tailscale control plane</h1>
<p class="lede">Keep official clients working: TS2021, Noise, MagicDNS, ACLs, DERP, Serve and Funnel behave as upstream defines them. Multi-tenant, separated human and machine identity, and a full audit log are built in, with no external assets and no CDN.</p>
<div class="cta">
{{if .Setup}}<a class="pbtn" href="/setup">Set up the administrator</a>
{{else}}<a class="pbtn" href="/login?return_to=%2Fconsole%2F">Sign in to the console</a>{{end}}
<a class="pbtn ghost" href="https://github.com/xunara-net/xunara/blob/master/Xunara_AI_Development_Docs_2026-10-05/PROJECT_SPEC.md">Read the specification</a>
</div>
<ul class="chips"><li>Official-client compatible</li><li>Self-hosted</li><li>Multi-tenant</li><li>Audit and access control</li></ul>
</div>
<aside class="panel">
<h2>Point a device here</h2>
<pre><code>tailscale up --login-server {{.ServerURL}}</code></pre>
<dl class="meta">
<dt>Control server</dt><dd>{{.ServerURL}}</dd>
<dt>Version</dt><dd>{{.Version}}</dd>
</dl>
<p class="fine">The device asks for approval once; an administrator approves it in the console.</p>
</aside>
</section>
<section class="features">
<article class="fcard"><h3>Protocol compatibility</h3><p>The control plane follows upstream Tailscale first: clients are never patched to fit the server.</p></article>
<article class="fcard"><h3>Separated identities</h3><p>Human, machine and service identities never imply each other; external accounts key on (provider, subject).</p></article>
<article class="fcard"><h3>Access control and audit</h3><p>ACLs, grants, SSH checks and sharing are compiled from one policy document, and every change is audited.</p></article>
<article class="fcard"><h3>Native client</h3><p>xunara-agent speaks the control plane's own protocol, so non-Tailscale hosts can join without touching TS2021.</p></article>
</section>
</main>`+publicFoot)

	// signInPageTemplate is the one entry point for humans: a password form
	// for locally managed accounts, plus whatever external providers this
	// deployment configured.
	signInPageTemplate = pageTemplate("signin", publicHead+`<main id="main" class="narrow">
<div class="card">
<h1>Sign in</h1>
{{if .Setup}}<p class="sub">This deployment has no administrator yet.</p>
<p class="notice">First run: read the one-time token from the server's state directory and finish setup.</p>
<p><a class="pbtn wide" href="/setup">Set up the administrator</a></p>
{{else}}<p class="sub">Sign in to the console to manage this tailnet.</p>{{end}}
{{if .LocalLogin}}{{if not .Setup}}
<form method="post" action="/login">
<input type="hidden" name="_csrf" value="{{.FormToken}}">
<input type="hidden" name="return_to" value="{{.ReturnTo}}">
<label for="login">Login name</label>
<input id="login" name="login" type="text" autocomplete="username" required autofocus>
<label for="password">Password</label>
<input id="password" name="password" type="password" autocomplete="current-password" required>
<button class="pbtn wide" type="submit">Sign in</button>
</form>
{{end}}{{end}}
{{if .Providers}}
<p class="divider">or continue with</p>
{{range .Providers}}<a class="provider" href="{{.URL}}">{{.Name}}</a>{{end}}
{{end}}
{{if .Passkey}}
<div class="divider">or</div>
<button id="passkey-signin" type="button" class="provider">Sign in with a passkey</button>
<p id="passkey-status" class="status" role="status"></p>
{{end}}
{{if .LocalLogin}}{{if not .Setup}}<p class="foot-links">No account yet? Ask an administrator for an invitation link.</p>{{end}}{{end}}
</div>
</main>`+`{{if .Passkey}}<script>`+passkeyBrowserJS+`
(function () {
  const button = document.getElementById("passkey-signin");
  const status = document.getElementById("passkey-status");
  button.addEventListener("click", async function () {
    button.disabled = true;
    status.textContent = "";
    try {
      const begin = await passkeyPost("/passkey/login/begin", {});
      const credential = await navigator.credentials.get({ publicKey: decodeRequestOptions(begin.options.publicKey) });
      const returnTo = new URLSearchParams(window.location.search).get("return_to");
      const url = "/passkey/login/finish" + (returnTo ? "?return_to=" + encodeURIComponent(returnTo) : "");
      const finish = await passkeyPost(url, encodeAssertion(credential));
      window.location = finish.redirect || "/";
    } catch (err) {
      status.textContent = err.message || {{T "Passkey sign-in failed."}};
      button.disabled = false;
    }
  });
})();
</script>{{end}}`+publicFoot)

	// setupPageTemplate creates the first administrator. It is only reachable
	// while no local password exists.
	setupPageTemplate = pageTemplate("setup", publicHead+`<main id="main" class="narrow">
<div class="card">
<h1>Set up the administrator</h1>
<p class="sub">This deployment has no administrator yet. The one-time token is written to the state directory when the server starts; it is removed as soon as this form is submitted.</p>
<form method="post" action="/setup">
<input type="hidden" name="_csrf" value="{{.FormToken}}">
<label for="token">One-time setup token</label>
<input id="token" name="token" type="password" autocomplete="off" required autofocus>
<p class="hint">Read it on the server: <code>sudo cat {{.TokenHint}}</code></p>
<label for="login">Login name</label>
<input id="login" name="login" type="text" value="{{.Login}}" autocomplete="username" required>
<label for="display_name">Display name</label>
<input id="display_name" name="display_name" type="text" placeholder="Owner" autocomplete="name">
<label for="email">Email (optional)</label>
<input id="email" name="email" type="email" autocomplete="email">
<label for="password">Password</label>
<input id="password" name="password" type="password" autocomplete="new-password" required>
<p class="hint">At least 12 characters; length beats punctuation.</p>
<label for="confirm">Repeat the password</label>
<input id="confirm" name="confirm" type="password" autocomplete="new-password" required>
<button class="pbtn wide" type="submit">Create the administrator</button>
</form>
</div>
</main>`+publicFoot)

	// signupPageTemplate creates an account. In the default (invite) mode it
	// redeems an invitation, which is how someone without an administrative
	// account gets one when the deployment has no external identity provider;
	// in open mode the invitation field is not rendered at all.
	signupPageTemplate = pageTemplate("signup", publicHead+`<main id="main" class="narrow">
<div class="card">
<h1>Create your account</h1>
{{if .InviteRequired}}<p class="sub">Registration needs an invitation from an administrator. The invitation works once and carries the role it grants.</p>{{else}}<p class="sub">Create an account to get your own tailnet. You can invite your own devices right after signing in.</p>{{end}}
<form method="post" action="/signup">
<input type="hidden" name="_csrf" value="{{.FormToken}}">
{{if .InviteRequired}}<label for="invite">Invitation code</label>
<input id="invite" name="invite" type="text" value="{{.Invite}}" autocomplete="off" required autofocus>
{{end}}<label for="login">Login name</label>
<input id="login" name="login" type="text" autocomplete="username" required>
<label for="display_name">Display name</label>
<input id="display_name" name="display_name" type="text" autocomplete="name">
<label for="email">Email (optional)</label>
<input id="email" name="email" type="email" autocomplete="email">
<label for="password">Password</label>
<input id="password" name="password" type="password" autocomplete="new-password" required>
<p class="hint">At least 12 characters; length beats punctuation.</p>
<label for="confirm">Repeat the password</label>
<input id="confirm" name="confirm" type="password" autocomplete="new-password" required>
<button class="pbtn wide" type="submit">Create account and sign in</button>
</form>
<p class="foot-links">Already have an account? <a href="/login">Sign in</a>.</p>
</div>
</main>`+publicFoot)
)
