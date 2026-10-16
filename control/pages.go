package control

import (
	"bytes"
	"html/template"
	"io"
	"net/http"
	"strings"
)

// pageTemplate parses one standalone page. T is registered here so the parser
// accepts the message ids in inline scripts; renderPage rebinds it per request
// so each page is rendered in the operator's language.
func pageTemplate(name, body string) *template.Template {
	return template.Must(template.New(name).Funcs(template.FuncMap{"T": translator("en")}).Parse(body))
}

var (
	errorPageTemplate = pageTemplate("error", publicHead+`<main id="main" class="narrow">
<div class="card">
<h1>{{.Title}}</h1>
<p>{{.Message}}</p>
<p><a href="/login">Back to sign-in</a></p>
`+`</div>
</main>`+publicFoot)

	approvePageTemplate = pageTemplate("approve", publicHead+`<main id="main" class="narrow">
<div class="card">
<h1>Device approval</h1>
<p>A device is asking to join the tailnet. Approving authorizes the machine keys
below; it does not make the device a human identity.</p>
<dl>
<dt>Device</dt><dd>{{.Hostname}}</dd>
<dt>Operating system</dt><dd>{{.OS}}</dd>
<dt>Requested</dt><dd>{{.Created}}</dd>
<dt>Signed in as</dt><dd>{{.LoginName}}</dd>
</dl>
{{if .CanWrite}}
<form method="post" action="{{.ApprovalURL}}">
<input type="hidden" name="csrf" value="{{.CSRF}}">
<div class="actions">
<button class="approve" type="submit">Approve device</button>
</div>
</form>
<form method="post" action="{{.DenialURL}}">
<input type="hidden" name="csrf" value="{{.CSRF}}">
<div class="actions">
<button class="deny" type="submit">Deny</button>
</div>
</form>
{{else}}
<p>Your role is read-only; ask an admin or owner to approve this device.</p>
{{end}}
`+`</div>
</main>`+publicFoot)

	decidedPageTemplate = pageTemplate("decided", publicHead+`<main id="main" class="narrow">
<div class="card">
<h1>Registration {{.State}}</h1>
<p>This device registration was already decided. You can close this window and return to the device.</p>
`+`</div>
</main>`+publicFoot)

	sshCheckPageTemplate = pageTemplate("sshcheck", publicHead+`<main id="main" class="narrow">
<div class="card">
<h1>SSH check</h1>
<p>A Tailscale SSH connection is waiting for a decision. Approving lets it
proceed; the decision is recorded in the audit log.</p>
<dl>
<dt>From</dt><dd>{{.Source}}</dd>
<dt>To</dt><dd>{{.Destination}}</dd>
<dt>Run as</dt><dd><code>{{.LocalUser}}</code></dd>
<dt>Requested</dt><dd>{{.Created}}</dd>
<dt>Expires</dt><dd>{{.Expires}}</dd>
<dt>Deciding as</dt><dd>{{.LoginName}}</dd>
</dl>
{{if .CanWrite}}
<form method="post" action="{{.ApprovalURL}}">
<input type="hidden" name="csrf" value="{{.CSRF}}">
<div class="actions">
<button class="approve" type="submit">Approve connection</button>
</div>
</form>
<form method="post" action="{{.DenialURL}}">
<input type="hidden" name="csrf" value="{{.CSRF}}">
<div class="actions">
<button class="deny" type="submit">Deny</button>
</div>
</form>
{{else}}
<p>Your role is read-only; ask an admin or owner to decide this connection.</p>
{{end}}
`+`</div>
</main>`+publicFoot)
)

// renderPage renders one standalone page (sign-in, errors, approvals) in the
// language and accent the operator selected in the console. The output is
// buffered so the localization step sees the whole page.
func (s *Server) renderPage(w http.ResponseWriter, r *http.Request, tmpl *template.Template, data map[string]any) {
	lang, accent := consoleLangFromRequest(r), consoleAccentFromRequest(r)
	data["Lang"], data["Accent"] = lang, accent
	if title, ok := data["Title"].(string); ok {
		data["Title"] = translateTitle(lang, title)
	}
	// Every public page shows the build it is running; pages that carry their
	// own value keep it.
	if _, ok := data["Version"]; !ok {
		data["Version"] = Version
	}
	if _, ok := data["ServerURL"]; !ok {
		data["ServerURL"] = s.cfg.ServerURL
	}
	data["ConsoleURL"] = s.consolePageURL("/dashboard")
	data["PreferencesURL"] = s.consolePageURL("/ui/prefs")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// The template is cloned per request so the T helper (used by inline
	// scripts, which the localization pass deliberately skips) is bound to the
	// operator's language without touching the shared parsed template.
	localized, err := tmpl.Clone()
	if err != nil {
		s.log.Error("cloning page template", "template", tmpl.Name(), "err", err)
		return
	}
	localized.Funcs(template.FuncMap{"T": translator(lang)})
	var buf bytes.Buffer
	if err := localized.Execute(&buf, data); err != nil {
		s.log.Error("rendering page", "template", tmpl.Name(), "err", err)
		return
	}
	io.WriteString(w, translateHTML(lang, buf.String()))
}

// renderError shows a plain error page. The message must be static, never
// provider- or request-controlled text.
func (s *Server) renderError(w http.ResponseWriter, r *http.Request, status int, title, message string) {
	lang := consoleLangFromRequest(r)
	page := translateHTML(lang, renderToString(errorPageTemplate, map[string]any{
		"Title": translateTitle(lang, title), "Message": message,
		"Lang": lang, "Accent": consoleAccentFromRequest(r),
		"ConsoleURL": s.consolePageURL("/dashboard"), "PreferencesURL": s.consolePageURL("/ui/prefs"),
	}))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	io.WriteString(w, page)
}

// handleNotFound answers requests no route matched. Browsers navigating the
// console get the localized error page; everything else (the client binaries
// and the API) keeps the plain-text reply it has always received, so an
// unknown path never turns into an HTML document a machine has to parse.
func (s *Server) handleNotFound(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/api/") || !strings.Contains(r.Header.Get("Accept"), "text/html") {
		http.Error(w, "404 page not found", http.StatusNotFound)
		return
	}
	s.renderError(w, r, http.StatusNotFound, "Page not found",
		"The page you asked for does not exist.")
}

// translateTitle localizes a page title: the console's T helper is not
// available to the standalone pages, and the browser tab should read the same
// language as the page.
func translateTitle(lang, title string) string {
	return translator(lang)(title)
}

// renderToString renders one template to a string; on error it logs and
// returns what was rendered so far, which keeps error pages best-effort.
func renderToString(tmpl *template.Template, data map[string]any) string {
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return buf.String()
	}
	return buf.String()
}

// renderApprovePage shows the device approval form.
func (s *Server) renderApprovePage(w http.ResponseWriter, r *http.Request, data map[string]any) {
	s.renderPage(w, r, approvePageTemplate, data)
}

// renderSSHCheckPage shows the SSH check approval form.
func (s *Server) renderSSHCheckPage(w http.ResponseWriter, r *http.Request, data map[string]any) {
	s.renderPage(w, r, sshCheckPageTemplate, data)
}

// renderDecidedPage shows the outcome of a device decision.
func (s *Server) renderDecidedPage(w http.ResponseWriter, r *http.Request, state string) {
	s.renderPage(w, r, decidedPageTemplate, map[string]any{
		"Title": "Registration " + state,
		"State": state,
	})
}
