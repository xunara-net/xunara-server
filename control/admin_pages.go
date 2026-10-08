package control

import (
	"bytes"
	"html/template"
	"net/http"
	"net/url"
	"strings"
	"time"

	"tailscale.com/tailcfg"

	"github.com/xunara-net/xunara-server/plan"
)

// The platform console's pages (PROJECT_SPEC section 54). They share the
// tenant console's design system (siteTokens) but not its shell: the platform
// operator navigates tenants, plans and accounts, so the sidebar lists those
// three, and every page is read-only unless a form says otherwise.

const adminCSS = `
body { font-family: var(--font); margin: 0; background: var(--bg); color: var(--fg); line-height: 1.6; }
.topbar { display: flex; align-items: center; gap: .8rem; flex-wrap: wrap;
          padding: .62rem 1.4rem; background: var(--chrome); color: var(--chrome-fg); }
.brand { display: flex; align-items: baseline; gap: .45rem; font-size: 1rem; font-weight: 700; }
.brand span { color: var(--chrome-muted); font-weight: 500; }
.who { margin-left: auto; display: flex; align-items: center; gap: .6rem; font-size: .84rem; color: var(--chrome-muted); }
.who form { margin: 0; }
button.ghost { background: transparent; color: var(--chrome-muted); border-color: rgba(255,255,255,.22); }
button.ghost:hover { color: var(--chrome-fg); background: rgba(255,255,255,.08); }
main { max-width: var(--wrap); margin: 0 auto; padding: 1.3rem 1.4rem 3rem; }
h1 { font-size: 1.4rem; margin: 0 0 .25rem; letter-spacing: -.01em; }
h2 { font-size: 1.1rem; margin: 1.6rem 0 .5rem; }
p { margin: .5rem 0; }
a { color: var(--accent); }
.lede { color: var(--muted); margin: 0 0 1rem; }
.nav { display: flex; gap: .2rem; flex-wrap: wrap; margin: 0 0 1rem; }
.nav a { padding: .35rem .7rem; border-radius: var(--radius-sm); text-decoration: none; color: var(--fg);
         border: 1px solid var(--border); background: var(--surface); font-size: .88rem; }
.nav a.active { background: var(--accent-soft); color: var(--accent); border-color: var(--accent); font-weight: 600; }
.cards { display: grid; grid-template-columns: repeat(auto-fill, minmax(10rem, 1fr)); gap: .7rem; margin: 1rem 0 1.4rem; }
.card { background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius); padding: .85rem 1rem; }
.card .num { display: block; font-size: 1.5rem; font-weight: 650; }
.card span:last-child { color: var(--muted); font-size: .84rem; }
.table-wrap { overflow-x: auto; margin: .6rem 0 1rem; background: var(--surface); border: 1px solid var(--border);
              border-radius: var(--radius); }
table { width: 100%; border-collapse: collapse; font-size: .88rem; }
th, td { text-align: left; padding: .55rem .8rem; border-bottom: 1px solid var(--border); vertical-align: top;
         overflow-wrap: anywhere; }
th { background: var(--surface-2); color: var(--muted); font-weight: 600; font-size: .8rem; white-space: nowrap; }
tbody tr:hover td { background: var(--surface-2); }
tr:last-child td { border-bottom: 0; }
td form { display: inline-flex; gap: .3rem; align-items: center; margin: 0; }
.badge { display: inline-flex; align-items: center; gap: .35rem; padding: .05rem .5rem; border-radius: 999px;
         border: 1px solid var(--border); background: var(--surface-2); color: var(--muted);
         font-size: .78rem; font-weight: 600; white-space: nowrap; }
.badge.ok { color: var(--ok); background: var(--ok-bg); border-color: currentColor; }
.notice { background: var(--accent-soft); border: 1px solid var(--border); border-radius: var(--radius-sm);
          padding: .6rem .9rem; margin: .6rem 0; }
.notice.warn { background: var(--warn-bg); border-color: var(--warn); }
form.stack { background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius);
             padding: 1rem 1.1rem; margin: .8rem 0 1.2rem; max-width: 46rem; }
.field { display: flex; flex-direction: column; gap: .2rem; margin: .55rem 0; }
.field label { color: var(--muted); font-size: .84rem; }
.field.row { flex-direction: row; align-items: center; gap: .5rem; }
input:not([type=checkbox]):not([type=hidden]), select { font: inherit; padding: .42rem .55rem;
  border: 1px solid var(--border-2); border-radius: var(--radius-sm); background: var(--surface); color: var(--fg); max-width: 100%; }
.grid2 { display: grid; grid-template-columns: repeat(auto-fit, minmax(12rem, 1fr)); gap: .2rem 1rem; }
button { font: inherit; font-size: .85rem; font-weight: 600; padding: .38rem .72rem; border: 1px solid transparent;
         border-radius: var(--radius-sm); cursor: pointer; background: var(--accent); color: var(--accent-fg); }
button.danger { background: transparent; color: var(--warn); border-color: var(--warn); }
code { font-family: var(--mono); font-size: .84em; background: var(--surface-2); border: 1px solid var(--border);
       padding: .05rem .3rem; border-radius: 5px; }
footer { border-top: 1px solid var(--border); margin-top: 1.4rem; padding: 1.2rem 0 2rem; color: var(--muted);
         font-size: .8rem; }
@media (max-width: 720px) { .cards { grid-template-columns: repeat(2, minmax(0, 1fr)); } main { padding: 1rem .9rem 2rem; } }
`

const adminHead = `<!doctype html>
<html lang="{{.Lang}}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<meta name="robots" content="noindex">
<title>{{T .Title}} — Xunara platform</title>
<style>` + siteTokens + adminCSS + `</style>
</head>
<body>
<header class="topbar">
<span class="brand">Xunara <span>{{T "platform"}}</span></span>
<div class="who">
{{if .SignedIn}}<span>{{T "Deployment operator"}}</span>
<form method="post" action="/admin/logout"><button class="ghost" type="submit">{{T "Sign out"}}</button></form>{{end}}
</div>
</header>
<main>
<h1>{{T .Title}}</h1>
{{if .Lede}}<p class="lede">{{T .Lede}}</p>{{end}}
{{if .Notice}}<p class="notice" role="status">{{T .Notice}}</p>{{end}}
{{if .Error}}<p class="notice warn" role="alert">{{T .Error}}</p>{{end}}
{{if .SignedIn}}<nav class="nav">
<a href="/admin/"{{if eq .Path "/admin/"}} class="active"{{end}}>{{T "Overview"}}</a>
<a href="/admin/tenants"{{if eq .Path "/admin/tenants"}} class="active"{{end}}>{{T "Tailnets"}}</a>
<a href="/admin/users"{{if eq .Path "/admin/users"}} class="active"{{end}}>{{T "Users"}}</a>
<a href="/admin/plans"{{if eq .Path "/admin/plans"}} class="active"{{end}}>{{T "Plans"}}</a>
</nav>{{end}}
`

const adminFoot = `</main>
<footer>Xunara {{T "platform"}} · v{{.Version}} ·
<a href="https://github.com/xunara-net/xunara">GitHub</a> ·
<a href="https://github.com/xunara-net/xunara/blob/master/Xunara_AI_Development_Docs_2026-10-05/PROJECT_SPEC.md">{{T "Documentation"}}</a></footer>
</body></html>`

// adminPageData is what every platform page needs. Extra fields are set by the
// page's handler before rendering.
type adminPageData struct {
	Lang     string
	Title    string
	Lede     string
	Path     string
	Notice   string
	Error    string
	Login    bool
	SignedIn bool
	Version  string
	// CSRF is the session's form token, required by every write.
	CSRF      string
	RowPlanID string

	Totals       adminTotals
	Distribution []adminPlanCount
	Tenants      []TenantPlanRow
	Users        []adminUserRow
	Plans        []plan.Plan
	DefaultPlan  string
	PlanCounts   map[string]int
	Managed      bool
}

// adminTotals are the deployment-wide numbers the overview shows.
type adminTotals struct {
	Tenants   int
	Devices   int
	Online    int
	Users     int
	Plans     int
	Version   string
	CatalogID string
}

// adminPlanCount is one row of the plan distribution.
type adminPlanCount struct {
	ID    string
	Name  string
	Count int
}

func adminPage(name, body string) *template.Template {
	return template.Must(template.New(name).Funcs(template.FuncMap{
		"T": translator("en"),
		"seq": func(n int) []int {
			out := make([]int, n)
			for i := range out {
				out[i] = i
			}
			return out
		},
	}).Parse(adminHead + body + adminFoot))
}

var (
	adminLoginTemplate = adminPage("admin-login", `
<form class="stack" method="post" action="/admin/login">
<div class="field">
<label for="token">{{T "Platform admin token"}}</label>
<input id="token" name="token" type="password" autocomplete="current-password" required autofocus>
</div>
<p>{{T "Read it from the server's environment (XUNARA_PLATFORM_ADMIN_TOKEN); it is never stored in the browser."}}</p>
<button type="submit">{{T "Sign in"}}</button>
</form>
<p>{{T "Tenant accounts sign in at their own console; this page accepts only the deployment operator's token."}}</p>
`)

	adminDashboardTemplate = adminPage("admin-dashboard", `
<div class="cards">
<div class="card"><span class="num">{{.Totals.Tenants}}</span><span>{{T "tailnets"}}</span></div>
<div class="card"><span class="num">{{.Totals.Online}}</span><span>{{T "devices online"}}</span></div>
<div class="card"><span class="num">{{.Totals.Devices}}</span><span>{{T "devices total"}}</span></div>
<div class="card"><span class="num">{{.Totals.Users}}</span><span>{{T "accounts"}}</span></div>
<div class="card"><span class="num">{{.Totals.Plans}}</span><span>{{T "plans"}}</span></div>
</div>
<h2>{{T "Plan distribution"}}</h2>
<div class="table-wrap"><table>
<thead><tr><th>{{T "Plan"}}</th><th>{{T "Tailnets"}}</th></tr></thead>
<tbody>{{range .Distribution}}<tr><td>{{.Name}} <code>{{.ID}}</code></td><td>{{.Count}}</td></tr>{{end}}</tbody>
</table></div>
<h2>{{T "Tenants"}}</h2>
<div class="table-wrap"><table>
<thead><tr><th>{{T "Tailnet"}}</th><th>{{T "Plan"}}</th><th>{{T "Network"}}</th><th>{{T "Devices"}}</th><th>{{T "Users"}}</th></tr></thead>
<tbody>{{range .Tenants}}<tr>
<td>{{if .Name}}{{.Name}} {{end}}<code>{{.OrgID}}</code></td>
<td>{{.Plan.Name}}{{if not .Assigned}} <span class="badge">{{T "default"}}</span>{{end}}</td>
<td>{{if .NetworkPrefix}}<code>{{.NetworkPrefix}}</code>{{else}}{{T "deployment default"}}{{end}}</td>
<td>{{.Devices}}{{if ne .Plan.MaxDevices -1}} / {{.Plan.MaxDevices}}{{end}} <span class="badge ok">{{.Online}} {{T "online"}}</span></td>
<td>{{.Users}}{{if ne .Plan.MaxUsers -1}} / {{.Plan.MaxUsers}}{{end}}</td>
</tr>{{end}}</tbody>
</table></div>
<p>{{T "System status"}}: <span class="badge ok">{{T "healthy"}}</span> · <code>xunarad v{{.Totals.Version}}</code> ·
{{if .Managed}}{{T "managed organizations enabled"}}{{else}}{{T "configured organizations only"}}{{end}} ·
{{T "default plan"}} <code>{{.Totals.CatalogID}}</code></p>
`)

	adminTenantsTemplate = adminPage("admin-tenants", `
<div class="table-wrap"><table>
<thead><tr><th>{{T "Tailnet"}}</th><th>{{T "Plan"}}</th><th>{{T "Devices"}}</th><th>{{T "Change plan"}}</th><th>{{T "Network range"}}</th>{{if .Managed}}<th>{{T "Delete"}}</th>{{end}}</tr></thead>
<tbody>{{range $row := .Tenants}}<tr>
<td>{{if $row.Name}}{{$row.Name}} {{end}}<code>{{$row.OrgID}}</code></td>
<td>{{$row.Plan.Name}} <code>{{$row.Plan.ID}}</code>{{if not $row.Assigned}} <span class="badge">{{T "default"}}</span>{{end}}</td>
<td>{{$row.Devices}}{{if ne $row.Plan.MaxDevices -1}} / {{$row.Plan.MaxDevices}}{{end}} <span class="badge ok">{{$row.Online}} {{T "online"}}</span></td>
<td><form method="post" action="/admin/tenants/plan">
<input type="hidden" name="csrf" value="{{$.CSRF}}">
<input type="hidden" name="org" value="{{$row.OrgID}}">
<select name="plan">{{range $.Plans}}<option value="{{.ID}}"{{if eq .ID $row.Plan.ID}} selected{{end}}>{{.Name}}</option>{{end}}</select>
<button type="submit">{{T "Save"}}</button>
</form></td>
<td><form method="post" action="/admin/tenants/network">
<input type="hidden" name="csrf" value="{{$.CSRF}}">
<input type="hidden" name="org" value="{{$row.OrgID}}">
<input name="network_prefix" value="{{$row.NetworkPrefix}}" placeholder="{{T "auto"}}" size="18">
<button type="submit">{{T "Save"}}</button>
</form></td>
{{if $.Managed}}<td><form method="post" action="/admin/tenants/delete">
<input type="hidden" name="csrf" value="{{$.CSRF}}">
<input type="hidden" name="org" value="{{$row.OrgID}}">
<button class="danger" type="submit">{{T "Delete"}}</button>
</form></td>{{end}}
</tr>{{end}}</tbody>
</table></div>
<p>{{T "Changing a network range does not re-address devices that are already registered; new devices use the new range."}}</p>
`)

	adminUsersTemplate = adminPage("admin-users", `
<div class="table-wrap"><table>
<thead><tr><th>{{T "Account"}}</th><th>{{T "Tailnet"}}</th><th>{{T "Role"}}</th><th>{{T "Plan"}}</th><th>{{T "Created"}}</th><th>{{T "Sessions"}}</th><th></th></tr></thead>
<tbody>{{range .Users}}<tr>
<td><code>{{.Login}}</code>{{if .Display}}<br>{{.Display}}{{end}}{{if .Email}}<br>{{.Email}}{{end}}</td>
<td>{{if .OrgName}}{{.OrgName}} {{end}}<code>{{.Org}}</code></td>
<td>{{.Role}}</td>
<td><code>{{.Plan}}</code></td>
<td>{{.CreatedAt}}</td>
<td>{{.Sessions}}{{if .LastSeen}}<br><span class="badge">{{T "last seen"}} {{.LastSeen}}</span>{{end}}</td>
<td><form method="post" action="/admin/users/revoke">
<input type="hidden" name="csrf" value="{{$.CSRF}}">
<input type="hidden" name="org" value="{{.Org}}">
<input type="hidden" name="user" value="{{.ID}}">
<button type="submit">{{T "Sign out everywhere"}}</button>
</form>
<form method="post" action="/admin/users/delete">
<input type="hidden" name="csrf" value="{{$.CSRF}}">
<input type="hidden" name="org" value="{{.Org}}">
<input type="hidden" name="user" value="{{.ID}}">
<button class="danger" type="submit">{{T "Delete"}}</button>
</form></td>
</tr>{{end}}</tbody>
</table></div>
`)

	adminPlansTemplate = adminPage("admin-plans", `
<div class="table-wrap"><table>
<thead><tr><th>{{T "Plan"}}</th><th>{{T "Price"}}</th><th>{{T "Devices"}}</th><th>{{T "Users"}}</th><th>{{T "Routes"}}</th><th>{{T "Auth keys"}}</th><th>{{T "Capabilities"}}</th><th>{{T "Tailnets"}}</th><th></th></tr></thead>
<tbody>{{range .Plans}}<tr>
<td>{{.Name}} <code>{{.ID}}</code>{{if eq .ID $.DefaultPlan}} <span class="badge ok">{{T "default"}}</span>{{end}}</td>
<td>{{if .PriceCents}}{{.PriceCents}} {{.Currency}} / {{.BillingCycle}}{{else}}—{{end}}</td>
<td>{{.DeviceAllowance}}</td>
<td>{{if eq .MaxUsers -1}}∞{{else}}{{.MaxUsers}}{{end}}</td>
<td>{{if eq .MaxRoutes -1}}∞{{else}}{{.MaxRoutes}}{{end}}</td>
<td>{{if eq .MaxAuthKeys -1}}∞{{else}}{{.MaxAuthKeys}}{{end}}</td>
<td>{{if .AllowCustomCIDR}}CIDR {{end}}{{if .AllowExitNode}}Exit {{end}}{{if .AllowSubnetRouter}}Subnet {{end}}{{if .AllowAPI}}API {{end}}{{if .AllowACL}}ACL {{end}}{{if .AllowGrants}}Grants {{end}}{{if .AllowCustomDNS}}DNS {{end}}{{if .AllowAuditLog}}Audit {{end}}{{if .AllowMultiMember}}Members{{end}}</td>
<td>{{index $.PlanCounts .ID}}</td>
<td><form method="post" action="/admin/plans/delete">
<input type="hidden" name="csrf" value="{{$.CSRF}}">
<input type="hidden" name="plan" value="{{.ID}}">
<button class="danger" type="submit">{{T "Delete"}}</button>
</form></td>
</tr>{{end}}</tbody>
</table></div>

<h2>{{T "Plan editor"}}</h2>
<form class="stack" method="post" action="/admin/plans/save">
<input type="hidden" name="csrf" value="{{.CSRF}}">
<div class="grid2">
<div class="field"><label for="id">{{T "ID"}}</label><input id="id" name="id" required placeholder="pro-plus"></div>
<div class="field"><label for="name">{{T "Name"}}</label><input id="name" name="name" required placeholder="Pro Plus"></div>
<div class="field"><label for="price_cents">{{T "Price (cents per cycle)"}}</label><input id="price_cents" name="price_cents" inputmode="numeric" placeholder="2990"></div>
<div class="field"><label for="currency">{{T "Currency"}}</label><input id="currency" name="currency" placeholder="CNY"></div>
<div class="field"><label for="billing_cycle">{{T "Billing cycle"}}</label>
<select id="billing_cycle" name="billing_cycle"><option value="month">{{T "month"}}</option><option value="year">{{T "year"}}</option><option value="">{{T "not for sale"}}</option></select></div>
</div>
<div class="grid2">
<div class="field"><label for="max_devices">{{T "Max devices"}}</label><input id="max_devices" name="max_devices" placeholder="50"></div>
<div class="field"><label for="max_users">{{T "Max users"}}</label><input id="max_users" name="max_users" placeholder="5"></div>
<div class="field"><label for="max_routes">{{T "Max routes"}}</label><input id="max_routes" name="max_routes" placeholder="32"></div>
<div class="field"><label for="max_auth_keys">{{T "Max auth keys"}}</label><input id="max_auth_keys" name="max_auth_keys" placeholder="25"></div>
</div>
<p class="lede">{{T "Leave a quota empty (or write unlimited) for no limit."}}</p>
<div class="grid2">
<div class="field row"><input type="checkbox" id="allow_custom_cidr" name="allow_custom_cidr"><label for="allow_custom_cidr">{{T "Custom network range"}}</label></div>
<div class="field row"><input type="checkbox" id="allow_exit_node" name="allow_exit_node"><label for="allow_exit_node">{{T "Exit nodes"}}</label></div>
<div class="field row"><input type="checkbox" id="allow_subnet_router" name="allow_subnet_router"><label for="allow_subnet_router">{{T "Subnet routers"}}</label></div>
<div class="field row"><input type="checkbox" id="allow_api" name="allow_api"><label for="allow_api">{{T "API keys"}}</label></div>
<div class="field row"><input type="checkbox" id="allow_acl" name="allow_acl"><label for="allow_acl">{{T "ACL policy"}}</label></div>
<div class="field row"><input type="checkbox" id="allow_grants" name="allow_grants"><label for="allow_grants">{{T "Grants"}}</label></div>
<div class="field row"><input type="checkbox" id="allow_custom_dns" name="allow_custom_dns"><label for="allow_custom_dns">{{T "Custom DNS"}}</label></div>
<div class="field row"><input type="checkbox" id="allow_audit_log" name="allow_audit_log"><label for="allow_audit_log">{{T "Audit log"}}</label></div>
<div class="field row"><input type="checkbox" id="allow_multi_member" name="allow_multi_member"><label for="allow_multi_member">{{T "Multiple members"}}</label></div>
</div>
<button type="submit">{{T "Save plan"}}</button>
</form>
`)
)

// renderAdmin writes one platform page.
func (r *Router) renderAdmin(w http.ResponseWriter, req *http.Request, tmpl *template.Template, data adminPageData, status ...int) {
	data.Lang = "en"
	if strings.Contains(strings.ToLower(req.Header.Get("Accept-Language")), "zh") {
		data.Lang = "zh"
	}
	if data.Version == "" {
		data.Version = Version
	}
	code := http.StatusOK
	if len(status) > 0 {
		code = status[0]
	}

	localized, err := tmpl.Clone()
	if err != nil {
		r.log.Error("cloning an admin template", "template", tmpl.Name(), "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	localized.Funcs(template.FuncMap{"T": translator(data.Lang)})

	var buf bytes.Buffer
	if err := localized.Execute(&buf, data); err != nil {
		r.log.Error("rendering an admin page", "template", tmpl.Name(), "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_, _ = w.Write(buf.Bytes())
}

// adminBaseData fills the fields every authenticated page needs.
func (r *Router) adminBaseData(req *http.Request, title, lede string) adminPageData {
	data := adminPageData{
		Title:    title,
		Lede:     lede,
		Path:     strings.TrimSuffix(req.URL.Path, "/"),
		SignedIn: true,
		Version:  Version,
	}
	if data.Path == "" {
		data.Path = "/admin/"
	}
	if notice := strings.TrimSpace(req.URL.Query().Get("notice")); notice != "" {
		data.Notice = notice
	}
	if session, ok := r.adminSession(req); ok {
		data.CSRF = session.CSRF
	}
	return data
}

// adminError answers a page request whose data could not be read.
func (r *Router) adminError(w http.ResponseWriter, req *http.Request, err error) {
	r.log.Error("platform console request failed", "path", req.URL.Path, "err", err)
	http.Error(w, "internal error", http.StatusInternalServerError)
}

// adminPlanDistribution renders the count of tenants per plan, in catalog
// order, so the overview reads like the price list.
func adminPlanDistribution(catalog *plan.Catalog, counts map[string]int) []adminPlanCount {
	out := make([]adminPlanCount, 0, len(counts))
	for _, p := range catalog.List() {
		out = append(out, adminPlanCount{ID: p.ID, Name: p.Name, Count: counts[p.ID]})
	}
	return out
}

// urlQueryEscape escapes a notice for a redirect.
func urlQueryEscape(value string) string { return url.QueryEscape(value) }

// tailcfgUserID converts a numeric account ID.
func tailcfgUserID(id uint64) tailcfg.UserID { return tailcfg.UserID(id) }

// nowUTC is the clock the platform pages use.
func nowUTC() time.Time { return time.Now().UTC() }
