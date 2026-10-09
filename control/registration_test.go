package control

import (
	"net/http"
	"strings"
	"testing"

	"github.com/xunara-net/xunara-server/identity"
	"github.com/xunara-net/xunara-server/plan"
)

// The registration policy is deployment-wide, so the interesting cases are:
// which role a self-service account gets, what a closed deployment answers,
// and that the console can tell the three modes apart.

func TestParseRegistrationMode(t *testing.T) {
	cases := []struct {
		in      string
		want    RegistrationMode
		wantErr bool
	}{
		{"", RegistrationInvite, false},
		{"  ", RegistrationInvite, false},
		{"invite", RegistrationInvite, false},
		{"INVITE", RegistrationInvite, false},
		{" open ", RegistrationOpen, false},
		{"closed", RegistrationClosed, false},
		{"anyone", "", true},
	}
	for _, tc := range cases {
		got, err := ParseRegistrationMode(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("ParseRegistrationMode(%q) = %q, want an error", tc.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseRegistrationMode(%q): %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("ParseRegistrationMode(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestRegistrationModePolicy(t *testing.T) {
	if !RegistrationInvite.AllowsSignup() || !RegistrationInvite.RequiresInvite() {
		t.Error("the invitation mode must accept sign-ups and require an invitation")
	}
	if !RegistrationOpen.AllowsSignup() || RegistrationOpen.RequiresInvite() {
		t.Error("open registration must accept sign-ups without an invitation")
	}
	if RegistrationClosed.AllowsSignup() {
		t.Error("closed registration must not accept sign-ups")
	}
}

// A deployment that never sets a mode keeps the invitation flow, and a
// deployment without local login cannot sign anyone up at all.
func TestRegistrationDefaults(t *testing.T) {
	if s := newTestServer(t); s.registration != RegistrationInvite {
		t.Fatalf("default registration mode = %q, want %q", s.registration, RegistrationInvite)
	}
	if s := newServerWithConfig(t, Config{Registration: RegistrationOpen}); s.registration != RegistrationOpen {
		t.Fatalf("configured registration mode = %q, want %q", s.registration, RegistrationOpen)
	}
}

func TestRegistrationReportsModeToClients(t *testing.T) {
	open := newServerWithConfig(t, Config{Registration: RegistrationOpen})
	hs := newTestHTTPServer(t, open)
	client := noRedirectClient()

	resp := getRequest(t, client, hs.URL+"/api/v1/auth/providers", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/v1/auth/providers = %d, want 200", resp.StatusCode)
	}
	var payload struct {
		Registration string `json:"registration"`
	}
	decodeJSONBody(t, resp, &payload)
	if payload.Registration != string(RegistrationOpen) {
		t.Fatalf("registration = %q, want %q", payload.Registration, RegistrationOpen)
	}

	// The capability probe is what a client reads before it renders a form.
	capResp := getRequest(t, client, hs.URL+"/api/v1/capabilities", nil)
	if capResp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/v1/capabilities = %d, want 200", capResp.StatusCode)
	}
	var caps struct {
		Capabilities []string `json:"capabilities"`
	}
	decodeJSONBody(t, capResp, &caps)
	if !containsString(caps.Capabilities, "auth.register.open") {
		t.Fatalf("capabilities = %v, want auth.register.open", caps.Capabilities)
	}
	if containsString(caps.Capabilities, "auth.register.invite") {
		t.Fatalf("capabilities = %v, must not advertise invitations in open mode", caps.Capabilities)
	}
}

// Open registration creates a member without any invitation, and signs the
// new account in.
func TestSignupOpenModeCreatesMember(t *testing.T) {
	s := newServerWithConfig(t, Config{Registration: RegistrationOpen})
	hs := newTestHTTPServer(t, s)
	client := noRedirectClient()

	resp := postJSON(t, client, hs.URL+"/api/v1/auth/signup", map[string]string{
		"login":        "open-alice",
		"display_name": "Alice",
		"email":        "alice@example.com",
		"password":     "correct horse battery staple",
	}, nil)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("self-service signup = %d (%s), want 201", resp.StatusCode, bodyString(t, resp))
	}
	var payload struct {
		Authenticated bool `json:"authenticated"`
		User          struct {
			LoginName string `json:"login_name"`
			Role      string `json:"role"`
		} `json:"user"`
	}
	decodeJSONBody(t, resp, &payload)
	if !payload.Authenticated {
		t.Fatalf("self-service signup did not start a session: %+v", payload)
	}
	if payload.User.LoginName != "open-alice" || payload.User.Role != string(identity.RoleMember) {
		t.Fatalf("signed-up user = %+v, want member open-alice", payload.User)
	}
	if _, ok := s.identity.GetUserByLoginName("open-alice"); !ok {
		t.Fatal("the account was not stored")
	}
	// No invitation may have been created or consumed by the open path.
	if invites := s.identity.ListRegistrationInvites(); len(invites) != 0 {
		t.Fatalf("open registration touched invitations: %+v", invites)
	}
}

// A closed deployment refuses to create anything and says so.
func TestSignupClosedModeRejects(t *testing.T) {
	s := newServerWithConfig(t, Config{Registration: RegistrationClosed})
	hs := newTestHTTPServer(t, s)
	client := noRedirectClient()

	resp := postJSON(t, client, hs.URL+"/api/v1/auth/signup", map[string]string{
		"login":    "closed-alice",
		"password": "correct horse battery staple",
	}, nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("closed signup = %d (%s), want 403", resp.StatusCode, bodyString(t, resp))
	}
	if _, ok := s.identity.GetUserByLoginName("closed-alice"); ok {
		t.Fatal("a closed deployment created an account")
	}

	page := getRequest(t, client, hs.URL+"/signup", nil)
	if page.StatusCode != http.StatusNotFound {
		t.Fatalf("GET /signup on a closed deployment = %d, want 404", page.StatusCode)
	}
}

// The HTML sign-up page asks for an invitation only when one is required.
func TestSignupPageShowsInviteOnlyWhenRequired(t *testing.T) {
	invite := newTestServer(t)
	inviteHS := newTestHTTPServer(t, invite)
	client := noRedirectClient()

	page := getRequest(t, client, inviteHS.URL+"/signup", nil)
	if page.StatusCode != http.StatusOK {
		t.Fatalf("GET /signup = %d, want 200", page.StatusCode)
	}
	if body := bodyString(t, page); !strings.Contains(body, `name="invite"`) {
		t.Fatalf("the invitation field is missing from the default sign-up page")
	}

	open := newServerWithConfig(t, Config{Registration: RegistrationOpen})
	openHS := newTestHTTPServer(t, open)
	page = getRequest(t, client, openHS.URL+"/signup", nil)
	if page.StatusCode != http.StatusOK {
		t.Fatalf("GET /signup (open) = %d, want 200", page.StatusCode)
	}
	if body := bodyString(t, page); strings.Contains(body, `name="invite"`) {
		t.Fatalf("the open sign-up page still asks for an invitation")
	}
}

// The commercial layer still applies: an open deployment does not sell more
// members than the tenant's plan allows.
func TestSignupOpenModeRespectsMemberQuota(t *testing.T) {
	free := freePlan(t) // MaxUsers = 1
	s := newServerWithConfig(t, Config{
		Registration: RegistrationOpen,
		PlanSource:   func(string) plan.Plan { return free },
	})
	hs := newTestHTTPServer(t, s)
	client := noRedirectClient()

	// The harness seeds one administrator, which is the whole allowance.
	resp := postJSON(t, client, hs.URL+"/api/v1/auth/signup", map[string]string{
		"login":    "over-quota",
		"password": "correct horse battery staple",
	}, nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("signup past the member quota = %d (%s), want 403", resp.StatusCode, bodyString(t, resp))
	}
	if body := bodyString(t, resp); !strings.Contains(body, "USER_LIMIT_REACHED") {
		t.Fatalf("signup past the member quota = %s, want USER_LIMIT_REACHED", body)
	}

	// The same deployment on Pro accepts the account.
	pro := proPlan(t)
	upgraded := newServerWithConfig(t, Config{
		Registration: RegistrationOpen,
		PlanSource:   func(string) plan.Plan { return pro },
	})
	resp = postJSON(t, noRedirectClient(), newTestHTTPServer(t, upgraded).URL+"/api/v1/auth/signup", map[string]string{
		"login":    "over-quota",
		"password": "correct horse battery staple",
	}, nil)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("signup on a plan with room = %d (%s), want 201", resp.StatusCode, bodyString(t, resp))
	}
}

func containsString(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}
