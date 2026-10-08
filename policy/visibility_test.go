package policy

import (
	"strings"
	"testing"

	"tailscale.com/tailcfg"

	"github.com/xunara-net/xunara-server/state"
)

// visibilityDoc declares the names service visibility selectors may reference.
const visibilityDoc = `{
	"groups": {"group:eng": ["alice@example.com"]},
	"tagOwners": {"tag:prod": ["alice@example.com"]},
	"hosts": {"db": "100.64.0.9"},
	"acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}],
}`

func TestNormalizeServiceVisibility(t *testing.T) {
	for _, tt := range []struct {
		name    string
		in      []string
		want    []string
		wantErr string
	}{
		{name: "default is the organization"},
		{name: "sorts and deduplicates", in: []string{" tag:prod ", "group:eng", "tag:prod"}, want: []string{"group:eng", "tag:prod"}},
		{name: "wildcard", in: []string{"*"}, want: []string{"*"}},
		{name: "empty entry", in: []string{" "}, wantErr: "empty"},
		{name: "control characters", in: []string{"group:eng\x1b"}, wantErr: "printable"},
		{name: "too long", in: []string{strings.Repeat("a", MaxServiceVisibilitySelectorLen+1)}, wantErr: "longer than"},
		{name: "too many", in: make([]string, MaxServiceVisibilitySelectors+1), wantErr: "at most"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NormalizeServiceVisibility(tt.in)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("NormalizeServiceVisibility(%v) error = %v, want %q", tt.in, err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("NormalizeServiceVisibility(%v): %v", tt.in, err)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("NormalizeServiceVisibility(%v) = %v, want %v", tt.in, got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Fatalf("NormalizeServiceVisibility(%v) = %v, want %v", tt.in, got, tt.want)
				}
			}
		})
	}
}

func TestValidateServiceVisibility(t *testing.T) {
	engine := mustEngine(t, visibilityDoc)

	for _, tt := range []struct {
		name    string
		sel     string
		wantErr bool
	}{
		{name: "wildcard", sel: "*"},
		{name: "member", sel: "autogroup:member"},
		{name: "tagged", sel: "autogroup:tagged"},
		{name: "self", sel: "autogroup:self"},
		{name: "group", sel: "group:eng"},
		{name: "tag", sel: "tag:prod"},
		{name: "host alias", sel: "db"},
		{name: "user", sel: "alice@example.com"},
		{name: "prefix", sel: "100.64.0.0/24"},
		{name: "internet", sel: "autogroup:internet", wantErr: true},
		{name: "unknown group", sel: "group:ops", wantErr: true},
		{name: "unknown tag", sel: "tag:dev", wantErr: true},
		{name: "bare name is a user selector", sel: "nobody@example.com"},
		{name: "malformed prefix", sel: "100.64.0.0/99", wantErr: true},
		{name: "other autogroup", sel: "autogroup:admins", wantErr: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			err := engine.ValidateServiceVisibility([]string{tt.sel})
			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidateServiceVisibility(%q) = %v, want error %v", tt.sel, err, tt.wantErr)
			}
		})
	}
}

func TestServiceVisibilityResolves(t *testing.T) {
	engine := mustEngineOpts(t, visibilityDoc, logins(map[tailcfg.UserID]string{1: "alice@example.com", 2: "bob@example.com"}))

	alice := testNode(1, "alice-laptop", "100.64.0.1")
	bob := testNode(2, "bob-laptop", "100.64.0.2")
	bob.UserID = 2
	tagged := testNode(3, "prod-1", "100.64.0.3")
	tagged.UserID = 2
	tagged.Tags = []string{"tag:prod"}
	other := testNode(4, "alice-desktop", "100.64.0.4")
	nodes := []state.Node{alice, bob, tagged, other}

	for _, tt := range []struct {
		name string
		sel  []string
		want []state.NodeID
	}{
		{name: "wildcard", sel: []string{"*"}, want: []state.NodeID{1, 2, 3, 4}},
		{name: "group", sel: []string{"group:eng"}, want: []state.NodeID{1, 4}},
		{name: "tag", sel: []string{"tag:prod"}, want: []state.NodeID{3}},
		{name: "self is the publisher's user", sel: []string{"autogroup:self"}, want: []state.NodeID{1, 4}},
		{name: "union", sel: []string{"tag:prod", "group:eng"}, want: []state.NodeID{1, 3, 4}},
		{name: "unknown selector resolves to nobody", sel: []string{"group:ops"}, want: nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got := engine.ServiceVisibility(nodes, alice, tt.sel)
			if len(got) != len(tt.want) {
				t.Fatalf("ServiceVisibility(%v) = %v, want %v", tt.sel, got, tt.want)
			}
			for _, id := range tt.want {
				if !got[id] {
					t.Fatalf("ServiceVisibility(%v) = %v, want node %d", tt.sel, got, id)
				}
			}
		})
	}

	// autogroup:self follows the publisher, not the caller.
	got := engine.ServiceVisibility(nodes, bob, []string{"autogroup:self"})
	if len(got) != 1 || !got[bob.ID] {
		t.Fatalf("ServiceVisibility(self) for bob = %v, want just bob", got)
	}
}
