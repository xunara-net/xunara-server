package control

import (
	"slices"
	"testing"

	"tailscale.com/tailcfg"

	"github.com/xunara-net/xunara-server/identity"
	"github.com/xunara-net/xunara-server/state"
)

func TestServerSeedsIdentityStore(t *testing.T) {
	s := newTestServer(t)

	if s.Identity() == nil {
		t.Fatal("Identity() returned nil")
	}

	users := s.Identity().ListUsers()
	if len(users) != 1 {
		t.Fatalf("ListUsers = %d users, want 1", len(users))
	}
	if users[0].ID != state.DefaultUserID {
		t.Errorf("local user ID = %d, want %d", users[0].ID, state.DefaultUserID)
	}
	if users[0].LoginName != identity.LocalLoginName {
		t.Errorf("local user login name = %q, want %q", users[0].LoginName, identity.LocalLoginName)
	}
	if _, ok := s.Identity().GetExternalIdentity(identity.LocalProviderID, identity.LocalLoginName); !ok {
		t.Error("local external identity (local, local) missing")
	}

	var actions []string
	for _, e := range s.Identity().ListAudit(0) {
		actions = append(actions, e.Action)
	}
	if !slices.Contains(actions, identity.AuditUserCreated) {
		t.Errorf("audit log %v does not contain %s", actions, identity.AuditUserCreated)
	}
}

func TestUserProfileFallsBackForUnknownUsers(t *testing.T) {
	s := newTestServer(t)

	got := s.UserProfile(tailcfg.UserID(4242))
	if got.ID != 4242 || got.LoginName != state.DefaultLoginName || got.DisplayName != state.DefaultDisplayName {
		t.Errorf("UserProfile(unknown) = %+v", got)
	}
}

func TestNetmapUserProfileComesFromIdentityStore(t *testing.T) {
	s := newTestServer(t)
	hs := newTestHTTPServer(t, s)
	_, client, nodeKey := registerNode(t, s, hs, "node1")

	u, ok := s.Identity().GetUser(state.DefaultUserID)
	if !ok {
		t.Fatalf("GetUser(%d): not found", state.DefaultUserID)
	}
	u.LoginName = "renamed@example.com"
	u.DisplayName = "Renamed User"
	if err := s.Identity().UpdateUser(u); err != nil {
		t.Fatalf("UpdateUser: %v", err)
	}

	resp := openMapSession(t, client, nodeKey.Public())
	defer resp.Body.Close()

	msg := waitForFrame(t, mapFrames(resp.Body), func(m *tailcfg.MapResponse) bool {
		return len(m.UserProfiles) > 0
	})

	profiles := make(map[tailcfg.UserID]tailcfg.UserProfile, len(msg.UserProfiles))
	for _, p := range msg.UserProfiles {
		profiles[p.ID] = p
	}
	got, ok := profiles[state.DefaultUserID]
	if !ok {
		t.Fatalf("netmap user profiles %+v lack user %d", msg.UserProfiles, state.DefaultUserID)
	}
	if got.LoginName != "renamed@example.com" || got.DisplayName != "Renamed User" {
		t.Errorf("netmap profile = %+v, want the identity store's user", got)
	}

	// The wire profile must match what Server.UserProfile reports.
	if want := s.UserProfile(state.DefaultUserID); got.ID != want.ID ||
		got.LoginName != want.LoginName || got.DisplayName != want.DisplayName {
		t.Errorf("netmap profile %+v != UserProfile %+v", got, want)
	}
}
