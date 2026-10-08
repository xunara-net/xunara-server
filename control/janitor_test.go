package control

import (
	"context"
	"testing"
	"time"

	"tailscale.com/tailcfg"
	"tailscale.com/types/key"

	"github.com/xunara-net/xunara-server/identity"
	"github.com/xunara-net/xunara-server/state"
)

func TestNodeKeyExpiryAppliedAtRegistration(t *testing.T) {
	s := newServerWithConfig(t, Config{NodeKeyExpiry: time.Hour})
	secret := seedPreAuthKey(t, s, state.PreAuthKey{})

	before := time.Now()
	resp, err := s.handleRegister(context.Background(), tailcfg.RegisterRequest{
		Version: tailcfg.CurrentCapabilityVersion,
		NodeKey: key.NewNode().Public(),
		Auth:    &tailcfg.RegisterResponseAuth{AuthKey: secret},
	}, key.NewMachine().Public())
	if err != nil {
		t.Fatalf("handleRegister: %v", err)
	}
	if !resp.MachineAuthorized {
		t.Fatalf("not authorized: %+v", resp)
	}

	node := s.store.ListNodes()[0]
	wantEarliest, wantLatest := before.Add(time.Hour), time.Now().Add(time.Hour)

	if node.Expiry.Before(wantEarliest) || node.Expiry.After(wantLatest) {
		t.Errorf("expiry = %v, want between %v and %v", node.Expiry, wantEarliest, wantLatest)
	}
}

func TestClientRequestedExpiryMayShortenButNotExtend(t *testing.T) {
	s := newServerWithConfig(t, Config{NodeKeyExpiry: time.Hour})

	tests := []struct {
		name      string
		requested time.Duration
		wantAbout time.Duration
	}{
		{"shorter wins", 10 * time.Minute, 10 * time.Minute},
		{"longer is capped by server policy", 5 * time.Hour, time.Hour},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			secret := seedPreAuthKey(t, s, state.PreAuthKey{})

			before := time.Now()
			if _, err := s.handleRegister(context.Background(), tailcfg.RegisterRequest{
				Version: tailcfg.CurrentCapabilityVersion,
				NodeKey: key.NewNode().Public(),
				Auth:    &tailcfg.RegisterResponseAuth{AuthKey: secret},
				Expiry:  before.Add(tc.requested),
			}, key.NewMachine().Public()); err != nil {
				t.Fatalf("handleRegister: %v", err)
			}

			nodes := s.store.ListNodes()
			node := nodes[len(nodes)-1]

			got := node.Expiry.Sub(before)
			if got < tc.wantAbout-time.Minute || got > tc.wantAbout+time.Minute {
				t.Errorf("expiry %v after registration, want about %v", got, tc.wantAbout)
			}
		})
	}
}

func TestNodeKeysNeverExpireByDefault(t *testing.T) {
	s := newTestServer(t)
	secret := seedPreAuthKey(t, s, state.PreAuthKey{})

	if _, err := s.handleRegister(context.Background(), tailcfg.RegisterRequest{
		Version: tailcfg.CurrentCapabilityVersion,
		NodeKey: key.NewNode().Public(),
		Auth:    &tailcfg.RegisterResponseAuth{AuthKey: secret},
	}, key.NewMachine().Public()); err != nil {
		t.Fatalf("handleRegister: %v", err)
	}

	if got := s.store.ListNodes()[0].Expiry; !got.IsZero() {
		t.Errorf("expiry = %v, want zero", got)
	}
}

func TestReapEphemeral(t *testing.T) {
	s := newServerWithConfig(t, Config{EphemeralInactivityTimeout: time.Hour})

	past := time.Now().Add(-2 * time.Hour)

	stale := state.Node{NodeKey: key.NewNode().Public(), Ephemeral: true, Created: past}
	fresh := state.Node{NodeKey: key.NewNode().Public(), Ephemeral: true, Created: time.Now().UTC()}
	permanent := state.Node{NodeKey: key.NewNode().Public(), Created: past}

	for _, n := range []*state.Node{&stale, &fresh, &permanent} {
		if err := s.store.CreateNode(n); err != nil {
			t.Fatalf("CreateNode: %v", err)
		}
	}

	if got := s.ReapEphemeral(time.Now()); got != 1 {
		t.Fatalf("reaped = %d, want 1", got)
	}

	if _, ok := s.store.GetNodeByID(stale.ID); ok {
		t.Error("stale ephemeral node survived reaping")
	}
	if _, ok := s.store.GetNodeByID(fresh.ID); !ok {
		t.Error("fresh ephemeral node was reaped")
	}
	if _, ok := s.store.GetNodeByID(permanent.ID); !ok {
		t.Error("non-ephemeral node was reaped")
	}
}

func TestReapEphemeralSparesOnlineNodes(t *testing.T) {
	s := newServerWithConfig(t, Config{EphemeralInactivityTimeout: time.Hour})

	node := state.Node{
		NodeKey:   key.NewNode().Public(),
		Ephemeral: true,
		Created:   time.Now().Add(-2 * time.Hour),
	}
	if err := s.store.CreateNode(&node); err != nil {
		t.Fatalf("CreateNode: %v", err)
	}

	s.markOnline(node)
	defer s.markOffline(node)

	if got := s.ReapEphemeral(time.Now()); got != 0 {
		t.Fatalf("reaped = %d, want 0 while the node holds a session", got)
	}
	if _, ok := s.store.GetNodeByID(node.ID); !ok {
		t.Error("online ephemeral node was reaped")
	}
}

// TestReapPasskeyCeremonies checks that expired WebAuthn challenges are
// removed while live ones survive.
func TestReapPasskeyCeremonies(t *testing.T) {
	s := newTestServer(t)

	expired, _, err := s.identity.CreatePasskeyCeremony(identity.NewPasskeyCeremonyOptions{
		Kind:      identity.PasskeyCeremonyLogin,
		Session:   []byte("{}"),
		ExpiresAt: time.Now().Add(-time.Minute),
	})
	if err != nil {
		t.Fatalf("CreatePasskeyCeremony: %v", err)
	}
	live, _, err := s.identity.CreatePasskeyCeremony(identity.NewPasskeyCeremonyOptions{
		Kind:      identity.PasskeyCeremonyLogin,
		Session:   []byte("{}"),
		ExpiresAt: time.Now().Add(time.Minute),
	})
	if err != nil {
		t.Fatalf("CreatePasskeyCeremony: %v", err)
	}

	s.reapPasskeyCeremonies(time.Now())

	if _, ok := s.identity.GetPasskeyCeremony(expired.ID); ok {
		t.Error("expired passkey ceremony survived the janitor")
	}
	if _, ok := s.identity.GetPasskeyCeremony(live.ID); !ok {
		t.Error("live passkey ceremony was reaped")
	}
}
