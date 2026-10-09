package identity

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestRegistrationInviteLifecycle(t *testing.T) {
	s := openTestStore(t)

	invite, token, err := s.CreateRegistrationInvite(NewRegistrationInviteOptions{
		Role:      RoleAdmin,
		Note:      "for the ops team",
		CreatedBy: "user:1",
		TTL:       time.Hour,
	})
	if err != nil {
		t.Fatalf("CreateRegistrationInvite: %v", err)
	}
	if invite.ID == "" {
		t.Fatal("invite has no ID")
	}
	if !strings.HasPrefix(token, InvitePrefix) {
		t.Errorf("token = %q, want the %q prefix", token, InvitePrefix)
	}
	if strings.Contains(invite.TokenHash, token) || invite.TokenHash == "" {
		t.Errorf("stored token hash = %q, want a hash of the token", invite.TokenHash)
	}
	if invite.Role != RoleAdmin || invite.Note != "for the ops team" || invite.CreatedBy != "user:1" {
		t.Errorf("invite = %+v", invite)
	}
	if invite.Redeemed() {
		t.Error("a new invite is already redeemed")
	}

	// The token resolves to the invite without consuming it, so the signup
	// page can show the role before the account is created.
	found, err := s.FindRegistrationInvite(token)
	if err != nil || found.ID != invite.ID {
		t.Fatalf("FindRegistrationInvite = %+v, %v", found, err)
	}
	if found.Redeemed() {
		t.Error("FindRegistrationInvite consumed the invite")
	}
	if _, err := s.FindRegistrationInvite(token + "x"); !errors.Is(err, ErrInviteNotFound) {
		t.Errorf("unknown token error = %v, want ErrInviteNotFound", err)
	}
	if _, err := s.FindRegistrationInvite(""); !errors.Is(err, ErrInviteNotFound) {
		t.Errorf("empty token error = %v, want ErrInviteNotFound", err)
	}

	if list := s.ListRegistrationInvites(); len(list) != 1 || list[0].ID != invite.ID {
		t.Fatalf("ListRegistrationInvites = %+v", list)
	}

	// Redeeming marks it used, records the user and makes it unusable.
	user, _, _, err := s.RegisterLocalAccount(context.Background(), registrationFixture("invite-member", token))
	if err != nil {
		t.Fatalf("RegisterLocalAccount: %v", err)
	}
	redeemed, ok := s.GetRegistrationInvite(invite.ID)
	if !ok || !redeemed.Redeemed() || redeemed.UsedBy != user.ID {
		t.Errorf("redeemed invite = %+v", redeemed)
	}
	if _, _, _, err := s.RegisterLocalAccount(context.Background(), registrationFixture("invite-replay", token)); !errors.Is(err, ErrInviteUsed) {
		t.Errorf("second redeem error = %v, want ErrInviteUsed", err)
	}
	if _, err := s.FindRegistrationInvite(token); !errors.Is(err, ErrInviteUsed) {
		t.Errorf("Find of a used invite = %v, want ErrInviteUsed", err)
	}
	if _, ok := s.GetRegistrationInvite(invite.ID); !ok {
		t.Error("the redeemed invite was deleted; it is kept as a record")
	}

	// A redeemed invite is a record, not something to revoke.
	if err := s.RevokeRegistrationInvite(invite.ID); !errors.Is(err, ErrInviteUsed) {
		t.Errorf("revoking a used invite = %v, want ErrInviteUsed", err)
	}
}

func TestRegistrationInviteExpiryAndRevocation(t *testing.T) {
	s := openTestStore(t)

	expired, expiredToken, err := s.CreateRegistrationInvite(NewRegistrationInviteOptions{
		Role: RoleMember,
		TTL:  time.Hour,
	})
	if err != nil {
		t.Fatalf("CreateRegistrationInvite: %v", err)
	}
	if _, err := s.db.Exec("UPDATE registration_invites SET expires_at = ? WHERE id = ?", time.Now().Add(-time.Minute).UnixNano(), expired.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.FindRegistrationInvite(expiredToken); !errors.Is(err, ErrInviteExpired) {
		t.Errorf("Find of an expired invite = %v, want ErrInviteExpired", err)
	}
	if _, _, _, err := s.RegisterLocalAccount(context.Background(), registrationFixture("expired-member", expiredToken)); !errors.Is(err, ErrInviteExpired) {
		t.Errorf("redeem of an expired invite = %v, want ErrInviteExpired", err)
	}
	if got, ok := s.GetRegistrationInvite(expired.ID); !ok || !got.Expired(time.Now()) {
		t.Errorf("expired invite = %+v, %v", got, ok)
	}

	live, liveToken, err := s.CreateRegistrationInvite(NewRegistrationInviteOptions{Role: RoleMember, TTL: time.Hour})
	if err != nil {
		t.Fatalf("CreateRegistrationInvite: %v", err)
	}
	if err := s.RevokeRegistrationInvite(live.ID); err != nil {
		t.Fatalf("RevokeRegistrationInvite: %v", err)
	}
	if _, ok := s.GetRegistrationInvite(live.ID); ok {
		t.Error("the revoked invite is still listed")
	}
	if _, err := s.FindRegistrationInvite(liveToken); !errors.Is(err, ErrInviteNotFound) {
		t.Errorf("revoked token error = %v, want ErrInviteNotFound", err)
	}
	if err := s.RevokeRegistrationInvite("no-such-invite"); !errors.Is(err, ErrInviteNotFound) {
		t.Errorf("revoking an unknown invite = %v, want ErrInviteNotFound", err)
	}
}

func TestRegistrationInviteRoles(t *testing.T) {
	s := openTestStore(t)

	member, _, err := s.CreateRegistrationInvite(NewRegistrationInviteOptions{})
	if err != nil {
		t.Fatalf("CreateRegistrationInvite: %v", err)
	}
	if member.Role != RoleMember {
		t.Errorf("an invite without a role grants %q, want member", member.Role)
	}
	if _, _, err := s.CreateRegistrationInvite(NewRegistrationInviteOptions{Role: RoleOwner}); err == nil {
		t.Error("an invite can mint another owner")
	}

	// An invite without a TTL does not expire, but is still single use.
	perpetual, token, err := s.CreateRegistrationInvite(NewRegistrationInviteOptions{Role: RoleAdmin})
	if err != nil {
		t.Fatalf("CreateRegistrationInvite: %v", err)
	}
	if !perpetual.ExpiresAt.IsZero() {
		t.Errorf("invite expiry = %v, want no expiry", perpetual.ExpiresAt)
	}
	if perpetual.Expired(time.Now().AddDate(1, 0, 0)) {
		t.Error("an invite without a TTL expired")
	}
	if _, _, _, err := s.RegisterLocalAccount(context.Background(), registrationFixture("perpetual-member", token)); err != nil {
		t.Fatalf("RegisterLocalAccount: %v", err)
	}
}

// TestRegistrationInviteRedeemIsAtomic checks that concurrent submissions of
// the same invitation produce exactly one account.
func TestRegistrationInviteRedeemIsAtomic(t *testing.T) {
	s := openTestStore(t)

	_, token, err := s.CreateRegistrationInvite(NewRegistrationInviteOptions{Role: RoleMember, TTL: time.Hour})
	if err != nil {
		t.Fatalf("CreateRegistrationInvite: %v", err)
	}

	const racers = 8
	start := make(chan struct{})
	results := make(chan error, racers)
	var wg sync.WaitGroup
	for index := 0; index < racers; index++ {
		wg.Add(1)
		go func(login string) {
			defer wg.Done()
			<-start
			_, _, _, err := s.RegisterLocalAccount(context.Background(), registrationFixture(login, token))
			results <- err
		}(fmt.Sprintf("invite-racer-%d", index))
	}
	close(start)
	wg.Wait()
	close(results)

	winners := 0
	for err := range results {
		switch {
		case err == nil:
			winners++
		case errors.Is(err, ErrInviteUsed):
		default:
			t.Errorf("unexpected redeem error: %v", err)
		}
	}
	if winners != 1 {
		t.Fatalf("concurrent redeem winners = %d, want exactly 1", winners)
	}
	if len(s.ListUsers()) != 1 {
		t.Fatal("failed invitations left orphan accounts")
	}
}

func TestNewSecret(t *testing.T) {
	first, err := NewSecret(32)
	if err != nil {
		t.Fatalf("NewSecret: %v", err)
	}
	second, err := NewSecret(32)
	if err != nil {
		t.Fatalf("NewSecret: %v", err)
	}
	if first == second {
		t.Error("two secrets are identical")
	}
	// 32 random bytes are 43 characters in unpadded base64url.
	if len(first) != 43 {
		t.Errorf("secret length = %d, want 43", len(first))
	}
	if strings.ContainsAny(first, "+/=") {
		t.Errorf("secret %q is not URL safe", first)
	}
	if _, err := NewSecret(0); err == nil {
		t.Error("NewSecret(0) succeeded")
	}
	if _, err := NewSecret(-1); err == nil {
		t.Error("NewSecret(-1) succeeded")
	}
}
