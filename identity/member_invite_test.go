package identity

import (
	"context"
	"errors"
	"testing"
	"time"
)

func memberInviteFixture(t *testing.T, store *SQLiteStore) MemberInvitation {
	t.Helper()
	owner := User{LoginName: "invite-owner", Role: RoleOwner}
	if err := store.CreateUser(&owner); err != nil {
		t.Fatal(err)
	}
	session, _, err := store.CreateSession(NewSessionOptions{UserID: owner.ID, AuthMethod: LocalProviderID, TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	return MemberInvitation{UserID: owner.ID, SessionID: session.ID, Role: RoleMember, Note: "fixture", TTL: time.Hour, MaxUsers: 2}
}

func TestMemberInvitationRechecksOwnerAndSession(t *testing.T) {
	for _, changed := range []string{"role", "session", "user"} {
		t.Run(changed, func(t *testing.T) {
			store := openTestStore(t)
			options := memberInviteFixture(t, store)
			invite, _, err := store.CreateMemberInvitation(context.Background(), options)
			if err != nil {
				t.Fatal(err)
			}
			want := ErrSessionRevoked
			switch changed {
			case "role":
				user, _ := store.GetUser(options.UserID)
				user.Role = RoleAdmin
				if err := store.UpdateUser(user); err != nil {
					t.Fatal(err)
				}
				want = ErrInviteOwnerRequired
			case "session":
				if err := store.RevokeSession(options.SessionID, "fixture revocation"); err != nil {
					t.Fatal(err)
				}
			case "user":
				if err := store.DeleteUser(options.UserID); err != nil {
					t.Fatal(err)
				}
			}
			if _, _, err := store.CreateMemberInvitation(context.Background(), options); !errors.Is(err, want) {
				t.Fatalf("changed %s still creates invitations: %v", changed, err)
			}
			if err := store.RevokeMemberInvitation(context.Background(), options.UserID, options.SessionID, invite.ID); !errors.Is(err, want) {
				t.Fatalf("changed %s still revokes invitations: %v", changed, err)
			}
			if len(store.ListRegistrationInvites()) != 1 || len(store.ListAudit(0)) != 1 {
				t.Fatal("rejected operation changed invitation or audit records")
			}
		})
	}
}

func TestMemberInvitationAuditFailureRollsBack(t *testing.T) {
	store := openTestStore(t)
	options := memberInviteFixture(t, store)
	invite, _, err := store.CreateMemberInvitation(context.Background(), options)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec("CREATE TRIGGER fail_invite_audit BEFORE INSERT ON audit_events BEGIN SELECT RAISE(ABORT, 'injected audit failure'); END"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.CreateMemberInvitation(context.Background(), options); err == nil {
		t.Fatal("invitation creation ignored audit failure")
	}
	if err := store.RevokeMemberInvitation(context.Background(), options.UserID, options.SessionID, invite.ID); err == nil {
		t.Fatal("invitation revocation ignored audit failure")
	}
	if len(store.ListRegistrationInvites()) != 1 || len(store.ListAudit(0)) != 1 {
		t.Fatal("audit failure did not roll back the invitation")
	}
	if _, err := store.db.Exec("DROP TRIGGER fail_invite_audit"); err != nil {
		t.Fatal(err)
	}
	if err := store.RevokeMemberInvitation(context.Background(), options.UserID, options.SessionID, invite.ID); err != nil {
		t.Fatal(err)
	}
	if len(store.ListRegistrationInvites()) != 0 || len(store.ListAudit(0)) != 2 {
		t.Fatal("revocation and its audit were not committed together")
	}
}

func TestMemberInvitationLimitsAndLifetime(t *testing.T) {
	store := openTestStore(t)
	options := memberInviteFixture(t, store)
	options.MaxUsers = 1
	if _, _, err := store.CreateMemberInvitation(context.Background(), options); !errors.Is(err, ErrMemberLimitReached) {
		t.Fatalf("exhausted plan issued invitation: %v", err)
	}
	options.MaxUsers = -1
	for _, ttl := range []time.Duration{0, -time.Hour, 366 * 24 * time.Hour} {
		options.TTL = ttl
		if _, _, err := store.CreateMemberInvitation(context.Background(), options); err == nil {
			t.Fatal("invalid invitation lifetime was accepted")
		}
	}
	options.TTL = time.Hour
	options.Role = RoleOwner
	if _, _, err := store.CreateMemberInvitation(context.Background(), options); err == nil {
		t.Fatal("invitation granted owner role")
	}
	if len(store.ListRegistrationInvites()) != 0 {
		t.Fatal("rejected invitation left stored records")
	}
}
