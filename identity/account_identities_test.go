package identity

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

func accountAuthorization(t *testing.T, store *SQLiteStore, options NewAuthTransactionOptions) AuthTransaction {
	t.Helper()
	if options.ProviderID == "" {
		options.ProviderID = "test-oidc"
	}
	authorization, _, err := store.CreateAccountAuthTransaction(t.Context(), options)
	if err != nil {
		t.Fatal(err)
	}
	return authorization
}

func TestAccountIdentityBindingAndLogin(t *testing.T) {
	store := openTestStore(t)
	user, _, initiating, _ := seedAccount(t, store, "owner")
	result := IdentityResult{ProviderID: "test-oidc", Subject: "subject-one", Email: "new-attribute@example.test", DisplayName: "外部账户"}
	authorization := accountAuthorization(t, store, NewAuthTransactionOptions{RequestedAction: AuthActionLink, AccountUserID: user.ID, AccountSessionID: initiating.ID})
	completed, err := store.CompleteExternalAuthentication(t.Context(), authorization.ID, result, ExternalAuthenticationOptions{MaxUsers: 0})
	if err != nil || !completed.Linked || completed.User.ID != user.ID || completed.Token != "" || completed.Session.ID != "" {
		t.Fatalf("binding: %+v %v", completed, err)
	}
	if len(store.ListUsers()) != 1 || len(store.ListSessions(user.ID)) != 1 {
		t.Fatal("binding created an account or session")
	}
	if _, err := store.CompleteExternalAuthentication(t.Context(), authorization.ID, result, ExternalAuthenticationOptions{}); !errors.Is(err, ErrTransactionConsumed) {
		t.Fatal("binding replay accepted")
	}
	authorization = accountAuthorization(t, store, NewAuthTransactionOptions{})
	completed, err = store.CompleteExternalAuthentication(t.Context(), authorization.ID, result, ExternalAuthenticationOptions{MaxUsers: 0})
	if err != nil || completed.Linked || completed.Session.UserID != user.ID || completed.Token == "" {
		t.Fatalf("bound identity login: %+v %v", completed, err)
	}
	unchanged, _ := store.GetUser(user.ID)
	if unchanged.Email != user.Email {
		t.Fatal("external login replaced user-maintained contact email")
	}
	links, err := store.ListAccountIdentities(t.Context(), user.ID)
	if err != nil || len(links) != 1 {
		t.Fatal("binding list failed")
	}
	revoked, err := store.UnlinkAccountIdentity(t.Context(), user.ID, initiating.ID, IdentityReference(links[0]), LoginMethods{Local: true, Providers: []string{result.ProviderID}})
	if err != nil || revoked {
		t.Fatalf("unlink: %v %v", revoked, err)
	}
	if _, err := store.GetSessionByToken(completed.Token); !errors.Is(err, ErrSessionNotFound) {
		t.Fatal("SSO session survived unlink")
	}
	current, _ := store.GetSessionByID(initiating.ID)
	if !current.RevokedAt.IsZero() {
		t.Fatal("unlink revoked independent password login")
	}
}

func TestAccountIdentityRejectsConfusionAndRevocation(t *testing.T) {
	for _, scenario := range []string{"other owner", "revoked session", "wrong provider", "audit abort", "audit ignore"} {
		t.Run(scenario, func(t *testing.T) {
			store := openTestStore(t)
			user, _, session, _ := seedAccount(t, store, "owner")
			authorization := accountAuthorization(t, store, NewAuthTransactionOptions{RequestedAction: AuthActionLink, AccountUserID: user.ID, AccountSessionID: session.ID})
			result := IdentityResult{ProviderID: "test-oidc", Subject: "private-subject", Email: user.Email}
			switch scenario {
			case "other owner":
				other, _, _, _ := seedAccount(t, store, "other")
				if err := store.LinkExternalIdentity(&ExternalIdentity{ProviderID: result.ProviderID, Subject: result.Subject, UserID: other.ID}); err != nil {
					t.Fatal(err)
				}
			case "revoked session":
				if err := store.RevokeSession(session.ID, "test"); err != nil {
					t.Fatal(err)
				}
			case "wrong provider":
				result.ProviderID = "another-provider"
			case "audit abort", "audit ignore":
				failure := "RAISE(ABORT, 'test')"
				if scenario == "audit ignore" {
					failure = "RAISE(IGNORE)"
				}
				if _, err := store.db.Exec("CREATE TRIGGER reject_binding_audit BEFORE INSERT ON audit_events WHEN NEW.action = 'identity.linked' BEGIN SELECT " + failure + "; END"); err != nil {
					t.Fatal(err)
				}
			}
			if completed, err := store.CompleteExternalAuthentication(t.Context(), authorization.ID, result, ExternalAuthenticationOptions{}); err == nil || completed.Token != "" {
				t.Fatal("unsafe binding succeeded")
			}
			persisted, _ := store.GetAuthTransaction(authorization.ID)
			if persisted.Consumed() {
				t.Fatal("failed binding partially consumed the authorization")
			}
			if links, err := store.ListAccountIdentities(t.Context(), user.ID); err != nil || len(links) != 0 {
				t.Fatal("failed binding partially linked identity")
			}
		})
	}
}

func TestAccountIdentityLastMethodAndUnlinkAtomicity(t *testing.T) {
	for _, scenario := range []string{"last method", "disabled password", "disabled provider", "another provider", "audit abort", "audit ignore"} {
		t.Run(scenario, func(t *testing.T) {
			store := openTestStore(t)
			user, _, session, _ := seedAccount(t, store, "owner")
			link := ExternalIdentity{ProviderID: "test-oidc", Subject: "private-subject", UserID: user.ID}
			if err := store.LinkExternalIdentity(&link); err != nil {
				t.Fatal(err)
			}
			methods := LoginMethods{Providers: []string{link.ProviderID}}
			if scenario == "another provider" || scenario == "disabled provider" {
				if err := store.LinkExternalIdentity(&ExternalIdentity{ProviderID: "other", Subject: "other-subject", UserID: user.ID}); err != nil {
					t.Fatal(err)
				}
				if scenario == "another provider" {
					methods.Providers = append(methods.Providers, "other")
				}
			}
			if scenario == "audit abort" || scenario == "audit ignore" {
				methods.Local = true
				failure := "RAISE(ABORT, 'test')"
				if scenario == "audit ignore" {
					failure = "RAISE(IGNORE)"
				}
				if _, err := store.db.Exec("CREATE TRIGGER reject_unlink_audit BEFORE INSERT ON audit_events WHEN NEW.action = 'identity.unlinked' BEGIN SELECT " + failure + "; END"); err != nil {
					t.Fatal(err)
				}
			}
			_, err := store.UnlinkAccountIdentity(t.Context(), user.ID, session.ID, IdentityReference(link), methods)
			if scenario == "another provider" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil {
				t.Fatal("unsafe unlink accepted")
			}
			if _, ok := store.GetExternalIdentity(link.ProviderID, link.Subject); !ok {
				t.Fatal("failed unlink removed binding")
			}
			current, _ := store.GetSessionByID(session.ID)
			if !current.RevokedAt.IsZero() {
				t.Fatal("failed unlink revoked initiating session")
			}
		})
	}
}

func TestExternalInvitationAdmissionIsAtomic(t *testing.T) {
	for _, scenario := range []string{"success", "revoked", "expired", "quota", "closed", "email collision", "audit abort", "audit ignore"} {
		t.Run(scenario, func(t *testing.T) {
			store := openTestStore(t)
			owner, _, _, _ := seedAccount(t, store, "owner")
			invite, _, err := store.CreateRegistrationInvite(NewRegistrationInviteOptions{Role: RoleAdmin, TTL: time.Hour})
			if err != nil {
				t.Fatal(err)
			}
			options := ExternalAuthenticationOptions{MaxUsers: 2, LoginName: "owner"}
			authOptions := NewAuthTransactionOptions{RequestedAction: AuthActionInvite, InviteTokenHash: invite.TokenHash}
			switch scenario {
			case "closed":
				authOptions.RequestedAction, authOptions.InviteTokenHash = "", ""
			case "quota":
				options.MaxUsers = 1
			case "revoked":
				if err := store.RevokeRegistrationInvite(invite.ID); err != nil {
					t.Fatal(err)
				}
			case "expired":
				if _, err := store.db.Exec("UPDATE registration_invites SET expires_at = 1 WHERE id = ?", invite.ID); err != nil {
					t.Fatal(err)
				}
			case "audit abort", "audit ignore":
				failure := "RAISE(ABORT, 'test')"
				if scenario == "audit ignore" {
					failure = "RAISE(IGNORE)"
				}
				if _, err := store.db.Exec("CREATE TRIGGER reject_external_audit BEFORE INSERT ON audit_events WHEN NEW.action = 'session.created' BEGIN SELECT " + failure + "; END"); err != nil {
					t.Fatal(err)
				}
			}
			authorization := accountAuthorization(t, store, authOptions)
			completed, err := store.CompleteExternalAuthentication(t.Context(), authorization.ID, IdentityResult{ProviderID: "test-oidc", Subject: "invite-subject", Email: owner.Email}, options)
			if scenario == "success" || scenario == "email collision" {
				if err != nil || completed.User.ID == owner.ID || completed.User.LoginName != "owner-2" || completed.User.Role != RoleAdmin || completed.Session.UserID != completed.User.ID {
					t.Fatalf("invited registration: %+v %v", completed, err)
				}
				used, _ := store.GetRegistrationInvite(invite.ID)
				if used.UsedBy != completed.User.ID || !used.Redeemed() {
					t.Fatal("invite was not redeemed")
				}
				return
			}
			if err == nil || completed.Token != "" || len(store.ListUsers()) != 1 {
				t.Fatal("rejected invitation partially registered account")
			}
			if _, ok := store.GetExternalIdentity("test-oidc", "invite-subject"); ok {
				t.Fatal("rejected invitation linked identity")
			}
			if persisted, ok := store.GetRegistrationInvite(invite.ID); ok && persisted.Redeemed() {
				t.Fatal("failed registration consumed invite")
			}
		})
	}
}

func TestExternalInvitationConcurrentStores(t *testing.T) {
	store, peer := openAccountStores(t)
	seedAccount(t, store, "owner")
	invite, _, err := store.CreateRegistrationInvite(NewRegistrationInviteOptions{Role: RoleMember, TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	var workers sync.WaitGroup
	results := make(chan error, 8)
	for attempt := 0; attempt < 8; attempt++ {
		authorization := accountAuthorization(t, store, NewAuthTransactionOptions{RequestedAction: AuthActionInvite, InviteTokenHash: invite.TokenHash})
		workers.Add(1)
		go func(attempt int, authorization AuthTransaction) {
			defer workers.Done()
			selected := store
			if attempt%2 != 0 {
				selected = peer
			}
			_, err := selected.CompleteExternalAuthentication(context.Background(), authorization.ID, IdentityResult{ProviderID: "test-oidc", Subject: fmt.Sprintf("subject-%d", attempt)}, ExternalAuthenticationOptions{MaxUsers: 2, LoginName: "member"})
			results <- err
		}(attempt, authorization)
	}
	workers.Wait()
	close(results)
	successes := 0
	for err := range results {
		if err == nil {
			successes++
		} else if !errors.Is(err, ErrInviteUsed) {
			t.Fatal(err)
		}
	}
	if successes != 1 || len(store.ListUsers()) != 2 {
		t.Fatal("concurrent callbacks reused a single-use invitation")
	}
}

func TestOIDCValidatedAccountBinding(t *testing.T) {
	provider, issuer, store, _ := newTestOIDC(t)
	user, _, session, _ := seedAccount(t, store, "owner")
	authorization := accountAuthorization(t, store, NewAuthTransactionOptions{ProviderID: provider.ID(), RedirectURI: provider.RedirectURL(), RequestedAction: AuthActionLink, AccountUserID: user.ID, AccountSessionID: session.ID})
	issuer.setChallenge(authorization.PKCEChallenge)
	issuer.setMint(mintOptions{subject: "validated-subject", nonce: authorization.Nonce, email: user.Email})
	if _, err := provider.Begin(t.Context(), &authorization); err != nil {
		t.Fatal(err)
	}
	result, err := provider.Callback(t.Context(), &authorization, &CallbackRequest{Code: issuer.freshCode(), State: authorization.State})
	if err != nil {
		t.Fatal(err)
	}
	completed, err := store.CompleteExternalAuthentication(t.Context(), authorization.ID, *result, ExternalAuthenticationOptions{MaxUsers: 1})
	if err != nil || !completed.Linked || completed.User.ID != user.ID || len(store.ListUsers()) != 1 {
		t.Fatal("verified OIDC binding did not preserve current account")
	}
}

func TestAccountIdentityMigrationPreservesPendingLogin(t *testing.T) {
	store := openTestStore(t)
	user, _, session, token := seedAccount(t, store, "existing")
	authorization := accountAuthorization(t, store, NewAuthTransactionOptions{ReturnTo: "/security"})
	if _, err := store.db.Exec(`ALTER TABLE auth_transactions DROP COLUMN account_user_id;
		ALTER TABLE auth_transactions DROP COLUMN account_session_id;
		ALTER TABLE auth_transactions DROP COLUMN invite_token_hash;
		ALTER TABLE auth_transactions DROP COLUMN authentication_revision;
		DROP TABLE authentication_config;
		ALTER TABLE users DROP COLUMN disabled_at;
		ALTER TABLE users DROP COLUMN disabled_reason;
		UPDATE schema_migrations SET version = 13 WHERE module = 'identity'`); err != nil {
		t.Fatal(err)
	}
	upgraded, err := NewSQLiteStore(t.Context(), store.db)
	if err != nil {
		t.Fatal(err)
	}
	pending, ok := upgraded.GetAuthTransaction(authorization.ID)
	if !ok || pending != authorization {
		t.Fatal("migration changed a pending browser login")
	}
	current, err := upgraded.GetSessionByToken(token)
	if err != nil || current.ID != session.ID || current.UserID != user.ID {
		t.Fatal("migration changed existing session identity")
	}
}

func TestAccountIdentityConcurrentUnlinkKeepsOneMethod(t *testing.T) {
	store, peer := openAccountStores(t)
	user, _, session, _ := seedAccount(t, store, "existing")
	links := []ExternalIdentity{{ProviderID: "first", Subject: "one", UserID: user.ID}, {ProviderID: "second", Subject: "two", UserID: user.ID}}
	for index := range links {
		if err := store.LinkExternalIdentity(&links[index]); err != nil {
			t.Fatal(err)
		}
	}
	results := make(chan error, 2)
	for index, selected := range []*SQLiteStore{store, peer} {
		go func(selected *SQLiteStore, link ExternalIdentity) {
			_, err := selected.UnlinkAccountIdentity(context.Background(), user.ID, session.ID, IdentityReference(link), LoginMethods{Providers: []string{"first", "second"}})
			results <- err
		}(selected, links[index])
	}
	successes := 0
	for attempt := 0; attempt < 2; attempt++ {
		if err := <-results; err == nil {
			successes++
		} else if !errors.Is(err, ErrLastLoginMethod) {
			t.Fatal(err)
		}
	}
	remaining, err := store.ListAccountIdentities(t.Context(), user.ID)
	if err != nil || successes != 1 || len(remaining) != 1 {
		t.Fatal("concurrent unlink removed all login methods")
	}
}
