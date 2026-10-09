package identity

import (
	"strings"
	"testing"
	"time"
)

func TestAuthTransactionLifecycle(t *testing.T) {
	s := openTestStore(t)

	tx, browserSecret, err := s.CreateAuthTransaction(NewAuthTransactionOptions{
		ProviderID:  "dex",
		RedirectURI: "https://login.example.com/oidc/callback",
		ReturnTo:    "/register/abc",
		TTL:         time.Hour,
	})
	if err != nil {
		t.Fatalf("CreateAuthTransaction: %v", err)
	}

	if tx.ID == "" || tx.State == "" || tx.Nonce == "" || tx.PKCEVerifier == "" || tx.PKCEChallenge == "" {
		t.Fatalf("transaction is missing generated material: %+v", tx)
	}
	if tx.PKCEMethod != "S256" {
		t.Errorf("PKCE method = %q, want S256", tx.PKCEMethod)
	}
	if tx.BrowserSessionHash == browserSecret || tx.BrowserSessionHash != HashSecret(browserSecret) {
		t.Error("browser secret must be stored hashed, never verbatim")
	}
	if !SecretEqual(tx.BrowserSessionHash, browserSecret) || SecretEqual(tx.BrowserSessionHash, "other") {
		t.Error("browser secret comparison is wrong")
	}

	stored, ok := s.GetAuthTransaction(tx.ID)
	if !ok || stored.State != tx.State || stored.Nonce != tx.Nonce || stored.PKCEVerifier != tx.PKCEVerifier {
		t.Fatalf("GetAuthTransaction = %+v, %v", stored, ok)
	}
	if stored.Consumed() || stored.Expired(time.Now()) {
		t.Fatal("fresh transaction is already consumed or expired")
	}

	consumed, err := s.ConsumeAuthTransaction(tx.ID)
	if err != nil {
		t.Fatalf("ConsumeAuthTransaction: %v", err)
	}
	if !consumed.Consumed() {
		t.Error("consumed transaction has no consumption time")
	}
	if _, err := s.ConsumeAuthTransaction(tx.ID); err != ErrTransactionConsumed {
		t.Errorf("second consume = %v, want ErrTransactionConsumed", err)
	}
	if _, err := s.ConsumeAuthTransaction("unknown"); err != ErrTransactionNotFound {
		t.Errorf("unknown consume = %v, want ErrTransactionNotFound", err)
	}
}

func TestAuthTransactionExpiry(t *testing.T) {
	s := openTestStore(t)

	tx, _, err := s.CreateAuthTransaction(NewAuthTransactionOptions{ProviderID: "dex", TTL: time.Hour})
	if err != nil {
		t.Fatalf("CreateAuthTransaction: %v", err)
	}
	// 直接构造已过期的持久事实，不依赖 CI 磁盘速度或毫秒级调度才能通过。
	if _, err := s.db.Exec("UPDATE auth_transactions SET expires_at = ? WHERE id = ?", time.Now().Add(-time.Hour).UnixNano(), tx.ID); err != nil {
		t.Fatalf("expire transaction fixture: %v", err)
	}

	if _, err := s.ConsumeAuthTransaction(tx.ID); err != ErrTransactionExpired {
		t.Errorf("consume expired = %v, want ErrTransactionExpired", err)
	}

	fresh, _, err := s.CreateAuthTransaction(NewAuthTransactionOptions{ProviderID: "dex", TTL: time.Hour})
	if err != nil {
		t.Fatalf("CreateAuthTransaction: %v", err)
	}
	live, _, err := s.CreateAuthTransaction(NewAuthTransactionOptions{ProviderID: "dex", TTL: 2 * time.Hour})
	if err != nil {
		t.Fatalf("create unexpired transaction: %v", err)
	}
	deleted, err := s.DeleteExpiredAuthTransactions(fresh.ExpiresAt)
	if err != nil {
		t.Fatalf("DeleteExpiredAuthTransactions: %v", err)
	}
	if deleted != 2 {
		t.Errorf("deleted = %d, want 2", deleted)
	}
	if _, ok := s.GetAuthTransaction(fresh.ID); ok {
		t.Error("deleted transaction is still present")
	}
	if _, ok := s.GetAuthTransaction(live.ID); !ok {
		t.Error("unexpired transaction was deleted")
	}
}

func TestSessionLifecycle(t *testing.T) {
	s := openTestStore(t)
	alice := createTestUser(t, s, "alice")

	session, token, err := s.CreateSession(NewSessionOptions{UserID: alice.ID, AuthMethod: "oidc:dex", TTL: time.Hour})
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	if session.ID == "" || token == "" {
		t.Fatal("session or token is empty")
	}

	// The token must be stored hashed, not verbatim.
	var storedHash string
	if err := s.db.QueryRow("SELECT token_hash FROM sessions WHERE id = ?", session.ID).Scan(&storedHash); err != nil {
		t.Fatalf("reading token hash: %v", err)
	}
	if storedHash == token || storedHash != HashSecret(token) {
		t.Error("session token must be stored hashed")
	}

	got, err := s.GetSessionByToken(token)
	if err != nil || got.ID != session.ID || got.UserID != alice.ID {
		t.Fatalf("GetSessionByToken = %+v, %v", got, err)
	}
	if _, err := s.GetSessionByToken("not-a-token"); err != ErrSessionNotFound {
		t.Errorf("unknown token = %v, want ErrSessionNotFound", err)
	}

	if err := s.TouchSession(session.ID, time.Now().Add(time.Minute)); err != nil {
		t.Fatalf("TouchSession: %v", err)
	}
	got, _ = s.GetSessionByToken(token)
	if got.LastSeenAt.Before(got.CreatedAt) {
		t.Errorf("LastSeenAt = %v, before CreatedAt %v", got.LastSeenAt, got.CreatedAt)
	}

	if err := s.RevokeSession(session.ID, "logout"); err != nil {
		t.Fatalf("RevokeSession: %v", err)
	}
	if _, err := s.GetSessionByToken(token); err != ErrSessionNotFound {
		t.Errorf("revoked token = %v, want ErrSessionNotFound", err)
	}
	if err := s.RevokeSession(session.ID, "logout again"); err != nil {
		t.Errorf("revoking twice = %v, want nil", err)
	}

	record, ok := s.GetSessionByID(session.ID)
	if !ok || record.RevokedAt.IsZero() || record.RevokedReason != "logout" {
		t.Fatalf("revoked record = %+v, %v", record, ok)
	}
}

func TestSessionExpiry(t *testing.T) {
	s := openTestStore(t)
	alice := createTestUser(t, s, "alice")

	_, token, err := s.CreateSession(NewSessionOptions{UserID: alice.ID, AuthMethod: "local", TTL: time.Millisecond})
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	time.Sleep(10 * time.Millisecond)

	if _, err := s.GetSessionByToken(token); err != ErrSessionNotFound {
		t.Errorf("expired token = %v, want ErrSessionNotFound", err)
	}
	deleted, err := s.DeleteExpiredSessions(time.Now())
	if err != nil || deleted != 1 {
		t.Errorf("DeleteExpiredSessions = %d, %v; want 1, nil", deleted, err)
	}
}

func TestSessionRotation(t *testing.T) {
	s := openTestStore(t)
	alice := createTestUser(t, s, "alice")

	old, oldToken, err := s.CreateSession(NewSessionOptions{UserID: alice.ID, AuthMethod: "oidc:dex", TTL: time.Hour})
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	fresh, freshToken, err := s.RotateSession(oldToken, time.Hour)
	if err != nil {
		t.Fatalf("RotateSession: %v", err)
	}
	if fresh.ID == old.ID || freshToken == oldToken {
		t.Fatal("rotation did not issue a new session and token")
	}
	if fresh.UserID != alice.ID || fresh.RotatedFrom != old.ID {
		t.Errorf("rotated session = %+v", fresh)
	}

	if _, err := s.GetSessionByToken(oldToken); err != ErrSessionNotFound {
		t.Errorf("old token after rotation = %v, want ErrSessionNotFound", err)
	}
	if _, err := s.GetSessionByToken(freshToken); err != nil {
		t.Errorf("new token after rotation: %v", err)
	}
	if _, _, err := s.RotateSession(oldToken, time.Hour); err != ErrSessionNotFound {
		t.Errorf("rotating a dead token = %v, want ErrSessionNotFound", err)
	}
}

func TestRevokeUserSessionsIsScopedToTheUser(t *testing.T) {
	s := openTestStore(t)
	alice := createTestUser(t, s, "alice")
	bob := createTestUser(t, s, "bob")

	for i := 0; i < 2; i++ {
		if _, _, err := s.CreateSession(NewSessionOptions{UserID: alice.ID, AuthMethod: "local"}); err != nil {
			t.Fatalf("CreateSession(alice): %v", err)
		}
	}
	_, bobToken, err := s.CreateSession(NewSessionOptions{UserID: bob.ID, AuthMethod: "local"})
	if err != nil {
		t.Fatalf("CreateSession(bob): %v", err)
	}

	revoked, err := s.RevokeUserSessions(alice.ID, "parallel logout")
	if err != nil || revoked != 2 {
		t.Fatalf("RevokeUserSessions = %d, %v; want 2, nil", revoked, err)
	}
	for _, session := range s.ListSessions(alice.ID) {
		if session.RevokedAt.IsZero() {
			t.Errorf("alice session %s is still live", session.ID)
		}
	}
	if _, err := s.GetSessionByToken(bobToken); err != nil {
		t.Errorf("bob's session was revoked: %v", err)
	}
}

func TestDeviceAuthorizationLifecycle(t *testing.T) {
	s := openTestStore(t)
	alice := createTestUser(t, s, "alice")
	bob := createTestUser(t, s, "bob")

	da, err := s.CreateDeviceAuthorization(NewDeviceAuthorizationOptions{
		ID:         "authid-1",
		MachineKey: "mkey:abc",
		NodeKey:    "nkey:def",
		TTL:        time.Hour,
	})
	if err != nil {
		t.Fatalf("CreateDeviceAuthorization: %v", err)
	}
	if da.ID != "authid-1" || !da.Pending() || da.UserID != 0 {
		t.Fatalf("device authorization = %+v", da)
	}

	approved, err := s.ApproveDeviceAuthorization(da.ID, alice.ID)
	if err != nil {
		t.Fatalf("ApproveDeviceAuthorization: %v", err)
	}
	if approved.State != DeviceApproved || approved.UserID != alice.ID || approved.ApprovedAt.IsZero() {
		t.Fatalf("approved = %+v", approved)
	}
	if approved.MachineKey != "mkey:abc" || approved.NodeKey != "nkey:def" {
		t.Error("approval must keep the exact machine and node keys")
	}

	// A retried approval by the same user is idempotent; a different user is
	// a replayed decision and must fail.
	if again, err := s.ApproveDeviceAuthorization(da.ID, alice.ID); err != nil || again.State != DeviceApproved {
		t.Errorf("idempotent approve = %+v, %v", again, err)
	}
	if _, err := s.ApproveDeviceAuthorization(da.ID, bob.ID); err != ErrDeviceDecided {
		t.Errorf("approval replay by another user = %v, want ErrDeviceDecided", err)
	}
	if _, err := s.DenyDeviceAuthorization(da.ID, alice.ID); err != ErrDeviceDecided {
		t.Errorf("denying an approved device = %v, want ErrDeviceDecided", err)
	}

	if _, err := s.ApproveDeviceAuthorization("unknown", alice.ID); err != ErrDeviceNotFound {
		t.Errorf("unknown device = %v, want ErrDeviceNotFound", err)
	}
}

func TestDeviceAuthorizationExpiryAndDenial(t *testing.T) {
	s := openTestStore(t)
	alice := createTestUser(t, s, "alice")

	da, err := s.CreateDeviceAuthorization(NewDeviceAuthorizationOptions{
		MachineKey: "mkey:1", NodeKey: "nkey:1", TTL: time.Millisecond,
	})
	if err != nil {
		t.Fatalf("CreateDeviceAuthorization: %v", err)
	}
	time.Sleep(10 * time.Millisecond)
	if _, err := s.ApproveDeviceAuthorization(da.ID, alice.ID); err != ErrDeviceExpired {
		t.Errorf("approving expired = %v, want ErrDeviceExpired", err)
	}
	if deleted, err := s.DeleteExpiredDeviceAuthorizations(time.Now()); err != nil || deleted != 1 {
		t.Errorf("DeleteExpiredDeviceAuthorizations = %d, %v; want 1, nil", deleted, err)
	}

	denied, err := s.CreateDeviceAuthorization(NewDeviceAuthorizationOptions{MachineKey: "mkey:2", NodeKey: "nkey:2"})
	if err != nil {
		t.Fatalf("CreateDeviceAuthorization: %v", err)
	}
	if got, err := s.DenyDeviceAuthorization(denied.ID, alice.ID); err != nil || got.State != DeviceDenied || got.DeniedAt.IsZero() {
		t.Fatalf("denied = %+v, %v", got, err)
	}
	if _, err := s.DenyDeviceAuthorization(denied.ID, alice.ID); err != nil {
		t.Errorf("idempotent deny: %v", err)
	}
	if _, err := s.ApproveDeviceAuthorization(denied.ID, alice.ID); err != ErrDeviceDecided {
		t.Errorf("approving a denied device = %v, want ErrDeviceDecided", err)
	}
}

// createTestUser creates a user with the given login name.
func createTestUser(t *testing.T, s *SQLiteStore, login string) User {
	t.Helper()

	u := User{LoginName: login, DisplayName: login}
	if err := s.CreateUser(&u); err != nil {
		t.Fatalf("CreateUser(%s): %v", login, err)
	}
	return u
}

// TestDefaultTTLs makes the security-relevant defaults explicit.
func TestDefaultTTLs(t *testing.T) {
	if DefaultAuthTransactionTTL > 15*time.Minute {
		t.Errorf("auth transaction TTL %v is too long", DefaultAuthTransactionTTL)
	}
	if DefaultSessionTTL > 7*24*time.Hour {
		t.Errorf("session TTL %v is too long", DefaultSessionTTL)
	}
	if DefaultDeviceAuthorizationTTL > 30*time.Minute {
		t.Errorf("device authorization TTL %v is too long", DefaultDeviceAuthorizationTTL)
	}
}

func TestDeleteUserRemovesLinks(t *testing.T) {
	s := openTestStore(t)
	alice := createTestUser(t, s, "alice")
	bob := createTestUser(t, s, "bob")

	for _, link := range []ExternalIdentity{
		{ProviderID: "dex", Subject: "sub-a", UserID: alice.ID},
		{ProviderID: "dex", Subject: "sub-b", UserID: bob.ID},
	} {
		link := link
		if err := s.LinkExternalIdentity(&link); err != nil {
			t.Fatalf("LinkExternalIdentity: %v", err)
		}
	}

	if err := s.DeleteUser(alice.ID); err != nil {
		t.Fatalf("DeleteUser: %v", err)
	}
	if _, ok := s.GetUser(alice.ID); ok {
		t.Error("deleted user is still present")
	}
	if _, ok := s.GetExternalIdentity("dex", "sub-a"); ok {
		t.Error("deleted user's external identity is still present")
	}
	if _, ok := s.GetExternalIdentity("dex", "sub-b"); !ok {
		t.Error("another user's external identity was deleted")
	}
	if err := s.DeleteUser(alice.ID); err != ErrUserNotFound {
		t.Errorf("deleting twice = %v, want ErrUserNotFound", err)
	}
}

func TestGetDeviceAuthorizationByNodeKey(t *testing.T) {
	s := openTestStore(t)

	da, err := s.CreateDeviceAuthorization(NewDeviceAuthorizationOptions{
		MachineKey: "mkey:abc", NodeKey: "nkey:def",
	})
	if err != nil {
		t.Fatalf("CreateDeviceAuthorization: %v", err)
	}

	got, ok := s.GetDeviceAuthorizationByNodeKey("nkey:def")
	if !ok || got.ID != da.ID {
		t.Fatalf("GetDeviceAuthorizationByNodeKey = %+v, %v", got, ok)
	}
	if _, ok := s.GetDeviceAuthorizationByNodeKey("nkey:unknown"); ok {
		t.Error("unknown node key returned an authorization")
	}
}

func TestAPIKeyLifecycle(t *testing.T) {
	s := openTestStore(t)
	alice := createTestUser(t, s, "alice")

	key, token, err := s.CreateAPIKey(NewAPIKeyOptions{
		Name: "ci", UserID: alice.ID, Scopes: []string{ScopeRead, ScopeWrite}, TTL: time.Hour,
	})
	if err != nil {
		t.Fatalf("CreateAPIKey: %v", err)
	}
	if key.ID == "" || key.Name != "ci" || key.UserID != alice.ID {
		t.Fatalf("key = %+v", key)
	}
	if !strings.HasPrefix(token, APIKeyPrefix) {
		t.Errorf("token %q does not carry the %q prefix", token, APIKeyPrefix)
	}
	if !key.HasScope(ScopeWrite) || key.HasScope("admin") {
		t.Errorf("scopes = %v", key.Scopes)
	}

	// The token must be stored hashed, never verbatim.
	var storedHash string
	if err := s.db.QueryRow("SELECT token_hash FROM api_keys WHERE id = ?", key.ID).Scan(&storedHash); err != nil {
		t.Fatalf("reading token hash: %v", err)
	}
	if storedHash == token || storedHash != HashSecret(token) {
		t.Error("API key token must be stored hashed")
	}

	got, err := s.GetAPIKeyByToken(token)
	if err != nil || got.ID != key.ID {
		t.Fatalf("GetAPIKeyByToken = %+v, %v", got, err)
	}
	if _, err := s.GetAPIKeyByToken("xunara_nope"); err != ErrAPIKeyNotFound {
		t.Errorf("unknown token = %v, want ErrAPIKeyNotFound", err)
	}

	if err := s.TouchAPIKey(key.ID, time.Now()); err != nil {
		t.Fatalf("TouchAPIKey: %v", err)
	}
	got, _ = s.GetAPIKeyByToken(token)
	if got.LastUsedAt.IsZero() {
		t.Error("LastUsedAt was not recorded")
	}

	if err := s.RevokeAPIKey(key.ID); err != nil {
		t.Fatalf("RevokeAPIKey: %v", err)
	}
	if _, err := s.GetAPIKeyByToken(token); err != ErrAPIKeyNotFound {
		t.Errorf("revoked token = %v, want ErrAPIKeyNotFound", err)
	}
	if err := s.RevokeAPIKey("key-999"); err != nil {
		t.Errorf("revoking an unknown key = %v, want nil (no-op)", err)
	}

	keys := s.ListAPIKeys()
	if len(keys) != 1 {
		t.Fatalf("ListAPIKeys = %+v", keys)
	}
	if keys[0].RevokedAt.IsZero() {
		t.Error("revoked key is missing its revocation time")
	}
}

func TestAPIKeyValidationAndExpiry(t *testing.T) {
	s := openTestStore(t)
	alice := createTestUser(t, s, "alice")

	bad := []NewAPIKeyOptions{
		{UserID: alice.ID, Scopes: []string{ScopeRead}},
		{Name: "x", Scopes: []string{ScopeRead}},
		{Name: "x", UserID: alice.ID},
		{Name: "x", UserID: alice.ID, Scopes: []string{"admin"}},
	}
	for _, opts := range bad {
		if _, _, err := s.CreateAPIKey(opts); err == nil {
			t.Errorf("CreateAPIKey(%+v) succeeded", opts)
		}
	}

	_, token, err := s.CreateAPIKey(NewAPIKeyOptions{
		Name: "short", UserID: alice.ID, Scopes: []string{ScopeRead}, TTL: time.Millisecond,
	})
	if err != nil {
		t.Fatalf("CreateAPIKey: %v", err)
	}
	time.Sleep(10 * time.Millisecond)
	if _, err := s.GetAPIKeyByToken(token); err != ErrAPIKeyNotFound {
		t.Errorf("expired token = %v, want ErrAPIKeyNotFound", err)
	}
}
