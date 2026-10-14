package control

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

// newTestShareRegistry opens a registry in a fresh state directory. The
// caller may close it early to exercise persistence; cleanup tolerates that.
func newTestShareRegistry(t *testing.T) *ShareRegistry {
	t.Helper()
	return newTestShareRegistryAt(t, filepath.Join(t.TempDir(), "shares.db"))
}

func newTestShareRegistryAt(t *testing.T, path string) *ShareRegistry {
	t.Helper()

	r, err := OpenShareRegistry(context.Background(), ShareRegistryConfig{Path: path})
	if err != nil {
		t.Fatalf("OpenShareRegistry: %v", err)
	}
	t.Cleanup(func() { r.Close() })
	return r
}

// registryShare builds a valid pending share request.
func registryShare() Share {
	return Share{
		SourceOrg:        "acme",
		SourceNode:       7,
		TargetOrg:        "globex",
		Provider:         "oidc:corp",
		Subject:          "u-1",
		CreatedBy:        3,
		SourceGeneration: "acme-generation", SourceStableID: "acme-node-7", SourceUserCreated: 1,
		TargetGeneration: "globex-generation",
	}
}

// TestShareRegistryLifecycle drives create -> accept -> revoke, checks the
// conditional decisions and the terminal-state errors.
func TestShareRegistryLifecycle(t *testing.T) {
	r := newTestShareRegistry(t)
	ctx := context.Background()
	base := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)

	share, err := r.CreateShare(ctx, registryShare(), base)
	if err != nil {
		t.Fatalf("CreateShare: %v", err)
	}
	if share.ID == "" {
		t.Error("created share has no ID")
	}
	if share.Status != SharePending || !share.Active() {
		t.Errorf("created status = %q, want pending", share.Status)
	}
	if !share.CreatedAt.Equal(base) {
		t.Errorf("created at = %v, want %v", share.CreatedAt, base)
	}

	got, ok := r.GetShare(share.ID)
	if !ok || got.SourceOrg != "acme" || got.SourceNode != 7 || got.Subject != "u-1" {
		t.Fatalf("GetShare = %+v, %v", got, ok)
	}

	// The active uniqueness slot rejects a second non-terminal share of the
	// same machine to the same identity.
	if _, err := r.CreateShare(ctx, registryShare(), base); !errors.Is(err, ErrShareExists) {
		t.Fatalf("duplicate create err = %v, want ErrShareExists", err)
	}

	// Listing filters by source, target identity and status.
	if got := r.ListShares(ShareFilter{SourceOrg: "acme"}); len(got) != 1 {
		t.Errorf("source list = %d shares, want 1", len(got))
	}
	if got := r.ListShares(ShareFilter{TargetOrg: "globex", Provider: "oidc:corp", Subject: "u-1"}); len(got) != 1 {
		t.Errorf("target list = %d shares, want 1", len(got))
	}
	if got := r.ListShares(ShareFilter{TargetOrg: "globex", Provider: "oidc:corp", Subject: "other"}); len(got) != 0 {
		t.Errorf("wrong subject list = %d shares, want 0", len(got))
	}
	if got := r.ListShares(ShareFilter{Statuses: []string{ShareAccepted}}); len(got) != 0 {
		t.Errorf("accepted list = %d shares, want 0", len(got))
	}

	// Only the target organization may decide, and only while pending.
	if _, err := r.AcceptShare(share.ID, "acme", 9, base); !errors.Is(err, ErrShareTarget) {
		t.Errorf("accept from source org err = %v, want ErrShareTarget", err)
	}
	accepted, err := r.AcceptShare(share.ID, "globex", 9, base.Add(time.Minute))
	if err != nil {
		t.Fatalf("AcceptShare: %v", err)
	}
	if accepted.Status != ShareAccepted || accepted.AcceptedBy != 9 || accepted.AcceptedAt.IsZero() {
		t.Errorf("accepted share = %+v", accepted)
	}
	if _, err := r.AcceptShare(share.ID, "globex", 9, base); !errors.Is(err, ErrShareState) {
		t.Errorf("second accept err = %v, want ErrShareState", err)
	}
	if _, err := r.RejectShare(share.ID, "globex", 9, base); !errors.Is(err, ErrShareState) {
		t.Errorf("reject after accept err = %v, want ErrShareState", err)
	}

	// The accepted share still occupies the slot.
	if _, err := r.CreateShare(ctx, registryShare(), base); !errors.Is(err, ErrShareExists) {
		t.Errorf("duplicate accepted create err = %v, want ErrShareExists", err)
	}
	// Target-user filtering only matches the bound user.
	if got := r.ListShares(ShareFilter{TargetOrg: "globex", TargetUser: 9}); len(got) != 1 {
		t.Errorf("accepted-by list = %d shares, want 1", len(got))
	}
	if got := r.ListShares(ShareFilter{TargetOrg: "globex", TargetUser: 10}); len(got) != 0 {
		t.Errorf("other-user list = %d shares, want 0", len(got))
	}

	revoked, err := r.RevokeShare(share.ID, "acme", 3, base.Add(2*time.Minute))
	if err != nil {
		t.Fatalf("RevokeShare: %v", err)
	}
	if revoked.Status != ShareRevoked || revoked.RevokedByOrg != "acme" || revoked.RevokedBy != 3 {
		t.Errorf("revoked share = %+v", revoked)
	}
	// Revoking twice is idempotent and keeps the first timestamp.
	again, err := r.RevokeShare(share.ID, "globex", 9, base.Add(3*time.Minute))
	if err != nil {
		t.Fatalf("second RevokeShare: %v", err)
	}
	if again.RevokedByOrg != "acme" || !again.RevokedAt.Equal(revoked.RevokedAt) {
		t.Errorf("idempotent revoke changed the row: %+v", again)
	}
	// A terminal share frees the uniqueness slot.
	reused, err := r.CreateShare(ctx, registryShare(), base.Add(4*time.Minute))
	if err != nil {
		t.Fatalf("recreate after revoke: %v", err)
	}
	if reused.ID == share.ID || reused.Status != SharePending {
		t.Errorf("recreated share = %+v", reused)
	}
	// Deciding a revoked share fails.
	if _, err := r.AcceptShare(share.ID, "globex", 9, base); !errors.Is(err, ErrShareState) {
		t.Errorf("accept revoked err = %v, want ErrShareState", err)
	}
}

// TestShareRegistryReject checks the reject path and that a rejected share is
// terminal but frees the machine-to-identity slot.
func TestShareRegistryReject(t *testing.T) {
	r := newTestShareRegistry(t)
	ctx := context.Background()
	now := time.Now().UTC()

	share, err := r.CreateShare(ctx, registryShare(), now)
	if err != nil {
		t.Fatalf("CreateShare: %v", err)
	}
	rejected, err := r.RejectShare(share.ID, "globex", 11, now)
	if err != nil {
		t.Fatalf("RejectShare: %v", err)
	}
	if rejected.Status != ShareRejected || rejected.RejectedBy != 11 || rejected.RejectedAt.IsZero() {
		t.Errorf("rejected share = %+v", rejected)
	}
	if _, err := r.RejectShare(share.ID, "globex", 11, now); !errors.Is(err, ErrShareState) {
		t.Errorf("second reject err = %v, want ErrShareState", err)
	}
	if _, err := r.RevokeShare(share.ID, "globex", 11, now); !errors.Is(err, ErrShareState) {
		t.Errorf("revoke rejected err = %v, want ErrShareState", err)
	}

	// The identity can be invited again after the explicit decline.
	if _, err := r.CreateShare(ctx, registryShare(), now.Add(time.Second)); err != nil {
		t.Errorf("recreate after reject: %v", err)
	}
}

// TestShareRegistryValidation checks the registry-level request validation.
func TestShareRegistryValidation(t *testing.T) {
	r := newTestShareRegistry(t)
	ctx := context.Background()
	now := time.Now().UTC()

	for name, mutate := range map[string]func(*Share){
		"no source org": func(s *Share) { s.SourceOrg = "" },
		"no target org": func(s *Share) { s.TargetOrg = "" },
		"no provider":   func(s *Share) { s.Provider = "" },
		"no subject":    func(s *Share) { s.Subject = "" },
		"no node":       func(s *Share) { s.SourceNode = 0 },
		"not pending":   func(s *Share) { s.Status = ShareAccepted },
	} {
		share := registryShare()
		mutate(&share)
		if _, err := r.CreateShare(ctx, share, now); err == nil {
			t.Errorf("%s: CreateShare accepted an invalid share", name)
		}
	}
}

// TestShareRegistryPersistence checks that shares survive a reopen, including
// the decision timestamps and the identity keys.
func TestShareRegistryPersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "shares.db")
	r := newTestShareRegistryAt(t, path)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)

	share, err := r.CreateShare(ctx, registryShare(), now)
	if err != nil {
		t.Fatalf("CreateShare: %v", err)
	}
	if _, err := r.AcceptShare(share.ID, "globex", 9, now.Add(time.Minute)); err != nil {
		t.Fatalf("AcceptShare: %v", err)
	}
	if err := r.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	reopened := newTestShareRegistryAt(t, path)
	got, ok := reopened.GetShare(share.ID)
	if !ok {
		t.Fatalf("share %s missing after reopen", share.ID)
	}
	if got.Status != ShareAccepted || got.AcceptedBy != 9 || !got.AcceptedAt.Equal(now.Add(time.Minute)) {
		t.Errorf("reopened share = %+v", got)
	}
	if again, err := reopened.CreateShare(ctx, registryShare(), now); !errors.Is(err, ErrShareExists) {
		t.Errorf("reopen duplicate err = %v, want ErrShareExists (got %+v)", err, again)
	}
}
