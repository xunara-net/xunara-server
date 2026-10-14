package control

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestShareRegistryAccountTargetAndEventsAtomic(t *testing.T) {
	registry := newTestShareRegistry(t)
	share := registryShare()
	share.TargetKind, share.Provider, share.Subject = ShareTargetAccount, "", ""
	share.TargetAccount, share.TargetAccountCreated = 5, 1
	created, err := registry.CreateShare(t.Context(), share, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := registry.AcceptShare(created.ID, "globex", 6, time.Now()); !errors.Is(err, ErrShareTarget) {
		t.Fatal("registry accepts wrong account")
	}
	if _, err := registry.db.Exec("CREATE TRIGGER reject_share_event BEFORE INSERT ON share_events BEGIN SELECT RAISE(ABORT, 'injected failure'); END"); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.AcceptShare(created.ID, "globex", 5, time.Now()); err == nil {
		t.Fatal("missing mandatory acceptance event treated as success")
	}
	pending, err := registry.LookupShare(t.Context(), created.ID)
	if err != nil || pending.Status != SharePending {
		t.Fatal("audit failure left an accepted relation")
	}
	share.TargetAccount = 6
	if _, err := registry.CreateShare(t.Context(), share, time.Now()); err == nil {
		t.Fatal("missing mandatory creation event treated as success")
	}
	if records, err := registry.QueryShares(t.Context(), ShareFilter{}); err != nil || len(records) != 1 {
		t.Fatal("audit failure left a new invitation")
	}
	if _, err := registry.db.Exec("DROP TRIGGER reject_share_event"); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.CreateShare(t.Context(), share, time.Now()); err != nil {
		t.Fatal("different account in same tenant collides in external index")
	}
	if _, err := registry.AcceptShare(created.ID, "globex", 5, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.RevokeShare(created.ID, "acme", 3, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.RevokeShare(created.ID, "globex", 5, time.Now()); err != nil {
		t.Fatal(err)
	}
	var events int
	if err := registry.db.QueryRow("SELECT count(*) FROM share_events WHERE share_id = ?", created.ID).Scan(&events); err != nil || events != 3 {
		t.Fatalf("idempotent lifecycle events = %d, %v", events, err)
	}
}

func TestShareRegistryConcurrentDecisionsAcrossInstances(t *testing.T) {
	path := filepath.Join(t.TempDir(), "shares.db")
	first, second := newTestShareRegistryAt(t, path), newTestShareRegistryAt(t, path)
	share, err := first.CreateShare(t.Context(), registryShare(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	var group sync.WaitGroup
	results := make(chan error, 2)
	group.Add(2)
	go func() {
		defer group.Done()
		_, err := first.AcceptShare(share.ID, "globex", 9, time.Now())
		results <- err
	}()
	go func() {
		defer group.Done()
		_, err := second.RejectShare(share.ID, "globex", 9, time.Now())
		results <- err
	}()
	group.Wait()
	close(results)
	var successes, conflicts int
	for err := range results {
		if err == nil {
			successes++
		} else if errors.Is(err, ErrShareState) {
			conflicts++
		} else {
			t.Fatal(err)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("decisions = %d successes, %d conflicts", successes, conflicts)
	}
}

func TestShareV1MigrationFailsClosedAndRollsBackDDL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "shares.db")
	database, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if _, err := database.Exec(shareMigrations[0] + `PRAGMA user_version = 1;
INSERT INTO shares(id,source_org,source_node,target_org,provider,subject,status,created_by,created_at) VALUES ('legacy','acme',1,'globex','oidc:corp','subject','accepted',1,1);`); err != nil {
		t.Fatal(err)
	}
	broken := []string{shareMigrations[0], shareMigrations[1] + " invalid injected migration;"}
	if err := migrateRegistry(t.Context(), database, broken, "share"); err == nil {
		t.Fatal("broken migration succeeded")
	}
	var version int
	var status string
	if err := database.QueryRow("PRAGMA user_version").Scan(&version); err != nil || version != 1 {
		t.Fatal("failed migration advanced schema version")
	}
	if err := database.QueryRow("SELECT status FROM shares WHERE id = 'legacy'").Scan(&status); err != nil || status != ShareAccepted {
		t.Fatal("failed migration changed live relation")
	}
	if _, err := database.Exec("SELECT target_kind FROM shares"); err == nil {
		t.Fatal("failed migration retained partial DDL")
	}
	registry, err := OpenShareRegistry(context.Background(), ShareRegistryConfig{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	defer registry.Close()
	legacy, err := registry.LookupShare(t.Context(), "legacy")
	if err != nil || legacy.Status != ShareRevoked || legacy.RevokedAt.IsZero() {
		t.Fatal("unbound v1 relation silently kept access")
	}
}
