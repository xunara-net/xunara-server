package state

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// runRateLimitConformance exercises the [RateLimitStore] contract. Both
// implementations must pass it.
func runRateLimitConformance(t *testing.T, newStore storeFactory) {
	t.Run("limit denies and the window resets", func(t *testing.T) {
		s := newStore(t)
		start := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)

		for i := 0; i < 3; i++ {
			allowed, retryAfter, err := s.AllowRate("id-token:1:sts", 3, time.Minute, start)
			if err != nil || !allowed || retryAfter != 0 {
				t.Fatalf("request %d = %v/%v/%v, want allowed", i+1, allowed, retryAfter, err)
			}
		}
		allowed, retryAfter, err := s.AllowRate("id-token:1:sts", 3, time.Minute, start)
		if err != nil || allowed {
			t.Fatalf("request 4 = %v/%v/%v, want denied", allowed, retryAfter, err)
		}
		if retryAfter != time.Minute {
			t.Errorf("retryAfter = %v, want %v", retryAfter, time.Minute)
		}

		// Mid-window the denial stands, with the remaining time.
		allowed, retryAfter, err = s.AllowRate("id-token:1:sts", 3, time.Minute, start.Add(40*time.Second))
		if err != nil || allowed || retryAfter != 20*time.Second {
			t.Fatalf("mid-window = %v/%v/%v, want denied with 20s left", allowed, retryAfter, err)
		}

		// The next window starts at its first request.
		allowed, _, err = s.AllowRate("id-token:1:sts", 3, time.Minute, start.Add(time.Minute))
		if err != nil || !allowed {
			t.Fatalf("next window = %v/%v, want allowed", allowed, err)
		}
	})

	t.Run("scopes are independent", func(t *testing.T) {
		s := newStore(t)
		now := time.Now().UTC()

		if allowed, _, err := s.AllowRate("a", 1, time.Minute, now); err != nil || !allowed {
			t.Fatalf("a = %v/%v", allowed, err)
		}
		if allowed, _, err := s.AllowRate("a", 1, time.Minute, now); err != nil || allowed {
			t.Fatalf("a second = %v/%v", allowed, err)
		}
		if allowed, _, err := s.AllowRate("b", 1, time.Minute, now); err != nil || !allowed {
			t.Fatalf("b = %v/%v, want an independent bucket", allowed, err)
		}
	})

	t.Run("invalid arguments are refused", func(t *testing.T) {
		s := newStore(t)
		for _, tc := range []struct {
			name   string
			scope  string
			limit  int
			window time.Duration
		}{
			{"empty scope", "", 1, time.Minute},
			{"zero limit", "a", 0, time.Minute},
			{"negative limit", "a", -1, time.Minute},
			{"zero window", "a", 1, 0},
		} {
			if _, _, err := s.AllowRate(tc.scope, tc.limit, tc.window, time.Now()); err == nil {
				t.Errorf("%s was accepted", tc.name)
			}
		}
	})

	t.Run("prune removes only stale buckets", func(t *testing.T) {
		s := newStore(t)
		start := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
		if _, _, err := s.AllowRate("old", 5, time.Minute, start); err != nil {
			t.Fatalf("AllowRate: %v", err)
		}
		if _, _, err := s.AllowRate("fresh", 5, time.Minute, start.Add(time.Hour)); err != nil {
			t.Fatalf("AllowRate: %v", err)
		}

		removed, err := s.PruneRateLimits(start.Add(30 * time.Minute))
		if err != nil || removed != 1 {
			t.Fatalf("prune = %d/%v, want one bucket", removed, err)
		}
		// The pruned bucket starts from scratch; the fresh one is untouched.
		if allowed, _, err := s.AllowRate("old", 1, time.Minute, start.Add(time.Hour)); err != nil || !allowed {
			t.Fatalf("old after prune = %v/%v, want allowed", allowed, err)
		}
		if allowed, _, err := s.AllowRate("fresh", 1, time.Minute, start.Add(time.Hour)); err != nil || allowed {
			t.Fatalf("fresh after prune = %v/%v, want its counter kept", allowed, err)
		}
	})

	t.Run("concurrent consumption never exceeds the limit", func(t *testing.T) {
		s := newStore(t)
		now := time.Now().UTC()

		var allowedCount atomic.Int64
		var wg sync.WaitGroup
		for range 32 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				allowed, _, err := s.AllowRate("race", 5, time.Minute, now)
				if err != nil {
					t.Errorf("AllowRate: %v", err)
					return
				}
				if allowed {
					allowedCount.Add(1)
				}
			}()
		}
		wg.Wait()

		if got := allowedCount.Load(); got != 5 {
			t.Errorf("%d requests were allowed, want exactly 5", got)
		}
	})
}

func TestMemoryRateLimitConformance(t *testing.T) {
	runRateLimitConformance(t, func(t *testing.T) Store { return NewMemoryStore() })
}

func TestSQLiteRateLimitConformance(t *testing.T) {
	runRateLimitConformance(t, func(t *testing.T) Store {
		return openTestSQLite(t, t.TempDir()+"/state.db")
	})
}

func TestSQLiteRateLimitIgnoredWritesFailClosed(test *testing.T) {
	for _, operation := range []string{"INSERT", "UPDATE"} {
		test.Run(operation, func(test *testing.T) {
			store := openTestSQLite(test, test.TempDir()+"/rate.db")
			now := time.Now()
			if operation == "UPDATE" {
				if allowed, _, err := store.AllowRate("export-test", 5, time.Minute, now); err != nil || !allowed {
					test.Fatal("could not initialize the isolated bucket")
				}
			}
			if _, err := store.db.Exec("CREATE TRIGGER ignore_rate BEFORE " + operation + " ON rate_limits BEGIN SELECT RAISE(IGNORE); END"); err != nil {
				test.Fatal(err)
			}
			if allowed, _, err := store.AllowRate("export-test", 5, time.Minute, now); err == nil || allowed {
				test.Fatal("ignored quota consumption was admitted")
			}
			var count int
			if err := store.db.QueryRow("SELECT COALESCE(SUM(count),0) FROM rate_limits WHERE scope = 'export-test'").Scan(&count); err != nil {
				test.Fatal(err)
			}
			if operation == "INSERT" && count != 0 || operation == "UPDATE" && count != 1 {
				test.Fatal("failed admission changed the persisted bucket")
			}
			if _, err := store.db.Exec("DROP TRIGGER ignore_rate"); err != nil {
				test.Fatal(err)
			}
			if allowed, _, err := store.AllowRate("export-test", 5, time.Minute, now); err != nil || !allowed {
				test.Fatal("rate admission did not recover")
			}
		})
	}
}
