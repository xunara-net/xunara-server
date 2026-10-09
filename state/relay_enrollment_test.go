package state

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
)

func seedRelayEnrollment(test *testing.T, store RelayStore, identifier string) string {
	test.Helper()
	secret := mustNewEnrollmentSecret(test)
	if err := store.CreateRelayEnrollmentToken(RelayEnrollmentToken{ID: identifier}, secret); err != nil {
		test.Fatalf("CreateRelayEnrollmentToken: %v", err)
	}
	return secret
}

func TestRelayEnrollmentQuotaRollback(test *testing.T) {
	for name, store := range relayTestStores(test) {
		test.Run(name, func(subtest *testing.T) {
			secret := seedRelayEnrollment(subtest, store, "enrollment")
			relay := Relay{ID: "relay", NodeKey: "nodekey:quota"}
			credential := mustNewRelayToken(subtest)
			for _, quota := range []int{0, -2} {
				if _, err := store.EnrollRelay(context.Background(), secret, relay, credential, quota); err == nil {
					subtest.Fatalf("quota %d accepted enrollment", quota)
				}
				assertRelayEnrollmentUnused(subtest, store, "enrollment")
				if len(store.ListRelays()) != 0 {
					subtest.Fatal("rejected enrollment left a relay")
				}
			}
			if _, err := store.EnrollRelay(context.Background(), secret, relay, credential, 1); err != nil {
				subtest.Fatalf("retry with available quota: %v", err)
			}
			if actual, exists := store.RelayByToken(credential); !exists || actual.ID != relay.ID {
				subtest.Fatal("committed relay credential does not resolve")
			}
		})
	}
}

func assertRelayEnrollmentUnused(test *testing.T, store RelayStore, identifier string) {
	test.Helper()
	record, exists := store.RelayEnrollmentTokenByID(identifier)
	if !exists || record.Used() {
		test.Fatal("failed enrollment consumed the token")
	}
}

func TestRelayEnrollmentDuplicateRollsBack(test *testing.T) {
	for name, store := range relayTestStores(test) {
		test.Run(name, func(subtest *testing.T) {
			first := seedRelayEnrollment(subtest, store, "first")
			credential := mustNewRelayToken(subtest)
			if _, err := store.EnrollRelay(context.Background(), first, Relay{ID: "first", NodeKey: "nodekey:shared"}, credential, -1); err != nil {
				subtest.Fatalf("first enrollment: %v", err)
			}
			second := seedRelayEnrollment(subtest, store, "second")
			if _, err := store.EnrollRelay(context.Background(), second, Relay{ID: "second", NodeKey: "nodekey:shared"}, mustNewRelayToken(subtest), -1); !errors.Is(err, ErrRelayAlreadyEnrolled) {
				subtest.Fatalf("duplicate node key: %v", err)
			}
			assertRelayEnrollmentUnused(subtest, store, "second")
			if _, err := store.EnrollRelay(context.Background(), second, Relay{ID: "second", NodeKey: "nodekey:other"}, credential, -1); !errors.Is(err, ErrRelayTokenExists) {
				subtest.Fatalf("duplicate credential: %v", err)
			}
			assertRelayEnrollmentUnused(subtest, store, "second")
			if _, err := store.EnrollRelay(context.Background(), second, Relay{ID: "second", NodeKey: "nodekey:other"}, mustNewRelayToken(subtest), -1); err != nil {
				subtest.Fatalf("retry corrected identity: %v", err)
			}
		})
	}
}

func TestRelayEnrollmentCancellation(test *testing.T) {
	for name, store := range relayTestStores(test) {
		test.Run(name, func(subtest *testing.T) {
			secret := seedRelayEnrollment(subtest, store, "cancelled")
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			if _, err := store.LookupRelayEnrollmentToken(ctx, secret); !errors.Is(err, context.Canceled) {
				subtest.Fatalf("cancelled lookup: %v", err)
			}
			if _, err := store.EnrollRelay(ctx, secret, Relay{ID: "cancelled"}, mustNewRelayToken(subtest), 1); !errors.Is(err, context.Canceled) {
				subtest.Fatalf("cancelled enrollment: %v", err)
			}
			assertRelayEnrollmentUnused(subtest, store, "cancelled")
			if len(store.ListRelays()) != 0 {
				subtest.Fatal("cancelled enrollment left a relay")
			}
		})
	}
}

func TestRelayEnrollmentSQLiteWriteRollback(test *testing.T) {
	store, err := OpenSQLite(context.Background(), filepath.Join(test.TempDir(), "state.db"))
	if err != nil {
		test.Fatal(err)
	}
	test.Cleanup(func() { store.Close() })
	secret := seedRelayEnrollment(test, store, "rollback")
	if _, err := store.DB().Exec(`CREATE TRIGGER reject_enrollment BEFORE UPDATE OF used_at ON relay_enrollment_tokens
		BEGIN SELECT RAISE(ABORT, 'injected enrollment failure'); END`); err != nil {
		test.Fatal(err)
	}
	credential := mustNewRelayToken(test)
	if _, err := store.EnrollRelay(context.Background(), secret, Relay{ID: "rollback"}, credential, 1); err == nil {
		test.Fatal("injected storage failure accepted enrollment")
	}
	assertRelayEnrollmentUnused(test, store, "rollback")
	if len(store.ListRelays()) != 0 {
		test.Fatal("token update failure did not roll back the inserted relay")
	}
	if _, err := store.DB().Exec(`DROP TRIGGER reject_enrollment`); err != nil {
		test.Fatal(err)
	}
	if _, err := store.EnrollRelay(context.Background(), secret, Relay{ID: "rollback"}, credential, 1); err != nil {
		test.Fatalf("retry after storage recovery: %v", err)
	}
}

func concurrentRelayEnrollment(test *testing.T, stores []Store, sharedToken bool, quota int) {
	test.Helper()
	const workers = 12
	start := make(chan struct{})
	results := make(chan error, workers)
	secrets := make([]string, workers)
	credentials := make([]string, workers)
	for index := range secrets {
		identifier := fmt.Sprintf("enrollment-%d", index)
		if sharedToken && index > 0 {
			secrets[index] = secrets[0]
		} else {
			secrets[index] = seedRelayEnrollment(test, stores[0], identifier)
		}
		credentials[index] = mustNewRelayToken(test)
	}
	for index := range secrets {
		go func() {
			<-start
			relay := Relay{ID: fmt.Sprintf("relay-%d", index), NodeKey: fmt.Sprintf("nodekey:%d", index)}
			_, err := stores[index%len(stores)].EnrollRelay(context.Background(), secrets[index], relay, credentials[index], quota)
			results <- err
		}()
	}
	close(start)
	succeeded := 0
	for range workers {
		err := <-results
		if err == nil {
			succeeded++
		} else if sharedToken {
			if !errors.Is(err, ErrRelayEnrollmentConsumed) {
				test.Fatalf("concurrent shared-token result: %v", err)
			}
		} else if !errors.Is(err, ErrRelayLimitReached) {
			test.Fatalf("concurrent quota result: %v", err)
		}
	}
	want := quota
	if sharedToken {
		want = 1
	} else if quota == -1 {
		want = workers
	}
	if succeeded != want || len(stores[0].ListRelays()) != want {
		test.Fatalf("enrolled %d, stored %d, want %d", succeeded, len(stores[0].ListRelays()), want)
	}
	used := 0
	for _, record := range stores[0].ListRelayEnrollmentTokens() {
		if record.Used() {
			used++
		}
	}
	if used != succeeded {
		test.Fatalf("consumed %d tokens for %d identities", used, succeeded)
	}
}

func TestRelayEnrollmentConcurrent(test *testing.T) {
	for _, sharedToken := range []bool{false, true} {
		for _, quota := range []int{0, 1, 3, -1} {
			if sharedToken && quota != -1 {
				continue
			}
			for name, store := range relayTestStores(test) {
				test.Run(fmt.Sprintf("%s/shared=%t/quota=%d", name, sharedToken, quota), func(subtest *testing.T) {
					concurrentRelayEnrollment(subtest, []Store{store}, sharedToken, quota)
				})
			}
		}
	}
}

func TestRelayEnrollmentAcrossSQLiteConnections(test *testing.T) {
	for _, sharedToken := range []bool{false, true} {
		test.Run(fmt.Sprintf("shared=%t", sharedToken), func(subtest *testing.T) {
			path := filepath.Join(subtest.TempDir(), "state.db")
			stores := make([]Store, 2)
			for index := range stores {
				store, err := OpenSQLite(context.Background(), path)
				if err != nil {
					subtest.Fatal(err)
				}
				subtest.Cleanup(func() { store.Close() })
				stores[index] = store
			}
			concurrentRelayEnrollment(subtest, stores, sharedToken, 1)
		})
	}
}

func TestRelayEnrollmentLookupStorageFailure(test *testing.T) {
	store, err := OpenSQLite(context.Background(), filepath.Join(test.TempDir(), "state.db"))
	if err != nil {
		test.Fatal(err)
	}
	secret := seedRelayEnrollment(test, store, "lookup")
	if _, err := store.LookupRelayEnrollmentToken(context.Background(), mustNewEnrollmentSecret(test)); !errors.Is(err, ErrRelayNotFound) {
		test.Fatalf("unknown credential: %v", err)
	}
	if err := store.Close(); err != nil {
		test.Fatal(err)
	}
	if _, err := store.LookupRelayEnrollmentToken(context.Background(), secret); err == nil || errors.Is(err, ErrRelayNotFound) {
		test.Fatalf("closed storage was misclassified: %v", err)
	}
}
