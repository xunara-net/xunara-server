package identity

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestAuthenticationLookupsDistinguishStorageFailure(t *testing.T) {
	store := openTestStore(t)
	user := User{LoginName: "lookup-user", Role: RoleMember}
	if err := store.CreateUser(&user); err != nil {
		t.Fatal(err)
	}
	_, sessionToken, err := store.CreateSession(NewSessionOptions{UserID: user.ID, TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	_, apiToken, err := store.CreateAPIKey(NewAPIKeyOptions{Name: "lookup-key", UserID: user.ID, Scopes: []string{ScopeRead}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.LookupUser(context.Background(), user.ID); err != nil {
		t.Fatal("known user could not be read")
	}
	if _, err := store.GetSessionByToken(sessionToken); err != nil {
		t.Fatal("known session could not be read")
	}
	if _, err := store.GetAPIKeyByToken(apiToken); err != nil {
		t.Fatal("known API key could not be read")
	}
	if _, err := store.LookupUser(context.Background(), user.ID+1); !errors.Is(err, ErrUserNotFound) {
		t.Fatal("unknown user did not return not found")
	}
	if _, err := store.GetSessionByToken("unknown"); !errors.Is(err, ErrSessionNotFound) {
		t.Fatal("unknown session did not return not found")
	}
	if _, err := store.GetAPIKeyByToken("unknown"); !errors.Is(err, ErrAPIKeyNotFound) {
		t.Fatal("unknown API key did not return not found")
	}
	if err := store.db.Close(); err != nil {
		t.Fatal(err)
	}
	for _, lookup := range []struct {
		name string
		read func() error
	}{
		{"user", func() error { _, err := store.LookupUser(context.Background(), user.ID); return err }},
		{"session", func() error { _, err := store.GetSessionByToken(sessionToken); return err }},
		{"API key", func() error { _, err := store.GetAPIKeyByToken(apiToken); return err }},
	} {
		t.Run(lookup.name, func(t *testing.T) {
			err := lookup.read()
			if err == nil || errors.Is(err, ErrUserNotFound) || errors.Is(err, ErrSessionNotFound) || errors.Is(err, ErrAPIKeyNotFound) {
				t.Fatal("database failure was disguised as a missing identity")
			}
		})
	}
}

func TestLookupUserPreservesCancellation(t *testing.T) {
	store := openTestStore(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := store.LookupUser(ctx, 1); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled lookup did not preserve the context error")
	}
}
