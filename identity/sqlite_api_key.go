package identity

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"tailscale.com/tailcfg"
)

const apiKeyColumns = "id, token_hash, name, user_id, scopes, created_at, expires_at, last_used_at, revoked_at"

// validScopes are the scopes an API key may carry.
var validScopes = []string{ScopeRead, ScopeWrite}

// CreateAPIKey implements [APIKeyStore].
func (s *SQLiteStore) CreateAPIKey(opts NewAPIKeyOptions) (APIKey, string, error) {
	if strings.TrimSpace(opts.Name) == "" {
		return APIKey{}, "", fmt.Errorf("identity: API key needs a name")
	}
	if opts.UserID == 0 {
		return APIKey{}, "", fmt.Errorf("identity: API key needs an owner")
	}
	if len(opts.Scopes) == 0 {
		return APIKey{}, "", fmt.Errorf("identity: API key needs at least one scope")
	}
	for _, scope := range opts.Scopes {
		if !slices.Contains(validScopes, scope) {
			return APIKey{}, "", fmt.Errorf("identity: unknown API key scope %q", scope)
		}
	}

	token, err := newSecret()
	if err != nil {
		return APIKey{}, "", err
	}
	token = APIKeyPrefix + token

	id, err := newID("key-")
	if err != nil {
		return APIKey{}, "", err
	}

	now := time.Now().UTC()
	key := APIKey{
		ID:        id,
		Name:      strings.TrimSpace(opts.Name),
		UserID:    opts.UserID,
		Scopes:    slices.Clone(opts.Scopes),
		CreatedAt: now,
	}
	if opts.TTL > 0 {
		key.ExpiresAt = now.Add(opts.TTL)
	}

	var expiresAt any
	if !key.ExpiresAt.IsZero() {
		expiresAt = key.ExpiresAt.UnixNano()
	}

	if _, err := s.db.ExecContext(context.Background(),
		"INSERT INTO api_keys (id, token_hash, name, user_id, scopes, created_at, expires_at, last_used_at, revoked_at)"+
			" VALUES (?, ?, ?, ?, ?, ?, ?, NULL, NULL)",
		key.ID, HashSecret(token), key.Name, int64(key.UserID), strings.Join(key.Scopes, ","),
		key.CreatedAt.UnixNano(), expiresAt); err != nil {
		return APIKey{}, "", fmt.Errorf("identity: creating API key: %w", err)
	}
	return key, token, nil
}

// GetAPIKeyByToken implements [APIKeyStore].
func (s *SQLiteStore) GetAPIKeyByToken(token string) (APIKey, error) {
	now := time.Now().UTC()
	row := s.db.QueryRowContext(context.Background(),
		"SELECT "+apiKeyColumns+" FROM api_keys WHERE token_hash = ? AND revoked_at IS NULL"+
			" AND (expires_at IS NULL OR expires_at > ?)",
		HashSecret(token), now.UnixNano())

	key, err := scanAPIKey(row)
	if errors.Is(err, sql.ErrNoRows) {
		return APIKey{}, ErrAPIKeyNotFound
	}
	if err != nil {
		return APIKey{}, fmt.Errorf("identity: looking up API key: %w", err)
	}
	return key, nil
}

// GetAPIKeyByID implements [APIKeyStore].
func (s *SQLiteStore) GetAPIKeyByID(id string) (APIKey, bool) {
	row := s.db.QueryRowContext(context.Background(),
		"SELECT "+apiKeyColumns+" FROM api_keys WHERE id = ?", id)
	key, err := scanAPIKey(row)
	if err != nil {
		return APIKey{}, false
	}
	return key, true
}

// ListAPIKeys implements [APIKeyStore].
func (s *SQLiteStore) ListAPIKeys() []APIKey {
	rows, err := s.db.QueryContext(context.Background(),
		"SELECT "+apiKeyColumns+" FROM api_keys ORDER BY created_at DESC")
	if err != nil {
		return nil
	}
	defer rows.Close()

	var out []APIKey
	for rows.Next() {
		key, err := scanAPIKey(rows)
		if err != nil {
			return nil
		}
		out = append(out, key)
	}
	return out
}

// TouchAPIKey implements [APIKeyStore].
func (s *SQLiteStore) TouchAPIKey(id string, now time.Time) error {
	_, err := s.db.ExecContext(context.Background(),
		"UPDATE api_keys SET last_used_at = ? WHERE id = ?", now.UnixNano(), id)
	if err != nil {
		return fmt.Errorf("identity: touching API key: %w", err)
	}
	return nil
}

// RevokeAPIKey implements [APIKeyStore].
func (s *SQLiteStore) RevokeAPIKey(id string) error {
	_, err := s.db.ExecContext(context.Background(),
		"UPDATE api_keys SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL",
		time.Now().UTC().UnixNano(), id)
	if err != nil {
		return fmt.Errorf("identity: revoking API key: %w", err)
	}
	return nil
}

func scanAPIKey(sc rowScanner) (APIKey, error) {
	var (
		key        APIKey
		tokenHash  string
		name       string
		userID     int64
		scopes     string
		createdAt  int64
		expiresAt  sql.NullInt64
		lastUsedAt sql.NullInt64
		revokedAt  sql.NullInt64
	)
	if err := sc.Scan(&key.ID, &tokenHash, &name, &userID, &scopes, &createdAt, &expiresAt, &lastUsedAt, &revokedAt); err != nil {
		return APIKey{}, err
	}
	key.Name = name
	key.UserID = tailcfg.UserID(userID)
	if scopes != "" {
		key.Scopes = strings.Split(scopes, ",")
	}
	key.CreatedAt = time.Unix(0, createdAt).UTC()
	if expiresAt.Valid {
		key.ExpiresAt = time.Unix(0, expiresAt.Int64).UTC()
	}
	if lastUsedAt.Valid {
		key.LastUsedAt = time.Unix(0, lastUsedAt.Int64).UTC()
	}
	if revokedAt.Valid {
		key.RevokedAt = time.Unix(0, revokedAt.Int64).UTC()
	}
	return key, nil
}
