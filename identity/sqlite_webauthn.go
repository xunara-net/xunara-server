package identity

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"tailscale.com/tailcfg"
)

const passkeyColumns = "id, user_id, name, credential_id, credential, created_at, last_used_at"

// CreatePasskey implements [PasskeyStore].
func (s *SQLiteStore) CreatePasskey(p *Passkey) error {
	return insertPasskey(context.Background(), s.db, p)
}

// insertPasskey 共享底层插入逻辑，允许账户注册将凭据和审计放在同一事务中。
// 私钥始终留在认证器，数据库只保存 WebAuthn 库验证过的凭据记录。
func insertPasskey(ctx context.Context, executor interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}, p *Passkey) error {
	if p == nil {
		return fmt.Errorf("identity: nil passkey")
	}
	if p.UserID == 0 {
		return fmt.Errorf("identity: passkey needs a user")
	}
	if len(p.CredentialID) == 0 {
		return fmt.Errorf("identity: passkey needs a credential ID")
	}

	id, err := newID("pk_")
	if err != nil {
		return err
	}
	raw, err := json.Marshal(p.Credential)
	if err != nil {
		return fmt.Errorf("identity: encoding passkey credential: %w", err)
	}

	now := time.Now().UTC()
	if p.CreatedAt.IsZero() {
		p.CreatedAt = now
	}

	_, err = executor.ExecContext(ctx, `
		INSERT INTO webauthn_credentials (id, user_id, name, credential_id, credential, created_at, last_used_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		id, int64(p.UserID), p.Name, p.CredentialID, string(raw), p.CreatedAt.UnixNano(), int64(0))
	if err != nil {
		if isUniqueViolation(err) {
			return fmt.Errorf("identity: credential ID is already registered")
		}
		return fmt.Errorf("identity: storing passkey: %w", err)
	}
	p.ID = id
	return nil
}

// ListPasskeys implements [PasskeyStore].
func (s *SQLiteStore) ListPasskeys(userID tailcfg.UserID) []Passkey {
	passkeys, _ := s.ListAccountPasskeys(context.Background(), userID)
	return passkeys
}

// GetPasskeyByCredentialID implements [PasskeyStore].
func (s *SQLiteStore) GetPasskeyByCredentialID(credentialID []byte) (Passkey, bool) {
	row := s.db.QueryRowContext(context.Background(),
		"SELECT "+passkeyColumns+" FROM webauthn_credentials WHERE credential_id = ?", credentialID)
	p, err := scanPasskey(row)
	if err != nil {
		return Passkey{}, false
	}
	return p, true
}

// UpdatePasskey implements [PasskeyStore].
//
// The stored credential is replaced wholesale: the library returns the
// post-assertion record, including the advanced sign counter that detects a
// cloned authenticator.
func (s *SQLiteStore) UpdatePasskey(id string, credential webauthn.Credential, usedAt time.Time) error {
	raw, err := json.Marshal(credential)
	if err != nil {
		return fmt.Errorf("identity: encoding passkey credential: %w", err)
	}

	res, err := s.db.ExecContext(context.Background(),
		"UPDATE webauthn_credentials SET credential = ?, last_used_at = ? WHERE id = ?",
		string(raw), usedAt.UTC().UnixNano(), id)
	if err != nil {
		return fmt.Errorf("identity: updating passkey: %w", err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("identity: updating passkey: %w", err)
	}
	if affected == 0 {
		return ErrPasskeyNotFound
	}
	return nil
}

// DeletePasskey implements [PasskeyStore]. The user ID is part of the WHERE
// clause: one account cannot delete (or probe) another's passkey.
func (s *SQLiteStore) DeletePasskey(id string, userID tailcfg.UserID) error {
	res, err := s.db.ExecContext(context.Background(),
		"DELETE FROM webauthn_credentials WHERE id = ? AND user_id = ?", id, int64(userID))
	if err != nil {
		return fmt.Errorf("identity: deleting passkey: %w", err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("identity: deleting passkey: %w", err)
	}
	if affected == 0 {
		return ErrPasskeyNotFound
	}
	return nil
}

// scanPasskey reads one passkey row.
func scanPasskey(sc rowScanner) (Passkey, error) {
	var (
		p          Passkey
		userID     int64
		raw        string
		createdAt  int64
		lastUsedAt int64
	)
	if err := sc.Scan(&p.ID, &userID, &p.Name, &p.CredentialID, &raw, &createdAt, &lastUsedAt); err != nil {
		return Passkey{}, err
	}
	if err := json.Unmarshal([]byte(raw), &p.Credential); err != nil {
		return Passkey{}, fmt.Errorf("identity: decoding passkey credential: %w", err)
	}
	p.UserID = tailcfg.UserID(userID)
	p.CreatedAt = time.Unix(0, createdAt).UTC()
	if lastUsedAt != 0 {
		p.LastUsedAt = time.Unix(0, lastUsedAt).UTC()
	}
	return p, nil
}

const passkeyCeremonyColumns = "id, kind, user_id, session, browser_session_hash, created_at, expires_at, consumed_at"

// CreatePasskeyCeremony implements [PasskeyCeremonyStore].
func (s *SQLiteStore) CreatePasskeyCeremony(opts NewPasskeyCeremonyOptions) (PasskeyCeremony, string, error) {
	if !opts.Kind.Valid() {
		return PasskeyCeremony{}, "", fmt.Errorf("identity: unknown passkey ceremony kind %q", opts.Kind)
	}
	if opts.Kind == PasskeyCeremonyRegister && opts.UserID == 0 {
		return PasskeyCeremony{}, "", fmt.Errorf("identity: registration ceremony needs a user")
	}
	if opts.Kind == PasskeyCeremonyLogin && opts.UserID != 0 {
		return PasskeyCeremony{}, "", fmt.Errorf("identity: login ceremony is usernameless")
	}
	if len(opts.Session) == 0 {
		return PasskeyCeremony{}, "", fmt.Errorf("identity: passkey ceremony needs session state")
	}

	id, err := newID("wc_")
	if err != nil {
		return PasskeyCeremony{}, "", err
	}
	browserSecret, err := newSecret()
	if err != nil {
		return PasskeyCeremony{}, "", err
	}

	now := time.Now().UTC()
	expiresAt := opts.ExpiresAt.UTC()
	if expiresAt.IsZero() {
		expiresAt = now.Add(DefaultPasskeyCeremonyTTL)
	}

	ceremony := PasskeyCeremony{
		ID:                 id,
		Kind:               opts.Kind,
		UserID:             opts.UserID,
		Session:            opts.Session,
		BrowserSessionHash: HashSecret(browserSecret),
		CreatedAt:          now,
		ExpiresAt:          expiresAt,
	}
	_, err = s.db.ExecContext(context.Background(), `
		INSERT INTO webauthn_ceremonies (id, kind, user_id, session, browser_session_hash, created_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		ceremony.ID, string(ceremony.Kind), int64(ceremony.UserID), string(ceremony.Session),
		ceremony.BrowserSessionHash, ceremony.CreatedAt.UnixNano(), ceremony.ExpiresAt.UnixNano())
	if err != nil {
		return PasskeyCeremony{}, "", fmt.Errorf("identity: storing passkey ceremony: %w", err)
	}
	return ceremony, browserSecret, nil
}

// GetPasskeyCeremony implements [PasskeyCeremonyStore].
func (s *SQLiteStore) GetPasskeyCeremony(id string) (PasskeyCeremony, bool) {
	row := s.db.QueryRowContext(context.Background(),
		"SELECT "+passkeyCeremonyColumns+" FROM webauthn_ceremonies WHERE id = ?", id)
	ceremony, err := scanPasskeyCeremony(row)
	if err != nil {
		return PasskeyCeremony{}, false
	}
	return ceremony, true
}

// ConsumePasskeyCeremony implements [PasskeyCeremonyStore].
//
// The atomic UPDATE ... WHERE consumed_at IS NULL is the replay guard: two
// concurrent finish requests for the same ceremony cannot both win.
func (s *SQLiteStore) ConsumePasskeyCeremony(id string) (PasskeyCeremony, error) {
	now := time.Now().UTC()

	res, err := s.db.ExecContext(context.Background(),
		"UPDATE webauthn_ceremonies SET consumed_at = ? WHERE id = ? AND consumed_at IS NULL AND expires_at > ?",
		now.UnixNano(), id, now.UnixNano())
	if err != nil {
		return PasskeyCeremony{}, fmt.Errorf("identity: consuming passkey ceremony: %w", err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return PasskeyCeremony{}, fmt.Errorf("identity: consuming passkey ceremony: %w", err)
	}

	ceremony, ok := s.GetPasskeyCeremony(id)
	if affected == 1 {
		if !ok {
			return PasskeyCeremony{}, ErrPasskeyCeremonyNotFound
		}
		return ceremony, nil
	}
	if !ok {
		return PasskeyCeremony{}, ErrPasskeyCeremonyNotFound
	}
	if ceremony.Consumed() {
		return ceremony, ErrPasskeyCeremonyConsumed
	}
	if ceremony.Expired(now) {
		return ceremony, ErrPasskeyCeremonyExpired
	}
	return ceremony, ErrPasskeyCeremonyNotFound
}

// DeleteExpiredPasskeyCeremonies implements [PasskeyCeremonyStore].
func (s *SQLiteStore) DeleteExpiredPasskeyCeremonies(now time.Time) (int64, error) {
	res, err := s.db.ExecContext(context.Background(),
		"DELETE FROM webauthn_ceremonies WHERE expires_at <= ?", now.UnixNano())
	if err != nil {
		return 0, fmt.Errorf("identity: deleting expired passkey ceremonies: %w", err)
	}
	return res.RowsAffected()
}

// scanPasskeyCeremony reads one ceremony row.
func scanPasskeyCeremony(sc rowScanner) (PasskeyCeremony, error) {
	var (
		ceremony   PasskeyCeremony
		kind       string
		userID     int64
		session    string
		createdAt  int64
		expiresAt  int64
		consumedAt sql.NullInt64
	)
	if err := sc.Scan(&ceremony.ID, &kind, &userID, &session, &ceremony.BrowserSessionHash,
		&createdAt, &expiresAt, &consumedAt); err != nil {
		return PasskeyCeremony{}, err
	}
	ceremony.Kind = PasskeyCeremonyKind(kind)
	ceremony.UserID = tailcfg.UserID(userID)
	ceremony.Session = []byte(session)
	ceremony.CreatedAt = time.Unix(0, createdAt).UTC()
	ceremony.ExpiresAt = time.Unix(0, expiresAt).UTC()
	if consumedAt.Valid {
		ceremony.ConsumedAt = time.Unix(0, consumedAt.Int64).UTC()
	}
	return ceremony, nil
}
