package identity

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

const authTransactionColumns = "id, provider_id, state, nonce, pkce_verifier, pkce_challenge, pkce_method, " +
	"redirect_uri, return_to, requested_action, machine_login_id, browser_session_hash, created_at, expires_at, consumed_at, account_user_id, account_session_id, invite_token_hash, authentication_revision"

// CreateAuthTransaction implements [AuthTransactionStore].
func (s *SQLiteStore) CreateAuthTransaction(opts NewAuthTransactionOptions) (AuthTransaction, string, error) {
	return s.CreateAccountAuthTransaction(context.Background(), opts)
}

func (s *SQLiteStore) CreateAccountAuthTransaction(ctx context.Context, opts NewAuthTransactionOptions) (AuthTransaction, string, error) {
	if opts.ProviderID == "" {
		return AuthTransaction{}, "", fmt.Errorf("identity: auth transaction needs a provider")
	}

	ttl := opts.TTL
	if ttl <= 0 {
		ttl = DefaultAuthTransactionTTL
	}

	id, err := newSecret()
	if err != nil {
		return AuthTransaction{}, "", err
	}
	state, err := newSecret()
	if err != nil {
		return AuthTransaction{}, "", err
	}
	nonce, err := newSecret()
	if err != nil {
		return AuthTransaction{}, "", err
	}
	verifier, challenge, err := PKCEPair()
	if err != nil {
		return AuthTransaction{}, "", err
	}
	browserSecret, err := newSecret()
	if err != nil {
		return AuthTransaction{}, "", err
	}

	now := time.Now().UTC()
	tx := AuthTransaction{
		ID:                     id,
		ProviderID:             opts.ProviderID,
		State:                  state,
		Nonce:                  nonce,
		PKCEVerifier:           verifier,
		PKCEChallenge:          challenge,
		PKCEMethod:             "S256",
		RedirectURI:            opts.RedirectURI,
		ReturnTo:               opts.ReturnTo,
		RequestedAction:        opts.RequestedAction,
		MachineLoginID:         opts.MachineLoginID,
		AccountUserID:          opts.AccountUserID,
		AccountSessionID:       opts.AccountSessionID,
		InviteTokenHash:        opts.InviteTokenHash,
		AuthenticationRevision: opts.AuthenticationRevision,
		BrowserSessionHash:     HashSecret(browserSecret),
		CreatedAt:              now,
		ExpiresAt:              now.Add(ttl),
	}

	databaseTx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return AuthTransaction{}, "", err
	}
	defer databaseTx.Rollback()
	if err := lockAuthenticationRevision(ctx, databaseTx, opts.AuthenticationRevision); err != nil {
		return AuthTransaction{}, "", err
	}
	if opts.RequestedAction == AuthActionLink {
		if err := lockAccountSession(ctx, databaseTx, opts.AccountUserID, opts.AccountSessionID, now); err != nil {
			return AuthTransaction{}, "", err
		}
	} else if opts.AccountUserID != 0 || opts.AccountSessionID != "" {
		return AuthTransaction{}, "", ErrCredentialChanged
	}
	if err := requireIdentityWrite(databaseTx.ExecContext(ctx,
		`INSERT INTO auth_transactions (`+authTransactionColumns+`)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?, ?, ?)`,
		tx.ID, tx.ProviderID, tx.State, tx.Nonce, tx.PKCEVerifier, tx.PKCEChallenge, tx.PKCEMethod,
		tx.RedirectURI, tx.ReturnTo, tx.RequestedAction, tx.MachineLoginID, tx.BrowserSessionHash,
		tx.CreatedAt.UnixNano(), tx.ExpiresAt.UnixNano(), int64(tx.AccountUserID), tx.AccountSessionID, tx.InviteTokenHash, tx.AuthenticationRevision)); err != nil {
		return AuthTransaction{}, "", fmt.Errorf("identity: creating auth transaction: %w", err)
	}
	if err := databaseTx.Commit(); err != nil {
		return AuthTransaction{}, "", err
	}
	return tx, browserSecret, nil
}

// GetAuthTransaction implements [AuthTransactionStore].
func (s *SQLiteStore) GetAuthTransaction(id string) (AuthTransaction, bool) {
	row := s.db.QueryRowContext(context.Background(),
		"SELECT "+authTransactionColumns+" FROM auth_transactions WHERE id = ?", id)
	tx, err := scanAuthTransaction(row)
	if err != nil {
		return AuthTransaction{}, false
	}
	return tx, true
}

// ConsumeAuthTransaction implements [AuthTransactionStore].
//
// The atomic UPDATE ... WHERE consumed_at IS NULL is the replay guard: two
// concurrent callbacks for the same transaction cannot both win.
func (s *SQLiteStore) ConsumeAuthTransaction(id string) (AuthTransaction, error) {
	now := time.Now().UTC()

	res, err := s.db.ExecContext(context.Background(),
		"UPDATE auth_transactions SET consumed_at = ? WHERE id = ? AND consumed_at IS NULL AND expires_at > ?",
		now.UnixNano(), id, now.UnixNano())
	if err != nil {
		return AuthTransaction{}, fmt.Errorf("identity: consuming auth transaction: %w", err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return AuthTransaction{}, fmt.Errorf("identity: consuming auth transaction: %w", err)
	}

	tx, ok := s.GetAuthTransaction(id)
	if affected == 1 {
		if !ok {
			return AuthTransaction{}, ErrTransactionNotFound
		}
		return tx, nil
	}
	if !ok {
		return AuthTransaction{}, ErrTransactionNotFound
	}
	if tx.Consumed() {
		return tx, ErrTransactionConsumed
	}
	if tx.Expired(now) {
		return tx, ErrTransactionExpired
	}
	return tx, ErrTransactionNotFound
}

// DeleteExpiredAuthTransactions implements [AuthTransactionStore].
func (s *SQLiteStore) DeleteExpiredAuthTransactions(now time.Time) (int64, error) {
	res, err := s.db.ExecContext(context.Background(),
		"DELETE FROM auth_transactions WHERE expires_at <= ?", now.UnixNano())
	if err != nil {
		return 0, fmt.Errorf("identity: deleting expired auth transactions: %w", err)
	}
	return res.RowsAffected()
}

type rowScanner interface{ Scan(dest ...any) error }

func scanAuthTransaction(sc rowScanner) (AuthTransaction, error) {
	var (
		tx         AuthTransaction
		createdAt  int64
		expiresAt  int64
		consumedAt sql.NullInt64
	)
	if err := sc.Scan(&tx.ID, &tx.ProviderID, &tx.State, &tx.Nonce, &tx.PKCEVerifier, &tx.PKCEChallenge,
		&tx.PKCEMethod, &tx.RedirectURI, &tx.ReturnTo, &tx.RequestedAction, &tx.MachineLoginID,
		&tx.BrowserSessionHash, &createdAt, &expiresAt, &consumedAt, &tx.AccountUserID, &tx.AccountSessionID, &tx.InviteTokenHash, &tx.AuthenticationRevision); err != nil {
		return AuthTransaction{}, err
	}
	tx.CreatedAt = time.Unix(0, createdAt).UTC()
	tx.ExpiresAt = time.Unix(0, expiresAt).UTC()
	if consumedAt.Valid {
		tx.ConsumedAt = time.Unix(0, consumedAt.Int64).UTC()
	}
	return tx, nil
}
