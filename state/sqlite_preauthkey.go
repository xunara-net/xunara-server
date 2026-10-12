package state

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"tailscale.com/tailcfg"
)

// counterNextPreAuthKeyID backs pre-auth key identifier allocation.
const counterNextPreAuthKeyID = "next_preauthkey_id"

const preAuthKeyColumns = "id, secret, user_id, reusable, ephemeral, used, expiry, created, used_at, tags"

// CreatePreAuthKey implements [PreAuthKeyStore].
func (s *SQLiteStore) CreatePreAuthKey(k *PreAuthKey) error {
	if k == nil || k.Key == "" {
		return errPreAuthKeyRequired
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	ctx := context.Background()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("state: beginning create pre-auth key: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // rollback after commit is a no-op

	candidate := *k
	if err := CreatePreAuthKeyTx(ctx, tx, &candidate, -1, time.Now().UTC()); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	*k = candidate
	return nil
}

// CreatePreAuthKeyTx 在租户写事务内计数，已消费或到期的密钥不占额度。
func CreatePreAuthKeyTx(ctx context.Context, tx *sql.Tx, k *PreAuthKey, limit int, now time.Time) error {
	if k == nil || k.Key == "" {
		return errPreAuthKeyRequired
	}
	used, err := UsablePreAuthKeyCount(ctx, tx, now)
	if err != nil {
		return err
	}
	if limit >= 0 && used >= limit {
		return ErrAuthKeyLimit
	}
	id, err := nextCounter(ctx, tx, counterNextPreAuthKeyID, 1)
	if err != nil {
		return err
	}
	k.ID = uint64(id)
	if k.Created.IsZero() {
		k.Created = now
	}

	tags, err := encodeStringList(k.Tags)
	if err != nil {
		return err
	}

	result, err := tx.ExecContext(ctx, `INSERT INTO preauthkeys (`+preAuthKeyColumns+`)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		int64(k.ID),
		k.Key,
		int64(k.UserID),
		boolToInt(k.Reusable),
		boolToInt(k.Ephemeral),
		boolToInt(k.Used),
		nullableTimePtr(k.Expiry),
		k.Created.UnixNano(),
		nullableTime(k.UsedAt),
		tags,
	)
	if err != nil {
		if isUniqueViolation(err) {
			return ErrPreAuthKeyExists
		}
		return fmt.Errorf("state: inserting pre-auth key: %w", err)
	}

	return requireSingleRow(result)
}

func UsablePreAuthKeyCount(ctx context.Context, query addressQuery, now time.Time) (int, error) {
	var count int
	err := query.QueryRowContext(ctx, `SELECT COUNT(*) FROM preauthkeys WHERE
		(expiry IS NULL OR expiry > ?) AND (reusable = 1 OR used = 0)`, now.UnixNano()).Scan(&count)
	return count, err
}

// GetPreAuthKey implements [PreAuthKeyStore].
func (s *SQLiteStore) GetPreAuthKey(secret string) (PreAuthKey, bool) {
	row := s.db.QueryRowContext(context.Background(),
		"SELECT "+preAuthKeyColumns+" FROM preauthkeys WHERE secret = ?", secret)

	k, err := scanPreAuthKey(row)
	if err != nil {
		return PreAuthKey{}, false
	}
	return k, true
}

// ListPreAuthKeys implements [PreAuthKeyStore].
func (s *SQLiteStore) ListPreAuthKeys() []PreAuthKey {
	rows, err := s.db.QueryContext(context.Background(),
		"SELECT "+preAuthKeyColumns+" FROM preauthkeys ORDER BY id")
	if err != nil {
		return nil
	}
	defer rows.Close()

	var out []PreAuthKey
	for rows.Next() {
		k, err := scanPreAuthKey(rows)
		if err != nil {
			return nil
		}
		out = append(out, k)
	}
	return out
}

// MarkPreAuthKeyUsed implements [PreAuthKeyStore].
func (s *SQLiteStore) MarkPreAuthKeyUsed(secret string, at time.Time) error {
	res, err := s.db.ExecContext(context.Background(),
		"UPDATE preauthkeys SET used = 1, used_at = ? WHERE secret = ?",
		at.UTC().UnixNano(), secret)
	if err != nil {
		return fmt.Errorf("state: marking pre-auth key used: %w", err)
	}

	affected, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("state: marking pre-auth key used: %w", err)
	}
	if affected == 0 {
		return errPreAuthKeyNotFound
	}
	return nil
}

// DeletePreAuthKey implements [PreAuthKeyStore].
func (s *SQLiteStore) DeletePreAuthKey(secret string) error {
	_, err := s.db.ExecContext(context.Background(), "DELETE FROM preauthkeys WHERE secret = ?", secret)
	if err != nil {
		return fmt.Errorf("state: deleting pre-auth key: %w", err)
	}
	return nil
}

func scanPreAuthKey(sc scanner) (PreAuthKey, error) {
	var (
		id        int64
		secret    string
		userID    int64
		reusable  int64
		ephemeral int64
		used      int64
		expiry    sql.NullInt64
		created   int64
		usedAt    sql.NullInt64
		tags      string
	)

	if err := sc.Scan(&id, &secret, &userID, &reusable, &ephemeral, &used, &expiry, &created, &usedAt, &tags); err != nil {
		return PreAuthKey{}, err
	}

	k := PreAuthKey{
		ID:        uint64(id),
		Key:       secret,
		UserID:    tailcfg.UserID(userID),
		Reusable:  reusable != 0,
		Ephemeral: ephemeral != 0,
		Used:      used != 0,
		Created:   time.Unix(0, created).UTC(),
	}
	if expiry.Valid {
		k.Expiry = time.Unix(0, expiry.Int64).UTC()
	}
	if usedAt.Valid {
		t := time.Unix(0, usedAt.Int64).UTC()
		k.UsedAt = &t
	}
	if err := decodeStringList(tags, &k.Tags); err != nil {
		return PreAuthKey{}, err
	}

	return k, nil
}
