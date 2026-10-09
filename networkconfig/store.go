// Package networkconfig implements tenant-local platform configuration; it never changes wire types.
package networkconfig

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"tailscale.com/tailcfg"

	"github.com/xunara-net/xunara-server/identity"
)

const (
	Policy = "policy"
	DNS    = "dns"
)

var (
	ErrConflict = errors.New("network configuration revision changed")
	ErrNotFound = errors.New("network configuration version not found")
)

type Document struct {
	Kind     string    `json:"kind"`
	Revision uint64    `json:"revision"`
	Content  string    `json:"content"`
	Actor    string    `json:"actor"`
	Created  time.Time `json:"created"`
}

type Writer struct {
	UserID    tailcfg.UserID
	SessionID string
	APIKeyID  string
}

type SQLiteStore struct{ db *sql.DB }

func NewSQLiteStore(db *sql.DB) *SQLiteStore { return &SQLiteStore{db: db} }

func scanDocument(row interface{ Scan(...any) error }) (Document, error) {
	var document Document
	var created int64
	err := row.Scan(&document.Kind, &document.Revision, &document.Content, &document.Actor, &created)
	document.Created = time.Unix(0, created).UTC()
	return document, err
}

func (store *SQLiteStore) Get(ctx context.Context, kind string) (Document, bool, error) {
	document, err := scanDocument(store.db.QueryRowContext(ctx,
		"SELECT kind, revision, content, actor, created FROM network_documents WHERE kind = ?", kind))
	if errors.Is(err, sql.ErrNoRows) {
		return Document{}, false, nil
	}
	return document, err == nil, err
}

func (store *SQLiteStore) History(ctx context.Context, kind string) ([]Document, error) {
	rows, err := store.db.QueryContext(ctx,
		"SELECT kind, revision, content, actor, created FROM network_document_history WHERE kind = ? ORDER BY revision DESC LIMIT 50", kind)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	documents := make([]Document, 0)
	for rows.Next() {
		document, err := scanDocument(rows)
		if err != nil {
			return nil, err
		}
		documents = append(documents, document)
	}
	return documents, rows.Err()
}

func (store *SQLiteStore) Version(ctx context.Context, kind string, revision uint64) (Document, error) {
	document, err := scanDocument(store.db.QueryRowContext(ctx,
		"SELECT kind, revision, content, actor, created FROM network_document_history WHERE kind = ? AND revision = ?", kind, revision))
	if errors.Is(err, sql.ErrNoRows) {
		return Document{}, ErrNotFound
	}
	return document, err
}

// Save 将配置、历史、审计与失效通知一起提交；任何一步失败均不留下“半发布”。
func (store *SQLiteStore) Save(ctx context.Context, kind, content, initial string, expected uint64, writer Writer) (Document, error) {
	if kind != Policy && kind != DNS {
		return Document{}, errors.New("unsupported configuration kind")
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return Document{}, err
	}
	defer tx.Rollback()
	now := time.Now().UTC()
	if err := identity.CheckNetworkWriter(ctx, tx, writer.UserID, writer.SessionID, writer.APIKeyID, now); err != nil {
		return Document{}, err
	}
	var current uint64
	err = tx.QueryRowContext(ctx, "SELECT revision FROM network_documents WHERE kind = ?", kind).Scan(&current)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return Document{}, err
	}
	if current != expected {
		return Document{}, ErrConflict
	}
	if current == 0 {
		if _, err := tx.ExecContext(ctx,
			"INSERT INTO network_document_history (kind, revision, content, actor, created) VALUES (?, 0, ?, 'system:import', ?)", kind, initial, now.UnixNano()); err != nil {
			return Document{}, err
		}
	}
	document := Document{Kind: kind, Revision: current + 1, Content: content, Actor: writer.Actor(), Created: now}
	if _, err := tx.ExecContext(ctx, `INSERT INTO network_documents (kind, revision, content, actor, created) VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(kind) DO UPDATE SET revision=excluded.revision, content=excluded.content, actor=excluded.actor, created=excluded.created`,
		kind, document.Revision, content, document.Actor, now.UnixNano()); err != nil {
		return Document{}, err
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO network_document_history (kind, revision, content, actor, created) VALUES (?, ?, ?, ?, ?)",
		kind, document.Revision, content, document.Actor, now.UnixNano()); err != nil {
		return Document{}, err
	}
	if kind == Policy {
		if _, err := tx.ExecContext(ctx, "DELETE FROM ssh_check_auth"); err != nil {
			return Document{}, err
		}
	}
	if err := commitChange(ctx, tx, document.Actor, kind+".published", kind, fmt.Sprintf("revision %d", document.Revision), now); err != nil {
		return Document{}, err
	}
	return document, tx.Commit()
}

func (writer Writer) Actor() string {
	actor := fmt.Sprintf("user:%d", writer.UserID)
	if writer.APIKeyID != "" {
		actor += "/apikey:" + writer.APIKeyID
	}
	return actor
}

func commitChange(ctx context.Context, tx *sql.Tx, actor, action, target, detail string, now time.Time) error {
	if _, err := tx.ExecContext(ctx, "INSERT INTO audit_events (ts, actor, action, target, detail) VALUES (?, ?, ?, ?, ?)",
		now.UnixNano(), actor, action, target, detail); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO counters (name, value) VALUES ('config_revision', 1)
		ON CONFLICT(name) DO UPDATE SET value = value + 1`)
	return err
}
