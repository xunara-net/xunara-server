package state

import (
	"context"
	"database/sql"
	"errors"
)

func ReadPreAuthKey(ctx context.Context, query interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, secret string) (PreAuthKey, error) {
	authorization, err := scanPreAuthKey(query.QueryRowContext(ctx, "SELECT "+preAuthKeyColumns+" FROM preauthkeys WHERE secret = ?", secret))
	if errors.Is(err, sql.ErrNoRows) {
		return PreAuthKey{}, ErrPreAuthKeyNotUsable
	}
	return authorization, err
}
