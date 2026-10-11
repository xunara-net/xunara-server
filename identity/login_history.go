package identity

import (
	"encoding/base64"
	"errors"
	"strconv"
	"strings"
)

var ErrInvalidLoginHistoryOptions = errors.New("identity: invalid login history pagination")

type LoginRecord struct {
	Session
	Kind string
}

type LoginHistoryOptions struct {
	Limit  int
	Cursor string
}

type LoginHistoryPage struct {
	Records    []LoginRecord
	NextCursor string
}

type loginHistoryCursor struct {
	createdAt int64
	id        string
}

func (options LoginHistoryOptions) validate() (int, loginHistoryCursor, error) {
	limit := options.Limit
	if limit == 0 {
		limit = 20
	}
	if limit < 1 || limit > 100 {
		return 0, loginHistoryCursor{}, ErrInvalidLoginHistoryOptions
	}
	if options.Cursor == "" {
		return limit, loginHistoryCursor{}, nil
	}
	if len(options.Cursor) > 128 {
		return 0, loginHistoryCursor{}, ErrInvalidLoginHistoryOptions
	}
	decoded, err := base64.RawURLEncoding.DecodeString(options.Cursor)
	if err != nil {
		return 0, loginHistoryCursor{}, ErrInvalidLoginHistoryOptions
	}
	created, id, found := strings.Cut(string(decoded), ".")
	createdAt, err := strconv.ParseInt(created, 10, 64)
	publicID, idErr := base64.RawURLEncoding.DecodeString(id)
	if !found || err != nil || createdAt <= 0 || idErr != nil || len(publicID) != 32 || len(id) != 43 {
		return 0, loginHistoryCursor{}, ErrInvalidLoginHistoryOptions
	}
	return limit, loginHistoryCursor{createdAt: createdAt, id: id}, nil
}

func encodeLoginHistoryCursor(record LoginRecord) string {
	return base64.RawURLEncoding.EncodeToString([]byte(strconv.FormatInt(record.CreatedAt.UnixNano(), 10) + "." + record.ID))
}
