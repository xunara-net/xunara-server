package control

import (
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/xunara-net/xunara-server/identity"
)

type accountLoginRecordView struct {
	accountSessionView
	Kind string `json:"kind"`
}

func (server *Server) handleAPIAccountLoginHistory(writer http.ResponseWriter, request *http.Request) {
	principal, ok := server.requireAccountSession(writer, request, false)
	if !ok {
		return
	}
	options := identity.LoginHistoryOptions{}
	query, queryErr := url.ParseQuery(request.URL.RawQuery)
	invalid := queryErr != nil || len(request.URL.RawQuery) > 1024
	for name, values := range query {
		if (name != "cursor" && name != "limit") || len(values) != 1 {
			invalid = true
		}
	}
	if values, present := query["limit"]; present && len(values) == 1 {
		limit, err := strconv.Atoi(values[0])
		if err != nil || limit < 1 || limit > 100 {
			invalid = true
		}
		options.Limit = limit
	}
	options.Cursor = query.Get("cursor")
	if invalid {
		writeAPIError(writer, http.StatusBadRequest, "INVALID_LOGIN_HISTORY_PAGE: choose a valid cursor and a limit from 1 to 100")
		return
	}
	page, err := server.identity.ListAccountLoginHistory(request.Context(), principal.UserID, options)
	if errors.Is(err, identity.ErrInvalidLoginHistoryOptions) {
		writeAPIError(writer, http.StatusBadRequest, "INVALID_LOGIN_HISTORY_PAGE: reload the login history")
		return
	}
	if err != nil {
		server.log.Error("listing account login history", "user", uint64(principal.UserID), "err", err)
		writeAPIError(writer, http.StatusInternalServerError, "LOGIN_HISTORY_FAILED: could not read login history")
		return
	}
	now := time.Now().UTC()
	records := make([]accountLoginRecordView, 0, len(page.Records))
	for _, record := range page.Records {
		records = append(records, accountLoginRecordView{accountSessionView: viewAccountSession(record.Session, now), Kind: record.Kind})
	}
	writeJSON(writer, http.StatusOK, map[string]any{
		"records": records, "next_cursor": page.NextCursor,
		"current_session_id": principal.Session.ID, "generated_at": now,
	})
}
