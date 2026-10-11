package control

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/xunara-net/xunara-server/identity"
)

const maxAccountExportBytes = 8 << 20

type accountExportRequest struct {
	Format string `json:"format"`
	From   string `json:"from,omitempty"`
	Until  string `json:"until,omitempty"`
}

type accountExportIdentityView struct {
	ProviderID  string    `json:"provider_id"`
	DisplayName string    `json:"display_name"`
	Email       string    `json:"email"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type accountExportPasskeyView struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
}

func (server *Server) handleAPIAccountExport(writer http.ResponseWriter, request *http.Request) {
	principal, ok := server.requireAccountSession(writer, request, true)
	if !ok {
		return
	}
	if request.URL.RawQuery != "" {
		writeAPIError(writer, http.StatusBadRequest, "INVALID_ACCOUNT_EXPORT: export options belong in the request body")
		return
	}
	var body accountExportRequest
	if !decodeAccountBody(writer, request, &body) {
		return
	}
	options := identity.AccountExportOptions{Scope: identity.AccountSecurityExportScope}
	if body.Format == "csv" {
		options.Scope = identity.LoginHistoryExportScope
	} else if body.Format != "json" {
		writeAPIError(writer, http.StatusBadRequest, "INVALID_ACCOUNT_EXPORT: choose json or csv")
		return
	}
	for _, field := range []struct {
		value  string
		target *time.Time
	}{{body.From, &options.From}, {body.Until, &options.Until}} {
		if field.value == "" {
			continue
		}
		parsed, err := time.Parse(time.RFC3339Nano, field.value)
		if err != nil || parsed.UnixNano() <= 0 || !time.Unix(0, parsed.UnixNano()).Equal(parsed) {
			writeAPIError(writer, http.StatusBadRequest, "INVALID_ACCOUNT_EXPORT: use valid timestamps with a timezone")
			return
		}
		*field.target = parsed.UTC()
	}
	if !options.From.IsZero() && !options.Until.IsZero() && !options.From.Before(options.Until) {
		writeAPIError(writer, http.StatusBadRequest, "INVALID_ACCOUNT_EXPORT: the history interval must be increasing")
		return
	}
	now := time.Now()
	for _, limit := range []struct {
		scope string
		count int
	}{{fmt.Sprintf("account-export-user:%d", principal.UserID), 5}, {"account-export-ip:" + server.clientIP(request), 20}} {
		allowed, retryAfter, err := server.store.AllowRate(limit.scope, limit.count, 15*time.Minute, now)
		if err != nil {
			writeAPIError(writer, http.StatusServiceUnavailable, "ACCOUNT_EXPORT_UNAVAILABLE: export admission could not be checked")
			return
		}
		if !allowed {
			writer.Header().Set("Retry-After", strconv.Itoa(int(retryAfter.Seconds())+1))
			writeAPIError(writer, http.StatusTooManyRequests, "ACCOUNT_EXPORT_RATE_LIMITED: try again later")
			return
		}
	}
	ctx, cancel := context.WithTimeout(request.Context(), 10*time.Second)
	defer cancel()
	snapshot, err := server.identity.PrepareAccountExport(ctx, principal.UserID, principal.Session.ID, options)
	if err != nil {
		switch {
		case errors.Is(err, identity.ErrSessionRevoked):
			writeAPIError(writer, http.StatusUnauthorized, "SESSION_CHANGED: initiating login is no longer active")
		case errors.Is(err, identity.ErrAccountExportTooLarge):
			writeAPIError(writer, http.StatusRequestEntityTooLarge, "ACCOUNT_EXPORT_TOO_LARGE: choose a smaller history interval")
		default:
			server.log.Error("preparing account export", "user", uint64(principal.UserID), "err", err)
			writeAPIError(writer, http.StatusServiceUnavailable, "ACCOUNT_EXPORT_UNAVAILABLE: could not prepare account export")
		}
		return
	}
	data, err := encodeAccountExport(snapshot, body.Format)
	if errors.Is(err, identity.ErrAccountExportTooLarge) {
		writeAPIError(writer, http.StatusRequestEntityTooLarge, "ACCOUNT_EXPORT_TOO_LARGE: choose a smaller history interval")
		return
	}
	if err != nil {
		writeAPIError(writer, http.StatusServiceUnavailable, "ACCOUNT_EXPORT_UNAVAILABLE: could not encode account export")
		return
	}
	if ctx.Err() != nil {
		writeAPIError(writer, http.StatusServiceUnavailable, "ACCOUNT_EXPORT_UNAVAILABLE: export preparation was interrupted")
		return
	}
	// 完整编码成功后才返回附件，避免浏览器保存半份资料或把错误页误当备份。
	filename := "xunara-" + string(options.Scope) + "-" + snapshot.GeneratedAt.Format("20060102T150405Z") + "." + body.Format
	contentType := "application/json; charset=utf-8"
	if body.Format == "csv" {
		contentType = "text/csv; charset=utf-8"
	}
	writer.Header().Set("Content-Type", contentType)
	writer.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
	writer.Header().Set("Content-Length", strconv.Itoa(len(data)))
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.Header().Set("Content-Security-Policy", "sandbox; default-src 'none'")
	writer.WriteHeader(http.StatusOK)
	_, _ = writer.Write(data)
}

func encodeAccountExport(snapshot identity.AccountExportSnapshot, format string) ([]byte, error) {
	if format == "csv" {
		return encodeAccountHistoryCSV(snapshot)
	}
	sessions := make([]accountSessionView, 0, len(snapshot.Sessions))
	for _, session := range snapshot.Sessions {
		sessions = append(sessions, viewAccountSession(session, snapshot.GeneratedAt))
	}
	records := make([]accountLoginRecordView, 0, len(snapshot.LoginHistory))
	for _, record := range snapshot.LoginHistory {
		records = append(records, accountLoginRecordView{accountSessionView: viewAccountSession(record.Session, snapshot.GeneratedAt), Kind: record.Kind})
	}
	links := make([]accountExportIdentityView, 0, len(snapshot.Identities))
	for _, link := range snapshot.Identities {
		links = append(links, accountExportIdentityView{link.ProviderID, link.DisplayName, link.Email, link.CreatedAt, link.UpdatedAt})
	}
	passkeys := make([]accountExportPasskeyView, 0, len(snapshot.Passkeys))
	for _, passkey := range snapshot.Passkeys {
		item := accountExportPasskeyView{ID: passkey.ID, Name: passkey.Name, CreatedAt: passkey.CreatedAt}
		if !passkey.LastUsedAt.IsZero() {
			item.LastUsedAt = &passkey.LastUsedAt
		}
		passkeys = append(passkeys, item)
	}
	// 沿用经过审查的展示 DTO，而不是序列化 Store / 原始认证材料。
	data, err := json.MarshalIndent(map[string]any{
		"schema_version": 1, "scope": string(identity.AccountSecurityExportScope), "generated_at": snapshot.GeneratedAt,
		"account": apiUserView(snapshot.User), "contact_email_verified": false,
		"local_password_configured": snapshot.LocalPasswordConfigured,
		"identities":                links, "passkeys": passkeys, "active_sessions": sessions, "login_history": records,
		"history_filter": map[string]string{"from": exportTimestamp(snapshot.Options.From), "until": exportTimestamp(snapshot.Options.Until)},
	}, "", "  ")
	if err != nil {
		return nil, err
	}
	if len(data)+1 > maxAccountExportBytes {
		return nil, identity.ErrAccountExportTooLarge
	}
	return append(data, '\n'), nil
}

func encodeAccountHistoryCSV(snapshot identity.AccountExportSnapshot) ([]byte, error) {
	var buffer bytes.Buffer
	buffer.WriteString("\xef\xbb\xbf")
	writer := csv.NewWriter(&buffer)
	writer.UseCRLF = true
	if err := writer.Write([]string{"记录标识", "登录方式", "记录类型", "创建时间(UTC)", "有效期(UTC)", "最近活动(UTC)", "状态", "撤销时间(UTC)", "撤销原因", "首次来源IP", "客户端线索"}); err != nil {
		return nil, err
	}
	for _, record := range snapshot.LoginHistory {
		view := viewAccountSession(record.Session, snapshot.GeneratedAt)
		if err := writer.Write([]string{
			exportCSVText(record.ID), exportCSVText(record.AuthMethod), exportCSVText(record.Kind),
			exportTimestamp(record.CreatedAt), exportTimestamp(record.ExpiresAt), exportTimestamp(record.LastSeenAt),
			exportCSVText(view.Status), exportTimestamp(record.RevokedAt), exportCSVText(record.RevokedReason),
			exportCSVText(record.ClientInfo.IP), exportCSVText(record.ClientInfo.UserAgent),
		}); err != nil {
			return nil, err
		}
		if buffer.Len() > maxAccountExportBytes {
			return nil, identity.ErrAccountExportTooLarge
		}
	}
	writer.Flush()
	if err := writer.Error(); err != nil {
		return nil, err
	}
	if buffer.Len() > maxAccountExportBytes {
		return nil, identity.ErrAccountExportTooLarge
	}
	return buffer.Bytes(), nil
}

func exportTimestamp(timestamp time.Time) string {
	if timestamp.IsZero() {
		return ""
	}
	return timestamp.UTC().Format(time.RFC3339Nano)
}

func exportCSVText(value string) string {
	leading := strings.TrimLeftFunc(value, func(character rune) bool {
		return unicode.IsSpace(character) || unicode.IsControl(character) || unicode.Is(unicode.Cf, character)
	})
	// 可见前缀不会依赖表格软件保留隐形转义；原值可从 JSON 获取。
	first, _ := utf8.DecodeRuneInString(leading)
	if strings.HasPrefix(value, "\t") || strings.HasPrefix(value, "\r") || strings.HasPrefix(value, "\n") ||
		strings.ContainsRune("=+-@＝＋－＠'\"", first) {
		return "文本：" + value
	}
	return value
}
