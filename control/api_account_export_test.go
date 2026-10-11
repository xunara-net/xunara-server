package control

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/xunara-net/xunara-server/identity"
	"github.com/xunara-net/xunara-server/state"
)

func TestAccountExportHTTPPrivateAttachments(test *testing.T) {
	server := newTestServer(test)
	memberID := seedRoleUser(test, server, "export-member", identity.RoleMember)
	cookie, token := seedUserSession(test, server, memberID)
	_, otherToken := seedUserSession(test, server, state.DefaultUserID)
	link := identity.ExternalIdentity{ProviderID: "example", Subject: "private-export-subject", UserID: memberID, DisplayName: "本人第三方绑定"}
	if err := server.identity.LinkExternalIdentity(&link); err != nil {
		test.Fatal(err)
	}
	passkey := identity.Passkey{UserID: memberID, Name: "本人密钥", CredentialID: []byte("export-private-credential")}
	if err := server.identity.CreatePasskey(&passkey); err != nil {
		test.Fatal(err)
	}
	for _, format := range []string{"json", "csv"} {
		response := accountRequest(test, server, http.MethodPost, "/api/v1/account/export", accountExportRequest{Format: format}, cookie,
			map[string]string{"X-CSRF-Token": csrfTokenFor(token)})
		if response.Code != http.StatusOK || response.Header().Get("Cache-Control") != "no-store" || response.Header().Get("X-Content-Type-Options") != "nosniff" || !strings.HasPrefix(response.Header().Get("Content-Disposition"), `attachment; filename="xunara-`) {
			test.Fatalf("private attachment missing: status=%d", response.Code)
		}
		for _, forbidden := range []string{token, otherToken, identity.HashSecret(token), "private-export-subject", "export-private-credential", "csrf_token", "token_hash", "password_hash", "credential_id"} {
			if strings.Contains(response.Body.String(), forbidden) {
				test.Fatal("export leaked authentication material")
			}
		}
		if format == "json" {
			var payload map[string]json.RawMessage
			if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
				test.Fatal(err)
			}
			var records []accountLoginRecordView
			if err := json.Unmarshal(payload["login_history"], &records); err != nil || len(records) != 1 {
				test.Fatal("another user exported or history omitted")
			}
			if string(payload["scope"]) != `"account-security"` || !strings.Contains(string(payload["account"]), "export-member") || !strings.Contains(string(payload["identities"]), "本人第三方绑定") || !strings.Contains(string(payload["passkeys"]), "本人密钥") {
				test.Fatal("JSON export omitted own public metadata")
			}
		} else {
			reader := csv.NewReader(bytes.NewReader(bytes.TrimPrefix(response.Body.Bytes(), []byte{0xef, 0xbb, 0xbf})))
			rows, err := reader.ReadAll()
			if err != nil || len(rows) != 2 || len(rows[0]) != 11 {
				test.Fatal("CSV export was not a complete table")
			}
		}
	}
}

func TestAccountExportHTTPAuthorizationAndInput(test *testing.T) {
	server := newTestServer(test)
	cookie, token := seedUserSession(test, server, state.DefaultUserID)
	_, serviceToken := seedAPIKey(test, server)
	body := accountExportRequest{Format: "json"}
	for _, sample := range []struct {
		cookie  *http.Cookie
		headers map[string]string
		status  int
	}{
		{nil, nil, http.StatusUnauthorized},
		{cookie, nil, http.StatusForbidden},
		{cookie, map[string]string{"Authorization": "Bearer " + serviceToken, "X-CSRF-Token": csrfTokenFor(serviceToken)}, http.StatusForbidden},
		{cookie, map[string]string{"Authorization": "Bearer foreign-platform-test-token", "X-CSRF-Token": csrfTokenFor(token)}, http.StatusUnauthorized},
	} {
		response := accountRequest(test, server, http.MethodPost, "/api/v1/account/export", body, sample.cookie, sample.headers)
		if response.Code != sample.status || response.Header().Get("Content-Disposition") != "" {
			test.Fatal("export authorization leaked an attachment")
		}
	}
	headers := map[string]string{"X-CSRF-Token": csrfTokenFor(token)}
	otherTenant := newTestServer(test)
	if response := accountRequest(test, otherTenant, http.MethodPost, "/api/v1/account/export", body, cookie, headers); response.Code != http.StatusUnauthorized {
		test.Fatal("cross-tenant export accepted")
	}
	for _, invalid := range []string{`{}`, `{"format":"zip"}`, `{"format":"json","user_id":1}`, `{"format":"json","from":"2026-10-11"}`, `{"format":"json","from":"3000-01-01T00:00:00Z"}`, `{"format":"json","from":"2026-10-11T00:00:00Z","until":"2026-10-10T00:00:00Z"}`, `{"format":"json"}{}`} {
		response := accountRequest(test, server, http.MethodPost, "/api/v1/account/export", invalid, cookie, headers)
		if response.Code != http.StatusBadRequest || response.Header().Get("Content-Disposition") != "" {
			test.Fatalf("invalid export body accepted: %d", response.Code)
		}
	}
	if response := accountRequest(test, server, http.MethodPost, "/api/v1/account/export?user_id=1", body, cookie, headers); response.Code != http.StatusBadRequest {
		test.Fatal("export query accepted")
	}
	if response := accountRequest(test, server, http.MethodPost, "/api/v1/account/export", body, nil, map[string]string{"Authorization": "Bearer " + token, "X-CSRF-Token": csrfTokenFor(token)}); response.Code != http.StatusOK {
		test.Fatal("own human Bearer export rejected")
	}
}

func TestAccountExportHTTPFailureAndPersistentRate(test *testing.T) {
	for _, fault := range []string{"audit-abort", "audit-ignore", "rate", "rate-ignore"} {
		test.Run(fault, func(test *testing.T) {
			server := newTestServer(test)
			cookie, token := seedUserSession(test, server, state.DefaultUserID)
			database := server.store.(*state.SQLiteStore).DB()
			body, table := "SELECT RAISE(ABORT,'isolated export failure');", "audit_events"
			if fault == "audit-ignore" || fault == "rate-ignore" {
				body = "SELECT RAISE(IGNORE);"
			}
			if fault == "rate" || fault == "rate-ignore" {
				table = "rate_limits"
			}
			if _, err := database.Exec("CREATE TRIGGER export_fault BEFORE INSERT ON " + table + " BEGIN " + body + " END"); err != nil {
				test.Fatal(err)
			}
			response := accountRequest(test, server, http.MethodPost, "/api/v1/account/export", accountExportRequest{Format: "json"}, cookie,
				map[string]string{"X-CSRF-Token": csrfTokenFor(token)})
			if response.Code != http.StatusServiceUnavailable || response.Header().Get("Content-Disposition") != "" || response.Header().Get("Set-Cookie") != "" {
				test.Fatal("failed export returned a file or discarded the cookie")
			}
		})
	}
	server := newTestServer(test)
	cookie, token := seedUserSession(test, server, state.DefaultUserID)
	for attempt := 0; attempt < 6; attempt++ {
		response := accountRequest(test, server, http.MethodPost, "/api/v1/account/export", accountExportRequest{Format: "csv"}, cookie,
			map[string]string{"X-CSRF-Token": csrfTokenFor(token)})
		if attempt < 5 && response.Code != http.StatusOK || attempt == 5 && (response.Code != http.StatusTooManyRequests || response.Header().Get("Retry-After") == "") {
			test.Fatal("account export rate admission was not enforced")
		}
	}
}

func TestAccountExportEncodingBoundAndCSVText(test *testing.T) {
	for _, text := range []string{"=HYPERLINK(\"https://example.test\")", "+1", "-1", "@SUM(1)", " ＝1", "\u200b＠value", "\tlabel", "\rlabel", "\nlabel", "'quoted", "\"quoted"} {
		if value := exportCSVText(text); value != "文本："+text {
			test.Fatalf("dangerous CSV text was not visibly prefixed: %q", text)
		}
	}
	for _, text := range []string{"", "Firefox, 中文", "IPv6 ::1", "local", "safe \"quote\"", "safe\nline"} {
		if exportCSVText(text) != text {
			test.Fatal("safe CSV display text was changed")
		}
	}
	now := time.Now().UTC()
	snapshot := identity.AccountExportSnapshot{GeneratedAt: now, LoginHistory: []identity.LoginRecord{{Session: identity.Session{
		ID: "record", AuthMethod: "local", CreatedAt: now, ExpiresAt: now.Add(time.Hour),
		ClientInfo: identity.SessionClientInfo{UserAgent: "=1,\"quoted\"\nline"},
	}, Kind: "login"}}}
	data, err := encodeAccountExport(snapshot, "csv")
	if err != nil {
		test.Fatal(err)
	}
	rows, err := csv.NewReader(bytes.NewReader(data[3:])).ReadAll()
	if err != nil || len(rows) != 2 || len(rows[1]) != 11 || rows[1][10] != "文本：=1,\"quoted\"\nline" {
		test.Fatal("CSV separator / quote / newline escaped incorrectly")
	}
	snapshot.LoginHistory[0].ClientInfo.UserAgent = strings.Repeat("oversized", maxAccountExportBytes/8)
	for _, format := range []string{"json", "csv"} {
		if data, err := encodeAccountExport(snapshot, format); !errors.Is(err, identity.ErrAccountExportTooLarge) || len(data) != 0 {
			test.Fatal("file byte limit did not reject the entire export")
		}
	}
}
