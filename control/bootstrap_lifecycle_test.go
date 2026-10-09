package control

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/xunara-net/xunara-server/identity"
	"github.com/xunara-net/xunara-server/state"
)

func TestBootstrapAcrossInstancesCannotReplaceTheWinner(t *testing.T) {
	first := newUnconfiguredServer(t)
	second, err := New(first.cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { second.Close() })
	if first.readSetupToken() != second.readSetupToken() {
		t.Fatal("instances did not share one published setup proof")
	}
	type setupResult struct {
		response *httptest.ResponseRecorder
		login    string
		password string
	}
	results := make(chan setupResult, 2)
	start := make(chan struct{})
	for index, server := range []*Server{first, second} {
		form := setupAdmissionForm(server)
		form.Set("login", fmt.Sprintf("bootstrap-owner-%d", index))
		form.Set("password", fmt.Sprintf("correct horse battery staple %d", index))
		form.Set("confirm", form.Get("password"))
		handler := server.Handler()
		go func() {
			request := httptest.NewRequest(http.MethodPost, "http://login.test/setup", strings.NewReader(form.Encode()))
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			response := httptest.NewRecorder()
			<-start
			handler.ServeHTTP(response, request)
			results <- setupResult{response: response, login: form.Get("login"), password: form.Get("password")}
		}()
	}
	close(start)
	var winner setupResult
	var successful, rejected int
	for attempt := 0; attempt < 2; attempt++ {
		result := <-results
		if result.response.Code == http.StatusFound && result.response.Header().Get("Location") == "/console/" {
			winner = result
			successful++
		} else if (result.response.Code == http.StatusConflict || (result.response.Code == http.StatusFound && result.response.Header().Get("Location") == "/login")) && result.response.Header().Get("Set-Cookie") == "" {
			rejected++
		} else {
			t.Fatalf("unexpected competing setup response: %d", result.response.Code)
		}
	}
	if successful != 1 || rejected != 1 {
		t.Fatal("concurrent instances did not choose one owner")
	}
	owner, err := first.identity.LookupUser(t.Context(), state.DefaultUserID)
	if err != nil || owner.LoginName != winner.login || owner.Role != identity.RoleOwner || len(first.identity.ListUsers()) != 1 {
		t.Fatal("the losing setup replaced the winning owner")
	}
	credential, err := first.identity.LookupLocalCredential(t.Context(), owner.ID)
	if err != nil || !identity.VerifyPassword(credential.PasswordHash, winner.password) {
		t.Fatal("the losing setup replaced the winning password")
	}
	if sessions, err := first.identity.ListAccountSessions(t.Context(), owner.ID); err != nil || len(sessions) != 1 {
		t.Fatal("concurrent setup returned multiple sessions")
	}
	var bootstraps int
	for _, event := range first.identity.ListAudit(0) {
		if event.Action == identity.AuditAdminBootstrap {
			bootstraps++
		}
	}
	if bootstraps != 1 {
		t.Fatal("concurrent setup duplicated bootstrap audits")
	}
}

func TestBootstrapCompletedStateSurvivesPasswordDeletionAndStaleProof(t *testing.T) {
	server := newUnconfiguredServer(t)
	host := newTestHTTPServer(t, server)
	form := setupAdmissionForm(server)
	response := postForm(t, noRedirectClient(), host.URL+"/setup", form, nil)
	if response.StatusCode != http.StatusFound || response.Header.Get("Location") != "/console/" {
		t.Fatal("initial setup did not complete")
	}
	owner, err := server.identity.LookupUser(t.Context(), state.DefaultUserID)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.identity.DeleteLocalCredential(owner.ID); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(server.setupTokenPath(), []byte(form.Get("token")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	form.Set("login", "replacement-owner")
	response = postForm(t, noRedirectClient(), host.URL+"/setup", form, nil)
	if response.StatusCode != http.StatusFound || response.Header.Get("Location") != "/login" || response.Header.Get("Set-Cookie") != "" {
		t.Fatal("stale proof reopened initialization after password deletion")
	}
	after, err := server.identity.LookupUser(t.Context(), owner.ID)
	if err != nil || !reflect.DeepEqual(owner, after) {
		t.Fatal("stale proof replaced the initialized owner")
	}
	response = postJSON(t, noRedirectClient(), host.URL+"/api/v1/auth/login", apiLoginRequest{Login: owner.LoginName, Password: "correct horse battery staple"}, nil)
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatal("missing password was treated as an uninitialized deployment")
	}
	// 用非空目录模拟无法清理令牌，不依赖测试进程是否具备 root 权限。
	if err := os.Remove(server.setupTokenPath()); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(server.setupTokenPath(), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(server.setupTokenPath(), "stale-proof"), []byte("not a usable setup proof"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := server.clearSetupToken(); err == nil {
		t.Fatal("cleanup failure fixture was ineffective")
	}
	reopened, err := New(server.cfg)
	if err != nil {
		t.Fatal("a stale proof prevented an already initialized account from reopening")
	}
	t.Cleanup(func() { reopened.Close() })
	if required, err := reopened.localSetupRequired(t.Context()); err != nil || required {
		t.Fatal("reopening an initialized account rearmed setup")
	}
}

func TestBootstrapStartupPreservesProofOnStateReadFailure(t *testing.T) {
	server := newUnconfiguredServer(t)
	token := server.readSetupToken()
	database := server.store.(*state.SQLiteStore).DB()
	if _, err := database.Exec("ALTER TABLE local_bootstrap_state RENAME TO unavailable_bootstrap_state"); err != nil {
		t.Fatal(err)
	}
	if reopened, err := New(server.cfg); err == nil || reopened != nil {
		if reopened != nil {
			reopened.Close()
		}
		t.Fatal("startup accepted unreadable initialization state")
	}
	if server.readSetupToken() != token {
		t.Fatal("failed startup changed the existing proof")
	}
	host := newTestHTTPServer(t, server)
	for _, endpoint := range []string{"/api/v1/auth/providers", "/api/v1/auth/session", "/api/v1/capabilities", "/setup", "/login", "/signup", "/"} {
		response := getHTML(t, noRedirectClient(), host.URL+endpoint)
		assertBootstrapUnavailable(t, response, token, "unavailable_bootstrap_state")
	}
	if _, err := database.Exec("ALTER TABLE unavailable_bootstrap_state RENAME TO local_bootstrap_state"); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := server.initSetupToken(ctx); !errors.Is(err, context.Canceled) || server.readSetupToken() != token {
		t.Fatal("cancelled startup changed proof or lost cancellation")
	}
	reopened, err := New(server.cfg)
	if err != nil {
		t.Fatal("startup did not recover its existing proof")
	}
	t.Cleanup(func() { reopened.Close() })
	if reopened.readSetupToken() != token {
		t.Fatal("recovered startup replaced a published proof")
	}
}

func TestBootstrapStartupRejectsUnsafeOrCorruptProof(t *testing.T) {
	for _, fixture := range []string{"permissions", "symlink", "directory", "corrupt", "oversized"} {
		t.Run(fixture, func(t *testing.T) {
			dir := t.TempDir()
			proof := filepath.Join(dir, setupTokenFile)
			token, err := identity.NewSecret(setupTokenBytes)
			if err != nil {
				t.Fatal(err)
			}
			switch fixture {
			case "permissions":
				err = os.WriteFile(proof, []byte(token+"\n"), 0o644)
			case "symlink":
				target := filepath.Join(dir, "protected-proof")
				if err := os.WriteFile(target, []byte(token+"\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				err = os.Symlink(target, proof)
			case "directory":
				err = os.Mkdir(proof, 0o700)
			case "corrupt":
				err = os.WriteFile(proof, []byte("private invalid setup proof"), 0o600)
			case "oversized":
				err = os.WriteFile(proof, []byte(token+strings.Repeat(" ", 256)), 0o600)
			}
			if err != nil {
				t.Fatal(err)
			}
			server, err := New(Config{StateDir: dir, ServerURL: "http://login.test"})
			if err == nil || server != nil {
				if server != nil {
					server.Close()
				}
				t.Fatal("startup accepted an unsafe or corrupt setup proof")
			}
			if fixture == "symlink" {
				content, err := os.ReadFile(filepath.Join(dir, "protected-proof"))
				if err != nil || string(content) != token+"\n" {
					t.Fatal("startup followed or overwrote a proof symlink")
				}
			}
		})
	}
}

func TestBootstrapProofPublicationDoesNotOverwriteAnotherInstance(t *testing.T) {
	first := newUnconfiguredServer(t)
	second, err := New(first.cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { second.Close() })
	if err := os.Remove(first.setupTokenPath()); err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	results := make(chan error, 2)
	for _, server := range []*Server{first, second} {
		go func() {
			<-start
			results <- server.initSetupToken(t.Context())
		}()
	}
	close(start)
	for attempt := 0; attempt < 2; attempt++ {
		if err := <-results; err != nil {
			t.Fatalf("concurrent proof publication failed: %v", err)
		}
	}
	token := first.readSetupToken()
	if token == "" || token != second.readSetupToken() {
		t.Fatal("instances published different or incomplete proof")
	}
	if err := first.initSetupToken(t.Context()); err != nil || first.readSetupToken() != token {
		t.Fatal("repeated publication replaced the shared proof")
	}
	if temporary, err := filepath.Glob(filepath.Join(first.cfg.StateDir, ".setup-token-*")); err != nil || len(temporary) != 0 {
		t.Fatal("publication left temporary secret files")
	}
}
