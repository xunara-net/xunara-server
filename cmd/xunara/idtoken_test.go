package main

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xunara-net/xunara-server/idtoken"
)

// TestShowIDTokenKeys covers the three states an operator can find a state
// directory in: no keyring yet, one active key, and a rotation in progress.
func TestShowIDTokenKeys(t *testing.T) {
	dir := t.TempDir()

	var buf bytes.Buffer
	if err := showIDTokenKeys(&buf, dir, "https://login.example.com"); err != nil {
		t.Fatalf("showIDTokenKeys (fresh dir): %v", err)
	}
	if !strings.Contains(buf.String(), "no identity-token keyring") {
		t.Errorf("fresh dir output = %q, want a no-keyring notice", buf.String())
	}

	kr := idtoken.NewKeyring(dir, nil)
	now := time.Now().UTC()
	active, err := kr.ActiveKeyID(now)
	if err != nil {
		t.Fatalf("ActiveKeyID: %v", err)
	}
	if err := showIDTokenKeys(&buf, dir, ""); err != nil {
		t.Fatalf("showIDTokenKeys (one key): %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, active) || !strings.Contains(out, "active") {
		t.Errorf("output does not name the active key %s:\n%s", active, out)
	}

	rotated, err := kr.Rotate(now.Add(time.Minute))
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	buf.Reset()
	if err := showIDTokenKeys(&buf, dir, "https://login.example.com"); err != nil {
		t.Fatalf("showIDTokenKeys (after rotation): %v", err)
	}
	out = buf.String()
	if !strings.Contains(out, rotated) || !strings.Contains(out, "active") {
		t.Errorf("output does not name the new active key %s:\n%s", rotated, out)
	}
	if !strings.Contains(out, active) || !strings.Contains(out, "retired") {
		t.Errorf("output does not keep the retired key %s:\n%s", active, out)
	}
	if !strings.Contains(out, "https://login.example.com") {
		t.Errorf("output does not print the issuer:\n%s", out)
	}

	// The state directory must be untouched by a read-only command.
	if _, err := kr.Keys(now.Add(2 * time.Minute)); err != nil {
		t.Fatalf("Keys after show: %v", err)
	}
	if _, err := filepath.Glob(filepath.Join(dir, ".id_token_keys-*")); err != nil {
		t.Fatalf("Glob: %v", err)
	}
}
