package policy

import (
	"encoding/json"
	"reflect"
	"testing"
)

// cloneDoc exercises every section Clone must copy deeply, including a grant
// capability value, an SSH check period and an unsupported top-level field.
const cloneDoc = `{
  "acls": [{"action": "accept", "src": ["group:admins"], "dst": ["tag:server:22"], "proto": "tcp"}],
  "grants": [{"src": ["group:dev"], "dst": ["tag:db"], "ip": ["tcp:5432"], "app": {"example.com/cap/x": [{"a": 1}]}}],
  "groups": {"group:admins": ["alice@example.com"], "group:dev": ["group:admins"]},
  "hosts": {"db": "100.64.0.1"},
  "tagOwners": {"tag:server": ["group:admins"], "tag:db": ["group:admins"]},
  "ssh": [{"action": "check", "src": ["autogroup:member"], "dst": ["tag:server"],
           "users": ["root"], "acceptEnv": ["LC_*"], "checkPeriod": "12h"}],
  "nodeAttrs": [{"target": ["tag:server"], "attr": ["https"]}],
  "tests": [{"src": "alice@example.com", "accept": ["db:5432"], "deny": ["web:22"]}]
}`

// TestDocumentClone mutates every part of a clone and checks the original is
// untouched: the management surface renders a copy while the engine enforces
// the original.
func TestDocumentClone(t *testing.T) {
	doc, err := ParseString(cloneDoc)
	if err != nil {
		t.Fatalf("parsing the document: %v", err)
	}
	doc.Unsupported = []string{"autoApprovers"}
	clone := doc.Clone()
	if clone == nil {
		t.Fatal("Clone returned nil")
	}

	clone.ACLs[0].Src[0] = "user:mallory@example.com"
	clone.ACLs[0].Users = append(clone.ACLs[0].Users, "nobody")
	clone.ACLs = append(clone.ACLs, ACLRow{Action: "accept"})
	clone.Grants[0].Src[0] = "user:mallory@example.com"
	clone.Grants[0].App["example.com/cap/x"][0] = json.RawMessage(`{"a": 2}`)
	clone.Grants[0].App["example.com/cap/new"] = []json.RawMessage{json.RawMessage(`null`)}
	clone.Groups["group:admins"][0] = "mallory@example.com"
	clone.Groups["group:new"] = []string{"group:admins"}
	clone.Hosts["db"] = "100.64.0.9"
	clone.Hosts["new"] = "100.64.0.10"
	clone.TagOwners["tag:server"][0] = "user:mallory@example.com"
	clone.SSH[0].Users[0] = "nobody"
	clone.SSH[0].AcceptEnv[0] = "EVIL_*"
	clone.SSH[0].CheckPeriod.Always = true
	clone.NodeAttrs[0].Attr[0] = "funnel"
	clone.Tests[0].Accept[0] = "evil:1"
	clone.Unsupported[0] = "sshTests"

	want, err := ParseString(cloneDoc)
	if err != nil {
		t.Fatalf("re-parsing the document: %v", err)
	}
	want.Unsupported = []string{"autoApprovers"}
	if !reflect.DeepEqual(doc, want) {
		t.Errorf("mutating the clone changed the original document:\ngot  %#v\nwant %#v", doc, want)
	}

	var nilDoc *Document
	if nilDoc.Clone() != nil {
		t.Error("Clone of a nil document is not nil")
	}
}

// TestEngineDocumentIsACopy checks the engine hands out a fresh copy each call,
// so the surface cannot reach the document the netmap compiler holds.
func TestEngineDocumentIsACopy(t *testing.T) {
	doc, err := ParseString(cloneDoc)
	if err != nil {
		t.Fatalf("parsing the document: %v", err)
	}
	engine, err := NewEngine(doc, Options{})
	if err != nil {
		t.Fatalf("compiling the document: %v", err)
	}

	first := engine.Document()
	first.Groups["group:admins"][0] = "mallory@example.com"

	second := engine.Document()
	if got := second.Groups["group:admins"][0]; got != "alice@example.com" {
		t.Errorf("engine document was mutated through a previous copy: group member = %q", got)
	}
	if doc.Groups["group:admins"][0] != "alice@example.com" {
		t.Errorf("original document was mutated: group member = %q", doc.Groups["group:admins"][0])
	}
}
