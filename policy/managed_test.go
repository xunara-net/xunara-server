package policy

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"tailscale.com/tailcfg"

	"github.com/xunara-net/xunara-server/state"
)

func TestParseManagedRejectsAmbiguousOrUnknownPolicy(t *testing.T) {
	for _, raw := range []string{
		`null`, `[]`, `{} {}`, `{"acls":[],"acls":[]}`, `{"grants":[],"grant":[]}`,
		`{"ACLs":[]}`, `{"acls":[{"src":["*"],"Src":["alice"],"dst":["*:443"]}]}`,
		`{"groups":{"group:home":[],"group:home":[]}}`, `{"acls":[{"src":["*"],"dest":["*:443"]}]}`,
		`{"grants":[{"src":["*"],"dst":["*"],"app":{"example.com/cap/read":[{"x":1,"x":2}]}}]}`,
		`{"hosts":{"nested":` + strings.Repeat("[", 66) + `0` + strings.Repeat("]", 66) + `}}`,
		strings.Repeat(" ", 256*1024+1),
	} {
		if _, _, err := ParseManaged([]byte(raw)); err == nil {
			t.Fatalf("ambiguous policy accepted: %.120s", raw)
		}
	}
	raw := `{// 中文注释和尾逗号保持 HuJSON 兼容
		"acls":[{"users":["*"],"ports":["*:443"],}],
		"tagOwners":{"tag:home":["alice"]},"ssh":[],"nodeAttrs":[],"tests":[],
	}`
	document, normalized, err := ParseManaged([]byte(raw))
	if err != nil || !json.Valid(normalized) || len(document.ACLs) != 1 || document.TagOwners["tag:home"][0] != "alice" {
		t.Fatalf("valid HuJSON lost data: %+v %v", document, err)
	}
}

func TestExplainMatchesTheActualCompiledPacketFilter(t *testing.T) {
	source := testNode(1, "laptop", "100.64.0.1")
	source.UserID = 1
	destination := testNode(2, "server", "100.64.0.2")
	destination.UserID = 2
	destination.Tags = []string{"tag:home"}
	nodes := []state.Node{source, destination}
	for _, raw := range []string{
		`{}`, `{"acls":[{"users":["*"],"ports":["*:22"],"proto":"tcp"}]}`,
		`{"grants":[{"src":["100.64.0.1/32"],"dst":["100.64.0.2"],"ip":["tcp:443","udp:53"]}]}`,
		`{"groups":{"group:office":["alice"]},"tagOwners":{"tag:home":["alice"]},"grants":[{"src":["group:office"],"dst":["tag:home"],"ip":["tcp:22-443"]}]}`,
		`{"acls":[{"src":["*"],"dst":["*:22"]}],"grants":[{"src":["*"],"dst":["*"],"ip":["tcp:443"]}]}`,
	} {
		engine := mustEngineOpts(t, raw, Options{LoginName: func(userID tailcfg.UserID) string {
			if userID == 1 {
				return "alice"
			}
			return "bob"
		}})
		for _, protocol := range []string{"tcp", "udp"} {
			for _, port := range []uint16{22, 53, 443, 444} {
				result := engine.Explain(nodes, source, destination, protocol, port)
				actual := AllowsIngress(engine.FilterFor(destination, nodes), destination, source, protocol, port)
				if result.Allowed != actual || actual != (len(result.Matches) > 0) {
					t.Fatalf("explanation drift: %s:%d %+v actual=%v", protocol, port, result, actual)
				}
				for _, match := range result.Matches {
					if len(match.Sources) == 0 || len(match.Destinations) == 0 {
						t.Fatal("explanation omitted original selectors")
					}
				}
			}
		}
	}
	engine := mustEngine(t, `{"acls":[{"src":["*"],"dst":["*:443"]}]}`)
	explanation := engine.Explain(nodes, source, destination, "tcp", 443)
	explanation.Matches[0].Sources[0] = "tampered"
	if !reflect.DeepEqual(engine.Document().ACLs[0].Src, []string{"*"}) {
		t.Fatal("explanation exposed mutable policy fields")
	}
}
