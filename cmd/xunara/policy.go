package main

import (
	"flag"
	"fmt"
	"os"
	"text/tabwriter"

	"tailscale.com/tailcfg"

	"github.com/xunara-net/xunara-server/identity"
	"github.com/xunara-net/xunara-server/policy"
	"github.com/xunara-net/xunara-server/state"
)

// userLoginName maps a user to the login name ACL selectors use. It mirrors the
// control plane's mapping: the trust plane when it knows the user, the default
// profile otherwise.
func userLoginName(users identity.UserStore) func(tailcfg.UserID) string {
	return func(id tailcfg.UserID) string {
		if u, ok := users.GetUser(id); ok {
			return u.LoginName
		}
		return state.DefaultUserProfile(id).LoginName
	}
}

// runPolicy implements "xunara policy": validating an ACL document and running
// its tests against the tailnet's current nodes.
func runPolicy(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "xunara: policy requires a subcommand: check")
		os.Exit(2)
	}

	switch args[0] {
	case "check":
		runPolicyCheck(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "xunara: unknown policy subcommand %q\n", args[0])
		os.Exit(2)
	}
}

func runPolicyCheck(args []string) {
	fs := flag.NewFlagSet("policy check", flag.ExitOnError)

	var (
		stateDir = fs.String("state-dir", "data", "control server state directory")
		domain   = fs.String("domain", "", "tailnet MagicDNS domain, for user selectors written as login@domain")
		noTests  = fs.Bool("skip-tests", false, "only validate the document, do not run its tests")
	)
	fs.Parse(args)

	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: xunara policy check [-state-dir DIR] [-domain DOMAIN] <policy-file>")
		os.Exit(2)
	}

	doc, err := policy.Load(fs.Arg(0))
	if err != nil {
		fatal("parsing policy", err)
	}

	store := openStore(*stateDir)
	defer store.Close()

	engine, err := policy.NewEngine(doc, policy.Options{
		Domain:    *domain,
		LoginName: userLoginName(openIdentity(store)),
	})
	if err != nil {
		fatal("compiling policy", err)
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "rules\t%d\n", engine.RuleCount())
	fmt.Fprintf(w, "unsupported fields\t%v\n", doc.Unsupported)
	w.Flush()

	for _, warning := range engine.Warnings() {
		fmt.Fprintf(os.Stderr, "warning: %s\n", warning)
	}

	if len(doc.Tests) == 0 || *noTests {
		fmt.Println("ok")
		return
	}

	nodes := store.ListNodes()
	if len(nodes) == 0 {
		// The tests are assertions about real devices; there is nothing to
		// check yet, and a failure here would be misleading.
		fmt.Printf("ok (skipped %d tests: no nodes registered yet)\n", len(doc.Tests))
		return
	}

	results, err := engine.RunTests(nodes)
	if err != nil {
		fatal("running policy tests", err)
	}

	failed := 0
	for _, result := range results {
		if result.Pass() {
			continue
		}
		failed++
		for _, failure := range result.Failures {
			fmt.Fprintf(os.Stderr, "tests[%d] (%s): %s\n", result.Index, result.Src, failure)
		}
	}

	if failed > 0 {
		fmt.Fprintf(os.Stderr, "xunara: %d of %d policy tests failed\n", failed, len(results))
		os.Exit(1)
	}
	fmt.Printf("ok (%d tests)\n", len(results))
}
