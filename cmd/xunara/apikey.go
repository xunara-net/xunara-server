package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"tailscale.com/tailcfg"

	"github.com/xunara-net/xunara-server/identity"
	"github.com/xunara-net/xunara-server/state"
)

// runAPIKey implements "xunara apikey": issuing and revoking service identity
// credentials for the platform API.
func runAPIKey(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "xunara: apikey requires a subcommand: create, list or revoke")
		os.Exit(2)
	}

	switch args[0] {
	case "create":
		runAPIKeyCreate(args[1:])
	case "list":
		runAPIKeyList(args[1:])
	case "revoke":
		runAPIKeyRevoke(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "xunara: unknown apikey subcommand %q\n", args[0])
		os.Exit(2)
	}
}

func runAPIKeyCreate(args []string) {
	fs := flag.NewFlagSet("apikey create", flag.ExitOnError)

	var (
		stateDir = fs.String("state-dir", "data", "control server state directory")
		name     = fs.String("name", "", "what the key is for (required)")
		scopes   = fs.String("scopes", identity.ScopeRead, "comma-separated scopes: read,write")
		ttl      = fs.Duration("ttl", 0, "key lifetime, e.g. 720h (0 means no expiry)")
		userID   = fs.Uint64("user", uint64(state.DefaultUserID), "user the key acts for")
	)
	fs.Parse(args)

	if strings.TrimSpace(*name) == "" {
		fmt.Fprintln(os.Stderr, "usage: xunara apikey create [-state-dir DIR] -name NAME [-scopes read,write] [-ttl 720h]")
		os.Exit(2)
	}

	store := openStore(*stateDir)
	defer store.Close()

	key, token, err := openIdentity(store).CreateAPIKey(identity.NewAPIKeyOptions{
		Name:   *name,
		UserID: tailcfg.UserID(*userID),
		Scopes: splitCSV(*scopes),
		TTL:    *ttl,
	})
	if err != nil {
		fatal("creating API key", err)
	}

	appendAudit(store, identity.AuditAPIKeyCreated, "apikey:"+key.ID, "created from the CLI")

	// The token is printed exactly once; only its hash is stored.
	fmt.Println(token)
}

func runAPIKeyList(args []string) {
	fs := flag.NewFlagSet("apikey list", flag.ExitOnError)
	stateDir := fs.String("state-dir", "data", "control server state directory")
	fs.Parse(args)

	store := openStore(*stateDir)
	defer store.Close()

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tNAME\tUSER\tSCOPES\tCREATED\tEXPIRES\tLAST USED\tSTATUS")
	for _, k := range openIdentity(store).ListAPIKeys() {
		status := "active"
		if !k.RevokedAt.IsZero() {
			status = "revoked"
		} else if k.Expired(time.Now()) {
			status = "expired"
		}
		fmt.Fprintf(w, "%s\t%s\t%d\t%s\t%s\t%s\t%s\t%s\n",
			k.ID, k.Name, k.UserID, strings.Join(k.Scopes, ","),
			k.CreatedAt.Format(time.RFC3339), formatTime(k.ExpiresAt), formatTime(k.LastUsedAt), status)
	}
	w.Flush()
}

func runAPIKeyRevoke(args []string) {
	fs := flag.NewFlagSet("apikey revoke", flag.ExitOnError)
	stateDir := fs.String("state-dir", "data", "control server state directory")
	fs.Parse(args)

	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: xunara apikey revoke [-state-dir DIR] <key-id>")
		os.Exit(2)
	}

	store := openStore(*stateDir)
	defer store.Close()

	id := fs.Arg(0)
	if err := openIdentity(store).RevokeAPIKey(id); err != nil {
		fatal("revoking API key", err)
	}
	appendAudit(store, identity.AuditAPIKeyRevoked, "apikey:"+id, "revoked from the CLI")
	fmt.Println("revoked", id)
}
