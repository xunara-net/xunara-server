package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"text/tabwriter"
	"time"

	"github.com/xunara-net/xunara-server/idtoken"
)

// runIDToken implements "xunara id-token": administration of the signing keys
// behind the OIDC identity tokens nodes fetch from /machine/id-token.
//
// The keys live in the server's state directory, so this command runs where
// that directory is reachable, like the rest of the CLI. The server re-reads
// the keyring on every use, so a rotation here takes effect on the next token
// without a restart.
func runIDToken(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "xunara: id-token requires a subcommand: show or rotate")
		os.Exit(2)
	}

	switch args[0] {
	case "show":
		runIDTokenShow(args[1:])
	case "rotate":
		runIDTokenRotate(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "xunara: unknown id-token subcommand %q\n", args[0])
		os.Exit(2)
	}
}

// runIDTokenShow implements "xunara id-token show": the issuer's current keys,
// which is what a relying party sees in the JWKS.
func runIDTokenShow(args []string) {
	fs := flag.NewFlagSet("id-token show", flag.ExitOnError)

	var (
		stateDir = fs.String("state-dir", "data", "control server state directory")
		issuer   = fs.String("issuer", "", "issuer URL to print alongside the keys (the server's -server-url)")
	)
	fs.Parse(args)

	if err := showIDTokenKeys(os.Stdout, *stateDir, *issuer); err != nil {
		fatal("reading the identity-token keyring", err)
	}
}

// showIDTokenKeys renders one deployment's issuer state: the keys published in
// the JWKS and which of them signs new tokens.
func showIDTokenKeys(w io.Writer, stateDir, issuer string) error {
	// A deployment that never issued a token has no keyring yet; that is a
	// state worth reporting, not an error.
	if _, err := os.Stat(filepath.Join(stateDir, idtoken.KeyFileName)); os.IsNotExist(err) {
		fmt.Fprintln(w, "no identity-token keyring yet; the first token or JWKS request creates it")
		if issuer != "" {
			fmt.Fprintf(w, "issuer\t%s\n", issuer)
		}
		return nil
	}

	kr := idtoken.NewKeyring(stateDir, nil)
	keys, err := kr.Keys(time.Now().UTC())
	if err != nil {
		return err
	}

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	if issuer != "" {
		fmt.Fprintf(tw, "ISSUER\t%s\n", issuer)
	}
	fmt.Fprintf(tw, "KEYS\t%d\n", len(keys))
	for _, key := range keys {
		state := "retired"
		retired := key.Retired.Format(time.RFC3339)
		if key.Active() {
			state = "active"
			retired = "-"
		}
		fmt.Fprintf(tw, "  %s\t%s\tcreated %s\tretired %s\n",
			key.KID, state, key.Created.Format(time.RFC3339), retired)
	}
	tw.Flush()

	fmt.Fprintf(w, "\nRelying parties read the public keys from <issuer>/.well-known/jwks.json.\n")
	return nil
}

// runIDTokenRotate implements "xunara id-token rotate": retire the active key
// and start signing with a new one.
//
// Rotating is safe at any time: the retired public key stays in the JWKS until
// every token it signed has expired, so relying parties that have not
// refreshed yet keep verifying.
func runIDTokenRotate(args []string) {
	fs := flag.NewFlagSet("id-token rotate", flag.ExitOnError)

	var (
		stateDir = fs.String("state-dir", "data", "control server state directory")
	)
	fs.Parse(args)

	kr := idtoken.NewKeyring(*stateDir, nil)
	now := time.Now().UTC()
	if _, err := kr.ActiveKeyID(now); err != nil {
		fatal("reading the identity-token keyring", err)
	}

	kid, err := kr.Rotate(now)
	if err != nil {
		fatal("rotating the identity-token key", err)
	}

	fmt.Printf("rotated the identity-token signing key\nnew key id: %s\n", kid)
	fmt.Println("the previous key stays published in the JWKS until the tokens it signed have expired")
}
