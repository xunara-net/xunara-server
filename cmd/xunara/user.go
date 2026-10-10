package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strconv"
	"text/tabwriter"
	"time"

	"tailscale.com/tailcfg"

	"github.com/xunara-net/xunara-server/identity"
)

// runUser implements "xunara user": inspecting and updating the trust plane's
// users.
func runUser(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "xunara: user requires a subcommand: list, update or role")
		os.Exit(2)
	}

	switch args[0] {
	case "list":
		runUserList(args[1:])
	case "update":
		runUserUpdate(args[1:])
	case "role":
		runUserRole(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "xunara: unknown user subcommand %q\n", args[0])
		os.Exit(2)
	}
}

func runUserList(args []string) {
	fs := flag.NewFlagSet("user list", flag.ExitOnError)
	stateDir := fs.String("state-dir", "data", "control server state directory")
	fs.Parse(args)

	store := openStore(*stateDir)
	defer store.Close()
	ids := openIdentity(store)

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tLOGIN\tROLE\tDISPLAY\tEMAIL\tIDENTITIES\tCREATED")
	for _, u := range ids.ListUsers() {
		role := u.Role
		if !role.Valid() {
			role = identity.RoleMember
		}
		fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\t%d\t%s\n",
			u.ID, u.LoginName, role, u.DisplayName, u.Email,
			len(ids.ListExternalIdentities(u.ID)), u.CreatedAt.Format(time.RFC3339))
	}
	w.Flush()
}

// runUserRole implements "xunara user role", the bootstrap path for granting
// the first OIDC user a platform role: the built-in local user starts as the
// owner and a deployment without local login promotes an operator by hand.
func runUserRole(args []string) {
	fs := flag.NewFlagSet("user role", flag.ExitOnError)
	stateDir := fs.String("state-dir", "data", "control server state directory")
	fs.Parse(args)

	if fs.NArg() != 2 {
		fmt.Fprintln(os.Stderr, "usage: xunara user role [-state-dir DIR] <id|login> <member|admin|owner>")
		os.Exit(2)
	}

	role, err := identity.ParseRole(fs.Arg(1))
	if err != nil {
		fmt.Fprintf(os.Stderr, "xunara: %v\n", err)
		os.Exit(2)
	}

	store := openStore(*stateDir)
	defer store.Close()
	ids := openIdentity(store)

	user, ok := lookupUser(ids, fs.Arg(0))
	if !ok {
		fmt.Fprintf(os.Stderr, "xunara: user %q not found\n", fs.Arg(0))
		os.Exit(1)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	updated, err := ids.UpdateUserByOperator(ctx, user.ID, identity.MemberPatch{Role: &role})
	if err != nil {
		fatal("updating user role", err)
	}
	fmt.Printf("%d\t%s\t%s\n", updated.ID, updated.LoginName, updated.Role)
}

// lookupUser resolves a user reference that is either a numeric ID or a login
// name.
func lookupUser(ids identity.UserStore, ref string) (identity.User, bool) {
	if id, err := strconv.ParseUint(ref, 10, 64); err == nil {
		return ids.GetUser(tailcfg.UserID(id))
	}
	return ids.GetUserByLoginName(ref)
}

func runUserUpdate(args []string) {
	fs := flag.NewFlagSet("user update", flag.ExitOnError)

	var (
		stateDir    = fs.String("state-dir", "data", "control server state directory")
		login       = fs.String("login", "", "new login name")
		displayName = fs.String("display-name", "", "new display name")
		email       = fs.String("email", "", "new email attribute")
	)
	fs.Parse(args)

	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr,
			"usage: xunara user update [-state-dir DIR] [-login LOGIN] [-display-name NAME] [-email EMAIL] <id|login>")
		os.Exit(2)
	}
	if *login == "" && *displayName == "" && *email == "" {
		fmt.Fprintln(os.Stderr, "xunara: user update needs at least one of -login, -display-name or -email")
		os.Exit(2)
	}

	store := openStore(*stateDir)
	defer store.Close()
	ids := openIdentity(store)

	user, ok := lookupUser(ids, fs.Arg(0))
	if !ok {
		fmt.Fprintf(os.Stderr, "xunara: user %q not found\n", fs.Arg(0))
		os.Exit(1)
	}

	patch := identity.MemberPatch{}
	if *login != "" {
		patch.LoginName = login
	}
	if *displayName != "" {
		patch.DisplayName = displayName
	}
	if *email != "" {
		patch.Email = email
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	updated, err := ids.UpdateUserByOperator(ctx, user.ID, patch)
	if err != nil {
		fatal("updating user", err)
	}
	fmt.Printf("%d\t%s\t%s\t%s\n", updated.ID, updated.LoginName, updated.DisplayName, updated.Email)
}
