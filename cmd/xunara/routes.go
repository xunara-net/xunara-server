package main

import (
	"flag"
	"fmt"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/xunara-net/xunara-server/identity"
	"github.com/xunara-net/xunara-server/state"
)

// runRoutes implements "xunara routes": listing, approving and unapproving
// subnet routes and exit nodes.
func runRoutes(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "xunara: routes requires a subcommand: list, approve or unapprove")
		os.Exit(2)
	}

	switch args[0] {
	case "list":
		runRoutesList(args[1:])
	case "approve":
		runRoutesApprove(args[1:], true)
	case "unapprove":
		runRoutesApprove(args[1:], false)
	default:
		fmt.Fprintf(os.Stderr, "xunara: unknown routes subcommand %q\n", args[0])
		os.Exit(2)
	}
}

func runRoutesList(args []string) {
	fs := flag.NewFlagSet("routes list", flag.ExitOnError)
	stateDir := fs.String("state-dir", "data", "control server state directory")
	fs.Parse(args)

	store := openStore(*stateDir)
	defer store.Close()

	nodes := store.ListNodes()
	slices.SortFunc(nodes, func(a, b state.Node) int { return int(a.ID) - int(b.ID) })

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "NODE\tHOSTNAME\tSTATUS\tROUTE\tAPPROVED")

	for _, n := range nodes {
		effective := n.EffectiveRoutes()
		announced := n.AnnouncedRoutes()
		approved := make(map[netip.Prefix]bool, len(n.ApprovedRoutes))
		for _, r := range n.ApprovedRoutes {
			approved[r] = true
		}

		// Every route the node talks about, announced first.
		routes := slices.Clone(announced)
		for _, r := range n.ApprovedRoutes {
			if !slices.Contains(routes, r) {
				routes = append(routes, r)
			}
		}
		slices.SortFunc(routes, netip.Prefix.Compare)

		if len(routes) == 0 {
			fmt.Fprintf(w, "%d\t%s\t-\t-\t-\n", n.ID, n.Hostname)
			continue
		}

		for _, r := range routes {
			serving := slices.Contains(effective, r)
			status := "approved"
			switch {
			case serving:
				status = "serving"
			case approved[r]:
				status = "unannounced"
			default:
				status = "pending"
			}
			if state.IsExitRoute(r) && serving {
				status = "exit-node"
			}
			fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%t\n", n.ID, n.Hostname, status, r, approved[r])
		}
	}
	w.Flush()
}

func runRoutesApprove(args []string, approve bool) {
	name := "routes approve"
	if !approve {
		name = "routes unapprove"
	}
	fs := flag.NewFlagSet(name, flag.ExitOnError)

	var (
		stateDir = fs.String("state-dir", "data", "control server state directory")
		nodeRef  = fs.String("node", "", "node ID or stable ID (required)")
		all      = fs.Bool("all", false, "apply to every route the node announces")
	)
	fs.Parse(args)

	if *nodeRef == "" {
		fmt.Fprintf(os.Stderr, "usage: xunara %s -node <id|stable-id> [(-all | <route>...)]\n", name)
		os.Exit(2)
	}

	var requested []netip.Prefix
	for _, arg := range fs.Args() {
		for _, part := range strings.Split(arg, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			p, err := netip.ParsePrefix(part)
			if err != nil {
				fatal("parsing route "+part, err)
			}
			requested = append(requested, p)
		}
	}
	if !*all && len(requested) == 0 {
		fmt.Fprintf(os.Stderr, "xunara: %s needs -all or at least one route\n", name)
		os.Exit(2)
	}

	store := openStore(*stateDir)
	defer store.Close()

	node, ok := lookupNode(store, *nodeRef)
	if !ok {
		fmt.Fprintf(os.Stderr, "xunara: node %q not found\n", *nodeRef)
		os.Exit(1)
	}

	approved := slices.Clone(node.ApprovedRoutes)
	before := slices.Clone(approved)
	if *all {
		if approve {
			approved = node.AnnouncedRoutes()
		} else {
			approved = nil
		}
	} else {
		for _, r := range requested {
			if approve {
				if !slices.Contains(approved, r) {
					approved = append(approved, r)
				}
				if !slices.Contains(node.AnnouncedRoutes(), r) {
					fmt.Fprintf(os.Stderr,
						"xunara: warning: node %d does not announce %s yet; approval is stored and takes effect once it does\n",
						node.ID, r)
				}
			} else {
				approved = slices.DeleteFunc(approved, func(x netip.Prefix) bool { return x == r })
			}
		}
	}

	if err := store.SetNodeApprovedRoutes(node.ID, approved); err != nil {
		fatal("setting approved routes", err)
	}
	if err := store.BumpConfigRevision(); err != nil {
		fatal("bumping configuration revision", err)
	}

	nodeRefAudit := "node:" + node.StableID
	for _, r := range approved {
		if !slices.Contains(before, r) {
			appendAudit(store, identity.AuditRouteApproved, nodeRefAudit, r.String())
		}
	}
	for _, r := range before {
		if !slices.Contains(approved, r) {
			appendAudit(store, identity.AuditRouteUnapproved, nodeRefAudit, r.String())
		}
	}

	for _, r := range approved {
		fmt.Printf("%s\t%v\n", node.Hostname, r)
	}
}

// lookupNode resolves a node reference that is either a numeric node ID or a
// stable ID.
func lookupNode(store state.Store, ref string) (state.Node, bool) {
	if id, err := strconv.ParseUint(ref, 10, 64); err == nil {
		return store.GetNodeByID(state.NodeID(id))
	}
	return store.GetNodeByStableID(ref)
}
