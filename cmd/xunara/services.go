package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/xunara-net/xunara-server/state"
)

// runServices implements "xunara services": the Xunara Atlas registry of
// services nodes advertise about themselves.
//
// The command is read-only. Only the node itself can publish its services
// (over the native client protocol), so an administrator's lever is
// inspection; reachability is decided by the ACL rules.
func runServices(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "xunara: services requires a subcommand: list or show")
		os.Exit(2)
	}

	switch args[0] {
	case "list":
		runServicesList(args[1:])
	case "show":
		runServicesShow(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "xunara: unknown services subcommand %q\n", args[0])
		os.Exit(2)
	}
}

// runServicesList implements "xunara services list".
func runServicesList(args []string) {
	fs := flag.NewFlagSet("services list", flag.ExitOnError)
	stateDir := fs.String("state-dir", "data", "control server state directory")
	fs.Parse(args)

	store := openStore(*stateDir)
	defer store.Close()

	if err := writeServicesList(os.Stdout, store); err != nil {
		fatal("listing services", err)
	}
}

// writeServicesList renders every advertised service with the node that
// publishes it.
func writeServicesList(w io.Writer, store state.Store) error {
	services := store.ListServices()
	if len(services) == 0 {
		fmt.Fprintln(w, "No services have been advertised.")
		fmt.Fprintln(w, "A node publishes them itself over /api/agent/v1/services.")
		return nil
	}

	// The MagicDNS name depends on the deployment's configured domain, which
	// the state directory does not record; the platform API reports it.
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tPROTO\tPORT\tVISIBILITY\tSHARED\tHEALTH\tNODE")
	for _, svc := range services {
		publisher := fmt.Sprintf("node %d", svc.NodeID)
		if node, ok := store.GetNodeByID(svc.NodeID); ok {
			publisher = node.StableID
			if node.Hostname != "" {
				publisher = node.Hostname + " (" + node.StableID + ")"
			}
		}
		fmt.Fprintf(tw, "%s\t%s\t%d\t%s\t%s\t%s\t%s\n", svc.Name, svc.Protocol, svc.Port,
			serviceVisibilityCell(svc), serviceSharedCell(svc), serviceHealthCell(svc), publisher)
	}
	return tw.Flush()
}

// serviceSharedCell renders whether a service is projected across an accepted
// share: "yes" or a dash.
func serviceSharedCell(svc state.Service) string {
	if svc.Shared {
		return "yes"
	}
	return "-"
}

// serviceVisibilityCell renders a service's discovery scope: the v1 default
// (the whole organization) reads as "*", a service that derives discovery
// from the ACL reads as "acl".
func serviceVisibilityCell(svc state.Service) string {
	parts := make([]string, 0, len(svc.Visibility)+1)
	if svc.VisibilityFromACL {
		parts = append(parts, "acl")
	}
	if len(parts) == 0 && len(svc.Visibility) == 0 {
		return "*"
	}
	return strings.Join(append(parts, svc.Visibility...), ", ")
}

// serviceHealthCell renders a service's health for the list: untracked
// services are always discoverable, so a dash says "not applicable".
func serviceHealthCell(svc state.Service) string {
	if svc.EffectiveHealth() == state.ServiceHealthUntracked {
		return "-"
	}
	return string(svc.EffectiveHealth())
}

// errServiceNotFound reports an unknown service name.
var errServiceNotFound = errors.New("service not found")

// runServicesShow implements "xunara services show <name>".
func runServicesShow(args []string) {
	fs := flag.NewFlagSet("services show", flag.ExitOnError)
	stateDir := fs.String("state-dir", "data", "control server state directory")
	fs.Parse(args)

	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: xunara services show [-state-dir <dir>] <name>")
		os.Exit(2)
	}
	name := fs.Arg(0)

	store := openStore(*stateDir)
	defer store.Close()

	if err := writeServicesShow(os.Stdout, store, name); err != nil {
		if errors.Is(err, errServiceNotFound) {
			fmt.Fprintf(os.Stderr, "xunara: service %q not found\n", name)
			os.Exit(1)
		}
		fatal("reading service", err)
	}
}

// writeServicesShow renders one service: who publishes it and its metadata.
func writeServicesShow(w io.Writer, store state.Store, name string) error {
	svc, ok := store.GetServiceByName(name)
	if !ok {
		return fmt.Errorf("%w: %s", errServiceNotFound, name)
	}

	node, ok := store.GetNodeByID(svc.NodeID)
	if !ok {
		return fmt.Errorf("%w: node %d that advertises %s", errServiceNotFound, svc.NodeID, name)
	}

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintf(tw, "NAME\t%s\n", svc.Name)
	fmt.Fprintf(tw, "PROTOCOL\t%s\n", svc.Protocol)
	fmt.Fprintf(tw, "PORT\t%d\n", svc.Port)
	fmt.Fprintf(tw, "NODE\t%s (%s)\n", node.Hostname, node.StableID)
	fmt.Fprintf(tw, "VISIBILITY\t%s\n", serviceVisibilityCell(svc))
	fmt.Fprintf(tw, "SHARED\t%s\n", serviceSharedCell(svc))
	if svc.Health {
		fmt.Fprintf(tw, "HEALTH\t%s\n", svc.EffectiveHealth())
		if !svc.HealthReportedAt.IsZero() {
			fmt.Fprintf(tw, "HEALTH REPORTED\t%s\n", svc.HealthReportedAt.Format("2006-01-02 15:04:05 MST"))
		}
	}
	fmt.Fprintf(tw, "CREATED\t%s\n", svc.Created.Format("2006-01-02 15:04:05 MST"))
	fmt.Fprintf(tw, "UPDATED\t%s\n", svc.Updated.Format("2006-01-02 15:04:05 MST"))
	tw.Flush()

	if len(svc.Metadata) == 0 {
		return nil
	}
	keys := make([]string, 0, len(svc.Metadata))
	for k := range svc.Metadata {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	fmt.Fprintln(w)
	tw = tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "METADATA\tVALUE")
	for _, k := range keys {
		fmt.Fprintf(tw, "%s\t%s\n", k, svc.Metadata[k])
	}
	return tw.Flush()
}
