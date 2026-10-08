package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"slices"
	"sort"
	"text/tabwriter"

	"github.com/xunara-net/xunara-server/state"
)

// runPosture implements "xunara posture": the device posture attributes nodes
// report about themselves through PATCH /machine/set-device-attr.
//
// The command is read-only. Only the node itself can change its attributes (the
// control plane validates the node key against the machine key that opened the
// Noise session), so an administrator's lever is inspection, not editing.
func runPosture(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "xunara: posture requires a subcommand: list or show")
		os.Exit(2)
	}

	switch args[0] {
	case "list":
		runPostureList(args[1:])
	case "show":
		runPostureShow(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "xunara: unknown posture subcommand %q\n", args[0])
		os.Exit(2)
	}
}

// runPostureList implements "xunara posture list".
func runPostureList(args []string) {
	fs := flag.NewFlagSet("posture list", flag.ExitOnError)
	stateDir := fs.String("state-dir", "data", "control server state directory")
	fs.Parse(args)

	store := openStore(*stateDir)
	defer store.Close()

	if err := writePostureList(os.Stdout, store); err != nil {
		fatal("listing device posture attributes", err)
	}
}

// writePostureList renders every machine that reported at least one attribute,
// with its attribute names (never the values: this is the "what do we know
// about" view; `posture show` prints the values).
func writePostureList(w io.Writer, store state.Store) error {
	nodes := store.ListNodes()
	slices.SortFunc(nodes, func(a, b state.Node) int { return int(a.ID) - int(b.ID) })

	var rendered int
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "NODE\tHOSTNAME\tATTRS")
	for _, n := range nodes {
		names, err := deviceAttrNames(store, n)
		if err != nil {
			return err
		}
		if len(names) == 0 {
			continue
		}
		rendered++
		fmt.Fprintf(tw, "%d\t%s\t%d (%v)\n", n.ID, n.Hostname, len(names), names)
	}
	tw.Flush()

	if rendered == 0 {
		fmt.Fprintln(w, "\nNo machine has reported device posture attributes.")
		fmt.Fprintln(w, "A node reports them itself; the control plane never sets them.")
	}
	return nil
}

// errNodeNotFound reports an unknown node reference.
var errNodeNotFound = errors.New("node not found")

// runPostureShow implements "xunara posture show <id|stable-id>".
func runPostureShow(args []string) {
	fs := flag.NewFlagSet("posture show", flag.ExitOnError)
	stateDir := fs.String("state-dir", "data", "control server state directory")
	fs.Parse(args)

	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: xunara posture show [-state-dir <dir>] <node-id|stable-id>")
		os.Exit(2)
	}

	store := openStore(*stateDir)
	defer store.Close()

	err := writePostureShow(os.Stdout, store, fs.Arg(0))
	if errors.Is(err, errNodeNotFound) {
		fmt.Fprintf(os.Stderr, "xunara: node %q not found\n", fs.Arg(0))
		os.Exit(1)
	}
	if err != nil {
		fatal("reading device posture attributes", err)
	}
}

// writePostureShow renders one machine's attributes and their values.
func writePostureShow(w io.Writer, store state.Store, ref string) error {
	node, ok := lookupNode(store, ref)
	if !ok {
		return fmt.Errorf("%w: %s", errNodeNotFound, ref)
	}

	attrs, err := store.NodeDeviceAttrs(node.ID)
	if err != nil {
		return err
	}

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintf(tw, "NODE\t%d\n", node.ID)
	fmt.Fprintf(tw, "STABLE ID\t%s\n", node.StableID)
	fmt.Fprintf(tw, "HOSTNAME\t%s\n", node.Hostname)
	fmt.Fprintf(tw, "ATTRS\t%d\n", len(attrs))
	tw.Flush()

	if len(attrs) == 0 {
		fmt.Fprintln(w, "\nThis machine has not reported any device posture attributes.")
		return nil
	}

	names := make([]string, 0, len(attrs))
	for name := range attrs {
		names = append(names, name)
	}
	sort.Strings(names)

	fmt.Fprintln(w)
	tw = tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ATTR\tVALUE")
	for _, name := range names {
		// Values are safe to print: the control plane refuses values with
		// control characters, so a stored value cannot move the cursor or
		// inject ANSI escapes.
		fmt.Fprintf(tw, "%s\t%v\n", name, attrs[name])
	}
	tw.Flush()
	return nil
}

// deviceAttrNames returns a machine's attribute names, sorted.
func deviceAttrNames(store state.Store, n state.Node) ([]string, error) {
	attrs, err := store.NodeDeviceAttrs(n.ID)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(attrs))
	for name := range attrs {
		names = append(names, name)
	}
	sort.Strings(names)
	return names, nil
}
