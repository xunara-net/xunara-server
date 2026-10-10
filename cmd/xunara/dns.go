package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"text/tabwriter"
	"time"

	"github.com/xunara-net/xunara-server/identity"
	"github.com/xunara-net/xunara-server/state"
)

// runDNS implements "xunara dns": inspecting and pruning the MagicDNS records
// clients publish through /machine/set-dns.
func runDNS(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "xunara: dns requires a subcommand: list, delete or check")
		os.Exit(2)
	}

	switch args[0] {
	case "list":
		runDNSList(args[1:])
	case "delete":
		runDNSDelete(args[1:])
	case "check":
		runDNSCheck(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "xunara: unknown dns subcommand %q\n", args[0])
		os.Exit(2)
	}
}

func runDNSCheck(args []string) {
	flags := flag.NewFlagSet("dns check", flag.ExitOnError)
	stateDir := flags.String("state-dir", "data", "control server state directory")
	domain := flags.String("domain", "", "configured MagicDNS domain; empty means disabled")
	flags.Parse(args)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := state.CheckDNSNamespace(ctx, filepath.Join(*stateDir, "state.db"), *domain); err != nil {
		fatal("checking DNS name ownership", err)
	}
	fmt.Println("DNS name ownership check passed (read-only; no migrations applied)")
}

func runDNSList(args []string) {
	fs := flag.NewFlagSet("dns list", flag.ExitOnError)
	stateDir := fs.String("state-dir", "data", "control server state directory")
	fs.Parse(args)

	store := openStore(*stateDir)
	defer store.Close()

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tNAME\tTYPE\tVALUE\tNODE\tCREATED")

	for _, r := range store.ListDNSRecords() {
		node := "-"
		if r.NodeID != 0 {
			node = strconv.FormatUint(uint64(r.NodeID), 10)
		}
		fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\t%s\n",
			r.ID, r.Name, r.Type, r.Value, node, r.Created.Format(time.RFC3339))
	}
	w.Flush()
}

func runDNSDelete(args []string) {
	fs := flag.NewFlagSet("dns delete", flag.ExitOnError)
	stateDir := fs.String("state-dir", "data", "control server state directory")
	all := fs.Bool("all", false, "delete every record")
	fs.Parse(args)

	store := openStore(*stateDir)
	defer store.Close()

	if *all {
		for _, r := range store.ListDNSRecords() {
			if err := store.DeleteDNSRecord(r.ID); err != nil {
				fatal("deleting DNS record", err)
			}
			appendAudit(store, identity.AuditDNSRecordDeleted,
				fmt.Sprintf("dns:%s/%s", r.Name, r.Type), fmt.Sprintf("deleted record %d", r.ID))
		}
	} else {
		if fs.NArg() != 1 {
			fmt.Fprintln(os.Stderr, "usage: xunara dns delete [-state-dir DIR] <record-id> | -all")
			os.Exit(2)
		}
		id, err := strconv.ParseUint(fs.Arg(0), 10, 64)
		if err != nil {
			fatal("parsing record ID", err)
		}
		var record *state.DNSRecord
		for _, r := range store.ListDNSRecords() {
			if r.ID == id {
				record = &r
				break
			}
		}
		if err := store.DeleteDNSRecord(id); err != nil {
			fatal("deleting DNS record", err)
		}
		if record != nil {
			appendAudit(store, identity.AuditDNSRecordDeleted,
				fmt.Sprintf("dns:%s/%s", record.Name, record.Type), fmt.Sprintf("deleted record %d", record.ID))
		}
	}

	if err := store.BumpConfigRevision(); err != nil {
		fatal("bumping configuration revision", err)
	}
}
