package main

// This file implements `xunara-agent flux`: sending files to and receiving
// files from other agents through the control plane (Xunara Flux, PROJECT_SPEC
// section 25).
//
// The control plane relays ciphertext only. Everything that keeps content
// private happens here: the sender seals the file for the recipient's
// per-transfer public key (client/flux), and the recipient decrypts with a key
// derived from its local seed, verifies the declared SHA-256, and only then
// confirms the transfer. A recipient that cannot decrypt or verify fails the
// transfer instead of writing unverified bytes.

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"
	"unicode"

	"github.com/xunara-net/xunara-server/client/flux"
	"github.com/xunara-net/xunara-server/client/protocol"
)

// Flux CLI defaults and bounds.
const (
	// fluxDefaultTimeout bounds one send from offer to confirmed delivery.
	fluxDefaultTimeout = 5 * time.Minute
	// fluxPollInterval is how often send and receive re-check a transfer.
	fluxPollInterval = 2 * time.Second
	// fluxWatchInterval is how often `flux receive -watch` looks for new work.
	fluxWatchInterval = 5 * time.Second
	// fluxUploadWait bounds how long receive waits for the sender to upload
	// after an accept; the transfer stays accepted, so a later run picks it
	// up when the sender comes back.
	fluxUploadWait = time.Minute
	// maxFluxFileSize is the client-side ceiling on a transfer. It mirrors
	// the control plane's hard cap (PROJECT_SPEC section 25.2); a given
	// deployment may refuse smaller files, which the server reports.
	maxFluxFileSize = 64 << 20
)

// runFlux implements `xunara-agent flux`.
func runFlux(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("flux needs a subcommand: send, list, deny or receive")
	}
	switch args[0] {
	case "send":
		return runFluxSend(ctx, args[1:])
	case "list":
		return runFluxList(ctx, args[1:])
	case "deny":
		return runFluxDeny(ctx, args[1:])
	case "receive":
		return runFluxReceive(ctx, args[1:])
	default:
		return fmt.Errorf("unknown flux subcommand %q", args[0])
	}
}

// runFluxSend implements `xunara-agent flux send -to <hostname|stable-id>
// -file <path>`: offer the file, wait for the recipient to accept, upload the
// sealed content, and wait for the recipient to confirm delivery.
func runFluxSend(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("flux send", flag.ExitOnError)
	stateDir := fs.String("state-dir", defaultStateDir(), "directory holding agent.json")
	to := fs.String("to", "", "recipient node: a hostname or a node stable ID")
	file := fs.String("file", "", "file to send")
	timeout := fs.Duration("timeout", fluxDefaultTimeout, "give up after this long")
	asJSON := fs.Bool("json", false, "print the final transfer as JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *to == "" {
		return errors.New("flux send needs -to <hostname|stable-id>")
	}
	if *file == "" {
		return errors.New("flux send needs -file <path>")
	}
	if *timeout <= 0 {
		return errors.New("flux send -timeout must be positive")
	}

	info, err := os.Stat(*file)
	if err != nil {
		return fmt.Errorf("reading -file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", *file)
	}
	if info.Size() > maxFluxFileSize {
		return fmt.Errorf("%s is %d bytes; Xunara Flux sends files up to %d bytes", *file, info.Size(), maxFluxFileSize)
	}

	state, keys, client, err := enrolledClient(*stateDir)
	if err != nil {
		return err
	}
	// One request must not outlive the whole operation's budget.
	client.HTTP.Timeout = *timeout

	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()

	recipient, err := resolvePeer(ctx, client, state.Token, keys, *to, "a node cannot send a file to itself")
	if err != nil {
		return err
	}
	plaintext, sum, err := readFluxFile(*file, info.Size())
	if err != nil {
		return err
	}

	transfer, err := client.CreateFluxTransfer(ctx, state.Token, keys, protocol.FluxOffer{
		Recipient: recipient,
		Name:      filepath.Base(*file),
		Size:      int64(len(plaintext)),
		SHA256:    sum,
	})
	if err != nil {
		return err
	}
	fluxProgress("Offered %s (%s) to %s as %s", transfer.Name, humanBytes(transfer.Size), *to, transfer.ID)

	transfer, err = waitForFluxTransfer(ctx, client, state.Token, keys, transfer.ID,
		func(t protocol.FluxTransfer) bool { return t.State != protocol.FluxPending })
	if err != nil {
		return err
	}
	if transfer.State != protocol.FluxAccepted {
		return fluxTerminalError(transfer)
	}
	fluxProgress("%s accepted %s", dashIfEmpty(transfer.RecipientHostname), transfer.ID)

	public, err := base64.StdEncoding.DecodeString(transfer.RecipientKey)
	if err != nil || len(public) != flux.PublicKeySize {
		return errors.New("the recipient published an invalid transfer key; ask it to retry")
	}
	sealed, err := flux.Seal(public, transfer.ID, plaintext)
	if err != nil {
		return err
	}
	plaintext = nil

	if _, err := client.UploadFluxContent(ctx, state.Token, keys, transfer.ID, bytes.NewReader(sealed)); err != nil {
		return err
	}
	transfer, err = waitForFluxTransfer(ctx, client, state.Token, keys, transfer.ID,
		func(t protocol.FluxTransfer) bool { return t.State != protocol.FluxUploaded })
	if err != nil {
		return err
	}
	if transfer.State != protocol.FluxCompleted {
		return fluxTerminalError(transfer)
	}

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(transfer)
	}
	fmt.Printf("Delivered %s (%s) to %s.\n", transfer.Name, humanBytes(transfer.Size), dashIfEmpty(transfer.RecipientHostname))
	return nil
}

// readFluxFile reads the file into memory and returns its plaintext SHA-256.
// The hash covers exactly the bytes that will be uploaded, so a file that
// changed size between stat and read is refused instead of sending content
// the recipient cannot verify.
func readFluxFile(path string, want int64) ([]byte, string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, "", fmt.Errorf("reading %s: %w", path, err)
	}
	defer f.Close()

	data, err := io.ReadAll(io.LimitReader(f, want+1))
	if err != nil {
		return nil, "", fmt.Errorf("reading %s: %w", path, err)
	}
	if int64(len(data)) != want {
		return nil, "", fmt.Errorf("%s changed while sending; try again", path)
	}
	sum := sha256.Sum256(data)
	return data, hex.EncodeToString(sum[:]), nil
}

// runFluxList implements `xunara-agent flux list`: this node's transfers.
func runFluxList(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("flux list", flag.ExitOnError)
	stateDir := fs.String("state-dir", defaultStateDir(), "directory holding agent.json")
	asJSON := fs.Bool("json", false, "print the transfers as JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}

	state, keys, client, err := enrolledClient(*stateDir)
	if err != nil {
		return err
	}
	transfers, err := client.ListFluxTransfers(ctx, state.Token, keys)
	if err != nil {
		return err
	}
	if *asJSON {
		if transfers == nil {
			transfers = []protocol.FluxTransfer{}
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(struct {
			Transfers []protocol.FluxTransfer `json:"transfers"`
		}{Transfers: transfers})
	}
	return writeFluxTransfers(os.Stdout, transfers)
}

// runFluxDeny implements `xunara-agent flux deny -reason <text> <id>`: refuse
// an inbound offer the recipient does not want.
func runFluxDeny(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("flux deny", flag.ExitOnError)
	stateDir := fs.String("state-dir", defaultStateDir(), "directory holding agent.json")
	reason := fs.String("reason", "", "static explanation shown to the sender")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("flux deny needs exactly one transfer ID")
	}
	id := fs.Arg(0)

	state, keys, client, err := enrolledClient(*stateDir)
	if err != nil {
		return err
	}
	transfer, err := client.DenyFluxTransfer(ctx, state.Token, keys, id, *reason)
	if err != nil {
		return err
	}
	fmt.Printf("Denied %s (%s from %s).\n", transfer.ID, transfer.Name, dashIfEmpty(transfer.SenderHostname))
	return nil
}

// runFluxReceive implements `xunara-agent flux receive -dir <dir>`: accept
// pending inbound offers, fetch and verify their content, and write the
// plaintext into a directory. `-yes` accepts without prompting; `-watch`
// keeps polling.
func runFluxReceive(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("flux receive", flag.ExitOnError)
	stateDir := fs.String("state-dir", defaultStateDir(), "directory holding agent.json")
	dir := fs.String("dir", "", "directory to write received files into")
	assumeYes := fs.Bool("yes", false, "accept without prompting (required without an interactive terminal)")
	watch := fs.Bool("watch", false, "keep polling for new transfers")
	interval := fs.Duration("interval", fluxWatchInterval, "poll interval with -watch")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dir == "" {
		return errors.New("flux receive needs -dir <directory>")
	}
	if *interval < time.Second {
		return errors.New("flux receive -interval must be at least 1s")
	}

	state, keys, client, err := enrolledClient(*stateDir)
	if err != nil {
		return err
	}
	seed, err := flux.LoadOrCreateSeed(*stateDir)
	if err != nil {
		return err
	}

	// Skipped offers are not asked about again while this process watches;
	// denying them stays an explicit `flux deny`.
	skipped := make(map[string]bool)
	for {
		worked, failed, err := receiveFluxOnce(ctx, client, state.Token, keys, seed, *dir, *assumeYes, skipped)
		if err != nil {
			return err
		}
		if !*watch {
			if failed > 0 {
				return fmt.Errorf("%d transfer(s) could not be received", failed)
			}
			if worked == 0 {
				fmt.Fprintln(os.Stdout, "No inbound transfers need attention.")
			}
			return nil
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(*interval):
		}
	}
}

// receiveFluxOnce runs one pass over this node's inbound transfers and
// returns how many it acted on and how many failed. Failures are reported to
// the caller, which decides whether they are fatal (single pass) or just
// logged (watch mode); every failure has already been reported to the control
// plane as a failed transfer.
func receiveFluxOnce(ctx context.Context, client *protocol.Client, token string, keys protocol.Keys, seed []byte, dir string, assumeYes bool, skipped map[string]bool) (worked, failed int, err error) {
	transfers, err := client.ListFluxTransfers(ctx, token, keys)
	if err != nil {
		return 0, 0, err
	}

	for _, transfer := range transfers {
		if transfer.Direction != "received" {
			continue
		}
		switch transfer.State {
		case protocol.FluxPending:
			if skipped[transfer.ID] {
				continue
			}
			ok, err := confirmFluxAccept(transfer, assumeYes)
			if err != nil {
				return worked, failed, err
			}
			if !ok {
				skipped[transfer.ID] = true
				fluxProgress("Skipped %s (%s from %s).", transfer.ID, transfer.Name, dashIfEmpty(transfer.SenderHostname))
				continue
			}
			public, err := flux.RecipientPublicKey(seed, transfer.ID)
			if err != nil {
				return worked, failed, err
			}
			accepted, err := client.AcceptFluxTransfer(ctx, token, keys, transfer.ID, public)
			if err != nil {
				reportFluxFailure(transfer, err)
				failed++
				continue
			}
			worked++
			fluxProgress("Accepted %s (%s from %s).", transfer.ID, transfer.Name, dashIfEmpty(transfer.SenderHostname))

			switch accepted.State {
			case protocol.FluxUploaded:
				transfer = accepted
			case protocol.FluxAccepted:
				transfer, err = waitForFluxUpload(ctx, client, token, keys, transfer.ID)
				if err != nil {
					reportFluxFailure(transfer, err)
					failed++
					continue
				}
				if transfer.State != protocol.FluxUploaded {
					// The transfer ended while waiting (expired, failed by
					// the sender, ...); there is nothing to download.
					reportFluxFailure(transfer, fluxTerminalError(transfer))
					failed++
					continue
				}
			default:
				reportFluxFailure(transfer, fluxTerminalError(accepted))
				failed++
				continue
			}
		case protocol.FluxUploaded:
		default:
			// Terminal transfers need no action; accepted ones wait for the
			// sender to upload and are picked up by a later pass.
			continue
		}

		if err := fetchFluxContent(ctx, client, token, keys, seed, dir, transfer); err != nil {
			reportFluxFailure(transfer, err)
			failed++
			continue
		}
	}
	return worked, failed, nil
}

// confirmFluxAccept asks the operator about one offer. Without -yes, an
// unanswered prompt (no terminal) is an error: a scripted receive must say
// `-yes` out loud rather than silently accepting files.
func confirmFluxAccept(t protocol.FluxTransfer, assumeYes bool) (bool, error) {
	if assumeYes {
		return true, nil
	}
	fmt.Fprintf(os.Stdout, "Accept %s (%s) from %s? [y/N] ", t.Name, humanBytes(t.Size), dashIfEmpty(t.SenderHostname))

	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return false, fmt.Errorf("reading the answer: %w", err)
	}
	if strings.TrimSpace(line) == "" {
		return false, errors.New("no answer on stdin; pass -yes to accept transfers without prompting")
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return true, nil
	default:
		return false, nil
	}
}

// waitForFluxUpload waits for the sender to upload after an accept.
func waitForFluxUpload(ctx context.Context, client *protocol.Client, token string, keys protocol.Keys, id string) (protocol.FluxTransfer, error) {
	ctx, cancel := context.WithTimeout(ctx, fluxUploadWait)
	defer cancel()
	return waitForFluxTransfer(ctx, client, token, keys, id,
		func(t protocol.FluxTransfer) bool { return t.State != protocol.FluxAccepted })
}

// fetchFluxContent downloads, decrypts and verifies one uploaded transfer,
// writes it into dir, and only then completes it on the control plane. A
// failure that is the peer's fault (bad name, oversized or undecryptable
// content, digest mismatch) is reported as a failed transfer; a local failure
// (disk) leaves the transfer uploaded so it can be fetched again.
func fetchFluxContent(ctx context.Context, client *protocol.Client, token string, keys protocol.Keys, seed []byte, dir string, t protocol.FluxTransfer) error {
	if !safeFluxFileName(t.Name) {
		return failFluxTransfer(ctx, client, token, keys, t, "unsafe file name")
	}
	if t.Size < 0 || t.Size > maxFluxFileSize {
		return failFluxTransfer(ctx, client, token, keys, t, "declared size is out of range")
	}

	sealed, err := client.DownloadFluxContent(ctx, token, keys, t.ID)
	if err != nil {
		return err
	}
	if int64(len(sealed)) > t.Size+flux.Overhead {
		return failFluxTransfer(ctx, client, token, keys, t, "content exceeds the declared size")
	}
	plaintext, err := flux.Open(seed, t.ID, sealed)
	if err != nil {
		return failFluxTransfer(ctx, client, token, keys, t, "decryption failed")
	}
	sum := sha256.Sum256(plaintext)
	if int64(len(plaintext)) != t.Size || !strings.EqualFold(hex.EncodeToString(sum[:]), t.SHA256) {
		return failFluxTransfer(ctx, client, token, keys, t, "sha256 mismatch")
	}

	path, err := writeFluxFile(dir, t.Name, plaintext)
	if err != nil {
		return err
	}
	if _, err := client.CompleteFluxTransfer(ctx, token, keys, t.ID); err != nil {
		return fmt.Errorf("wrote %s but could not complete transfer %s on the control plane: %w", path, t.ID, err)
	}
	fmt.Printf("Received %s (%s) from %s as %s\n", t.Name, humanBytes(t.Size), dashIfEmpty(t.SenderHostname), path)
	return nil
}

// failFluxTransfer reports a peer-caused failure and returns a describing
// error. The reason is a fixed printable string: text that crosses to the
// other side never comes from local error values, which can carry paths.
func failFluxTransfer(ctx context.Context, client *protocol.Client, token string, keys protocol.Keys, t protocol.FluxTransfer, reason string) error {
	if _, err := client.FailFluxTransfer(ctx, token, keys, t.ID, reason); err != nil {
		return fmt.Errorf("transfer %s (%s) failed: %s; reporting the failure also failed: %w", t.ID, t.Name, reason, err)
	}
	return fmt.Errorf("transfer %s (%s) failed: %s", t.ID, t.Name, reason)
}

// reportFluxFailure logs a failed handling attempt. Watching keeps running,
// so failures do not stop the loop.
func reportFluxFailure(t protocol.FluxTransfer, err error) {
	fmt.Fprintf(os.Stderr, "xunara-agent: flux: %v\n", err)
}

// waitForFluxTransfer polls until the transfer satisfies done. Transient poll
// errors are tolerated (a transfer that is already moving must not die on one
// bad response); an expired credential is not.
func waitForFluxTransfer(ctx context.Context, client *protocol.Client, token string, keys protocol.Keys, id string, done func(protocol.FluxTransfer) bool) (protocol.FluxTransfer, error) {
	last := protocol.FluxTransfer{ID: id}
	for {
		transfers, err := client.ListFluxTransfers(ctx, token, keys)
		switch {
		case err == nil:
			found := false
			for _, t := range transfers {
				if t.ID != id {
					continue
				}
				last, found = t, true
				if done(t) {
					return t, nil
				}
			}
			if !found {
				return last, fmt.Errorf("transfer %s is no longer known to the control plane", id)
			}
		case protocol.IsUnauthorized(err):
			return last, err
		default:
			fmt.Fprintf(os.Stderr, "xunara-agent: flux: polling %s: %v\n", id, err)
		}

		select {
		case <-ctx.Done():
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				return last, fmt.Errorf("timed out while transfer %s is %s; it stays open until the control plane expires it", id, dashIfEmpty(last.State))
			}
			return last, ctx.Err()
		case <-time.After(fluxPollInterval):
		}
	}
}

// writeFluxTransfers renders the transfer table.
func writeFluxTransfers(w io.Writer, transfers []protocol.FluxTransfer) error {
	if len(transfers) == 0 {
		fmt.Fprintln(w, "No transfers.")
		return nil
	}

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tDIR\tPEER\tNAME\tSIZE\tSTATE\tUPDATED")
	for _, t := range transfers {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			t.ID, t.Direction, dashIfEmpty(t.Peer()), t.Name,
			humanBytes(t.Size), t.State, dashIfZeroTime(t.UpdatedAt))
	}
	if err := tw.Flush(); err != nil {
		return err
	}

	for _, t := range transfers {
		if t.Reason == "" {
			continue
		}
		fmt.Fprintf(w, "\n%s (%s): %s\n", t.Name, t.State, t.Reason)
	}
	return nil
}

// humanBytes renders a byte count compactly, which is what transfer messages
// need; exact numbers are in the JSON output.
func humanBytes(n int64) string {
	switch {
	case n < 1<<10:
		return fmt.Sprintf("%d B", n)
	case n < 1<<20:
		return fmt.Sprintf("%.1f KiB", float64(n)/(1<<10))
	case n < 1<<30:
		return fmt.Sprintf("%.1f MiB", float64(n)/(1<<20))
	default:
		return fmt.Sprintf("%.1f GiB", float64(n)/(1<<30))
	}
}

// safeFluxFileName accepts only names that are safe to open inside the
// receive directory. The control plane validates names too; this is the same
// rule applied where the file is actually created.
func safeFluxFileName(name string) bool {
	if name == "" || name == "." || name == ".." {
		return false
	}
	if strings.ContainsAny(name, `/\`) || filepath.Base(name) != name {
		return false
	}
	for _, r := range name {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

// fluxCopyLimit bounds how many numbered copies receive tries before giving
// up on a directory.
const fluxCopyLimit = 1000

// writeFluxFile writes content into dir under name, never overwriting: an
// existing file shifts the new one to "name.1", "name.2", and so on. The
// content lands in a 0600 temp file first (a crash cannot leave a truncated
// file under the final name) and is hard-linked into place, so even a file
// that appears between the checks is not replaced.
func writeFluxFile(dir, name string, content []byte) (string, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("creating %s: %w", dir, err)
	}

	tmp, err := os.CreateTemp(dir, "."+name+".tmp*")
	if err != nil {
		return "", fmt.Errorf("creating a temporary file in %s: %w", dir, err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return "", fmt.Errorf("setting permissions on %s: %w", tmpName, err)
	}
	if _, err := tmp.Write(content); err != nil {
		tmp.Close()
		return "", fmt.Errorf("writing %s: %w", tmpName, err)
	}
	if err := tmp.Close(); err != nil {
		return "", fmt.Errorf("closing %s: %w", tmpName, err)
	}

	for i := 0; i <= fluxCopyLimit; i++ {
		target := filepath.Join(dir, name)
		if i > 0 {
			target = filepath.Join(dir, fmt.Sprintf("%s.%d", name, i))
		}
		switch err := os.Link(tmpName, target); {
		case err == nil:
			return target, nil
		case errors.Is(err, os.ErrExist):
			continue
		default:
			// A filesystem without hard links: fall back to rename, which
			// cannot be made no-replace portably; the explicit check keeps
			// the common case honest.
			if _, statErr := os.Stat(target); statErr == nil {
				continue
			}
			if err := os.Rename(tmpName, target); err != nil {
				return "", fmt.Errorf("moving the received file into place: %w", err)
			}
			return target, nil
		}
	}
	return "", fmt.Errorf("more than %d copies of %s already exist in %s", fluxCopyLimit, name, dir)
}

// fluxTerminalError renders a transfer that ended without delivery.
func fluxTerminalError(t protocol.FluxTransfer) error {
	message := fmt.Sprintf("transfer %s is %s", t.ID, dashIfEmpty(t.State))
	if t.Reason != "" {
		message += ": " + t.Reason
	}
	return errors.New(message)
}

// fluxProgress reports long-running progress on stderr, so stdout stays
// machine-readable.
func fluxProgress(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "xunara-agent: flux: "+format+"\n", args...)
}
