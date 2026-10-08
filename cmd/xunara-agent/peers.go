package main

// This file resolves a user-typed peer address (`-to <hostname|stable-id>`)
// into a node stable ID using this agent's netmap. Flux and Reach address
// peers the same way; the control plane always receives a stable ID, so a
// duplicated hostname can never be resolved to the wrong node server-side.

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"

	"tailscale.com/tailcfg"

	"github.com/xunara-net/xunara-server/client/protocol"
)

// resolvePeer maps -to onto a node stable ID. A stable ID is passed through
// when no peer matches it (the control plane validates it); any other value
// must match exactly one peer by hostname. selfError is returned when the
// value resolves to this node itself.
func resolvePeer(ctx context.Context, client *protocol.Client, token string, keys protocol.Keys, to, selfError string) (string, error) {
	to = strings.TrimSpace(to)
	netmap, err := client.Netmap(ctx, token, keys)
	if err != nil {
		return "", fmt.Errorf("resolving %q: %w", to, err)
	}

	type match struct{ stableID, name string }
	var matches []match
	add := func(n *tailcfg.Node) {
		if n == nil {
			return
		}
		for _, m := range matches {
			if m.stableID == string(n.StableID) {
				return
			}
		}
		matches = append(matches, match{stableID: string(n.StableID), name: peerName(n)})
	}
	if peerMatches(netmap.Node, to) {
		add(netmap.Node)
	}
	for _, peer := range netmap.Peers {
		if peerMatches(peer, to) {
			add(peer)
		}
	}

	switch {
	case len(matches) == 1:
		if netmap.Node != nil && matches[0].stableID == string(netmap.Node.StableID) {
			return "", errors.New(selfError)
		}
		return matches[0].stableID, nil
	case len(matches) > 1:
		ids := make([]string, 0, len(matches))
		for _, m := range matches {
			ids = append(ids, m.stableID)
		}
		sort.Strings(ids)
		return "", fmt.Errorf("%q matches several nodes (%s); use a stable ID", to, strings.Join(ids, ", "))
	case looksLikeStableID(to):
		return to, nil
	default:
		return "", fmt.Errorf("no node matches %q", to)
	}
}

// peerMatches reports whether a netmap node answers to a user-typed name.
func peerMatches(n *tailcfg.Node, want string) bool {
	if n == nil {
		return false
	}
	want = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(want), "."))
	if want == "" {
		return false
	}
	if strings.ToLower(string(n.StableID)) == want {
		return true
	}
	for _, candidate := range peerNames(n) {
		if strings.ToLower(strings.TrimSuffix(candidate, ".")) == want {
			return true
		}
	}
	return false
}

// peerNames are the names a user may type for a node.
func peerNames(n *tailcfg.Node) []string {
	var names []string
	if n.Hostinfo.Valid() {
		names = append(names, n.Hostinfo.Hostname())
	}
	if n.ComputedName != "" {
		names = append(names, n.ComputedName)
	}
	if n.Name != "" {
		names = append(names, strings.TrimSuffix(n.Name, "."))
		if label, _, ok := strings.Cut(n.Name, "."); ok {
			names = append(names, label)
		}
	}
	return names
}

// peerName picks the friendliest name of a node for messages.
func peerName(n *tailcfg.Node) string {
	for _, name := range peerNames(n) {
		if name != "" {
			return name
		}
	}
	if n != nil {
		return string(n.StableID)
	}
	return ""
}

// looksLikeStableID reports whether a value has the shape of a node stable ID
// ("n" + 16 hex characters), so a node that is not in this netmap can still
// be addressed by its ID.
func looksLikeStableID(value string) bool {
	if len(value) != 17 || value[0] != 'n' {
		return false
	}
	_, err := hex.DecodeString(value[1:])
	return err == nil
}
