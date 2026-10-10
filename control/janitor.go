package control

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/xunara-net/xunara-server/identity"
	"github.com/xunara-net/xunara-server/state"
)

// runJanitor periodically reaps ephemeral nodes that have been offline for
// longer than the configured inactivity timeout.
func (s *Server) runJanitor(ctx context.Context) {
	ticker := time.NewTicker(ephemeralReapInterval)
	defer ticker.Stop()
	// Service health expiry runs on its own, faster ticker: withdrawal from
	// discovery is time-sensitive in a way the other reaps are not.
	health := time.NewTicker(serviceHealthSweepInterval)
	defer health.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			now := time.Now().UTC()
			s.ReapEphemeral(now)
			s.reapSSHChecks(now)
			s.reapACMEChallenges(now)
			s.reapPasskeyCeremonies(now)
			s.reapFluxTransfers(now)
			s.reapRateLimits(now)
			s.reapReach(now)
		case <-health.C:
			s.reapServiceHealth(time.Now().UTC())
		}
	}
}

// reapRateLimits deletes idle rate limit buckets. Nothing references a bucket
// once its window passed, so age alone decides when it goes (spec section 28).
func (s *Server) reapRateLimits(now time.Time) {
	removed, err := s.store.PruneRateLimits(now.Add(-rateLimitPruneAge))
	if err != nil {
		s.log.Warn("pruning rate limit buckets failed", "err", err)
		return
	}
	if removed > 0 {
		s.log.Debug("pruned rate limit buckets", "count", removed)
	}
}

// reapServiceHealth withdraws health-tracked services whose last readiness
// report has expired (spec section 26). A node that stopped reporting - agent
// stopped, network gone - therefore leaves discovery on its own; the service
// record survives, so administrators still see what the node claims, and the
// next report makes it discoverable again.
func (s *Server) reapServiceHealth(now time.Time) {
	changes, err := s.store.ExpireServiceHealth(now)
	if err != nil {
		s.log.Warn("expiring service health", "err", err)
		return
	}
	if len(changes) == 0 {
		return
	}
	var affected []state.Node
	seen := make(map[state.NodeID]bool, len(changes))
	for _, change := range changes {
		node, ok := s.store.GetNodeByID(change.NodeID)
		if !ok {
			// The node was deleted; the cascade already dropped its
			// services, so there is nothing to announce.
			continue
		}
		s.auditServiceHealth(change, node)
		if !seen[node.ID] {
			seen[node.ID] = true
			affected = append(affected, node)
		}
	}
	s.log.Info("withdrew services with expired health reports", "count", len(changes))
	// Withdrawal removes MagicDNS records, so every session whose netmap
	// carries them must be woken - including the other side of a share.
	for _, node := range affected {
		s.notifyNodePeers(node)
	}
}

// reapACMEChallenges removes DNS-01 challenge records past their TTL, from
// both the internal table and the public zone. Certificate authorities read a
// challenge within minutes; keeping the records for a day leaves ample slack
// for retries without letting them pile up.
func (s *Server) reapACMEChallenges(now time.Time) {
	for _, r := range s.store.ListDNSRecords() {
		if !isACMEChallengeName(r.Name) || r.Type != "TXT" {
			continue
		}
		if now.Sub(r.Created) < certChallengeTTL {
			continue
		}
		if err := s.store.DeleteDNSRecord(r.ID); err != nil {
			s.log.Warn("removing expired ACME challenge record", "record_id", r.ID, "err", err)
			continue
		}
		if s.cfg.DNSProvider != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			if err := s.cfg.DNSProvider.DeleteTXT(ctx, r.Name); err != nil {
				s.log.Warn("removing ACME challenge from the public zone", "name", r.Name, "err", err)
			}
			cancel()
		}
		s.log.Info("removed expired ACME challenge record", "name", r.Name, "record_id", r.ID)
	}
}

// reapSSHChecks removes SSH check sessions past their TTL.
func (s *Server) reapSSHChecks(now time.Time) {
	deleted, err := s.identity.DeleteExpiredSSHCheckSessions(now)
	if err != nil {
		s.log.Warn("reaping ssh check sessions", "err", err)
		return
	}
	if deleted > 0 {
		s.log.Info("reaped expired ssh check sessions", "count", deleted)
	}
}

// reapPasskeyCeremonies removes WebAuthn challenges past their TTL. A
// ceremony is answered within seconds; keeping the rows for their five-minute
// TTL leaves slack for a slow user gesture without letting challenges pile up.
func (s *Server) reapPasskeyCeremonies(now time.Time) {
	deleted, err := s.identity.DeleteExpiredPasskeyCeremonies(now)
	if err != nil {
		s.log.Warn("reaping passkey ceremonies", "err", err)
		return
	}
	if deleted > 0 {
		s.log.Info("reaped expired passkey ceremonies", "count", deleted)
	}
}

// reapFluxTransfers expires transfers past their TTL, prunes finished ones
// after their retention window, and sweeps content files whose row is gone
// (the cascade that runs when a node is deleted cannot remove files).
func (s *Server) reapFluxTransfers(now time.Time) {
	if s.flux == nil {
		return
	}

	expired, err := s.store.ExpireFluxTransfers(now)
	if err != nil {
		s.log.Warn("expiring flux transfers", "err", err)
	} else {
		for _, transfer := range expired {
			s.flux.removeContent(transfer.ID)
			s.audit("system", identity.AuditFluxExpired, "flux:"+transfer.ID,
				fmt.Sprintf("expired %s (%d bytes)", transfer.Name, transfer.Size))
		}
		if len(expired) > 0 {
			s.log.Info("expired flux transfers", "count", len(expired))
		}
	}

	if pruned, err := s.store.PruneFluxTransfers(now.Add(-fluxTerminalRetention)); err != nil {
		s.log.Warn("pruning flux transfers", "err", err)
	} else {
		for _, transfer := range pruned {
			s.flux.removeContent(transfer.ID)
		}
	}

	s.sweepFluxOrphans()
}

// sweepFluxOrphans removes content files that no transfer row references.
// Without it, deleting a node would leave its uploaded ciphertext behind
// forever.
func (s *Server) sweepFluxOrphans() {
	entries, err := os.ReadDir(s.flux.dir)
	if err != nil {
		s.log.Warn("scanning the flux content directory", "err", err)
		return
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		id, ok := strings.CutSuffix(name, ".bin")
		if !ok {
			// A leftover upload temp file from a crash.
			if strings.HasPrefix(name, ".upload-") {
				os.Remove(filepath.Join(s.flux.dir, name))
			}
			continue
		}
		if _, ok := s.store.GetFluxTransfer(id); !ok {
			if err := os.Remove(filepath.Join(s.flux.dir, name)); err != nil {
				s.log.Warn("removing orphaned flux content", "file", name, "err", err)
			}
		}
	}
}

// ReapEphemeral deletes ephemeral nodes that have been offline for at least the
// configured inactivity timeout, and reports how many were removed.
//
// A node that never came online is measured from its creation time, so a
// machine that registers and disappears is still collected.
func (s *Server) ReapEphemeral(now time.Time) int {
	timeout := s.cfg.EphemeralInactivityTimeout
	if timeout <= 0 {
		timeout = DefaultEphemeralInactivityTimeout
	}

	reaped := 0
	var removed []state.Node
	for _, n := range s.store.ListNodes() {
		if !n.Ephemeral || s.isOnline(n.ID) {
			continue
		}

		lastActive := n.Created
		if n.LastSeen != nil {
			lastActive = *n.LastSeen
		}
		if now.Sub(lastActive) < timeout {
			continue
		}

		if err := s.store.DeleteNode(n.ID); err != nil {
			s.log.Warn("reaping ephemeral node", "node_id", int(n.ID), "err", err)
			continue
		}
		s.log.Info("reaped ephemeral node", "node_id", int(n.ID), "stable_id", n.StableID)
		s.audit("system", identity.AuditNodeReaped, nodeTarget(n),
			"deleted an ephemeral node that stayed offline past the inactivity timeout")
		removed = append(removed, n)
		reaped++
	}

	for _, n := range removed {
		s.notifyNodePeers(n)
	}
	return reaped
}

// nodeKeyExpiry returns the expiry timestamp to grant a node registering now.
func (s *Server) nodeKeyExpiry(now time.Time) time.Time {
	if s.cfg.NodeKeyExpiry <= 0 {
		return time.Time{}
	}
	return now.Add(s.cfg.NodeKeyExpiry).UTC()
}

// applyRegistrationDefaults fills in the fields every new node shares.
func (s *Server) applyRegistrationDefaults(n *state.Node, now time.Time) {
	// Tagged nodes carry a tag instead of a user identity and never expire:
	// that is the upstream behaviour, and a tagged node can always be
	// re-authorized by whoever owns its tag.
	if len(n.Tags) > 0 {
		n.Expiry = time.Time{}
		return
	}

	n.Expiry = s.nodeKeyExpiry(now)

	// The client may request a shorter expiry than the server default.
	if req := n.RequestedExpiry; !req.IsZero() {
		if n.Expiry.IsZero() || req.Before(n.Expiry) {
			n.Expiry = req.UTC()
		}
	}
}

// configWatchInterval is how often the server checks for configuration changes
// made outside a control session (the administration CLI, or a second server
// instance writing to the same database).
const configWatchInterval = 2 * time.Second

// runConfigWatcher re-pushes the netmap to every connected client whenever the
// store's configuration revision advances.
//
// Node facts learned from a live session wake watchers directly; this covers
// everything that happens out of band. See [state.Store.ConfigRevision].
func (s *Server) runConfigWatcher(ctx context.Context) {
	ticker := time.NewTicker(configWatchInterval)
	defer ticker.Stop()

	last := s.store.ConfigRevision()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// 期望库已提交而节点库失败时，通知版本尚未增加，也必须重试收敛。
			if err := s.refreshAddressAllocation(ctx); err != nil {
				s.log.Error("reconciling allocation range", "err", err)
				continue
			}
			if rev := s.store.ConfigRevision(); rev != last {
				if err := s.refreshManagedConfiguration(ctx); err != nil {
					s.log.Error("refreshing committed network configuration", "err", err)
					continue
				}
				last = rev
				s.notifyWatchers()
			}
		}
	}
}
