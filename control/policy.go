package control

import (
	"context"
	"os"
	"time"

	"tailscale.com/tailcfg"

	"github.com/xunara-net/xunara-server/identity"
	"github.com/xunara-net/xunara-server/policy"
)

// policyWatchInterval is how often the server checks the policy file for
// changes, so an edited ACL takes effect without a restart.
const policyWatchInterval = 2 * time.Second

// loadPolicy reads, parses and compiles the configured policy document,
// replacing the engine the server compiles netmaps from.
//
// A broken document is never applied: the previous policy stays in force and
// the error is returned, because silently falling back to allow-all would open
// the tailnet up.
func (s *Server) loadPolicy() error {
	if s.cfg.PolicyPath == "" {
		return nil
	}

	doc, err := policy.Load(s.cfg.PolicyPath)
	if err != nil {
		return err
	}

	engine, err := policy.NewEngine(doc, policy.Options{
		Domain:    s.cfg.Domain,
		LoginName: s.userLoginName,
		ServerURL: s.cfg.ServerURL,
	})
	if err != nil {
		return err
	}

	for _, warning := range engine.Warnings() {
		s.log.Warn("policy", "warning", warning)
	}
	s.log.Info("policy loaded",
		"path", s.cfg.PolicyPath,
		"rules", engine.RuleCount(),
		"unsupported_fields", doc.Unsupported)

	s.policy.Store(engine)

	// Remembered SSH check approvals belong to the rules that granted them;
	// a policy swap must not silently keep them alive.
	if err := s.identity.ClearSSHCheckAuth(); err != nil {
		s.log.Warn("clearing ssh check approvals", "err", err)
	}
	return nil
}

// runPolicyWatcher reloads the policy file when it changes on disk.
func (s *Server) runPolicyWatcher(ctx context.Context) {
	if s.cfg.PolicyPath == "" {
		return
	}

	ticker := time.NewTicker(policyWatchInterval)
	defer ticker.Stop()

	last := policyModTime(s.cfg.PolicyPath)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			mod := policyModTime(s.cfg.PolicyPath)
			if mod.IsZero() || mod.Equal(last) {
				continue
			}
			last = mod

			if err := s.loadPolicy(); err != nil {
				s.log.Error("reloading policy failed; keeping the previous policy",
					"path", s.cfg.PolicyPath, "err", err)
				continue
			}
			s.audit("system", identity.AuditPolicyReloaded, "policy:"+s.cfg.PolicyPath,
				"reloaded after the file changed on disk")
			s.notifyWatchers()
		}
	}
}

// policyModTime returns the file's modification time, or the zero time when it
// cannot be read.
func policyModTime(path string) time.Time {
	info, err := os.Stat(path)
	if err != nil {
		return time.Time{}
	}
	return info.ModTime()
}

// userLoginName maps a user to the login name ACL selectors are written with.
//
// It reads the trust plane so that renaming a user also renames what selectors
// like "user:alice@example.com" match, and falls back to the default profile
// for users the identity store does not know.
func (s *Server) userLoginName(id tailcfg.UserID) string {
	return s.UserProfile(id).LoginName
}
