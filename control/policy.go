package control

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"time"

	"github.com/tailscale/hujson"
	"tailscale.com/tailcfg"

	"github.com/xunara-net/xunara-server/identity"
	"github.com/xunara-net/xunara-server/networkconfig"
	"github.com/xunara-net/xunara-server/policy"
)

const policyWatchInterval = 2 * time.Second
const legacyDefaultPolicy = `{"acls":[{"action":"accept","src":["*"],"dst":["*:*"]}]}`

type policyConfiguration struct {
	Revision uint64
	Source   string
	Content  string
	JSON     json.RawMessage
}

func contentHash(content string) string {
	hash := sha256.Sum256([]byte(content))
	return hex.EncodeToString(hash[:])
}

func (server *Server) policyOptions() policy.Options {
	return policy.Options{Domain: server.cfg.Domain, LoginName: server.userLoginName, ServerURL: server.cfg.ServerURL}
}

func (server *Server) loadPolicy() error {
	server.networkMu.Lock()
	defer server.networkMu.Unlock()
	return server.loadPolicyLocked(context.Background(), true)
}

// 数据库发布后不再读取文件作为权威；读取/编译失败绝不替换为 allow-all。
func (server *Server) loadPolicyLocked(ctx context.Context, force ...bool) error {
	document, found, err := server.networkConfig.Get(ctx, networkconfig.Policy)
	if err != nil {
		return err
	}
	configuration := &policyConfiguration{Source: "default", Content: legacyDefaultPolicy}
	if !found && server.policyConfig.Load() != nil && server.policyConfig.Load().Source == "database" {
		return networkconfig.ErrNotFound
	}
	if found {
		configuration.Revision = document.Revision
		configuration.Source = "database"
		configuration.Content = document.Content
	} else if server.cfg.PolicyPath != "" {
		raw, err := os.ReadFile(server.cfg.PolicyPath)
		if err != nil {
			return err
		}
		configuration.Source = "file"
		configuration.Content = string(raw)
	}
	forceFileReload := len(force) != 0 && force[0] && configuration.Source == "file"
	if current := server.policyConfig.Load(); !forceFileReload && current != nil && configuration.Revision == current.Revision && configuration.Source == current.Source && configuration.Content == current.Content {
		return nil
	}
	var parsed *policy.Document
	if found {
		parsed, configuration.JSON, err = policy.ParseManaged([]byte(configuration.Content))
	} else {
		parsed, err = policy.ParseString(configuration.Content)
		if err == nil {
			configuration.JSON, err = hujson.Standardize([]byte(configuration.Content))
		}
	}
	if err != nil {
		return err
	}
	engine, err := policy.NewEngine(parsed, server.policyOptions())
	if err != nil {
		return err
	}
	if configuration.Source != "default" {
		if !found {
			if err := server.identity.ClearSSHCheckAuth(); err != nil {
				return err
			}
		}
		server.policy.Store(engine)
	} else {
		server.policy.Store(nil)
	}
	server.policyConfig.Store(configuration)
	return nil
}

func (server *Server) refreshManagedConfiguration(ctx context.Context) error {
	server.networkMu.Lock()
	defer server.networkMu.Unlock()
	previousPolicy, previousDNS := server.policyConfig.Load(), server.dnsConfig.Load()
	result := errors.Join(server.loadPolicyLocked(ctx), server.loadDNSConfiguration(ctx), server.refreshRelayMap(ctx))
	if previousPolicy != server.policyConfig.Load() || previousDNS != server.dnsConfig.Load() {
		server.notifyWatchers()
	}
	return result
}

func (server *Server) runPolicyWatcher(ctx context.Context) {
	ticker := time.NewTicker(policyWatchInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			previousPolicy := server.policyConfig.Load()
			previousDNS := server.dnsConfig.Load()
			if err := server.refreshManagedConfiguration(ctx); err != nil {
				server.log.Error("configuration refresh failed; keeping last valid snapshots for failed components", "err", err)
				continue
			}
			if server.policyConfig.Load() != previousPolicy || server.dnsConfig.Load() != previousDNS {
				if current := server.policyConfig.Load(); current.Source == "file" && current != previousPolicy {
					server.audit("system", identity.AuditPolicyReloaded, "policy", "reloaded deployment policy")
				}
				server.notifyWatchers()
			}
		}
	}
}

func policyModTime(path string) time.Time {
	info, err := os.Stat(path)
	if err != nil {
		return time.Time{}
	}
	return info.ModTime()
}

func (server *Server) userLoginName(userID tailcfg.UserID) string {
	return server.UserProfile(userID).LoginName
}
