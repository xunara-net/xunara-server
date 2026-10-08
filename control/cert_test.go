package control

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"sync"
	"testing"
	"time"

	"tailscale.com/tailcfg"

	"github.com/xunara-net/xunara-server/state"
)

// fakeDNSProvider records the calls the control plane makes to the public
// zone.
type fakeDNSProvider struct {
	mu      sync.Mutex
	puts    []fakeDNSWrite
	deletes []string
	err     error
}

type fakeDNSWrite struct {
	name  string
	value string
}

func (f *fakeDNSProvider) PutTXT(_ context.Context, name, value string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	f.puts = append(f.puts, fakeDNSWrite{name: name, value: value})
	return nil
}

func (f *fakeDNSProvider) DeleteTXT(_ context.Context, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	f.deletes = append(f.deletes, name)
	return nil
}

func (f *fakeDNSProvider) putCalls() []fakeDNSWrite {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.puts)
}

func (f *fakeDNSProvider) deleteCalls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.deletes)
}

// TestCertIssuanceAdvertisedWithDNSProvider checks the netmap tells clients
// which names they may obtain certificates for: their own FQDN plus the
// operator's extra domains.
func TestCertIssuanceAdvertisedWithDNSProvider(t *testing.T) {
	s := newServerWithConfig(t, Config{
		Domain:      "xunara.test",
		CertDomains: []string{"extra.example.com", "extra.example.com."},
		DNSProvider: &fakeDNSProvider{},
	})
	hs := newTestHTTPServer(t, s)

	conn, client, nodeKey := registerNode(t, s, hs, "node-a")
	defer conn.Close()

	msg := decodeMapResponse(t, postRaw(t, client, "/machine/map", tailcfg.MapRequest{
		Version: tailcfg.CurrentCapabilityVersion,
		NodeKey: nodeKey.Public(),
	}), "")
	if msg.DNSConfig == nil {
		t.Fatal("netmap has no DNSConfig")
	}
	want := []string{"extra.example.com", "node-a.xunara.test"}
	if !slices.Equal(msg.DNSConfig.CertDomains, want) {
		t.Errorf("CertDomains = %v, want %v", msg.DNSConfig.CertDomains, want)
	}
}

// TestSetDNSPublishesACMEChallenge covers the DNS-01 path: the challenge goes
// to the public zone through the provider, is stored for the janitor, and is
// not published to MagicDNS.
func TestSetDNSPublishesACMEChallenge(t *testing.T) {
	provider := &fakeDNSProvider{}
	s := newServerWithConfig(t, Config{
		Domain:      "xunara.test",
		DNSProvider: provider,
	})
	hs := newTestHTTPServer(t, s)

	conn, client, nodeKey := registerNode(t, s, hs, "node-a")
	defer conn.Close()

	postRaw(t, client, "/machine/set-dns", tailcfg.SetDNSRequest{
		Version: tailcfg.CurrentCapabilityVersion,
		NodeKey: nodeKey.Public(),
		Name:    "_acme-challenge.node-a.xunara.test.",
		Type:    "TXT",
		Value:   "challenge-token",
	})

	puts := provider.putCalls()
	if len(puts) != 1 {
		t.Fatalf("provider puts = %v, want one", puts)
	}
	if puts[0].name != "_acme-challenge.node-a.xunara.test" || puts[0].value != "challenge-token" {
		t.Errorf("provider put = %+v", puts[0])
	}

	stored := s.Store().ListDNSRecords()
	if len(stored) != 1 || stored[0].Name != "_acme-challenge.node-a.xunara.test" {
		t.Fatalf("stored records = %+v, want the challenge", stored)
	}

	// Challenge records are for the public CA, not for tailnet resolvers.
	node, ok := s.store.GetNodeByNodeKey(nodeKey.Public())
	if !ok {
		t.Fatal("registered node is missing from the store")
	}
	if got := s.extraDNSRecordsFor(node); len(got) != 0 {
		t.Errorf("ExtraRecords = %+v, want none", got)
	}
}

// TestSetDNSRejectsChallengeOutsideCertDomains checks that a node cannot
// answer DNS-01 challenges for names it was never offered.
func TestSetDNSRejectsChallengeOutsideCertDomains(t *testing.T) {
	provider := &fakeDNSProvider{}
	s := newServerWithConfig(t, Config{
		Domain:      "xunara.test",
		CertDomains: []string{"extra.example.com"},
		DNSProvider: provider,
	})
	hs := newTestHTTPServer(t, s)

	conn, client, nodeKey := registerNode(t, s, hs, "node-a")
	defer conn.Close()

	for _, name := range []string{
		"_acme-challenge.other.example.com",  // not a configured domain
		"_acme-challenge.node-b.xunara.test", // another node's FQDN
		"_acme-challenge.xunara.test",        // the bare domain is not a cert domain
	} {
		_, status := postRawStatus(t, client, "/machine/set-dns", tailcfg.SetDNSRequest{
			Version: tailcfg.CurrentCapabilityVersion,
			NodeKey: nodeKey.Public(),
			Name:    name,
			Type:    "TXT",
			Value:   "token",
		})
		if status != http.StatusBadRequest {
			t.Errorf("set-dns %q status = %d, want 400", name, status)
		}
	}
	if puts := provider.putCalls(); len(puts) != 0 {
		t.Errorf("provider puts = %v, want none", puts)
	}

	// The operator's extra domain is allowed.
	postRaw(t, client, "/machine/set-dns", tailcfg.SetDNSRequest{
		Version: tailcfg.CurrentCapabilityVersion,
		NodeKey: nodeKey.Public(),
		Name:    "_acme-challenge.extra.example.com",
		Type:    "TXT",
		Value:   "token",
	})
	if puts := provider.putCalls(); len(puts) != 1 {
		t.Errorf("provider puts = %v, want the extra-domain challenge", puts)
	}
}

// TestSetDNSProviderFailureFailsClosed checks that a zone write failure is
// reported to the client instead of being swallowed.
func TestSetDNSProviderFailureFailsClosed(t *testing.T) {
	provider := &fakeDNSProvider{err: errors.New("zone is read-only")}
	s := newServerWithConfig(t, Config{
		Domain:      "xunara.test",
		DNSProvider: provider,
	})
	hs := newTestHTTPServer(t, s)

	conn, client, nodeKey := registerNode(t, s, hs, "node-a")
	defer conn.Close()

	_, status := postRawStatus(t, client, "/machine/set-dns", tailcfg.SetDNSRequest{
		Version: tailcfg.CurrentCapabilityVersion,
		NodeKey: nodeKey.Public(),
		Name:    "_acme-challenge.node-a.xunara.test",
		Type:    "TXT",
		Value:   "token",
	})
	if status != http.StatusBadGateway {
		t.Errorf("status = %d, want 502 when the zone writer fails", status)
	}
}

// TestReapACMEChallenges removes expired DNS-01 records from the store and the
// public zone, leaving ordinary records alone.
func TestReapACMEChallenges(t *testing.T) {
	provider := &fakeDNSProvider{}
	s := newServerWithConfig(t, Config{
		Domain:      "xunara.test",
		DNSProvider: provider,
	})
	now := time.Now().UTC()

	old := state.DNSRecord{
		Name:    "_acme-challenge.node-a.xunara.test",
		Type:    "TXT",
		Value:   "old-token",
		Created: now.Add(-certChallengeTTL - time.Hour),
	}
	fresh := state.DNSRecord{
		Name:    "_acme-challenge.node-a.xunara.test",
		Type:    "TXT",
		Value:   "fresh-token",
		Created: now,
	}
	ordinary := state.DNSRecord{
		Name:    "notes.node-a.xunara.test",
		Type:    "TXT",
		Value:   "keep me",
		Created: now.Add(-certChallengeTTL - time.Hour),
	}
	for _, rec := range []*state.DNSRecord{&old, &fresh, &ordinary} {
		if err := s.Store().UpsertDNSRecord(rec); err != nil {
			t.Fatalf("UpsertDNSRecord: %v", err)
		}
	}

	s.reapACMEChallenges(now)

	remaining := s.Store().ListDNSRecords()
	if len(remaining) != 2 {
		t.Fatalf("remaining records = %+v, want the fresh challenge and the ordinary record", remaining)
	}
	for _, rec := range remaining {
		if rec.Value == "old-token" {
			t.Error("expired challenge was not removed")
		}
	}
	if deletes := provider.deleteCalls(); len(deletes) != 1 || deletes[0] != old.Name {
		t.Errorf("provider deletes = %v, want [%s]", deletes, old.Name)
	}
}
