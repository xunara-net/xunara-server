package catalog

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xunara-net/xunara-server/client/protocol"
)

func k8sService(name string, annotations map[string]string) kubernetesService {
	return kubernetesService{Metadata: kubernetesObjectMeta{Name: name, Annotations: annotations}}
}

func k8sSlice(service string, node string, ready *bool, ports ...kubernetesEndpointPort) kubernetesEndpointSlice {
	return kubernetesEndpointSlice{
		Metadata:  kubernetesObjectMeta{Labels: map[string]string{KubernetesServiceNameLabel: service}},
		Endpoints: []kubernetesEndpoint{{NodeName: &node, Conditions: kubernetesEndpointConditions{Ready: ready}}},
		Ports:     ports,
	}
}

func k8sPort(name, protocolName string, number int32) kubernetesEndpointPort {
	port := kubernetesEndpointPort{Port: &number}
	if name != "" {
		port.Name = &name
	}
	if protocolName != "" {
		port.Protocol = &protocolName
	}
	return port
}

func k8sBool(b bool) *bool { return &b }

// TestMapKubernetesServices covers the mapping rules of spec section 27.2.
func TestMapKubernetesServices(t *testing.T) {
	optedIn := map[string]string{KubernetesAdvertiseAnnotation: "true"}

	t.Run("not opted in is ignored silently", func(t *testing.T) {
		services, warnings, err := mapKubernetesServices(
			[]kubernetesService{k8sService("api", nil)},
			[]kubernetesEndpointSlice{k8sSlice("api", "node-a", k8sBool(true), k8sPort("", "", 8080))},
			"node-a")
		if err != nil || len(services) != 0 || len(warnings) != 0 {
			t.Fatalf("services = %+v, warnings = %v, err = %v", services, warnings, err)
		}
	})

	t.Run("no local endpoint is skipped", func(t *testing.T) {
		services, warnings, err := mapKubernetesServices(
			[]kubernetesService{k8sService("api", optedIn)},
			[]kubernetesEndpointSlice{k8sSlice("api", "other-node", k8sBool(true), k8sPort("", "", 8080))},
			"node-a")
		if err != nil || len(services) != 0 || len(warnings) != 1 || !strings.Contains(warnings[0], "no ready endpoints") {
			t.Fatalf("services = %+v, warnings = %v, err = %v", services, warnings, err)
		}
	})

	t.Run("not-ready endpoint is skipped", func(t *testing.T) {
		services, warnings, err := mapKubernetesServices(
			[]kubernetesService{k8sService("api", optedIn)},
			[]kubernetesEndpointSlice{k8sSlice("api", "node-a", k8sBool(false), k8sPort("", "", 8080))},
			"node-a")
		if err != nil || len(services) != 0 || len(warnings) != 1 {
			t.Fatalf("services = %+v, warnings = %v, err = %v", services, warnings, err)
		}
	})

	t.Run("nil ready is unknown and treated as ready", func(t *testing.T) {
		services, warnings, err := mapKubernetesServices(
			[]kubernetesService{k8sService("api", optedIn)},
			[]kubernetesEndpointSlice{k8sSlice("api", "node-a", nil, k8sPort("", "", 8080))},
			"node-a")
		if err != nil || len(warnings) != 0 || len(services) != 1 {
			t.Fatalf("services = %+v, warnings = %v, err = %v", services, warnings, err)
		}
		if services[0].Name != "api" || services[0].Protocol != "tcp" || services[0].Port != 8080 {
			t.Errorf("service = %+v", services[0])
		}
	})

	t.Run("udp protocol is lowercased and duplicates deduped", func(t *testing.T) {
		services, warnings, err := mapKubernetesServices(
			[]kubernetesService{k8sService("dns", optedIn)},
			[]kubernetesEndpointSlice{
				k8sSlice("dns", "node-a", k8sBool(true), k8sPort("dns", "UDP", 53)),
				k8sSlice("dns", "node-a", k8sBool(true), k8sPort("dns", "UDP", 53)),
			},
			"node-a")
		if err != nil || len(warnings) != 0 || len(services) != 1 {
			t.Fatalf("services = %+v, warnings = %v, err = %v", services, warnings, err)
		}
		if services[0].Protocol != "udp" || services[0].Port != 53 {
			t.Errorf("service = %+v", services[0])
		}
	})

	t.Run("unsupported ports leave nothing to declare", func(t *testing.T) {
		services, warnings, err := mapKubernetesServices(
			[]kubernetesService{k8sService("api", optedIn)},
			[]kubernetesEndpointSlice{k8sSlice("api", "node-a", k8sBool(true),
				k8sPort("", "SCTP", 8080), k8sPort("", "", 0))},
			"node-a")
		if err != nil || len(services) != 0 || len(warnings) != 1 || !strings.Contains(warnings[0], "no ready endpoints") {
			t.Fatalf("services = %+v, warnings = %v, err = %v", services, warnings, err)
		}
	})

	t.Run("multi-port needs the annotation", func(t *testing.T) {
		ports := []kubernetesEndpointPort{k8sPort("http", "", 80), k8sPort("metrics", "", 9090)}
		services, warnings, err := mapKubernetesServices(
			[]kubernetesService{k8sService("web", optedIn)},
			[]kubernetesEndpointSlice{k8sSlice("web", "node-a", k8sBool(true), ports...)},
			"node-a")
		if err != nil || len(services) != 0 || len(warnings) != 1 || !strings.Contains(warnings[0], KubernetesPortAnnotation) {
			t.Fatalf("services = %+v, warnings = %v, err = %v", services, warnings, err)
		}

		annotations := map[string]string{KubernetesAdvertiseAnnotation: "true", KubernetesPortAnnotation: "metrics"}
		services, warnings, err = mapKubernetesServices(
			[]kubernetesService{k8sService("web", annotations)},
			[]kubernetesEndpointSlice{k8sSlice("web", "node-a", k8sBool(true), ports...)},
			"node-a")
		if err != nil || len(warnings) != 0 || len(services) != 1 || services[0].Port != 9090 {
			t.Fatalf("services = %+v, warnings = %v, err = %v", services, warnings, err)
		}

		annotations[KubernetesPortAnnotation] = "nope"
		if services, _, _ := mapKubernetesServices(
			[]kubernetesService{k8sService("web", annotations)},
			[]kubernetesEndpointSlice{k8sSlice("web", "node-a", k8sBool(true), ports...)},
			"node-a"); len(services) != 0 {
			t.Errorf("a missing port name was accepted: %+v", services)
		}
	})

	t.Run("metadata is opt-in and never leaks values", func(t *testing.T) {
		annotations := map[string]string{
			KubernetesAdvertiseAnnotation: "true",
			KubernetesMetadataAnnotation:  `{"version":"2"}`,
			"secret.example.com/token":    "super-secret",
		}
		services, warnings, err := mapKubernetesServices(
			[]kubernetesService{k8sService("api", annotations)},
			[]kubernetesEndpointSlice{k8sSlice("api", "node-a", k8sBool(true), k8sPort("", "", 8080))},
			"node-a")
		if err != nil || len(warnings) != 0 || len(services) != 1 {
			t.Fatalf("services = %+v, warnings = %v, err = %v", services, warnings, err)
		}
		if services[0].Metadata["version"] != "2" || len(services[0].Metadata) != 1 {
			t.Errorf("metadata = %+v", services[0].Metadata)
		}

		annotations[KubernetesMetadataAnnotation] = `{"password":"super-secret","replicas":2}`
		services, warnings, err = mapKubernetesServices(
			[]kubernetesService{k8sService("api", annotations)},
			[]kubernetesEndpointSlice{k8sSlice("api", "node-a", k8sBool(true), k8sPort("", "", 8080))},
			"node-a")
		if err != nil || len(services) != 0 || len(warnings) != 1 {
			t.Fatalf("services = %+v, warnings = %v, err = %v", services, warnings, err)
		}
		if strings.Contains(warnings[0], "super-secret") {
			t.Errorf("warning leaks the annotation value: %s", warnings[0])
		}
	})

	t.Run("declaration annotations are carried", func(t *testing.T) {
		annotations := map[string]string{
			KubernetesAdvertiseAnnotation:  "true",
			KubernetesVisibilityAnnotation: `["tag:prod","group:eng","tag:prod"]`,
			KubernetesSharedAnnotation:     "true",
		}
		services, warnings, err := mapKubernetesServices(
			[]kubernetesService{k8sService("api", annotations)},
			[]kubernetesEndpointSlice{k8sSlice("api", "node-a", k8sBool(true), k8sPort("", "", 8080))},
			"node-a")
		if err != nil || len(warnings) != 0 || len(services) != 1 {
			t.Fatalf("services = %+v, warnings = %v, err = %v", services, warnings, err)
		}
		if got := strings.Join(services[0].Visibility, ","); got != "group:eng,tag:prod" {
			t.Errorf("visibility = %q", got)
		}
		if !services[0].Shared || services[0].VisibilityFromACL {
			t.Errorf("service = %+v", services[0])
		}

		annotations[KubernetesSharedAnnotation] = "false"
		annotations[KubernetesVisibilityAnnotation] = `["*"]`
		annotations[KubernetesVisibilityFromACLAnnotation] = "true"
		services, warnings, err = mapKubernetesServices(
			[]kubernetesService{k8sService("api", annotations)},
			[]kubernetesEndpointSlice{k8sSlice("api", "node-a", k8sBool(true), k8sPort("", "", 8080))},
			"node-a")
		if err != nil || len(services) != 0 || len(warnings) != 1 || !strings.Contains(warnings[0], "visibilityFromACL") {
			t.Fatalf("services = %+v, warnings = %v, err = %v", services, warnings, err)
		}
	})

	t.Run("malformed declaration annotations skip without echoing values", func(t *testing.T) {
		annotations := map[string]string{
			KubernetesAdvertiseAnnotation:  "true",
			KubernetesVisibilityAnnotation: `{"password":"super-secret"}`,
		}
		services, warnings, err := mapKubernetesServices(
			[]kubernetesService{k8sService("api", annotations)},
			[]kubernetesEndpointSlice{k8sSlice("api", "node-a", k8sBool(true), k8sPort("", "", 8080))},
			"node-a")
		if err != nil || len(services) != 0 || len(warnings) != 1 {
			t.Fatalf("services = %+v, warnings = %v, err = %v", services, warnings, err)
		}
		if !strings.Contains(warnings[0], KubernetesVisibilityAnnotation) || strings.Contains(warnings[0], "super-secret") {
			t.Errorf("warning = %q", warnings[0])
		}

		annotations[KubernetesVisibilityAnnotation] = `["tag:prod"]`
		annotations[KubernetesSharedAnnotation] = "TRUE"
		services, warnings, err = mapKubernetesServices(
			[]kubernetesService{k8sService("api", annotations)},
			[]kubernetesEndpointSlice{k8sSlice("api", "node-a", k8sBool(true), k8sPort("", "", 8080))},
			"node-a")
		if err != nil || len(services) != 0 || len(warnings) != 1 || !strings.Contains(warnings[0], KubernetesSharedAnnotation) {
			t.Fatalf("services = %+v, warnings = %v, err = %v", services, warnings, err)
		}
	})

	t.Run("output is sorted by name", func(t *testing.T) {
		services, warnings, err := mapKubernetesServices(
			[]kubernetesService{k8sService("zebra", optedIn), k8sService("api", optedIn)},
			[]kubernetesEndpointSlice{
				k8sSlice("zebra", "node-a", k8sBool(true), k8sPort("", "", 1)),
				k8sSlice("api", "node-a", k8sBool(true), k8sPort("", "", 2)),
			},
			"node-a")
		if err != nil || len(warnings) != 0 || len(services) != 2 {
			t.Fatalf("services = %+v, warnings = %v, err = %v", services, warnings, err)
		}
		if services[0].Name != "api" || services[1].Name != "zebra" {
			t.Errorf("order = %s, %s", services[0].Name, services[1].Name)
		}
	})

	t.Run("over the per-node limit is an error, not a truncation", func(t *testing.T) {
		var svcs []kubernetesService
		var slices []kubernetesEndpointSlice
		for i := 0; i <= protocol.MaxServicesPerNode; i++ {
			name := fmt.Sprintf("svc-%02d", i)
			svcs = append(svcs, k8sService(name, optedIn))
			slices = append(slices, k8sSlice(name, "node-a", k8sBool(true), k8sPort("", "", 80)))
		}
		if _, _, err := mapKubernetesServices(svcs, slices, "node-a"); err == nil {
			t.Fatal("an oversized import was accepted")
		}
	})
}

// kubernetesTLSServer starts a TLS API server trusting the CA written to a
// temp file, and returns the pieces the importer needs.
func kubernetesTLSServer(t *testing.T, handler http.Handler) (address, tokenFile, caFile string) {
	t.Helper()

	hs := httptest.NewTLSServer(handler)
	t.Cleanup(hs.Close)

	dir := t.TempDir()
	tokenFile = filepath.Join(dir, "token")
	if err := os.WriteFile(tokenFile, []byte("test-token\n"), 0o600); err != nil {
		t.Fatalf("writing the token: %v", err)
	}
	caFile = filepath.Join(dir, "ca.crt")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: hs.Certificate().Raw})
	if err := os.WriteFile(caFile, pemBytes, 0o600); err != nil {
		t.Fatalf("writing the CA: %v", err)
	}
	return hs.URL, tokenFile, caFile
}

// TestKubernetesServicesHTTP drives the importer against a fake API server:
// auth header, namespace path, pagination and the join of Services with
// EndpointSlices.
func TestKubernetesServicesHTTP(t *testing.T) {
	var paths []string
	var authSeen string
	mux := http.NewServeMux()

	mux.HandleFunc("/api/v1/namespaces/tailnet/services", func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.RequestURI())
		authSeen = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Query().Get("continue") == "" {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"metadata": map[string]any{"continue": "page-two"},
				"items": []map[string]any{
					{"metadata": map[string]any{
						"name":        "api",
						"annotations": map[string]string{KubernetesAdvertiseAnnotation: "true"},
					}},
				},
			})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"metadata": map[string]any{},
			"items": []map[string]any{
				{"metadata": map[string]any{"name": "plain"}},
			},
		})
	})
	mux.HandleFunc("/apis/discovery.k8s.io/v1/namespaces/tailnet/endpointslices", func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.RequestURI())
		w.Header().Set("Content-Type", "application/json")
		ready := true
		port := int32(8080)
		name := "http"
		proto := "TCP"
		_ = json.NewEncoder(w).Encode(map[string]any{
			"metadata": map[string]any{},
			"items": []map[string]any{
				{
					"metadata": map[string]any{
						"labels": map[string]string{KubernetesServiceNameLabel: "api"},
					},
					"endpoints": []map[string]any{
						{"nodeName": "node-a", "conditions": map[string]any{"ready": ready}},
						{"nodeName": "other-node", "conditions": map[string]any{"ready": true}},
					},
					"ports": []map[string]any{{"name": name, "protocol": proto, "port": port}},
				},
			},
		})
	})

	address, tokenFile, caFile := kubernetesTLSServer(t, mux)

	services, warnings, err := KubernetesServices(context.Background(), KubernetesConfig{
		Address:   address,
		TokenFile: tokenFile,
		CAFile:    caFile,
		Namespace: "tailnet",
		Node:      "node-a",
	})
	if err != nil {
		t.Fatalf("KubernetesServices: %v", err)
	}
	if len(warnings) != 0 || len(services) != 1 || services[0].Name != "api" || services[0].Port != 8080 {
		t.Fatalf("services = %+v, warnings = %v", services, warnings)
	}
	if authSeen != "Bearer test-token" {
		t.Errorf("Authorization = %q", authSeen)
	}
	if len(paths) != 3 {
		t.Fatalf("request paths = %v", paths)
	}
	for _, path := range paths {
		if !strings.Contains(path, "limit=") {
			t.Errorf("request %q does not bound the page size", path)
		}
	}
	if !strings.Contains(paths[0], "continue=") && !strings.Contains(paths[1], "continue=page-two") {
		t.Errorf("pagination cursor did not travel: %v", paths)
	}
}

// TestKubernetesServicesAPIError checks that a rejected request surfaces the
// status without echoing the token.
func TestKubernetesServicesAPIError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "forbidden", http.StatusForbidden)
	})
	address, tokenFile, caFile := kubernetesTLSServer(t, mux)

	_, _, err := KubernetesServices(context.Background(), KubernetesConfig{
		Address: address, TokenFile: tokenFile, CAFile: caFile, Namespace: "tailnet", Node: "node-a",
	})
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("error = %v, want the HTTP status", err)
	}
	if strings.Contains(err.Error(), "test-token") {
		t.Fatalf("error leaks the token: %v", err)
	}
}

// TestKubernetesConfigFailClosed covers the configuration refusals.
func TestKubernetesConfigFailClosed(t *testing.T) {
	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "token")
	if err := os.WriteFile(tokenFile, []byte("t"), 0o600); err != nil {
		t.Fatalf("writing the token: %v", err)
	}

	cases := []struct {
		name string
		cfg  KubernetesConfig
		want string
	}{
		{"missing node", KubernetesConfig{Address: "https://api.example.com", TokenFile: tokenFile}, "node name is required"},
		{"plaintext non-loopback", KubernetesConfig{Address: "http://10.0.0.1:6443", TokenFile: tokenFile, Node: "n"}, "plaintext"},
		{"bad scheme", KubernetesConfig{Address: "ftp://api.example.com", TokenFile: tokenFile, Node: "n"}, "https"},
		{"credentials in the address", KubernetesConfig{Address: "https://user:pass@api.example.com", TokenFile: tokenFile, Node: "n"}, "credentials"},
		{"missing token file", KubernetesConfig{Address: "https://api.example.com", TokenFile: filepath.Join(dir, "missing"), Node: "n"}, "token"},
		{"bad namespace", KubernetesConfig{Address: "https://api.example.com", TokenFile: tokenFile, Namespace: "../etc", Node: "n"}, "namespace"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := KubernetesServices(context.Background(), tc.cfg)
			if err == nil {
				t.Fatal("configuration was accepted")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want it to mention %q", err, tc.want)
			}
		})
	}
}

// TestKubernetesServicesInClusterResolution checks that the missing in-cluster
// environment is reported instead of guessing an API server.
func TestKubernetesServicesInClusterResolution(t *testing.T) {
	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	t.Setenv("KUBERNETES_SERVICE_PORT", "")

	_, _, err := KubernetesServices(context.Background(), KubernetesConfig{Node: "node-a"})
	if err == nil || !strings.Contains(err.Error(), "KUBERNETES_SERVICE_HOST") {
		t.Fatalf("error = %v, want a missing in-cluster configuration", err)
	}
}

// TestKubernetesTLSCAIsVerified checks that the configured CA is enforced:
// the same API server with an unrelated CA fails the TLS handshake.
func TestKubernetesTLSCAIsVerified(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"items":[]}`))
	})
	address, tokenFile, _ := kubernetesTLSServer(t, mux)

	otherCA := filepath.Join(t.TempDir(), "other-ca.crt")
	if err := os.WriteFile(otherCA, selfSignedCAPEM(t), 0o600); err != nil {
		t.Fatalf("writing the CA: %v", err)
	}

	_, _, err := KubernetesServices(context.Background(), KubernetesConfig{
		Address: address, TokenFile: tokenFile, CAFile: otherCA, Namespace: "tailnet", Node: "node-a",
	})
	if err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("error = %v, want a certificate verification failure", err)
	}
}

// selfSignedCAPEM mints an unrelated self-signed CA certificate; httptest
// servers share one built-in certificate, so trusting a second httptest
// server would not be an unrelated trust root.
func selfSignedCAPEM(t *testing.T) []byte {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating a key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "not-the-api-server"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating the certificate: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
