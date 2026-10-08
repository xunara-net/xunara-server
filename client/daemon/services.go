package daemon

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/xunara-net/xunara-server/client/protocol"
)

// servicesFile is the durable service declaration inside the state directory.
// It is separate from agent.json so publishing services never rewrites the
// credential file.
const servicesFile = "services.json"

// serviceDeclaration is the on-disk shape. The wrapper leaves room for
// declaration metadata without breaking the file format.
type serviceDeclaration struct {
	Services []protocol.Service `json:"services"`
}

// LoadServices reads the agent's service declaration. A missing file returns
// an error wrapping [os.ErrNotExist]: this agent publishes no services.
func LoadServices(stateDir string) ([]protocol.Service, error) {
	raw, err := os.ReadFile(filepath.Join(stateDir, servicesFile))
	if err != nil {
		return nil, err
	}

	var decl serviceDeclaration
	if err := json.Unmarshal(raw, &decl); err != nil {
		return nil, fmt.Errorf("daemon: parsing %s: %w", servicesFile, err)
	}
	return decl.Services, nil
}

// SaveServices writes the service declaration atomically with 0600
// permissions, so a running agent picks it up on its next refresh.
func SaveServices(stateDir string, services []protocol.Service) error {
	if services == nil {
		services = []protocol.Service{}
	}
	raw, err := json.MarshalIndent(serviceDeclaration{Services: services}, "", "  ")
	if err != nil {
		return fmt.Errorf("daemon: encoding services: %w", err)
	}
	return writeFileAtomic(stateDir, servicesFile, raw)
}

// RemoveServices deletes the local declaration. It does not touch the control
// plane: callers withdraw the set first (the CLI publishes an empty set).
func RemoveServices(stateDir string) error {
	err := os.Remove(filepath.Join(stateDir, servicesFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

// ServiceHealthFileName is the durable readiness source inside the state
// directory. It is deliberately a separate file from the declaration:
// readiness is volatile telemetry (the control plane expires it), while
// services.json is the declaration that a republish reconciles. A service
// manager writes this file; the agent only reads and reports it.
const ServiceHealthFileName = "services-health.json"

// serviceHealthDeclaration is the on-disk shape of the readiness file.
type serviceHealthDeclaration struct {
	Services []protocol.ServiceHealth `json:"services"`
}

// LoadServiceHealth reads the agent's readiness file. A missing file returns
// an error wrapping [os.ErrNotExist]; callers treat that as "everything not
// ready", which withdraws health-tracked services from discovery
// (fail-closed, spec section 26).
func LoadServiceHealth(stateDir string) ([]protocol.ServiceHealth, error) {
	raw, err := os.ReadFile(filepath.Join(stateDir, ServiceHealthFileName))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxServiceHealthBytes {
		return nil, fmt.Errorf("daemon: %s is larger than %d bytes", ServiceHealthFileName, maxServiceHealthBytes)
	}

	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var decl serviceHealthDeclaration
	if err := dec.Decode(&decl); err != nil {
		return nil, fmt.Errorf("daemon: parsing %s: %w", ServiceHealthFileName, err)
	}
	if err := dec.Decode(new(json.RawMessage)); err != io.EOF {
		return nil, fmt.Errorf("daemon: parsing %s: trailing data after the declaration", ServiceHealthFileName)
	}
	return decl.Services, nil
}

// maxServiceHealthBytes bounds the readiness file; a declaration is tiny
// (protocol.MaxServicesPerNode entries at most), so anything larger is a
// mistake.
const maxServiceHealthBytes = 1 << 20
