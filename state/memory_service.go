package state

import (
	"fmt"
	"slices"
	"strings"
	"time"
)

// ReplaceNodeServices implements [ServiceStore].
func (s *MemoryStore) ReplaceNodeServices(id NodeID, services []Service) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.byID[id]; !ok {
		return errUnknownNode(id)
	}
	owners, err := s.dnsNameOwnersLocked(0, id)
	if err != nil {
		return err
	}

	now := time.Now().UTC()
	existing := make(map[string]Service)
	for name, svc := range s.services {
		if svc.NodeID == id {
			existing[name] = svc
		}
	}

	// Apply the replacement only after every name passed the ownership check,
	// so a conflict cannot leave the node with half a set.
	next := make(map[string]Service, len(services))
	for _, svc := range services {
		name := strings.ToLower(svc.Name)
		if _, taken := owners[name]; taken {
			return errServiceNameTaken(svc.Name)
		}
		owners[name] = "pending-service"
		if _, duplicate := next[svc.Name]; duplicate {
			return errServiceNameTaken(svc.Name)
		}
		if other, ok := s.services[svc.Name]; ok && other.NodeID != id {
			return errServiceNameTaken(svc.Name)
		}
		if prev, ok := existing[svc.Name]; ok {
			svc.Created = prev.Created
			if svc.Health && prev.Health {
				// Still tracked under the same name: keep the standing
				// report so a periodic republish cannot flap discovery.
				svc.Healthy = prev.Healthy
				svc.HealthReportedAt = prev.HealthReportedAt
				svc.HealthUntil = prev.HealthUntil
			}
		}
		if svc.Created.IsZero() {
			svc.Created = now
		}
		svc.NodeID = id
		svc.Updated = now
		next[svc.Name] = svc
	}

	for name, svc := range s.services {
		if svc.NodeID == id {
			delete(s.services, name)
		}
	}
	for name, svc := range next {
		s.services[name] = svc
	}
	return nil
}

// ListServices implements [ServiceStore].
func (s *MemoryStore) ListServices() []Service {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]Service, 0, len(s.services))
	for _, svc := range s.services {
		out = append(out, copyService(svc))
	}
	slices.SortFunc(out, func(a, b Service) int {
		switch {
		case a.Name < b.Name:
			return -1
		case a.Name > b.Name:
			return 1
		default:
			return 0
		}
	})
	return out
}

// ServicesForNode implements [ServiceStore].
func (s *MemoryStore) ServicesForNode(id NodeID) ([]Service, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := []Service{}
	for _, svc := range s.services {
		if svc.NodeID == id {
			out = append(out, copyService(svc))
		}
	}
	slices.SortFunc(out, func(a, b Service) int {
		switch {
		case a.Name < b.Name:
			return -1
		case a.Name > b.Name:
			return 1
		default:
			return 0
		}
	})
	return out, nil
}

// GetServiceByName implements [ServiceStore].
func (s *MemoryStore) GetServiceByName(name string) (Service, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	svc, ok := s.services[name]
	if !ok {
		return Service{}, false
	}
	return copyService(svc), true
}

// NodeServiceCounts implements [ServiceStore].
func (s *MemoryStore) NodeServiceCounts() (map[NodeID]int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	counts := make(map[NodeID]int)
	for _, svc := range s.services {
		counts[svc.NodeID]++
	}
	return counts, nil
}

// copyService returns a copy that shares no mutable state with the store.
func copyService(svc Service) Service {
	out := svc
	if len(svc.Visibility) > 0 {
		out.Visibility = slices.Clone(svc.Visibility)
	}
	if len(svc.Metadata) > 0 {
		out.Metadata = make(map[string]string, len(svc.Metadata))
		for k, v := range svc.Metadata {
			out.Metadata[k] = v
		}
	}
	return out
}

// ReportServiceHealth implements [ServiceStore].
func (s *MemoryStore) ReportServiceHealth(id NodeID, reports []ServiceHealthReport, ttl time.Duration) ([]ServiceHealthChange, error) {
	if ttl <= 0 {
		return nil, fmt.Errorf("state: service health TTL must be positive")
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.byID[id]; !ok {
		return nil, errUnknownNode(id)
	}

	ready := make(map[string]bool, len(reports))
	for _, report := range reports {
		svc, ok := s.services[report.Name]
		if !ok || svc.NodeID != id || !svc.Health {
			return nil, errServiceHealthUnknown(report.Name)
		}
		if _, duplicate := ready[report.Name]; duplicate {
			return nil, fmt.Errorf("state: duplicate health report for service %q", report.Name)
		}
		ready[report.Name] = report.Ready
	}

	now := time.Now().UTC()
	until := now.Add(ttl)
	var changes []ServiceHealthChange
	for name, svc := range s.services {
		if svc.NodeID != id || !svc.Health {
			continue
		}
		want := ready[name]
		if svc.Healthy != want {
			changes = append(changes, ServiceHealthChange{
				NodeID: id, Name: name, Protocol: svc.Protocol, Port: svc.Port,
				Healthy: want, Reason: ServiceHealthReasonReported,
			})
		}
		svc.Healthy = want
		svc.HealthReportedAt = now
		svc.HealthUntil = until
		s.services[name] = svc
	}
	sortHealthChanges(changes)
	return changes, nil
}

// ExpireServiceHealth implements [ServiceStore].
func (s *MemoryStore) ExpireServiceHealth(now time.Time) ([]ServiceHealthChange, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var changes []ServiceHealthChange
	for name, svc := range s.services {
		if !svc.Health || !svc.Healthy || svc.HealthUntil.IsZero() || !svc.HealthUntil.Before(now) {
			continue
		}
		changes = append(changes, ServiceHealthChange{
			NodeID: svc.NodeID, Name: name, Protocol: svc.Protocol, Port: svc.Port,
			Reason: ServiceHealthReasonExpired,
		})
		svc.Healthy = false
		svc.HealthUntil = time.Time{}
		s.services[name] = svc
	}
	sortHealthChanges(changes)
	return changes, nil
}
