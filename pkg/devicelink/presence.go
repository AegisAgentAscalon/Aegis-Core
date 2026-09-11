package devicelink

import (
	"context"
	"time"
)

func (s *Service) PublishPresence(ctx context.Context) (PresenceRecord, error) {
	ctx = normalizeContext(ctx)
	if err := contextError(ctx); err != nil {
		return PresenceRecord{}, err
	}
	s.mu.Lock()
	current, err := s.store.readIdentity()
	if err != nil {
		s.mu.Unlock()
		return PresenceRecord{}, err
	}
	resources, err := s.store.readResources()
	if err != nil {
		s.mu.Unlock()
		return PresenceRecord{}, err
	}
	record := PresenceRecord{
		SchemaVersion:        schemaVersion,
		DeviceID:             current.DeviceID,
		DisplayName:          current.DisplayName,
		Capabilities:         append([]string{}, current.Capabilities...),
		ResourcesSummary:     summarizeResources(resources.Resources),
		LastSeen:             s.clock.Now().UTC(),
		PublicKeyFingerprint: current.PublicKeyFingerprint,
	}
	discovery := s.discovery
	s.mu.Unlock()
	if err := discovery.Publish(ctx, record); err != nil {
		return PresenceRecord{}, ErrDiscoveryUnavailable
	}
	return record, nil
}

func (s *Service) DiscoverPeers(ctx context.Context) ([]DiscoveredPeer, error) {
	ctx = normalizeContext(ctx)
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	s.mu.Lock()
	discovery := s.discovery
	s.mu.Unlock()
	records, err := discovery.Discover(ctx)
	if err != nil {
		return nil, ErrDiscoveryUnavailable
	}
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	current, _ := s.store.readIdentity()
	reg, err := s.store.readRegistry()
	if err != nil {
		return nil, err
	}
	trust := map[string]TrustedDevice{}
	for _, dev := range reg.Devices {
		trust[dev.DeviceID] = dev
	}
	peers := make([]PresenceRecord, 0)
	out := make([]DiscoveredPeer, 0)
	now := s.clock.Now().UTC()
	for _, rec := range records {
		rec = clonePresenceRecord(rec)
		if rec.DeviceID == "" || rec.PublicKeyFingerprint == "" || rec.SchemaVersion != schemaVersion {
			continue
		}
		if current.DeviceID != "" && rec.DeviceID == current.DeviceID {
			continue
		}
		dev := trust[rec.DeviceID]
		status := dev.TrustStatus
		if status == "" {
			status = TrustUnknown
		}
		stale := isStale(now, rec.LastSeen)
		if stale && status == TrustTrusted {
			status = TrustStale
		}
		if dev.TrustStatus == TrustTrusted {
			dev.LastSeen = rec.LastSeen
			trust[rec.DeviceID] = dev
		}
		peers = append(peers, rec)
		out = append(out, DiscoveredPeer{Presence: rec, TrustStatus: status, Stale: stale})
	}
	if err := s.store.writePeers(peerFile{SchemaVersion: schemaVersion, Peers: peers, UpdatedAt: now}); err != nil {
		return nil, err
	}
	for i, dev := range reg.Devices {
		if updated, ok := trust[dev.DeviceID]; ok {
			reg.Devices[i] = updated
		}
	}
	if err := s.store.writeRegistry(reg); err != nil {
		return nil, err
	}
	return out, nil
}

func remoteResourceAvailability(now time.Time, peer PresenceRecord, dev TrustedDevice) ResourceAvailability {
	switch dev.TrustStatus {
	case TrustTrusted:
		if isStale(now, peer.LastSeen) || dev.PublicKeyFingerprint == "" || dev.PublicKeyFingerprint != peer.PublicKeyFingerprint {
			return ResourceUnavailable
		}
		return ResourceAvailable
	case TrustRevoked, TrustStale:
		return ResourceUnavailable
	default:
		return ResourceUnknown
	}
}

func clonePresenceRecord(record PresenceRecord) PresenceRecord {
	record.EndpointHints = append([]EndpointHint{}, record.EndpointHints...)
	record.Capabilities = append([]string{}, record.Capabilities...)
	record.ResourcesSummary = append([]ResourceSummary{}, record.ResourcesSummary...)
	return record
}
