package devicelink

import (
	"context"
	"strings"
)

func (s *Service) AdvertiseResources(ctx context.Context, req ResourceAdvertisementRequest) error {
	now, err := s.lockAtTime(ctx)
	if err != nil {
		return err
	}
	defer s.mu.Unlock()
	current, err := s.store.readIdentity()
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	out := make([]ResourceDescriptor, 0, len(req.Resources))
	for _, res := range req.Resources {
		res.ResourceID = strings.TrimSpace(res.ResourceID)
		res.DisplayName = strings.TrimSpace(res.DisplayName)
		if res.ResourceID == "" || seen[res.ResourceID] || !validResourceType(res.Type) {
			return ErrInvalidResource
		}
		seen[res.ResourceID] = true
		if res.OwnerDeviceID == "" {
			res.OwnerDeviceID = current.DeviceID
		}
		if res.OwnerDeviceID != current.DeviceID {
			return ErrInvalidResource
		}
		if res.Availability == "" {
			res.Availability = ResourceUnknown
		}
		if res.LastUpdated.IsZero() {
			res.LastUpdated = now
		}
		res.Tags = append([]string{}, res.Tags...)
		res.Metadata = cloneMap(res.Metadata)
		if res.Metadata == nil {
			res.Metadata = map[string]string{}
		}
		out = append(out, res)
	}
	return s.store.writeResources(resourceFile{SchemaVersion: schemaVersion, Resources: out, UpdatedAt: now})
}

func (s *Service) ListLocalResources(ctx context.Context) ([]ResourceDescriptor, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	res, err := s.store.readResources()
	if err != nil {
		return nil, err
	}
	return cloneResourceDescriptors(res.Resources), nil
}

func (s *Service) ListKnownRemoteResources(ctx context.Context) ([]RemoteResourceDescriptor, error) {
	now, err := s.lockAtTime(ctx)
	if err != nil {
		return nil, err
	}
	defer s.mu.Unlock()
	peers, err := s.store.readPeers()
	if err != nil {
		return nil, err
	}
	reg, err := s.store.readRegistry()
	if err != nil {
		return nil, err
	}
	trust := map[string]TrustedDevice{}
	for _, dev := range reg.Devices {
		trust[dev.DeviceID] = dev
	}
	out := make([]RemoteResourceDescriptor, 0)
	for _, peer := range peers.Peers {
		dev := trust[peer.DeviceID]
		availability := remoteResourceAvailability(now, peer, dev)
		for _, summary := range peer.ResourcesSummary {
			out = append(out, RemoteResourceDescriptor{
				ResourceDescriptor: ResourceDescriptor{
					ResourceID:    peer.DeviceID + ":" + string(summary.Type),
					Type:          summary.Type,
					DisplayName:   string(summary.Type),
					OwnerDeviceID: peer.DeviceID,
					Availability:  availability,
					Tags:          []string{},
					LastUpdated:   peer.LastSeen,
				},
				DeviceDisplayName:    peer.DisplayName,
				DeviceTrustStatus:    dev.TrustStatus,
				PublicKeyFingerprint: peer.PublicKeyFingerprint,
			})
		}
	}
	return out, nil
}
