package profilemesh

import (
	"context"
	"sort"
	"strings"
)

func (s *Service) RegisterProfileDevice(ctx context.Context, req RegisterProfileDeviceRequest) (ProfileDeviceRecord, error) {
	return s.registerProfileDevice(ctx, req, false)
}

func (s *Service) registerProfileDevice(ctx context.Context, req RegisterProfileDeviceRequest, strict bool) (ProfileDeviceRecord, error) {
	if err := contextError(ctx); err != nil {
		return ProfileDeviceRecord{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.store.readProfile(); err != nil {
		return ProfileDeviceRecord{}, err
	}
	req.DeviceID = strings.TrimSpace(req.DeviceID)
	req.PublicKeyFingerprint = normalizeFingerprint(req.PublicKeyFingerprint)
	req.MetadataSource = strings.TrimSpace(req.MetadataSource)
	if req.DeviceID == "" || !validID(req.DeviceID) || !validFingerprint(req.PublicKeyFingerprint) {
		return ProfileDeviceRecord{}, ErrDeviceNotAllowed
	}
	if req.TrustStatus == "" {
		req.TrustStatus = DeviceTrustTrusted
	}
	if req.Status == "" {
		req.Status = DeviceStatusActive
	}
	if !validDeviceTrustStatus(req.TrustStatus) || !validDeviceStatus(req.Status) {
		return ProfileDeviceRecord{}, ErrDeviceNotAllowed
	}
	if (strict && !validStrictDeviceLifecycle(req.TrustStatus, req.Status)) || (req.Status == DeviceStatusRemoved && req.TrustStatus != DeviceTrustRevoked) {
		return ProfileDeviceRecord{}, ErrDeviceNotAllowed
	}
	now := s.clock.Now().UTC()
	reg, err := s.store.readDevices()
	if err != nil {
		return ProfileDeviceRecord{}, err
	}
	for i, device := range reg.Devices {
		if device.DeviceID != req.DeviceID {
			continue
		}
		if normalizeFingerprint(device.PublicKeyFingerprint) != req.PublicKeyFingerprint {
			return ProfileDeviceRecord{}, ErrDeviceNotAllowed
		}
		device.DisplayName = displayOrID(req.DisplayName, req.DeviceID)
		device.TrustStatus = req.TrustStatus
		device.Status = req.Status
		device.Capabilities = compactStrings(req.Capabilities)
		device.MetadataSource = req.MetadataSource
		device.UpdatedAt = now
		switch req.Status {
		case DeviceStatusActive, DeviceStatusStale:
			device.LastSeen = now
			device.RemovedAt = nil
		case DeviceStatusRemoved:
			if device.RemovedAt == nil {
				removedAt := now
				device.RemovedAt = &removedAt
			}
		default:
			device.RemovedAt = nil
		}
		device.ProfileMetadataVersion = metadataVersion
		reg.Devices[i] = device
		reg.UpdatedAt = now
		if err := s.store.writeDevices(reg); err != nil {
			return ProfileDeviceRecord{}, err
		}
		return cloneProfileDevice(device), nil
	}
	device := ProfileDeviceRecord{
		DeviceID:               req.DeviceID,
		DisplayName:            displayOrID(req.DisplayName, req.DeviceID),
		PublicKeyFingerprint:   req.PublicKeyFingerprint,
		TrustStatus:            req.TrustStatus,
		Status:                 req.Status,
		Capabilities:           compactStrings(req.Capabilities),
		RegisteredAt:           now,
		UpdatedAt:              now,
		MetadataSource:         req.MetadataSource,
		ProfileMetadataVersion: metadataVersion,
	}
	if req.Status == DeviceStatusActive || req.Status == DeviceStatusStale {
		device.LastSeen = now
	}
	if req.Status == DeviceStatusRemoved {
		removedAt := now
		device.RemovedAt = &removedAt
	}
	reg.Devices = append(reg.Devices, device)
	reg.UpdatedAt = now
	if err := s.store.writeDevices(reg); err != nil {
		return ProfileDeviceRecord{}, err
	}
	return cloneProfileDevice(device), nil
}

// RegisterProfileDeviceStrict requires callers to make trust and lifecycle
// state explicit. It does not infer app membership or passphrase policy.
func (s *Service) RegisterProfileDeviceStrict(ctx context.Context, req RegisterProfileDeviceRequest) (ProfileDeviceRecord, error) {
	if err := contextError(ctx); err != nil {
		return ProfileDeviceRecord{}, err
	}
	if req.TrustStatus == "" || req.Status == "" {
		return ProfileDeviceRecord{}, ErrDeviceNotAllowed
	}
	return s.registerProfileDevice(ctx, req, true)
}

func (s *Service) ListProfileDevices(ctx context.Context) ([]ProfileDeviceRecord, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	reg, err := s.store.readDevices()
	if err != nil {
		return nil, err
	}
	out := cloneProfileDevices(reg.Devices)
	sort.Slice(out, func(i, j int) bool { return out[i].DeviceID < out[j].DeviceID })
	return out, nil
}

func (s *Service) RemoveProfileDevice(ctx context.Context, deviceID string) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	reg, err := s.store.readDevices()
	if err != nil {
		return err
	}
	now := s.clock.Now().UTC()
	for i, device := range reg.Devices {
		if device.DeviceID == deviceID {
			device.Status = DeviceStatusRemoved
			device.TrustStatus = DeviceTrustRevoked
			device.RemovedAt = &now
			device.UpdatedAt = now
			reg.Devices[i] = device
			reg.UpdatedAt = now
			return s.store.writeDevices(reg)
		}
	}
	return ErrDeviceNotRegistered
}
