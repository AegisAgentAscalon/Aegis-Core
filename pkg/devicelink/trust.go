package devicelink

import (
	"context"
	"sort"
	"strings"
	"time"
)

func (s *Service) ListTrustedDevices(ctx context.Context) ([]TrustedDevice, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	reg, err := s.store.readRegistry()
	if err != nil {
		return nil, err
	}
	out := cloneTrustedDevices(reg.Devices)
	sort.Slice(out, func(i, j int) bool { return out[i].DeviceID < out[j].DeviceID })
	return out, nil
}

func (s *Service) TrustDevice(ctx context.Context, req TrustDeviceRequest) (TrustedDevice, error) {
	now, err := s.lockAtTime(ctx)
	if err != nil {
		return TrustedDevice{}, err
	}
	defer s.mu.Unlock()
	return s.trustDeviceLocked(req, now)
}

func (s *Service) trustDeviceLocked(req TrustDeviceRequest, now time.Time) (TrustedDevice, error) {
	req.DeviceID = strings.TrimSpace(req.DeviceID)
	req.DisplayName = strings.TrimSpace(req.DisplayName)
	if req.DeviceID == "" || !validSafeName(req.DeviceID) {
		return TrustedDevice{}, ErrDeviceNotFound
	}
	publicKey, err := decodePublicKey(req.PublicKey)
	if err != nil {
		return TrustedDevice{}, err
	}
	req.PublicKey = encodePublicKey(publicKey)
	fp := fingerprintPublicKey(publicKey)
	providedFingerprint := strings.ToLower(strings.TrimSpace(req.PublicKeyFingerprint))
	if providedFingerprint != "" && providedFingerprint != fp {
		return TrustedDevice{}, ErrFingerprintMismatch
	}
	req.PublicKeyFingerprint = fp
	reg, err := s.store.readRegistry()
	if err != nil {
		return TrustedDevice{}, err
	}
	for i, dev := range reg.Devices {
		if dev.DeviceID != req.DeviceID {
			continue
		}
		if dev.PublicKeyFingerprint != fp {
			return TrustedDevice{}, ErrDeviceAlreadyExists
		}
		retrust := dev.TrustStatus == TrustRevoked
		var previous registryFile
		var links linkStatusFile
		if retrust {
			previous = cloneRegistryFile(reg)
			links, err = s.store.readLinks()
			if err != nil {
				return TrustedDevice{}, err
			}
		}
		dev.DisplayName = req.DisplayName
		if dev.DisplayName == "" {
			dev.DisplayName = req.DeviceID
		}
		dev.PublicKey = req.PublicKey
		dev.PublicKeyFingerprint = fp
		dev.TrustStatus = TrustTrusted
		dev.RevokedAt = nil
		dev.Capabilities = compactStrings(req.Capabilities)
		dev.ProfileMetadataVersion = metadataVersion
		if retrust {
			dev.TrustedAt = nextTrustTransitionTime(now, dev.TrustedAt, latestProofTime(links, dev.DeviceID))
			now = dev.TrustedAt
		} else if dev.TrustedAt.IsZero() {
			dev.TrustedAt = now
		}
		reg.Devices[i] = dev
		reg.UpdatedAt = now
		if err := s.store.writeRegistry(reg); err != nil {
			return TrustedDevice{}, err
		}
		if retrust {
			links, changed := withoutDeviceLinkStatus(links, dev.DeviceID, now)
			if changed {
				if err := s.store.writeLinks(links); err != nil {
					_ = s.store.writeRegistry(previous)
					return TrustedDevice{}, err
				}
			}
		}
		return cloneTrustedDevice(dev), nil
	}
	dev := TrustedDevice{
		DeviceID:               req.DeviceID,
		DisplayName:            req.DisplayName,
		PublicKey:              req.PublicKey,
		PublicKeyFingerprint:   fp,
		TrustStatus:            TrustTrusted,
		TrustedAt:              now,
		Capabilities:           compactStrings(req.Capabilities),
		ProfileMetadataVersion: metadataVersion,
	}
	if dev.DisplayName == "" {
		dev.DisplayName = req.DeviceID
	}
	reg.Devices = append(reg.Devices, dev)
	reg.UpdatedAt = now
	if err := s.store.writeRegistry(reg); err != nil {
		return TrustedDevice{}, err
	}
	return cloneTrustedDevice(dev), nil
}

func (s *Service) RevokeDevice(ctx context.Context, deviceID string) error {
	now, err := s.lockAtTime(ctx)
	if err != nil {
		return err
	}
	defer s.mu.Unlock()
	reg, err := s.store.readRegistry()
	if err != nil {
		return err
	}
	for i, dev := range reg.Devices {
		if dev.DeviceID == deviceID {
			if now.Before(dev.TrustedAt) {
				now = dev.TrustedAt
			}
			dev.TrustStatus = TrustRevoked
			dev.RevokedAt = &now
			reg.Devices[i] = dev
			reg.UpdatedAt = now
			if err := s.store.writeRegistry(reg); err != nil {
				return err
			}
			// Revocation is already effective after the registry commit. A damaged
			// link cache cannot be allowed to roll trust back to trusted.
			_ = s.clearDeviceLinkStatusLocked(deviceID, now)
			return nil
		}
	}
	return ErrDeviceNotFound
}

func (s *Service) GetDeviceTrustStatus(ctx context.Context, deviceID string) (DeviceTrustStatus, error) {
	if err := contextError(ctx); err != nil {
		return DeviceTrustStatus{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	dev, found, err := s.findTrustedDeviceLocked(deviceID)
	if err != nil {
		return DeviceTrustStatus{}, err
	}
	if !found {
		return DeviceTrustStatus{DeviceID: deviceID, TrustStatus: TrustUnknown, Reason: "device is not trusted"}, nil
	}
	status := DeviceTrustStatus{DeviceID: deviceID, TrustStatus: dev.TrustStatus, Trusted: dev.TrustStatus == TrustTrusted}
	if dev.TrustStatus == TrustRevoked {
		status.Reason = "device is revoked"
	}
	return status, nil
}

func (s *Service) ExportRegistrySnapshot(ctx context.Context) (RegistrySnapshot, error) {
	now, err := s.lockAtTime(ctx)
	if err != nil {
		return RegistrySnapshot{}, err
	}
	defer s.mu.Unlock()
	reg, err := s.store.readRegistry()
	if err != nil {
		return RegistrySnapshot{}, err
	}
	origin := ""
	if id, err := s.store.readIdentity(); err == nil {
		origin = id.DeviceID
	}
	snap := RegistrySnapshot{
		SchemaVersion:          RegistrySnapshotSchemaVersion,
		Purpose:                RegistrySnapshotLocalBackup,
		AppID:                  s.cfg.AppID,
		Namespace:              s.cfg.Namespace,
		Devices:                append([]TrustedDevice{}, reg.Devices...),
		CreatedAt:              now,
		UpdatedAt:              now,
		OriginDeviceID:         origin,
		ProfileMetadataVersion: metadataVersion,
	}
	snap, err = normalizeRegistrySnapshotTrustMaterial(snap)
	if err != nil {
		return RegistrySnapshot{}, ErrStorageUnavailable
	}
	snap.SnapshotFingerprint = snapshotFingerprint(snap)
	return snap, nil
}

func (s *Service) ImportRegistrySnapshot(ctx context.Context, snapshot RegistrySnapshot) error {
	now, err := s.lockAtTime(ctx)
	if err != nil {
		return err
	}
	defer s.mu.Unlock()
	normalized, err := validateRegistryBackupSnapshot(s.cfg, snapshot)
	if err != nil {
		return err
	}
	previous, err := s.store.readRegistry()
	if err != nil {
		return err
	}
	replacement := registryFile{SchemaVersion: schemaVersion, Devices: cloneTrustedDevices(normalized.Devices), UpdatedAt: normalized.UpdatedAt}
	if err := s.store.writeRegistry(replacement); err != nil {
		return err
	}
	// Registry commit comes first. A failed proof clear rolls the registry back;
	// if rollback itself faults, a second clear leaves the imported state safe.
	cleared := linkStatusFile{SchemaVersion: schemaVersion, Links: []ConnectionStatus{}, UpdatedAt: now}
	if err := s.store.writeLinks(cleared); err != nil {
		if rollbackErr := s.store.writeRegistry(previous); rollbackErr == nil {
			return err
		}
		if recoveryErr := s.store.writeLinks(cleared); recoveryErr != nil {
			return ErrStorageUnavailable
		}
		return ErrStorageUnavailable
	}
	return nil
}
