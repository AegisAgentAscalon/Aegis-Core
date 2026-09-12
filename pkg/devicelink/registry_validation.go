package devicelink

import (
	"encoding/json"
	"sort"
	"strings"
)

func snapshotFingerprint(snapshot RegistrySnapshot) string {
	canonical, err := normalizeRegistrySnapshotTrustMaterial(snapshot)
	if err != nil {
		canonical = snapshot
	}
	canonical.SnapshotFingerprint = ""
	canonical.Devices = cloneTrustedDevices(canonical.Devices)
	for i := range canonical.Devices {
		canonical.Devices[i].Capabilities = compactStrings(canonical.Devices[i].Capabilities)
	}
	sort.Slice(canonical.Devices, func(i, j int) bool {
		if canonical.Devices[i].DeviceID == canonical.Devices[j].DeviceID {
			return canonical.Devices[i].PublicKeyFingerprint < canonical.Devices[j].PublicKeyFingerprint
		}
		return canonical.Devices[i].DeviceID < canonical.Devices[j].DeviceID
	})
	// Registry snapshots have a public codec that materializes nil capability
	// slices as [] for compatibility. Fingerprints retain the historical
	// canonical wire shape, including private-wire nil capability handling.
	raw, _ := json.Marshal(registrySnapshotRecordFrom(canonical, false))
	sum := sha256String(string(raw))
	return sum[:16]
}

func legacyRegistrySnapshotFingerprint(snapshot RegistrySnapshot) string {
	parts := make([]string, 0, len(snapshot.Devices))
	for _, dev := range snapshot.Devices {
		parts = append(parts, dev.DeviceID+"="+dev.PublicKeyFingerprint)
	}
	sort.Strings(parts)
	return sha256String(snapshot.AppID + "|" + snapshot.Namespace + "|" + strings.Join(parts, "|"))[:16]
}

func normalizeRegistrySnapshotTrustMaterial(snapshot RegistrySnapshot) (RegistrySnapshot, error) {
	normalized := snapshot
	normalized.Devices = cloneTrustedDevices(snapshot.Devices)
	for i := range normalized.Devices {
		dev := &normalized.Devices[i]
		publicKey, err := decodePublicKey(dev.PublicKey)
		if err != nil {
			return RegistrySnapshot{}, err
		}
		dev.PublicKey = encodePublicKey(publicKey)
		dev.PublicKeyFingerprint = strings.ToLower(strings.TrimSpace(dev.PublicKeyFingerprint))
		dev.Capabilities = compactStrings(dev.Capabilities)
	}
	return normalized, nil
}

func validateRegistryBackupSnapshot(cfg AppConfig, snapshot RegistrySnapshot) (RegistrySnapshot, error) {
	if snapshot.AppID != cfg.AppID || snapshot.Namespace != cfg.Namespace {
		return RegistrySnapshot{}, ErrInvalidRegistrySnapshot
	}
	switch snapshot.SchemaVersion {
	case legacyRegistrySnapshotSchemaVersion:
		if snapshot.Purpose != "" && snapshot.Purpose != RegistrySnapshotLocalBackup {
			return RegistrySnapshot{}, ErrInvalidRegistrySnapshot
		}
		if snapshot.SnapshotFingerprint != "" && snapshot.SnapshotFingerprint != legacyRegistrySnapshotFingerprint(snapshot) {
			return RegistrySnapshot{}, ErrInvalidRegistrySnapshot
		}
	case RegistrySnapshotSchemaVersion:
		if snapshot.Purpose != RegistrySnapshotLocalBackup || snapshot.SnapshotFingerprint == "" {
			return RegistrySnapshot{}, ErrInvalidRegistrySnapshot
		}
	default:
		return RegistrySnapshot{}, ErrInvalidRegistrySnapshot
	}
	if snapshot.ProfileMetadataVersion != metadataVersion || snapshot.CreatedAt.IsZero() || snapshot.UpdatedAt.IsZero() || snapshot.UpdatedAt.Before(snapshot.CreatedAt) {
		return RegistrySnapshot{}, ErrInvalidRegistrySnapshot
	}
	if snapshot.OriginDeviceID != "" && !validSafeName(snapshot.OriginDeviceID) {
		return RegistrySnapshot{}, ErrInvalidRegistrySnapshot
	}
	normalized, err := normalizeRegistrySnapshotTrustMaterial(snapshot)
	if err != nil {
		return RegistrySnapshot{}, err
	}
	if snapshot.SchemaVersion == RegistrySnapshotSchemaVersion && snapshot.SnapshotFingerprint != snapshotFingerprint(normalized) {
		return RegistrySnapshot{}, ErrInvalidRegistrySnapshot
	}
	seen := map[string]string{}
	for _, dev := range normalized.Devices {
		if !validSafeName(dev.DeviceID) || strings.TrimSpace(dev.DisplayName) == "" || dev.DisplayName != strings.TrimSpace(dev.DisplayName) || dev.PublicKey == "" {
			return RegistrySnapshot{}, ErrInvalidRegistrySnapshot
		}
		if !validTrustStatus(dev.TrustStatus) || dev.ProfileMetadataVersion != metadataVersion {
			return RegistrySnapshot{}, ErrInvalidRegistrySnapshot
		}
		if (dev.TrustStatus == TrustTrusted || dev.TrustStatus == TrustRevoked) && dev.TrustedAt.IsZero() {
			return RegistrySnapshot{}, ErrInvalidRegistrySnapshot
		}
		if dev.TrustStatus == TrustRevoked {
			if dev.RevokedAt == nil || dev.RevokedAt.Before(dev.TrustedAt) {
				return RegistrySnapshot{}, ErrInvalidRegistrySnapshot
			}
		} else if dev.RevokedAt != nil {
			return RegistrySnapshot{}, ErrInvalidRegistrySnapshot
		}
		publicKey, err := decodePublicKey(dev.PublicKey)
		if err != nil {
			return RegistrySnapshot{}, err
		}
		fingerprint := fingerprintPublicKey(publicKey)
		if dev.PublicKeyFingerprint != fingerprint {
			return RegistrySnapshot{}, ErrFingerprintMismatch
		}
		if old, ok := seen[dev.DeviceID]; ok {
			if old != fingerprint {
				return RegistrySnapshot{}, ErrFingerprintMismatch
			}
			return RegistrySnapshot{}, ErrInvalidRegistrySnapshot
		}
		seen[dev.DeviceID] = fingerprint
	}
	normalized.SchemaVersion = RegistrySnapshotSchemaVersion
	normalized.Purpose = RegistrySnapshotLocalBackup
	normalized.SnapshotFingerprint = snapshotFingerprint(normalized)
	return normalized, nil
}

func validTrustStatus(status TrustStatus) bool {
	switch status {
	case TrustUnknown, TrustPending, TrustTrusted, TrustRevoked, TrustStale:
		return true
	default:
		return false
	}
}
