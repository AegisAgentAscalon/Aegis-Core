package devicelink

import (
	"encoding/json"
	"time"
)

// registryDeviceRecord is the private persisted/backup view. Public device
// status intentionally keeps PublicKey out of ordinary JSON.
type registryDeviceRecord struct {
	DeviceID               string      `json:"device_id"`
	DisplayName            string      `json:"display_name"`
	PublicKey              string      `json:"public_key"`
	PublicKeyFingerprint   string      `json:"public_key_fingerprint"`
	TrustStatus            TrustStatus `json:"trust_status"`
	TrustedAt              time.Time   `json:"trusted_at,omitempty"`
	RevokedAt              *time.Time  `json:"revoked_at,omitempty"`
	LastSeen               time.Time   `json:"last_seen,omitempty"`
	Capabilities           []string    `json:"capabilities"`
	ProfileMetadataVersion int         `json:"profile_metadata_version"`
}

type registrySnapshotRecord struct {
	SchemaVersion          int                     `json:"schema_version"`
	Purpose                RegistrySnapshotPurpose `json:"purpose"`
	AppID                  string                  `json:"app_id"`
	Namespace              string                  `json:"namespace"`
	Devices                []registryDeviceRecord  `json:"devices"`
	CreatedAt              time.Time               `json:"created_at"`
	UpdatedAt              time.Time               `json:"updated_at"`
	OriginDeviceID         string                  `json:"origin_device_id,omitempty"`
	SnapshotFingerprint    string                  `json:"snapshot_fingerprint,omitempty"`
	ProfileMetadataVersion int                     `json:"profile_metadata_version"`
}

type identityFile struct {
	DeviceID             string    `json:"device_id"`
	DisplayName          string    `json:"display_name"`
	AppID                string    `json:"app_id"`
	Namespace            string    `json:"namespace"`
	PublicKey            string    `json:"public_key"`
	PublicKeyFingerprint string    `json:"public_key_fingerprint"`
	CreatedAt            time.Time `json:"created_at"`
	UpdatedAt            time.Time `json:"updated_at"`
	Capabilities         []string  `json:"capabilities"`
	MetadataVersion      int       `json:"metadata_version"`
}

func identityFileFrom(device DeviceIdentity) identityFile {
	return identityFile{
		DeviceID: device.DeviceID, DisplayName: device.DisplayName, AppID: device.AppID,
		Namespace: device.Namespace, PublicKey: device.PublicKey,
		PublicKeyFingerprint: device.PublicKeyFingerprint, CreatedAt: device.CreatedAt,
		UpdatedAt: device.UpdatedAt, Capabilities: append([]string(nil), device.Capabilities...),
		MetadataVersion: device.MetadataVersion,
	}
}

func (device identityFile) identity() DeviceIdentity {
	return DeviceIdentity{
		DeviceID: device.DeviceID, DisplayName: device.DisplayName, AppID: device.AppID,
		Namespace: device.Namespace, PublicKey: device.PublicKey,
		PublicKeyFingerprint: device.PublicKeyFingerprint, CreatedAt: device.CreatedAt,
		UpdatedAt: device.UpdatedAt, Capabilities: append([]string(nil), device.Capabilities...),
		MetadataVersion: device.MetadataVersion,
	}
}

func registryDeviceRecordFrom(device TrustedDevice) registryDeviceRecord {
	return registryDeviceRecord{
		DeviceID: device.DeviceID, DisplayName: device.DisplayName,
		PublicKey: device.PublicKey, PublicKeyFingerprint: device.PublicKeyFingerprint,
		TrustStatus: device.TrustStatus, TrustedAt: device.TrustedAt,
		RevokedAt: device.RevokedAt, LastSeen: device.LastSeen,
		Capabilities:           append([]string(nil), device.Capabilities...),
		ProfileMetadataVersion: device.ProfileMetadataVersion,
	}
}

func trustedDeviceFromRegistryRecord(device registryDeviceRecord) TrustedDevice {
	return TrustedDevice{
		DeviceID: device.DeviceID, DisplayName: device.DisplayName,
		PublicKey: device.PublicKey, PublicKeyFingerprint: device.PublicKeyFingerprint,
		TrustStatus: device.TrustStatus, TrustedAt: device.TrustedAt,
		RevokedAt: device.RevokedAt, LastSeen: device.LastSeen,
		Capabilities:           append([]string(nil), device.Capabilities...),
		ProfileMetadataVersion: device.ProfileMetadataVersion,
	}
}

func registrySnapshotRecordFrom(snapshot RegistrySnapshot, materializeEmptyCapabilities bool) registrySnapshotRecord {
	devices := make([]registryDeviceRecord, 0, len(snapshot.Devices))
	for _, device := range snapshot.Devices {
		record := registryDeviceRecordFrom(device)
		if materializeEmptyCapabilities {
			// The public facade's converters materialized absent capability slices
			// as an empty slice in registry snapshots. Keep that public JSON shape
			// separate from the private registry file's nil-preserving wire form.
			record.Capabilities = append([]string{}, device.Capabilities...)
		}
		devices = append(devices, record)
	}
	return registrySnapshotRecord{
		SchemaVersion: snapshot.SchemaVersion, Purpose: snapshot.Purpose,
		AppID: snapshot.AppID, Namespace: snapshot.Namespace, Devices: devices,
		CreatedAt: snapshot.CreatedAt, UpdatedAt: snapshot.UpdatedAt,
		OriginDeviceID: snapshot.OriginDeviceID, SnapshotFingerprint: snapshot.SnapshotFingerprint,
		ProfileMetadataVersion: snapshot.ProfileMetadataVersion,
	}
}

func trustedDeviceFromRegistrySnapshotRecord(device registryDeviceRecord) TrustedDevice {
	trusted := trustedDeviceFromRegistryRecord(device)
	trusted.Capabilities = append([]string{}, device.Capabilities...)
	return trusted
}

func (reg registryFile) MarshalJSON() ([]byte, error) {
	type wire struct {
		SchemaVersion int                    `json:"schema_version"`
		Devices       []registryDeviceRecord `json:"devices"`
		UpdatedAt     time.Time              `json:"updated_at"`
	}
	devices := make([]registryDeviceRecord, 0, len(reg.Devices))
	for _, device := range reg.Devices {
		devices = append(devices, registryDeviceRecordFrom(device))
	}
	return json.Marshal(wire{SchemaVersion: reg.SchemaVersion, Devices: devices, UpdatedAt: reg.UpdatedAt})
}

func (reg *registryFile) UnmarshalJSON(data []byte) error {
	type wire struct {
		SchemaVersion int                    `json:"schema_version"`
		Devices       []registryDeviceRecord `json:"devices"`
		UpdatedAt     time.Time              `json:"updated_at"`
	}
	var decoded wire
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	devices := make([]TrustedDevice, 0, len(decoded.Devices))
	for _, device := range decoded.Devices {
		devices = append(devices, trustedDeviceFromRegistryRecord(device))
	}
	*reg = registryFile{SchemaVersion: decoded.SchemaVersion, Devices: devices, UpdatedAt: decoded.UpdatedAt}
	return nil
}

func (snapshot RegistrySnapshot) MarshalJSON() ([]byte, error) {
	return json.Marshal(registrySnapshotRecordFrom(snapshot, true))
}

func (snapshot *RegistrySnapshot) UnmarshalJSON(data []byte) error {
	var decoded registrySnapshotRecord
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	devices := make([]TrustedDevice, 0, len(decoded.Devices))
	for _, device := range decoded.Devices {
		devices = append(devices, trustedDeviceFromRegistrySnapshotRecord(device))
	}
	*snapshot = RegistrySnapshot{
		SchemaVersion: decoded.SchemaVersion, Purpose: decoded.Purpose,
		AppID: decoded.AppID, Namespace: decoded.Namespace, Devices: devices,
		CreatedAt: decoded.CreatedAt, UpdatedAt: decoded.UpdatedAt,
		OriginDeviceID:         decoded.OriginDeviceID,
		SnapshotFingerprint:    decoded.SnapshotFingerprint,
		ProfileMetadataVersion: decoded.ProfileMetadataVersion,
	}
	return nil
}
