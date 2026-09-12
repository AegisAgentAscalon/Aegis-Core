package devicelink

import (
	"context"
	"time"
)

type TrustStatus string

const (
	TrustUnknown TrustStatus = "unknown"
	TrustPending TrustStatus = "pending"
	TrustTrusted TrustStatus = "trusted"
	TrustRevoked TrustStatus = "revoked"
	TrustStale   TrustStatus = "stale"
)

type RegistrySnapshotPurpose string

const RegistrySnapshotLocalBackup RegistrySnapshotPurpose = "local_backup"

type TrustedDevice struct {
	DeviceID               string      `json:"device_id"`
	DisplayName            string      `json:"display_name"`
	PublicKey              string      `json:"-"`
	PublicKeyFingerprint   string      `json:"public_key_fingerprint"`
	TrustStatus            TrustStatus `json:"trust_status"`
	TrustedAt              time.Time   `json:"trusted_at,omitempty"`
	RevokedAt              *time.Time  `json:"revoked_at,omitempty"`
	LastSeen               time.Time   `json:"last_seen,omitempty"`
	Capabilities           []string    `json:"capabilities"`
	ProfileMetadataVersion int         `json:"profile_metadata_version"`
}

type TrustDeviceRequest struct {
	DeviceID             string
	DisplayName          string
	PublicKey            string
	PublicKeyFingerprint string
	Capabilities         []string
}

type DeviceTrustStatus struct {
	DeviceID    string      `json:"device_id"`
	TrustStatus TrustStatus `json:"trust_status"`
	Trusted     bool        `json:"trusted"`
	Reason      string      `json:"reason,omitempty"`
}

type RegistrySnapshot struct {
	SchemaVersion          int                     `json:"schema_version"`
	Purpose                RegistrySnapshotPurpose `json:"purpose"`
	AppID                  string                  `json:"app_id"`
	Namespace              string                  `json:"namespace"`
	Devices                []TrustedDevice         `json:"devices"`
	CreatedAt              time.Time               `json:"created_at"`
	UpdatedAt              time.Time               `json:"updated_at"`
	OriginDeviceID         string                  `json:"origin_device_id,omitempty"`
	SnapshotFingerprint    string                  `json:"snapshot_fingerprint,omitempty"`
	ProfileMetadataVersion int                     `json:"profile_metadata_version"`
}

type ProfileMetadataProvider interface {
	LoadRegistrySnapshot(ctx context.Context) (RegistrySnapshot, error)
	SaveRegistrySnapshot(ctx context.Context, snapshot RegistrySnapshot) error
}
