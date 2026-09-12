package devicelink

import (
	"time"
)

type BootstrapState string

const (
	BootstrapAbsent  BootstrapState = "absent"
	BootstrapPartial BootstrapState = "partial"
	BootstrapReady   BootstrapState = "ready"
	BootstrapInvalid BootstrapState = "invalid"
)

type BootstrapDeviceRequest struct {
	DisplayName  string
	Capabilities []string
}

type BootstrapStatus struct {
	State             BootstrapState `json:"state"`
	Bootstrapped      bool           `json:"bootstrapped"`
	Ready             bool           `json:"ready"`
	IdentityPresent   bool           `json:"identity_present"`
	PrivateKeyPresent bool           `json:"private_key_present"`
	DeviceID          string         `json:"device_id,omitempty"`
	Message           string         `json:"message,omitempty"`
}

type DeviceIdentity struct {
	DeviceID             string    `json:"device_id"`
	DisplayName          string    `json:"display_name"`
	AppID                string    `json:"app_id"`
	Namespace            string    `json:"namespace"`
	PublicKey            string    `json:"-"`
	PublicKeyFingerprint string    `json:"public_key_fingerprint"`
	CreatedAt            time.Time `json:"created_at"`
	UpdatedAt            time.Time `json:"updated_at"`
	Capabilities         []string  `json:"capabilities"`
	MetadataVersion      int       `json:"metadata_version"`
}

type PublicIdentityBundle struct {
	SchemaVersion        int       `json:"schema_version"`
	BundleVersion        int       `json:"bundle_version"`
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
	BundleFingerprint    string    `json:"bundle_fingerprint"`
}
