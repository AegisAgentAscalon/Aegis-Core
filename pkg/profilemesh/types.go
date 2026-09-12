// Package profilemesh owns profile-centered device, resource and snapshot metadata.
package profilemesh

import (
	"errors"
	"time"
)

const (
	schemaVersion                          = 1
	ProfileMeshSnapshotSchemaVersion       = 2
	legacyProfileMeshSnapshotSchemaVersion = 1
	metadataVersion                        = 1
	defaultStaleAge                        = 10 * time.Minute
	defaultFutureSkew                      = 2 * time.Minute
)

var (
	ErrNotConfigured          = errors.New("profile mesh is not configured")
	ErrInvalidNamespace       = errors.New("invalid app id or namespace")
	ErrProfileNotFound        = errors.New("profile is not bootstrapped")
	ErrProfileAlreadyExists   = errors.New("profile already exists")
	ErrInvalidProfileSnapshot = errors.New("invalid profile mesh snapshot")
	ErrDeviceNotRegistered    = errors.New("device is not registered with the profile")
	ErrDeviceNotAllowed       = errors.New("device is not allowed for this profile resource")
	ErrDeviceRevoked          = errors.New("device is revoked or removed")
	ErrDeviceStale            = errors.New("device is stale")
	ErrResourceNotFound       = errors.New("profile resource not found")
	ErrInvalidResource        = errors.New("invalid profile resource")
	ErrHostUnavailable        = errors.New("profile resource host is unavailable")
	ErrUnsupportedHostingMode = errors.New("profile hosting mode is not supported in this version")
	ErrStorageUnavailable     = errors.New("profile mesh storage unavailable")
	ErrContextCanceled        = errors.New("profile mesh operation canceled")
)

type AppConfig struct {
	AppID       string
	DisplayName string
	DataDir     string
	Namespace   string
}

type Option func(*options)

type options struct {
	clock Clock
}

type Clock interface {
	Now() time.Time
}

type realClock struct{}

type BootstrapProfileRequest struct {
	DisplayName string
	ProfileID   string
}

type ProfileIdentity struct {
	ProfileID                string    `json:"profile_id"`
	AppID                    string    `json:"app_id"`
	Namespace                string    `json:"namespace"`
	DisplayName              string    `json:"display_name"`
	CreatedAt                time.Time `json:"created_at"`
	UpdatedAt                time.Time `json:"updated_at"`
	SchemaVersion            int       `json:"schema_version"`
	MetadataVersion          int       `json:"metadata_version"`
	ProfilePublicFingerprint string    `json:"profile_public_fingerprint,omitempty"`
}

type ProfileHostingMode string

const (
	HostingSingleProfileDevice ProfileHostingMode = "single_hosted_profile_device"
	HostingMultiProfileDevices ProfileHostingMode = "multi_hosted_profile_devices"
)

type ProfileHostingConfig struct {
	HostingMode              ProfileHostingMode `json:"hosting_mode"`
	PrimaryProfileDeviceID   string             `json:"primary_profile_device_id,omitempty"`
	ProfileDataHostDeviceID  string             `json:"profile_data_host_device_id,omitempty"`
	LocalCacheEnabled        bool               `json:"local_cache_enabled"`
	OfflineBranchModePlanned bool               `json:"offline_branch_mode_planned"`
	UpdatedAt                time.Time          `json:"updated_at"`
}

type SetProfileHostingModeRequest struct {
	HostingMode             ProfileHostingMode
	PrimaryProfileDeviceID  string
	ProfileDataHostDeviceID string
	LocalCacheEnabled       bool
}

type ProfileDeviceTrustStatus string

const (
	DeviceTrustUnknown ProfileDeviceTrustStatus = "unknown"
	DeviceTrustTrusted ProfileDeviceTrustStatus = "trusted"
	DeviceTrustRevoked ProfileDeviceTrustStatus = "revoked"
	DeviceTrustStale   ProfileDeviceTrustStatus = "stale"
)

type ProfileDeviceStatus string

const (
	DeviceStatusActive  ProfileDeviceStatus = "active"
	DeviceStatusStale   ProfileDeviceStatus = "stale"
	DeviceStatusRevoked ProfileDeviceStatus = "revoked"
	DeviceStatusRemoved ProfileDeviceStatus = "removed"
)

type RegisterProfileDeviceRequest struct {
	DeviceID             string
	DisplayName          string
	PublicKeyFingerprint string
	TrustStatus          ProfileDeviceTrustStatus
	Status               ProfileDeviceStatus
	Capabilities         []string
	MetadataSource       string
}

type ProfileDeviceRecord struct {
	DeviceID               string                   `json:"device_id"`
	DisplayName            string                   `json:"display_name"`
	PublicKeyFingerprint   string                   `json:"public_key_fingerprint"`
	TrustStatus            ProfileDeviceTrustStatus `json:"trust_status"`
	Status                 ProfileDeviceStatus      `json:"status"`
	Capabilities           []string                 `json:"capabilities"`
	LastSeen               time.Time                `json:"last_seen,omitempty"`
	RegisteredAt           time.Time                `json:"registered_at"`
	UpdatedAt              time.Time                `json:"updated_at"`
	RemovedAt              *time.Time               `json:"removed_at,omitempty"`
	MetadataSource         string                   `json:"metadata_source,omitempty"`
	ProfileMetadataVersion int                      `json:"profile_metadata_version"`
}

type ProfileResourceType string

const (
	ResourceProfileData ProfileResourceType = "profile_data"
	ResourceService     ProfileResourceType = "service"
	ResourceConnector   ProfileResourceType = "connector"
	ResourceRuntime     ProfileResourceType = "runtime"
	ResourceTool        ProfileResourceType = "tool"
	ResourceOther       ProfileResourceType = "other"
)

type ProfileResourceAvailability string

const (
	ResourceAvailable   ProfileResourceAvailability = "available"
	ResourceUnavailable ProfileResourceAvailability = "unavailable"
	ResourceStale       ProfileResourceAvailability = "stale"
	ResourceMigrating   ProfileResourceAvailability = "migrating"
	ResourceUnknown     ProfileResourceAvailability = "unknown"
)

type ProfileResourceHostingMode string

const (
	ResourceHostingSingleHost       ProfileResourceHostingMode = "single_host"
	ResourceHostingMultiHostPlanned ProfileResourceHostingMode = "multi_host_planned"
)

type RegisterProfileResourceRequest struct {
	ResourceID           string
	ResourceType         ProfileResourceType
	DisplayName          string
	CurrentHostDeviceID  string
	AllowedHostDeviceIDs []string
	Availability         ProfileResourceAvailability
	HostingMode          ProfileResourceHostingMode
	Tags                 []string
	Metadata             map[string]string
}

type SetResourceHostRequest struct {
	ResourceID string
	DeviceID   string
}

type ProfileResourceRecord struct {
	ResourceID           string                      `json:"resource_id"`
	ResourceType         ProfileResourceType         `json:"resource_type"`
	DisplayName          string                      `json:"display_name"`
	ProfileOwnerID       string                      `json:"profile_owner_id"`
	CurrentHostDeviceID  string                      `json:"current_host_device_id,omitempty"`
	AllowedHostDeviceIDs []string                    `json:"allowed_host_device_ids"`
	Availability         ProfileResourceAvailability `json:"availability"`
	HostingMode          ProfileResourceHostingMode  `json:"hosting_mode"`
	Tags                 []string                    `json:"tags"`
	Metadata             map[string]string           `json:"metadata"`
	CreatedAt            time.Time                   `json:"created_at"`
	UpdatedAt            time.Time                   `json:"updated_at"`
}

type ProfileResourceHostStatus struct {
	ResourceID     string                      `json:"resource_id"`
	ProfileOwnerID string                      `json:"profile_owner_id"`
	HostDeviceID   string                      `json:"host_device_id,omitempty"`
	HostStatus     ProfileDeviceStatus         `json:"host_status,omitempty"`
	Availability   ProfileResourceAvailability `json:"availability"`
	HostAvailable  bool                        `json:"host_available"`
	Message        string                      `json:"message,omitempty"`
}

type ProfileEndpointType string

const (
	EndpointLocal  ProfileEndpointType = "local"
	EndpointRelay  ProfileEndpointType = "relay"
	EndpointDirect ProfileEndpointType = "direct"
)

type ProfileEndpointHint struct {
	ProfileID    string              `json:"profile_id"`
	DeviceID     string              `json:"device_id"`
	EndpointType ProfileEndpointType `json:"endpoint_type"`
	Address      string              `json:"address,omitempty"`
	ExpiresAt    time.Time           `json:"expires_at,omitempty"`
	LastSeen     time.Time           `json:"last_seen,omitempty"`
	Capabilities []string            `json:"capabilities"`
	Metadata     map[string]string   `json:"metadata,omitempty"`
}

type ProfileRelayHint struct {
	ProfileID       string              `json:"profile_id"`
	DeviceID        string              `json:"device_id"`
	RelayProviderID string              `json:"relay_provider_id"`
	EndpointType    ProfileEndpointType `json:"endpoint_type"`
	ExpiresAt       time.Time           `json:"expires_at,omitempty"`
	LastSeen        time.Time           `json:"last_seen,omitempty"`
	Capabilities    []string            `json:"capabilities"`
	Metadata        map[string]string   `json:"metadata,omitempty"`
}

type RelayRendezvousRecord struct {
	ProfileID       string              `json:"profile_id"`
	DeviceID        string              `json:"device_id"`
	RelayProviderID string              `json:"relay_provider_id"`
	EndpointType    ProfileEndpointType `json:"endpoint_type"`
	ExpiresAt       time.Time           `json:"expires_at,omitempty"`
	LastSeen        time.Time           `json:"last_seen,omitempty"`
	Capabilities    []string            `json:"capabilities"`
	Metadata        map[string]string   `json:"metadata,omitempty"`
}

type ProfileMeshSnapshot struct {
	SchemaVersion       int                     `json:"schema_version"`
	AppID               string                  `json:"app_id"`
	Namespace           string                  `json:"namespace"`
	Profile             ProfileIdentity         `json:"profile"`
	HostingConfig       ProfileHostingConfig    `json:"hosting_config"`
	Devices             []ProfileDeviceRecord   `json:"devices"`
	Resources           []ProfileResourceRecord `json:"resources"`
	RelayHints          []ProfileRelayHint      `json:"relay_hints,omitempty"`
	EndpointHints       []ProfileEndpointHint   `json:"endpoint_hints,omitempty"`
	CreatedAt           time.Time               `json:"created_at"`
	UpdatedAt           time.Time               `json:"updated_at"`
	SnapshotFingerprint string                  `json:"snapshot_fingerprint,omitempty"`
	MetadataVersion     int                     `json:"metadata_version"`
}

type ProfileMeshIssue struct {
	Code     string `json:"code"`
	Message  string `json:"message"`
	Blocking bool   `json:"blocking"`
}

type ProfileMeshOverview struct {
	ProfileID               string             `json:"profile_id,omitempty"`
	AppID                   string             `json:"app_id"`
	Namespace               string             `json:"namespace"`
	DisplayName             string             `json:"display_name"`
	Bootstrapped            bool               `json:"bootstrapped"`
	Ready                   bool               `json:"ready"`
	HostingMode             ProfileHostingMode `json:"hosting_mode"`
	PrimaryProfileDeviceID  string             `json:"primary_profile_device_id,omitempty"`
	ProfileDataHostDeviceID string             `json:"profile_data_host_device_id,omitempty"`
	DeviceCount             int                `json:"device_count"`
	ResourceCount           int                `json:"resource_count"`
	Issues                  []ProfileMeshIssue `json:"issues"`
	Warnings                []ProfileMeshIssue `json:"warnings"`
	Message                 string             `json:"message,omitempty"`
}
