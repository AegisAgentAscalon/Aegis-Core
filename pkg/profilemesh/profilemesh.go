// Package profilemesh exposes profile-centered, device-assisted mesh metadata contracts.
package profilemesh

import (
	"context"
	"time"

	internal "github.com/AegisAgentAscalon/aegis-core/internal/profilemesh"
)

var (
	ErrNotConfigured          = internal.ErrNotConfigured
	ErrInvalidNamespace       = internal.ErrInvalidNamespace
	ErrProfileNotFound        = internal.ErrProfileNotFound
	ErrProfileAlreadyExists   = internal.ErrProfileAlreadyExists
	ErrInvalidProfileSnapshot = internal.ErrInvalidProfileSnapshot
	ErrDeviceNotRegistered    = internal.ErrDeviceNotRegistered
	ErrDeviceNotAllowed       = internal.ErrDeviceNotAllowed
	ErrDeviceRevoked          = internal.ErrDeviceRevoked
	ErrDeviceStale            = internal.ErrDeviceStale
	ErrResourceNotFound       = internal.ErrResourceNotFound
	ErrInvalidResource        = internal.ErrInvalidResource
	ErrHostUnavailable        = internal.ErrHostUnavailable
	ErrUnsupportedHostingMode = internal.ErrUnsupportedHostingMode
	ErrStorageUnavailable     = internal.ErrStorageUnavailable
	ErrContextCanceled        = internal.ErrContextCanceled
)

type AppConfig struct {
	AppID       string
	DisplayName string
	DataDir     string
	Namespace   string
}

// Option configures a public Profile Mesh service without exposing internal
// service implementation knobs as a stable API.
type Option func(*options)

type options struct {
	clock Clock
}

type Clock interface {
	Now() time.Time
}

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

type Service struct{ svc *internal.Service }

func WithClock(clock Clock) Option {
	return func(opts *options) {
		opts.clock = clock
	}
}

func NewService(config AppConfig, opts ...Option) (*Service, error) {
	publicOptions := options{}
	for _, opt := range opts {
		if opt != nil {
			opt(&publicOptions)
		}
	}
	var internalOptions []internal.Option
	if publicOptions.clock != nil {
		internalOptions = append(internalOptions, internal.WithClock(publicOptions.clock))
	}
	svc, err := internal.NewService(internal.AppConfig(config), internalOptions...)
	if err != nil {
		return nil, err
	}
	return &Service{svc: svc}, nil
}

func (s *Service) ValidateConfig() error { return s.svc.ValidateConfig() }

func (s *Service) BootstrapProfile(ctx context.Context, req BootstrapProfileRequest) (ProfileIdentity, error) {
	res, err := s.svc.BootstrapProfile(ctx, internal.BootstrapProfileRequest(req))
	return fromInternalProfile(res), err
}
func (s *Service) GetProfile(ctx context.Context) (ProfileIdentity, error) {
	res, err := s.svc.GetProfile(ctx)
	return fromInternalProfile(res), err
}
func (s *Service) SetProfileHostingMode(ctx context.Context, req SetProfileHostingModeRequest) (ProfileHostingConfig, error) {
	res, err := s.svc.SetProfileHostingMode(ctx, internal.SetProfileHostingModeRequest{HostingMode: internal.ProfileHostingMode(req.HostingMode), PrimaryProfileDeviceID: req.PrimaryProfileDeviceID, ProfileDataHostDeviceID: req.ProfileDataHostDeviceID, LocalCacheEnabled: req.LocalCacheEnabled})
	return fromInternalHosting(res), err
}
func (s *Service) GetProfileHostingConfig(ctx context.Context) (ProfileHostingConfig, error) {
	res, err := s.svc.GetProfileHostingConfig(ctx)
	return fromInternalHosting(res), err
}
func (s *Service) RegisterProfileDevice(ctx context.Context, req RegisterProfileDeviceRequest) (ProfileDeviceRecord, error) {
	res, err := s.svc.RegisterProfileDevice(ctx, internal.RegisterProfileDeviceRequest{DeviceID: req.DeviceID, DisplayName: req.DisplayName, PublicKeyFingerprint: req.PublicKeyFingerprint, TrustStatus: internal.ProfileDeviceTrustStatus(req.TrustStatus), Status: internal.ProfileDeviceStatus(req.Status), Capabilities: append([]string{}, req.Capabilities...), MetadataSource: req.MetadataSource})
	return fromInternalDevice(res), err
}
func (s *Service) ListProfileDevices(ctx context.Context) ([]ProfileDeviceRecord, error) {
	res, err := s.svc.ListProfileDevices(ctx)
	return fromInternalDevices(res), err
}
func (s *Service) RemoveProfileDevice(ctx context.Context, deviceID string) error {
	return s.svc.RemoveProfileDevice(ctx, deviceID)
}
func (s *Service) RegisterProfileResource(ctx context.Context, req RegisterProfileResourceRequest) (ProfileResourceRecord, error) {
	res, err := s.svc.RegisterProfileResource(ctx, toInternalResourceRequest(req))
	return fromInternalResource(res), err
}
func (s *Service) ListProfileResources(ctx context.Context) ([]ProfileResourceRecord, error) {
	res, err := s.svc.ListProfileResources(ctx)
	return fromInternalResources(res), err
}
func (s *Service) SetResourceHost(ctx context.Context, req SetResourceHostRequest) (ProfileResourceRecord, error) {
	res, err := s.svc.SetResourceHost(ctx, internal.SetResourceHostRequest(req))
	return fromInternalResource(res), err
}
func (s *Service) GetResourceHost(ctx context.Context, resourceID string) (ProfileResourceHostStatus, error) {
	res, err := s.svc.GetResourceHost(ctx, resourceID)
	return fromInternalHostStatus(res), err
}
func (s *Service) ExportProfileMeshSnapshot(ctx context.Context) (ProfileMeshSnapshot, error) {
	res, err := s.svc.ExportProfileMeshSnapshot(ctx)
	return fromInternalSnapshot(res), err
}
func (s *Service) ImportProfileMeshSnapshot(ctx context.Context, snapshot ProfileMeshSnapshot) error {
	return s.svc.ImportProfileMeshSnapshot(ctx, toInternalSnapshot(snapshot))
}
func (s *Service) BuildProfileMeshOverview(ctx context.Context) (ProfileMeshOverview, error) {
	res, err := s.svc.BuildProfileMeshOverview(ctx)
	return fromInternalOverview(res), err
}

func fromInternalProfile(p internal.ProfileIdentity) ProfileIdentity {
	return ProfileIdentity(p)
}
func fromInternalHosting(h internal.ProfileHostingConfig) ProfileHostingConfig {
	return ProfileHostingConfig{HostingMode: ProfileHostingMode(h.HostingMode), PrimaryProfileDeviceID: h.PrimaryProfileDeviceID, ProfileDataHostDeviceID: h.ProfileDataHostDeviceID, LocalCacheEnabled: h.LocalCacheEnabled, OfflineBranchModePlanned: h.OfflineBranchModePlanned, UpdatedAt: h.UpdatedAt}
}
func fromInternalDevice(d internal.ProfileDeviceRecord) ProfileDeviceRecord {
	return ProfileDeviceRecord{DeviceID: d.DeviceID, DisplayName: d.DisplayName, PublicKeyFingerprint: d.PublicKeyFingerprint, TrustStatus: ProfileDeviceTrustStatus(d.TrustStatus), Status: ProfileDeviceStatus(d.Status), Capabilities: append([]string{}, d.Capabilities...), LastSeen: d.LastSeen, RegisteredAt: d.RegisteredAt, UpdatedAt: d.UpdatedAt, RemovedAt: d.RemovedAt, MetadataSource: d.MetadataSource, ProfileMetadataVersion: d.ProfileMetadataVersion}
}
func fromInternalDevices(in []internal.ProfileDeviceRecord) []ProfileDeviceRecord {
	out := make([]ProfileDeviceRecord, 0, len(in))
	for _, item := range in {
		out = append(out, fromInternalDevice(item))
	}
	return out
}
func toInternalResourceRequest(req RegisterProfileResourceRequest) internal.RegisterProfileResourceRequest {
	return internal.RegisterProfileResourceRequest{ResourceID: req.ResourceID, ResourceType: internal.ProfileResourceType(req.ResourceType), DisplayName: req.DisplayName, CurrentHostDeviceID: req.CurrentHostDeviceID, AllowedHostDeviceIDs: append([]string{}, req.AllowedHostDeviceIDs...), Availability: internal.ProfileResourceAvailability(req.Availability), HostingMode: internal.ProfileResourceHostingMode(req.HostingMode), Tags: append([]string{}, req.Tags...), Metadata: cloneMap(req.Metadata)}
}
func fromInternalResource(r internal.ProfileResourceRecord) ProfileResourceRecord {
	return ProfileResourceRecord{ResourceID: r.ResourceID, ResourceType: ProfileResourceType(r.ResourceType), DisplayName: r.DisplayName, ProfileOwnerID: r.ProfileOwnerID, CurrentHostDeviceID: r.CurrentHostDeviceID, AllowedHostDeviceIDs: append([]string{}, r.AllowedHostDeviceIDs...), Availability: ProfileResourceAvailability(r.Availability), HostingMode: ProfileResourceHostingMode(r.HostingMode), Tags: append([]string{}, r.Tags...), Metadata: cloneMap(r.Metadata), CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt}
}
func fromInternalResources(in []internal.ProfileResourceRecord) []ProfileResourceRecord {
	out := make([]ProfileResourceRecord, 0, len(in))
	for _, item := range in {
		out = append(out, fromInternalResource(item))
	}
	return out
}
func fromInternalHostStatus(s internal.ProfileResourceHostStatus) ProfileResourceHostStatus {
	return ProfileResourceHostStatus{ResourceID: s.ResourceID, ProfileOwnerID: s.ProfileOwnerID, HostDeviceID: s.HostDeviceID, HostStatus: ProfileDeviceStatus(s.HostStatus), Availability: ProfileResourceAvailability(s.Availability), HostAvailable: s.HostAvailable, Message: s.Message}
}
func fromInternalSnapshot(s internal.ProfileMeshSnapshot) ProfileMeshSnapshot {
	return ProfileMeshSnapshot{SchemaVersion: s.SchemaVersion, AppID: s.AppID, Namespace: s.Namespace, Profile: fromInternalProfile(s.Profile), HostingConfig: fromInternalHosting(s.HostingConfig), Devices: fromInternalDevices(s.Devices), Resources: fromInternalResources(s.Resources), RelayHints: fromInternalRelayHints(s.RelayHints), EndpointHints: fromInternalEndpointHints(s.EndpointHints), CreatedAt: s.CreatedAt, UpdatedAt: s.UpdatedAt, SnapshotFingerprint: s.SnapshotFingerprint, MetadataVersion: s.MetadataVersion}
}
func toInternalSnapshot(s ProfileMeshSnapshot) internal.ProfileMeshSnapshot {
	return internal.ProfileMeshSnapshot{SchemaVersion: s.SchemaVersion, AppID: s.AppID, Namespace: s.Namespace, Profile: internal.ProfileIdentity(s.Profile), HostingConfig: internal.ProfileHostingConfig{HostingMode: internal.ProfileHostingMode(s.HostingConfig.HostingMode), PrimaryProfileDeviceID: s.HostingConfig.PrimaryProfileDeviceID, ProfileDataHostDeviceID: s.HostingConfig.ProfileDataHostDeviceID, LocalCacheEnabled: s.HostingConfig.LocalCacheEnabled, OfflineBranchModePlanned: s.HostingConfig.OfflineBranchModePlanned, UpdatedAt: s.HostingConfig.UpdatedAt}, Devices: toInternalDevices(s.Devices), Resources: toInternalResources(s.Resources), RelayHints: toInternalRelayHints(s.RelayHints), EndpointHints: toInternalEndpointHints(s.EndpointHints), CreatedAt: s.CreatedAt, UpdatedAt: s.UpdatedAt, SnapshotFingerprint: s.SnapshotFingerprint, MetadataVersion: s.MetadataVersion}
}
func toInternalDevices(in []ProfileDeviceRecord) []internal.ProfileDeviceRecord {
	out := make([]internal.ProfileDeviceRecord, 0, len(in))
	for _, d := range in {
		out = append(out, internal.ProfileDeviceRecord{DeviceID: d.DeviceID, DisplayName: d.DisplayName, PublicKeyFingerprint: d.PublicKeyFingerprint, TrustStatus: internal.ProfileDeviceTrustStatus(d.TrustStatus), Status: internal.ProfileDeviceStatus(d.Status), Capabilities: append([]string{}, d.Capabilities...), LastSeen: d.LastSeen, RegisteredAt: d.RegisteredAt, UpdatedAt: d.UpdatedAt, RemovedAt: d.RemovedAt, MetadataSource: d.MetadataSource, ProfileMetadataVersion: d.ProfileMetadataVersion})
	}
	return out
}
func toInternalResources(in []ProfileResourceRecord) []internal.ProfileResourceRecord {
	out := make([]internal.ProfileResourceRecord, 0, len(in))
	for _, r := range in {
		out = append(out, internal.ProfileResourceRecord{ResourceID: r.ResourceID, ResourceType: internal.ProfileResourceType(r.ResourceType), DisplayName: r.DisplayName, ProfileOwnerID: r.ProfileOwnerID, CurrentHostDeviceID: r.CurrentHostDeviceID, AllowedHostDeviceIDs: append([]string{}, r.AllowedHostDeviceIDs...), Availability: internal.ProfileResourceAvailability(r.Availability), HostingMode: internal.ProfileResourceHostingMode(r.HostingMode), Tags: append([]string{}, r.Tags...), Metadata: cloneMap(r.Metadata), CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt})
	}
	return out
}
func fromInternalOverview(o internal.ProfileMeshOverview) ProfileMeshOverview {
	out := ProfileMeshOverview{ProfileID: o.ProfileID, AppID: o.AppID, Namespace: o.Namespace, DisplayName: o.DisplayName, Bootstrapped: o.Bootstrapped, Ready: o.Ready, HostingMode: ProfileHostingMode(o.HostingMode), PrimaryProfileDeviceID: o.PrimaryProfileDeviceID, ProfileDataHostDeviceID: o.ProfileDataHostDeviceID, DeviceCount: o.DeviceCount, ResourceCount: o.ResourceCount, Message: o.Message}
	for _, issue := range o.Issues {
		out.Issues = append(out.Issues, ProfileMeshIssue(issue))
	}
	for _, warning := range o.Warnings {
		out.Warnings = append(out.Warnings, ProfileMeshIssue(warning))
	}
	return out
}
func fromInternalRelayHints(in []internal.ProfileRelayHint) []ProfileRelayHint {
	out := make([]ProfileRelayHint, 0, len(in))
	for _, hint := range in {
		out = append(out, ProfileRelayHint{ProfileID: hint.ProfileID, DeviceID: hint.DeviceID, RelayProviderID: hint.RelayProviderID, EndpointType: ProfileEndpointType(hint.EndpointType), ExpiresAt: hint.ExpiresAt, LastSeen: hint.LastSeen, Capabilities: append([]string{}, hint.Capabilities...), Metadata: cloneMap(hint.Metadata)})
	}
	return out
}
func toInternalRelayHints(in []ProfileRelayHint) []internal.ProfileRelayHint {
	out := make([]internal.ProfileRelayHint, 0, len(in))
	for _, hint := range in {
		out = append(out, internal.ProfileRelayHint{ProfileID: hint.ProfileID, DeviceID: hint.DeviceID, RelayProviderID: hint.RelayProviderID, EndpointType: internal.ProfileEndpointType(hint.EndpointType), ExpiresAt: hint.ExpiresAt, LastSeen: hint.LastSeen, Capabilities: append([]string{}, hint.Capabilities...), Metadata: cloneMap(hint.Metadata)})
	}
	return out
}
func fromInternalEndpointHints(in []internal.ProfileEndpointHint) []ProfileEndpointHint {
	out := make([]ProfileEndpointHint, 0, len(in))
	for _, hint := range in {
		out = append(out, ProfileEndpointHint{ProfileID: hint.ProfileID, DeviceID: hint.DeviceID, EndpointType: ProfileEndpointType(hint.EndpointType), Address: hint.Address, ExpiresAt: hint.ExpiresAt, LastSeen: hint.LastSeen, Capabilities: append([]string{}, hint.Capabilities...), Metadata: cloneMap(hint.Metadata)})
	}
	return out
}
func toInternalEndpointHints(in []ProfileEndpointHint) []internal.ProfileEndpointHint {
	out := make([]internal.ProfileEndpointHint, 0, len(in))
	for _, hint := range in {
		out = append(out, internal.ProfileEndpointHint{ProfileID: hint.ProfileID, DeviceID: hint.DeviceID, EndpointType: internal.ProfileEndpointType(hint.EndpointType), Address: hint.Address, ExpiresAt: hint.ExpiresAt, LastSeen: hint.LastSeen, Capabilities: append([]string{}, hint.Capabilities...), Metadata: cloneMap(hint.Metadata)})
	}
	return out
}
func cloneMap(in map[string]string) map[string]string {
	if in == nil {
		return nil
	}
	out := map[string]string{}
	for k, v := range in {
		out[k] = v
	}
	return out
}
