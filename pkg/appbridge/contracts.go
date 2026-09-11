package appbridge

import (
	"context"
	"errors"
	"regexp"

	"github.com/AegisAgentAscalon/aegis-core/pkg/auth"
	"github.com/AegisAgentAscalon/aegis-core/pkg/devicelink"
	"github.com/AegisAgentAscalon/aegis-core/pkg/profilemesh"
	"github.com/AegisAgentAscalon/aegis-core/pkg/profilesync"
	"github.com/AegisAgentAscalon/aegis-core/pkg/relay"
	"github.com/AegisAgentAscalon/aegis-core/pkg/securityposture"
	"github.com/AegisAgentAscalon/aegis-core/pkg/setupstate"
	"github.com/AegisAgentAscalon/aegis-core/pkg/updates"
)

var (
	ErrInvalidConfig = errors.New("invalid app bridge configuration")
	ErrDisabled      = errors.New("app bridge capability is disabled")
	ErrNotConfigured = errors.New("app bridge capability is not configured")
)

var bridgeSafeNamePattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$`)

type AppIdentity struct {
	AppID          string
	DisplayName    string
	ConfigRoot     string
	TokenNamespace string
	DataNamespace  string
}

type CapabilityConfig struct {
	Enabled bool
}

type AuthBridgeConfig struct {
	CapabilityConfig
	Service AuthService
}

type UpdateBridgeConfig struct {
	CapabilityConfig
	Service UpdateService
}

type DeviceLinkBridgeConfig struct {
	CapabilityConfig
	Service DeviceLinkService
}

type ProfileMeshBridgeConfig struct {
	CapabilityConfig
	Service ProfileMeshService
}

type ProfileSyncBridgeConfig struct {
	CapabilityConfig
	Service ProfileSyncStatusProvider
}

type RelayBridgeConfig struct {
	CapabilityConfig
	Provider RelayStatusProvider
}

type SecurityPostureBridgeConfig struct {
	CapabilityConfig
	Provider SecurityPostureStatusProvider
}

type AppBridgeConfig struct {
	Identity        AppIdentity
	Auth            AuthBridgeConfig
	Updates         UpdateBridgeConfig
	DeviceLink      DeviceLinkBridgeConfig
	ProfileMesh     ProfileMeshBridgeConfig
	ProfileSync     ProfileSyncBridgeConfig
	Relay           RelayBridgeConfig
	SecurityPosture SecurityPostureBridgeConfig
}

type SetupBridge interface {
	BuildSetupOverview(ctx context.Context) (SetupOverview, error)
}

type SetupOverview struct {
	AppID          string                `json:"app_id"`
	DisplayName    string                `json:"display_name"`
	Ready          bool                  `json:"ready"`
	Cards          []SetupCapabilityCard `json:"cards"`
	BlockingIssues []SetupIssue          `json:"blocking_issues,omitempty"`
	Warnings       []SetupIssue          `json:"warnings,omitempty"`
}

type SetupCapabilityCard struct {
	Capability setupstate.Capability      `json:"capability"`
	Enabled    bool                       `json:"enabled"`
	Ready      bool                       `json:"ready"`
	State      setupstate.CapabilityState `json:"state"`
	Summary    string                     `json:"summary,omitempty"`
	Issues     []SetupIssue               `json:"issues,omitempty"`
}

type SetupIssue struct {
	Capability setupstate.Capability `json:"capability,omitempty"`
	Code       string                `json:"code"`
	Message    string                `json:"message"`
	Blocking   bool                  `json:"blocking"`
}

type AuthStatusResult struct {
	Status auth.AuthStatus     `json:"status"`
	Card   SetupCapabilityCard `json:"card"`
}

type UpdateStatusResult struct {
	Status updates.CurrentState `json:"status"`
	Card   SetupCapabilityCard  `json:"card"`
}

type DeviceLinkStatus struct {
	Bootstrapped         bool                   `json:"bootstrapped"`
	Ready                bool                   `json:"ready"`
	DeviceID             string                 `json:"device_id,omitempty"`
	DisplayName          string                 `json:"display_name,omitempty"`
	PublicKeyFingerprint string                 `json:"public_key_fingerprint,omitempty"`
	TrustedDevices       []TrustedDeviceSummary `json:"trusted_devices,omitempty"`
	Message              string                 `json:"message,omitempty"`
}

type TrustedDeviceSummary struct {
	DeviceID             string                 `json:"device_id"`
	DisplayName          string                 `json:"display_name,omitempty"`
	PublicKeyFingerprint string                 `json:"public_key_fingerprint,omitempty"`
	TrustStatus          devicelink.TrustStatus `json:"trust_status"`
}

type ProfileMeshStatus struct {
	Overview        profilemesh.ProfileMeshOverview `json:"overview"`
	HostedResources []HostedResourceSummary         `json:"hosted_resources,omitempty"`
}

type HostedResourceSummary struct {
	ResourceID          string                                  `json:"resource_id"`
	ResourceType        profilemesh.ProfileResourceType         `json:"resource_type"`
	DisplayName         string                                  `json:"display_name,omitempty"`
	CurrentHostDeviceID string                                  `json:"current_host_device_id,omitempty"`
	Availability        profilemesh.ProfileResourceAvailability `json:"availability"`
}

type RelayStatusResult struct {
	Status relay.RelayStatus   `json:"status"`
	Card   SetupCapabilityCard `json:"card"`
}

type ProfileSyncStatusResult struct {
	Status profilesync.SyncStatus `json:"status"`
	Card   SetupCapabilityCard    `json:"card"`
}

type SecurityPostureStatusResult struct {
	Summary securityposture.Summary `json:"summary"`
	Card    SetupCapabilityCard     `json:"card"`
}

type InfrastructureStatusOverview struct {
	AppID           string                      `json:"app_id"`
	DisplayName     string                      `json:"display_name"`
	Ready           bool                        `json:"ready"`
	Updates         UpdateStatusResult          `json:"updates"`
	ProfileSync     ProfileSyncStatusResult     `json:"profile_sync"`
	Relay           RelayStatusResult           `json:"relay"`
	SecurityPosture SecurityPostureStatusResult `json:"security_posture"`
	Cards           []SetupCapabilityCard       `json:"cards"`
	BlockingIssues  []SetupIssue                `json:"blocking_issues,omitempty"`
	Warnings        []SetupIssue                `json:"warnings,omitempty"`
}

type AuthService interface {
	Status(ctx context.Context) (auth.AuthStatus, error)
	StartSignIn(ctx context.Context) (auth.SignInStartResult, error)
	CompleteSignIn(ctx context.Context, req auth.CompleteSignInRequest) (auth.CompleteSignInResult, error)
	SignOut(ctx context.Context) error
}

type UpdateService interface {
	GetStatus(ctx context.Context) (updates.CurrentState, error)
	CheckForUpdates(ctx context.Context) (updates.CheckResult, error)
	DownloadUpdate(ctx context.Context, version string) (updates.DownloadResult, error)
	VerifyUpdate(ctx context.Context, version string) (updates.VerifyResult, error)
	StageUpdate(ctx context.Context, version string) (updates.StageResult, error)
	DescribeStagedUpdate(ctx context.Context) (updates.StagedUpdateSummary, error)
	BuildApplyPlan(ctx context.Context) (updates.ApplyPlan, error)
	ApplyUpdate(ctx context.Context) (updates.ApplyResult, error)
	ClearStagedUpdate(ctx context.Context) (updates.ClearResult, error)
}

type DeviceLinkService interface {
	GetCurrentDevice(ctx context.Context) (devicelink.DeviceIdentity, error)
	ListTrustedDevices(ctx context.Context) ([]devicelink.TrustedDevice, error)
}

type ProfileMeshService interface {
	BuildProfileMeshOverview(ctx context.Context) (profilemesh.ProfileMeshOverview, error)
	ListProfileResources(ctx context.Context) ([]profilemesh.ProfileResourceRecord, error)
}

type ProfileSyncStatusProvider interface {
	BuildStatus(ctx context.Context) profilesync.SyncStatus
}

type RelayStatusProvider interface {
	GetStatus(ctx context.Context) relay.RelayStatus
}

type SecurityPostureStatusProvider interface {
	BuildSecurityPosture(ctx context.Context) securityposture.Summary
}
