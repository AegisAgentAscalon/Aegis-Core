// Package appbridge provides a generic app-facing setup facade over public
// Aegis Core packages.
package appbridge

import (
	"context"
	"errors"
	"regexp"
	"strings"

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

type Bridge struct {
	cfg AppBridgeConfig
}

func NewSetupBridge(cfg AppBridgeConfig) (*Bridge, error) {
	if !validBridgeName(cfg.Identity.AppID) || strings.TrimSpace(cfg.Identity.DisplayName) == "" {
		return nil, ErrInvalidConfig
	}
	return &Bridge{cfg: cfg}, nil
}

func (b *Bridge) BuildSetupOverview(ctx context.Context) (SetupOverview, error) {
	providers := map[setupstate.Capability]setupstate.StatusProvider{}
	for _, capability := range b.enabledCapabilities() {
		switch capability {
		case setupstate.CapabilityAuth:
			providers[capability] = setupstate.StatusProviderFunc(b.authSetupStatus)
		case setupstate.CapabilityUpdates:
			providers[capability] = setupstate.StatusProviderFunc(b.updateSetupStatus)
		case setupstate.CapabilityDeviceLink:
			providers[capability] = setupstate.StatusProviderFunc(b.deviceLinkSetupStatus)
		case setupstate.CapabilityProfileMesh:
			providers[capability] = setupstate.StatusProviderFunc(b.profileMeshSetupStatus)
		case setupstate.CapabilityProfileSync:
			providers[capability] = setupstate.StatusProviderFunc(b.profileSyncSetupStatus)
		case setupstate.CapabilityRelay:
			providers[capability] = setupstate.StatusProviderFunc(b.relaySetupStatus)
		case setupstate.CapabilitySecurityPosture:
			providers[capability] = setupstate.StatusProviderFunc(b.securityPostureSetupStatus)
		}
	}
	stateOverview, err := setupstate.BuildOverview(ctx, setupstate.AppSetupConfig{
		AppID:               b.cfg.Identity.AppID,
		DisplayName:         b.cfg.Identity.DisplayName,
		EnabledCapabilities: b.enabledCapabilities(),
	}, providers)
	if err != nil {
		return SetupOverview{}, err
	}
	return b.fromSetupStateOverview(stateOverview), nil
}

func (b *Bridge) AuthStatus(ctx context.Context) (AuthStatusResult, error) {
	if !b.cfg.Auth.Enabled {
		return AuthStatusResult{}, ErrDisabled
	}
	status, err := b.authSetupStatus(ctx)
	if err != nil {
		return AuthStatusResult{}, err
	}
	var authStatus auth.AuthStatus
	if b.cfg.Auth.Service != nil {
		authStatus, _ = b.cfg.Auth.Service.Status(ctx)
	}
	return AuthStatusResult{Status: sanitizeAuthStatus(authStatus), Card: cardFromStatus(status)}, nil
}

func (b *Bridge) StartSignIn(ctx context.Context) (auth.SignInStartResult, error) {
	if !b.cfg.Auth.Enabled {
		return auth.SignInStartResult{}, ErrDisabled
	}
	if b.cfg.Auth.Service == nil {
		return auth.SignInStartResult{}, ErrNotConfigured
	}
	return b.cfg.Auth.Service.StartSignIn(ctx)
}

func (b *Bridge) CompleteSignIn(ctx context.Context, req auth.CompleteSignInRequest) (auth.CompleteSignInResult, error) {
	if !b.cfg.Auth.Enabled {
		return auth.CompleteSignInResult{}, ErrDisabled
	}
	if b.cfg.Auth.Service == nil {
		return auth.CompleteSignInResult{}, ErrNotConfigured
	}
	return b.cfg.Auth.Service.CompleteSignIn(ctx, req)
}

func (b *Bridge) SignOut(ctx context.Context) error {
	if !b.cfg.Auth.Enabled {
		return ErrDisabled
	}
	if b.cfg.Auth.Service == nil {
		return ErrNotConfigured
	}
	return b.cfg.Auth.Service.SignOut(ctx)
}

func (b *Bridge) UpdateStatus(ctx context.Context) (UpdateStatusResult, error) {
	if !b.cfg.Updates.Enabled {
		return UpdateStatusResult{}, ErrDisabled
	}
	status, err := b.updateSetupStatus(ctx)
	if err != nil {
		return UpdateStatusResult{}, err
	}
	var updateStatus updates.CurrentState
	if b.cfg.Updates.Service != nil {
		updateStatus, _ = b.cfg.Updates.Service.GetStatus(ctx)
	}
	return UpdateStatusResult{Status: sanitizeUpdateStatus(updateStatus), Card: cardFromStatus(status)}, nil
}

func (b *Bridge) BuildInfrastructureStatus(ctx context.Context) (InfrastructureStatusOverview, error) {
	updatesStatus := b.safeUpdateStatus(ctx)
	profileSyncStatus := b.safeProfileSyncStatus(ctx)
	relayStatus, err := b.RelayStatus(ctx)
	if err != nil {
		return InfrastructureStatusOverview{}, err
	}
	securityPostureStatus := b.safeSecurityPostureStatus(ctx)
	out := InfrastructureStatusOverview{
		AppID:           b.cfg.Identity.AppID,
		DisplayName:     b.cfg.Identity.DisplayName,
		Ready:           true,
		Updates:         updatesStatus,
		ProfileSync:     profileSyncStatus,
		Relay:           relayStatus,
		SecurityPosture: securityPostureStatus,
		Cards:           []SetupCapabilityCard{updatesStatus.Card, profileSyncStatus.Card, relayStatus.Card, securityPostureStatus.Card},
	}
	for _, card := range out.Cards {
		if !card.Ready || card.State == setupstate.StateBlocked {
			out.Ready = false
			out.BlockingIssues = append(out.BlockingIssues, SetupIssue{Capability: card.Capability, Code: "status_not_ready", Message: sanitizeSummary(card.Summary, "status is not ready"), Blocking: true})
			continue
		}
		if card.State == setupstate.StateWarning {
			out.Warnings = append(out.Warnings, SetupIssue{Capability: card.Capability, Code: "status_warning", Message: sanitizeSummary(card.Summary, "status is degraded"), Blocking: false})
		}
		for _, issue := range card.Issues {
			issue.Blocking = false
			out.Warnings = append(out.Warnings, issue)
		}
	}
	return out, nil
}

func (b *Bridge) CheckForUpdates(ctx context.Context) (updates.CheckResult, error) {
	if !b.cfg.Updates.Enabled {
		return updates.CheckResult{}, ErrDisabled
	}
	if b.cfg.Updates.Service == nil {
		return updates.CheckResult{}, ErrNotConfigured
	}
	return b.cfg.Updates.Service.CheckForUpdates(ctx)
}

func (b *Bridge) DownloadUpdate(ctx context.Context, version string) (updates.DownloadResult, error) {
	if !b.cfg.Updates.Enabled {
		return updates.DownloadResult{}, ErrDisabled
	}
	if b.cfg.Updates.Service == nil {
		return updates.DownloadResult{}, ErrNotConfigured
	}
	return b.cfg.Updates.Service.DownloadUpdate(ctx, version)
}

func (b *Bridge) VerifyUpdate(ctx context.Context, version string) (updates.VerifyResult, error) {
	if !b.cfg.Updates.Enabled {
		return updates.VerifyResult{}, ErrDisabled
	}
	if b.cfg.Updates.Service == nil {
		return updates.VerifyResult{}, ErrNotConfigured
	}
	return b.cfg.Updates.Service.VerifyUpdate(ctx, version)
}

func (b *Bridge) StageUpdate(ctx context.Context, version string) (updates.StageResult, error) {
	if !b.cfg.Updates.Enabled {
		return updates.StageResult{}, ErrDisabled
	}
	if b.cfg.Updates.Service == nil {
		return updates.StageResult{}, ErrNotConfigured
	}
	return b.cfg.Updates.Service.StageUpdate(ctx, version)
}

func (b *Bridge) DescribeStagedUpdate(ctx context.Context) (updates.StagedUpdateSummary, error) {
	if !b.cfg.Updates.Enabled {
		return updates.StagedUpdateSummary{}, ErrDisabled
	}
	if b.cfg.Updates.Service == nil {
		return updates.StagedUpdateSummary{}, ErrNotConfigured
	}
	return b.cfg.Updates.Service.DescribeStagedUpdate(ctx)
}

func (b *Bridge) BuildUpdateApplyPlan(ctx context.Context) (updates.ApplyPlan, error) {
	if !b.cfg.Updates.Enabled {
		return updates.ApplyPlan{}, ErrDisabled
	}
	if b.cfg.Updates.Service == nil {
		return updates.ApplyPlan{}, ErrNotConfigured
	}
	return b.cfg.Updates.Service.BuildApplyPlan(ctx)
}

func (b *Bridge) ApplyUpdate(ctx context.Context) (updates.ApplyResult, error) {
	if !b.cfg.Updates.Enabled {
		return updates.ApplyResult{}, ErrDisabled
	}
	if b.cfg.Updates.Service == nil {
		return updates.ApplyResult{}, ErrNotConfigured
	}
	return b.cfg.Updates.Service.ApplyUpdate(ctx)
}

func (b *Bridge) ClearStagedUpdate(ctx context.Context) (updates.ClearResult, error) {
	if !b.cfg.Updates.Enabled {
		return updates.ClearResult{}, ErrDisabled
	}
	if b.cfg.Updates.Service == nil {
		return updates.ClearResult{}, ErrNotConfigured
	}
	return b.cfg.Updates.Service.ClearStagedUpdate(ctx)
}

func (b *Bridge) DeviceLinkStatus(ctx context.Context) (DeviceLinkStatus, error) {
	if !b.cfg.DeviceLink.Enabled {
		return DeviceLinkStatus{}, ErrDisabled
	}
	if b.cfg.DeviceLink.Service == nil {
		return DeviceLinkStatus{Ready: false, Message: "device link service is not configured"}, nil
	}
	id, err := b.cfg.DeviceLink.Service.GetCurrentDevice(ctx)
	if errors.Is(err, devicelink.ErrCurrentDeviceNotFound) {
		return DeviceLinkStatus{Ready: false, Message: "device link is not bootstrapped"}, nil
	}
	if err != nil {
		return DeviceLinkStatus{}, err
	}
	devices, err := b.cfg.DeviceLink.Service.ListTrustedDevices(ctx)
	if err != nil {
		return DeviceLinkStatus{}, err
	}
	return DeviceLinkStatus{
		Bootstrapped:         true,
		Ready:                true,
		DeviceID:             sanitizeIdentifier(id.DeviceID),
		DisplayName:          sanitizeSummary(id.DisplayName, "local device"),
		PublicKeyFingerprint: sanitizeIdentifier(id.PublicKeyFingerprint),
		TrustedDevices:       summarizeTrustedDevices(devices),
		Message:              "device link ready",
	}, nil
}

func (b *Bridge) ProfileMeshStatus(ctx context.Context) (ProfileMeshStatus, error) {
	if !b.cfg.ProfileMesh.Enabled {
		return ProfileMeshStatus{}, ErrDisabled
	}
	if b.cfg.ProfileMesh.Service == nil {
		return ProfileMeshStatus{Overview: profilemesh.ProfileMeshOverview{Ready: false, Message: "profile mesh service is not configured"}}, nil
	}
	overview, err := b.cfg.ProfileMesh.Service.BuildProfileMeshOverview(ctx)
	if err != nil {
		return ProfileMeshStatus{}, err
	}
	resources, err := b.cfg.ProfileMesh.Service.ListProfileResources(ctx)
	if err != nil {
		resources = nil
	}
	return ProfileMeshStatus{Overview: sanitizeProfileMeshOverview(overview), HostedResources: summarizeHostedResources(resources)}, nil
}

func (b *Bridge) ProfileSyncStatus(ctx context.Context) (ProfileSyncStatusResult, error) {
	return b.safeProfileSyncStatus(ctx), nil
}

func (b *Bridge) SecurityPostureStatus(ctx context.Context) (SecurityPostureStatusResult, error) {
	return b.safeSecurityPostureStatus(ctx), nil
}

func (b *Bridge) RelayStatus(ctx context.Context) (RelayStatusResult, error) {
	if !b.cfg.Relay.Enabled {
		status := relay.DisabledStatus()
		return RelayStatusResult{Status: status, Card: SetupCapabilityCard{Capability: setupstate.CapabilityRelay, Enabled: false, Ready: true, State: setupstate.StateDisabled, Summary: status.Summary}}, nil
	}
	status := b.safeRelayStatus(ctx)
	card := SetupCapabilityCard{Capability: setupstate.CapabilityRelay, Enabled: true, Ready: true, State: setupstate.StateWarning, Summary: sanitizeSummary(status.Summary, "relay is degraded")}
	if status.Available {
		card.State = setupstate.StateReady
		card.Summary = sanitizeSummary(status.Summary, "relay provider is available")
	}
	for _, issue := range status.Issues {
		card.Issues = append(card.Issues, SetupIssue{Capability: setupstate.CapabilityRelay, Code: sanitizeIdentifier(issue.Code), Message: sanitizeSummary(issue.Message, "relay is degraded"), Blocking: false})
	}
	return RelayStatusResult{Status: status, Card: card}, nil
}

func (b *Bridge) authSetupStatus(ctx context.Context) (setupstate.CapabilityStatus, error) {
	if b.cfg.Auth.Service == nil {
		return setupstate.CapabilityStatus{Capability: setupstate.CapabilityAuth, Enabled: true, Ready: false, State: setupstate.StateBlocked, Summary: "auth service is not configured"}, nil
	}
	status, err := b.cfg.Auth.Service.Status(ctx)
	if err != nil {
		return setupstate.CapabilityStatus{}, err
	}
	status = sanitizeAuthStatus(status)
	if !status.Configured {
		return setupstate.CapabilityStatus{Capability: setupstate.CapabilityAuth, Enabled: true, Ready: false, State: setupstate.StateBlocked, Summary: "auth is not configured"}, nil
	}
	if !status.SignedIn || status.NeedsReconnect {
		return setupstate.CapabilityStatus{Capability: setupstate.CapabilityAuth, Enabled: true, Ready: false, State: setupstate.StateBlocked, Summary: "auth sign-in is required"}, nil
	}
	return setupstate.CapabilityStatus{Capability: setupstate.CapabilityAuth, Enabled: true, Ready: true, State: setupstate.StateReady, Summary: "auth ready"}, nil
}

func (b *Bridge) updateSetupStatus(ctx context.Context) (setupstate.CapabilityStatus, error) {
	if b.cfg.Updates.Service == nil {
		return setupstate.CapabilityStatus{Capability: setupstate.CapabilityUpdates, Enabled: true, Ready: false, State: setupstate.StateBlocked, Summary: "update service is not configured"}, nil
	}
	status, err := b.cfg.Updates.Service.GetStatus(ctx)
	if err != nil {
		return setupstate.CapabilityStatus{}, err
	}
	status = sanitizeUpdateStatus(status)
	if !status.Configured {
		return setupstate.CapabilityStatus{Capability: setupstate.CapabilityUpdates, Enabled: true, Ready: false, State: setupstate.StateBlocked, Summary: "updates are not configured"}, nil
	}
	if status.UpdateAvailable {
		return setupstate.CapabilityStatus{Capability: setupstate.CapabilityUpdates, Enabled: true, Ready: true, State: setupstate.StateWarning, Summary: "update is available"}, nil
	}
	return setupstate.CapabilityStatus{Capability: setupstate.CapabilityUpdates, Enabled: true, Ready: true, State: setupstate.StateReady, Summary: "updates ready"}, nil
}

func (b *Bridge) deviceLinkSetupStatus(ctx context.Context) (setupstate.CapabilityStatus, error) {
	status, err := b.DeviceLinkStatus(ctx)
	if err != nil {
		return setupstate.CapabilityStatus{}, err
	}
	if !status.Ready {
		return setupstate.CapabilityStatus{Capability: setupstate.CapabilityDeviceLink, Enabled: true, Ready: false, State: setupstate.StateBlocked, Summary: sanitizeSummary(status.Message, "device link is not ready")}, nil
	}
	return setupstate.CapabilityStatus{Capability: setupstate.CapabilityDeviceLink, Enabled: true, Ready: true, State: setupstate.StateReady, Summary: "device link ready"}, nil
}

func (b *Bridge) profileMeshSetupStatus(ctx context.Context) (setupstate.CapabilityStatus, error) {
	status, err := b.ProfileMeshStatus(ctx)
	if err != nil {
		return setupstate.CapabilityStatus{}, err
	}
	if !status.Overview.Ready {
		return setupstate.CapabilityStatus{Capability: setupstate.CapabilityProfileMesh, Enabled: true, Ready: false, State: setupstate.StateBlocked, Summary: sanitizeSummary(status.Overview.Message, "profile mesh is not ready")}, nil
	}
	return setupstate.CapabilityStatus{Capability: setupstate.CapabilityProfileMesh, Enabled: true, Ready: true, State: setupstate.StateReady, Summary: "profile mesh ready"}, nil
}

func (b *Bridge) profileSyncSetupStatus(ctx context.Context) (setupstate.CapabilityStatus, error) {
	return statusFromCard(b.safeProfileSyncStatus(ctx).Card), nil
}

func (b *Bridge) relaySetupStatus(ctx context.Context) (setupstate.CapabilityStatus, error) {
	status := b.safeRelayStatus(ctx)
	if status.Available {
		return setupstate.CapabilityStatus{Capability: setupstate.CapabilityRelay, Enabled: true, Ready: true, State: setupstate.StateReady, Summary: sanitizeSummary(status.Summary, "relay provider is available")}, nil
	}
	return setupstate.CapabilityStatus{Capability: setupstate.CapabilityRelay, Enabled: true, Ready: true, State: setupstate.StateWarning, Summary: sanitizeSummary(status.Summary, "relay is degraded")}, nil
}

func (b *Bridge) securityPostureSetupStatus(ctx context.Context) (setupstate.CapabilityStatus, error) {
	return statusFromCard(b.safeSecurityPostureStatus(ctx).Card), nil
}

func (b *Bridge) enabledCapabilities() []setupstate.Capability {
	var out []setupstate.Capability
	if b.cfg.Auth.Enabled {
		out = append(out, setupstate.CapabilityAuth)
	}
	if b.cfg.Updates.Enabled {
		out = append(out, setupstate.CapabilityUpdates)
	}
	if b.cfg.DeviceLink.Enabled {
		out = append(out, setupstate.CapabilityDeviceLink)
	}
	if b.cfg.ProfileMesh.Enabled {
		out = append(out, setupstate.CapabilityProfileMesh)
	}
	if b.cfg.ProfileSync.Enabled {
		out = append(out, setupstate.CapabilityProfileSync)
	}
	if b.cfg.Relay.Enabled {
		out = append(out, setupstate.CapabilityRelay)
	}
	if b.cfg.SecurityPosture.Enabled {
		out = append(out, setupstate.CapabilitySecurityPosture)
	}
	return out
}

func (b *Bridge) fromSetupStateOverview(in setupstate.SetupOverview) SetupOverview {
	out := SetupOverview{AppID: in.AppID, DisplayName: in.DisplayName, Ready: in.Ready}
	statusByCapability := map[setupstate.Capability]setupstate.CapabilityStatus{}
	for _, status := range in.Capabilities {
		statusByCapability[status.Capability] = status
	}
	for _, capability := range allCapabilities() {
		if status, ok := statusByCapability[capability]; ok {
			out.Cards = append(out.Cards, cardFromStatus(status))
			continue
		}
		out.Cards = append(out.Cards, SetupCapabilityCard{Capability: capability, Enabled: false, Ready: true, State: setupstate.StateDisabled, Summary: string(capability) + " disabled"})
	}
	for _, issue := range in.BlockingIssues {
		out.BlockingIssues = append(out.BlockingIssues, fromSetupStateIssue(issue))
	}
	for _, issue := range in.Warnings {
		out.Warnings = append(out.Warnings, fromSetupStateIssue(issue))
	}
	return out
}

func allCapabilities() []setupstate.Capability {
	return []setupstate.Capability{
		setupstate.CapabilityAuth,
		setupstate.CapabilityUpdates,
		setupstate.CapabilityDeviceLink,
		setupstate.CapabilityProfileMesh,
		setupstate.CapabilityProfileSync,
		setupstate.CapabilityRelay,
		setupstate.CapabilitySecurityPosture,
	}
}

func cardFromStatus(status setupstate.CapabilityStatus) SetupCapabilityCard {
	return SetupCapabilityCard{
		Capability: status.Capability,
		Enabled:    status.Enabled,
		Ready:      status.Ready,
		State:      status.State,
		Summary:    sanitizeSummary(status.Summary, "setup status is unavailable"),
	}
}

func fromSetupStateIssue(issue setupstate.SetupIssue) SetupIssue {
	return SetupIssue{Capability: issue.Capability, Code: sanitizeIdentifier(issue.Code), Message: sanitizeSummary(issue.Message, "setup issue is unavailable"), Blocking: issue.Blocking}
}

func statusFromCard(card SetupCapabilityCard) setupstate.CapabilityStatus {
	return setupstate.CapabilityStatus{Capability: card.Capability, Enabled: card.Enabled, Ready: card.Ready, State: card.State, Summary: card.Summary}
}

func (b *Bridge) safeUpdateStatus(ctx context.Context) UpdateStatusResult {
	if !b.cfg.Updates.Enabled {
		status := updates.CurrentState{Configured: false, Message: "updates are disabled"}
		return UpdateStatusResult{Status: status, Card: SetupCapabilityCard{Capability: setupstate.CapabilityUpdates, Enabled: false, Ready: true, State: setupstate.StateDisabled, Summary: "updates disabled"}}
	}
	if b.cfg.Updates.Service == nil {
		status := updates.CurrentState{Configured: false, Message: "update status provider is not configured"}
		card := SetupCapabilityCard{Capability: setupstate.CapabilityUpdates, Enabled: true, Ready: true, State: setupstate.StateWarning, Summary: "update status provider is not configured", Issues: []SetupIssue{{Capability: setupstate.CapabilityUpdates, Code: "update_status_provider_missing", Message: "update status provider is not configured", Blocking: false}}}
		return UpdateStatusResult{Status: status, Card: card}
	}
	status, err := b.cfg.Updates.Service.GetStatus(ctx)
	if err != nil {
		status = updates.CurrentState{Configured: true, LastError: "update status is unavailable", Message: "updates are degraded"}
		card := SetupCapabilityCard{Capability: setupstate.CapabilityUpdates, Enabled: true, Ready: true, State: setupstate.StateWarning, Summary: "updates are degraded", Issues: []SetupIssue{{Capability: setupstate.CapabilityUpdates, Code: "update_status_unavailable", Message: "updates are degraded", Blocking: false}}}
		return UpdateStatusResult{Status: status, Card: card}
	}
	status = sanitizeUpdateStatus(status)
	card := SetupCapabilityCard{Capability: setupstate.CapabilityUpdates, Enabled: true, Ready: true, State: setupstate.StateReady, Summary: "updates ready"}
	if !status.Configured {
		card.State = setupstate.StateWarning
		card.Summary = "updates are not configured"
	} else if status.UpdateAvailable {
		card.State = setupstate.StateWarning
		card.Summary = "update is available"
	} else if status.LastError != "" {
		card.State = setupstate.StateWarning
		card.Summary = sanitizeSummary(status.Message, "updates are degraded")
		card.Issues = append(card.Issues, SetupIssue{Capability: setupstate.CapabilityUpdates, Code: "update_status_degraded", Message: card.Summary, Blocking: false})
	}
	return UpdateStatusResult{Status: status, Card: card}
}

func (b *Bridge) safeProfileSyncStatus(ctx context.Context) ProfileSyncStatusResult {
	if !b.cfg.ProfileSync.Enabled {
		status := profilesync.SyncStatus{Enabled: false, Available: false, Summary: "profile sync is disabled"}
		return ProfileSyncStatusResult{Status: status, Card: SetupCapabilityCard{Capability: setupstate.CapabilityProfileSync, Enabled: false, Ready: true, State: setupstate.StateDisabled, Summary: status.Summary}}
	}
	if b.cfg.ProfileSync.Service == nil {
		status := profilesync.SyncStatus{Enabled: true, Available: false, Summary: "profile sync status provider is not configured", Issues: []profilesync.SyncIssue{{Code: "profile_sync_status_provider_missing", Message: "profile sync status provider is not configured", Blocking: false}}}
		return ProfileSyncStatusResult{Status: status, Card: profileSyncCard(status)}
	}
	status := sanitizeProfileSyncStatus(b.cfg.ProfileSync.Service.BuildStatus(ctx))
	return ProfileSyncStatusResult{Status: status, Card: profileSyncCard(status)}
}

func (b *Bridge) safeSecurityPostureStatus(ctx context.Context) SecurityPostureStatusResult {
	if !b.cfg.SecurityPosture.Enabled {
		summary := securityposture.Summary{Capability: "security_posture", Posture: securityposture.PostureOutOfScope, Boundary: securityposture.BoundaryExplicitlyOutOfScope, Risk: securityposture.RiskDeferred, Redaction: securityposture.RedactionNotApplicable}
		return SecurityPostureStatusResult{Summary: summary, Card: SetupCapabilityCard{Capability: setupstate.CapabilitySecurityPosture, Enabled: false, Ready: true, State: setupstate.StateDisabled, Summary: "security posture disabled"}}
	}
	if b.cfg.SecurityPosture.Provider == nil {
		summary := securityposture.Summary{
			Capability: "security_posture",
			Posture:    securityposture.PostureDegraded,
			Boundary:   securityposture.BoundaryAegisCoreOwned,
			Risk:       securityposture.RiskCaveated,
			Redaction:  securityposture.RedactionNotApplicable,
			Issues: []securityposture.Issue{{
				Code:           "security_posture_provider_missing",
				Severity:       securityposture.SeverityLow,
				Posture:        securityposture.PostureDegraded,
				Boundary:       securityposture.BoundaryAegisCoreOwned,
				Risk:           securityposture.RiskCaveated,
				Redaction:      securityposture.RedactionNotApplicable,
				Summary:        "security posture status provider is not configured",
				ReviewRequired: false,
			}},
		}
		return SecurityPostureStatusResult{Summary: summary, Card: securityPostureCard(summary)}
	}
	summary := sanitizeSecurityPostureSummary(b.cfg.SecurityPosture.Provider.BuildSecurityPosture(ctx))
	return SecurityPostureStatusResult{Summary: summary, Card: securityPostureCard(summary)}
}

func (b *Bridge) safeRelayStatus(ctx context.Context) relay.RelayStatus {
	if b.cfg.Relay.Provider == nil {
		return relay.RelayStatus{Enabled: true, Available: false, Summary: "relay provider is not configured", Issues: []relay.RelayIssue{{Code: "relay_provider_missing", Message: "relay provider is not configured", Blocking: false}}}
	}
	status := b.cfg.Relay.Provider.GetStatus(ctx)
	status.Enabled = true
	status.ProviderID = sanitizeIdentifier(status.ProviderID)
	status.Summary = sanitizeSummary(status.Summary, "relay is degraded")
	for i, issue := range status.Issues {
		status.Issues[i] = relay.RelayIssue{Code: sanitizeIdentifier(issue.Code), Message: sanitizeSummary(issue.Message, "relay is degraded"), Blocking: false}
	}
	return status
}

func securityPostureCard(summary securityposture.Summary) SetupCapabilityCard {
	card := SetupCapabilityCard{Capability: setupstate.CapabilitySecurityPosture, Enabled: true, Ready: true, State: setupstate.StateReady, Summary: sanitizeSummary(summary.Capability+" posture ready", "security posture ready")}
	switch summary.Posture {
	case securityposture.PostureBlocked:
		card.Ready = false
		card.State = setupstate.StateBlocked
		card.Summary = "security posture is blocked"
	case securityposture.PostureReady:
		card.State = setupstate.StateReady
		card.Summary = "security posture ready"
	case securityposture.PostureDegraded, securityposture.PostureReviewRequired, securityposture.PostureUnknown, securityposture.PostureOutOfScope:
		card.State = setupstate.StateWarning
		card.Summary = "security posture requires review"
	}
	for _, issue := range summary.Issues {
		blocking := issue.Posture == securityposture.PostureBlocked
		card.Issues = append(card.Issues, SetupIssue{Capability: setupstate.CapabilitySecurityPosture, Code: sanitizeIdentifier(issue.Code), Message: sanitizeSecurityPostureText(issue.Summary, "security posture issue"), Blocking: blocking})
		if blocking {
			card.Ready = false
			card.State = setupstate.StateBlocked
		}
	}
	return card
}

func profileSyncCard(status profilesync.SyncStatus) SetupCapabilityCard {
	card := SetupCapabilityCard{Capability: setupstate.CapabilityProfileSync, Enabled: true, Ready: true, State: setupstate.StateReady, Summary: sanitizeSummary(status.Summary, "profile sync status is available")}
	if !status.Enabled {
		card.Enabled = false
		card.State = setupstate.StateDisabled
		card.Summary = sanitizeSummary(status.Summary, "profile sync disabled")
		return card
	}
	if !status.Available {
		card.State = setupstate.StateWarning
		card.Summary = sanitizeSummary(status.Summary, "profile sync is degraded")
	} else if status.ReviewRequired {
		card.State = setupstate.StateWarning
		card.Summary = sanitizeSummary(status.Summary, "profile sync requires review")
	}
	for _, issue := range status.Issues {
		card.Issues = append(card.Issues, SetupIssue{Capability: setupstate.CapabilityProfileSync, Code: sanitizeIdentifier(issue.Code), Message: sanitizeSummary(issue.Message, "profile sync issue"), Blocking: false})
	}
	return card
}

func sanitizeAuthStatus(status auth.AuthStatus) auth.AuthStatus {
	status.LastError = sanitizeSummary(status.LastError, "")
	status.DisplayName = sanitizeSummary(status.DisplayName, status.AppID)
	status.AppID = sanitizeIdentifier(status.AppID)
	status.TokenNamespace = sanitizeIdentifier(status.TokenNamespace)
	status.ClientIDFingerprint = sanitizeIdentifier(status.ClientIDFingerprint)
	status.Profile.DisplayName = sanitizeSummary(status.Profile.DisplayName, "")
	return status
}

func sanitizeUpdateStatus(status updates.CurrentState) updates.CurrentState {
	status.AppID = sanitizeIdentifier(status.AppID)
	status.DisplayName = sanitizeSummary(status.DisplayName, status.AppID)
	status.LastError = sanitizeSummary(status.LastError, "")
	status.Message = sanitizeSummary(status.Message, "")
	status.StagedVersion = sanitizeIdentifier(status.StagedVersion)
	return status
}

func sanitizeSecurityPostureSummary(summary securityposture.Summary) securityposture.Summary {
	summary.Capability = sanitizeIdentifier(summary.Capability)
	if summary.Capability == "" {
		summary.Capability = "security_posture"
	}
	if summary.Posture == "" {
		summary.Posture = securityposture.PostureUnknown
	}
	for i, issue := range summary.Issues {
		summary.Issues[i] = securityposture.Issue{
			Code:           sanitizeIdentifier(issue.Code),
			Severity:       issue.Severity,
			Posture:        issue.Posture,
			Boundary:       issue.Boundary,
			Risk:           issue.Risk,
			Redaction:      issue.Redaction,
			Summary:        sanitizeSecurityPostureText(issue.Summary, "security posture issue"),
			ReviewRequired: issue.ReviewRequired,
		}
	}
	return summary
}

func sanitizeSecurityPostureText(value, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}
	redacted := securityposture.RedactPublicSurfaceText(value)
	if redacted == "[redacted-public-surface]" {
		return fallback
	}
	return sanitizeSummary(redacted, fallback)
}

func sanitizeProfileSyncStatus(status profilesync.SyncStatus) profilesync.SyncStatus {
	status.ProfileNamespace = sanitizeIdentifier(status.ProfileNamespace)
	status.LocalSnapshotID = sanitizeIdentifier(status.LocalSnapshotID)
	status.Summary = sanitizeSummary(status.Summary, "")
	for i, issue := range status.Issues {
		status.Issues[i] = profilesync.SyncIssue{Code: sanitizeIdentifier(issue.Code), Message: sanitizeSummary(issue.Message, "profile sync issue"), Blocking: issue.Blocking}
	}
	return status
}

func sanitizeProfileMeshOverview(overview profilemesh.ProfileMeshOverview) profilemesh.ProfileMeshOverview {
	overview.AppID = sanitizeIdentifier(overview.AppID)
	overview.Namespace = sanitizeIdentifier(overview.Namespace)
	overview.ProfileID = sanitizeIdentifier(overview.ProfileID)
	overview.DisplayName = sanitizeSummary(overview.DisplayName, overview.ProfileID)
	overview.Message = sanitizeSummary(overview.Message, "")
	overview.PrimaryProfileDeviceID = sanitizeIdentifier(overview.PrimaryProfileDeviceID)
	overview.ProfileDataHostDeviceID = sanitizeIdentifier(overview.ProfileDataHostDeviceID)
	for i, issue := range overview.Issues {
		overview.Issues[i] = profilemesh.ProfileMeshIssue{Code: sanitizeIdentifier(issue.Code), Message: sanitizeSummary(issue.Message, "profile mesh issue"), Blocking: issue.Blocking}
	}
	for i, warning := range overview.Warnings {
		overview.Warnings[i] = profilemesh.ProfileMeshIssue{Code: sanitizeIdentifier(warning.Code), Message: sanitizeSummary(warning.Message, "profile mesh warning"), Blocking: false}
	}
	return overview
}

func summarizeTrustedDevices(devices []devicelink.TrustedDevice) []TrustedDeviceSummary {
	out := make([]TrustedDeviceSummary, 0, len(devices))
	for _, device := range devices {
		out = append(out, TrustedDeviceSummary{
			DeviceID:             sanitizeIdentifier(device.DeviceID),
			DisplayName:          sanitizeSummary(device.DisplayName, device.DeviceID),
			PublicKeyFingerprint: sanitizeIdentifier(device.PublicKeyFingerprint),
			TrustStatus:          device.TrustStatus,
		})
	}
	return out
}

func summarizeHostedResources(resources []profilemesh.ProfileResourceRecord) []HostedResourceSummary {
	out := make([]HostedResourceSummary, 0, len(resources))
	for _, resource := range resources {
		out = append(out, HostedResourceSummary{
			ResourceID:          sanitizeIdentifier(resource.ResourceID),
			ResourceType:        resource.ResourceType,
			DisplayName:         sanitizeSummary(resource.DisplayName, resource.ResourceID),
			CurrentHostDeviceID: sanitizeIdentifier(resource.CurrentHostDeviceID),
			Availability:        resource.Availability,
		})
	}
	return out
}

func sanitizeIdentifier(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if unsafeBridgeDetail(value) {
		return ""
	}
	return value
}

func sanitizeSummary(value, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}
	if unsafeBridgeDetail(value) {
		return fallback
	}
	return value
}

func validBridgeName(value string) bool {
	value = strings.TrimSpace(value)
	return bridgeSafeNamePattern.MatchString(value) && !strings.Contains(value, "..") && !strings.ContainsAny(value, `/\`) && !unsafeBridgeDetail(value)
}

func unsafeBridgeDetail(value string) bool {
	lower := strings.ToLower(strings.TrimSpace(value))
	if lower == "" {
		return false
	}
	for _, marker := range []string{"client_secret", "refresh_token", "access_token", "id_token", "auth_code", "pkce", "verifier", "private_key", "begin private key", "github_pat", "ghp_", "token=", "password=", "secret=", "secret"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	for _, marker := range []string{`:\`, `/users/`, `/home/`, `/tmp/`, `\\`, "appdata", "downloads", "desktop"} {
		if strings.Contains(lower, strings.ToLower(marker)) {
			return true
		}
	}
	return false
}
