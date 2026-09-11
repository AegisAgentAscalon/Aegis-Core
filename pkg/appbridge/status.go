package appbridge

import (
	"context"
	"errors"

	"github.com/AegisAgentAscalon/aegis-core/pkg/auth"
	"github.com/AegisAgentAscalon/aegis-core/pkg/devicelink"
	"github.com/AegisAgentAscalon/aegis-core/pkg/profilemesh"
	"github.com/AegisAgentAscalon/aegis-core/pkg/profilesync"
	"github.com/AegisAgentAscalon/aegis-core/pkg/relay"
	"github.com/AegisAgentAscalon/aegis-core/pkg/securityposture"
	"github.com/AegisAgentAscalon/aegis-core/pkg/setupstate"
	"github.com/AegisAgentAscalon/aegis-core/pkg/updates"
)

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
