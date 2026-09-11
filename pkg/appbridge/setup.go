package appbridge

import (
	"context"
	"github.com/AegisAgentAscalon/aegis-core/pkg/setupstate"
)

func (b *Bridge) BuildSetupOverview(ctx context.Context) (SetupOverview, error) {
	// Binding order also defines display order. Disabled providers are never called.
	bindings := []struct {
		capability setupstate.Capability
		enabled    bool
		status     setupstate.StatusProviderFunc
	}{
		{setupstate.CapabilityAuth, b.cfg.Auth.Enabled, b.authSetupStatus},
		{setupstate.CapabilityUpdates, b.cfg.Updates.Enabled, b.updateSetupStatus},
		{setupstate.CapabilityDeviceLink, b.cfg.DeviceLink.Enabled, b.deviceLinkSetupStatus},
		{setupstate.CapabilityProfileMesh, b.cfg.ProfileMesh.Enabled, b.profileMeshSetupStatus},
		{setupstate.CapabilityProfileSync, b.cfg.ProfileSync.Enabled, b.profileSyncSetupStatus},
		{setupstate.CapabilityRelay, b.cfg.Relay.Enabled, b.relaySetupStatus},
		{setupstate.CapabilitySecurityPosture, b.cfg.SecurityPosture.Enabled, b.securityPostureSetupStatus},
	}
	var capabilities, enabled []setupstate.Capability
	providers := make(map[setupstate.Capability]setupstate.StatusProvider)
	for _, binding := range bindings {
		capabilities = append(capabilities, binding.capability)
		if binding.enabled {
			enabled = append(enabled, binding.capability)
			providers[binding.capability] = binding.status
		}
	}
	stateOverview, err := setupstate.BuildOverview(ctx, setupstate.AppSetupConfig{
		AppID: b.cfg.Identity.AppID, DisplayName: b.cfg.Identity.DisplayName,
		EnabledCapabilities: enabled,
	}, providers)
	if err != nil {
		return SetupOverview{}, err
	}
	return fromSetupStateOverview(stateOverview, capabilities), nil
}

func (b *Bridge) authSetupStatus(ctx context.Context) (setupstate.CapabilityStatus, error) {
	result, err := b.AuthStatus(ctx)
	return statusFromCard(result.Card), err
}

func (b *Bridge) updateSetupStatus(ctx context.Context) (setupstate.CapabilityStatus, error) {
	result, err := b.UpdateStatus(ctx)
	return statusFromCard(result.Card), err
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
	return statusFromCard(relayCard(b.safeRelayStatus(ctx))), nil
}

func (b *Bridge) securityPostureSetupStatus(ctx context.Context) (setupstate.CapabilityStatus, error) {
	return statusFromCard(b.safeSecurityPostureStatus(ctx).Card), nil
}
