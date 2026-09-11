package appbridge

import (
	"context"
	"errors"
	"github.com/AegisAgentAscalon/aegis-core/pkg/devicelink"
	"github.com/AegisAgentAscalon/aegis-core/pkg/profilemesh"
	"github.com/AegisAgentAscalon/aegis-core/pkg/relay"
	"github.com/AegisAgentAscalon/aegis-core/pkg/setupstate"
)

func (b *Bridge) AuthStatus(ctx context.Context) (AuthStatusResult, error) {
	if !b.cfg.Auth.Enabled {
		return AuthStatusResult{}, ErrDisabled
	}
	if b.cfg.Auth.Service == nil {
		return AuthStatusResult{Card: SetupCapabilityCard{Capability: setupstate.CapabilityAuth, Enabled: true, State: setupstate.StateBlocked, Summary: "auth service is not configured"}}, nil
	}
	status, err := b.cfg.Auth.Service.Status(ctx)
	if err != nil {
		return AuthStatusResult{}, err
	}
	status = sanitizeAuthStatus(status)
	capability := authCapabilityStatus(status)
	return AuthStatusResult{Status: status, Card: cardFromStatus(capability)}, nil
}

func (b *Bridge) UpdateStatus(ctx context.Context) (UpdateStatusResult, error) {
	return b.updateStatus(ctx, setupProjection)
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
	return RelayStatusResult{Status: status, Card: relayCard(status)}, nil
}
