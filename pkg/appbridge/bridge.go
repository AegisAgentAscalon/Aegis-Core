package appbridge

import (
	"context"
	"strings"

	"github.com/AegisAgentAscalon/aegis-core/pkg/setupstate"
)

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
