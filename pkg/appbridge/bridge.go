package appbridge

import (
	"context"
	"github.com/AegisAgentAscalon/aegis-core/pkg/setupstate"
	"strings"
)

type Bridge struct{ cfg AppBridgeConfig }

func NewSetupBridge(cfg AppBridgeConfig) (*Bridge, error) {
	if !validBridgeName(cfg.Identity.AppID) || strings.TrimSpace(cfg.Identity.DisplayName) == "" {
		return nil, ErrInvalidConfig
	}
	return &Bridge{cfg: cfg}, nil
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
