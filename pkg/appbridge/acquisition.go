package appbridge

import (
	"context"
	"github.com/AegisAgentAscalon/aegis-core/pkg/profilesync"
	"github.com/AegisAgentAscalon/aegis-core/pkg/relay"
	"github.com/AegisAgentAscalon/aegis-core/pkg/securityposture"
	"github.com/AegisAgentAscalon/aegis-core/pkg/setupstate"
	"github.com/AegisAgentAscalon/aegis-core/pkg/updates"
	"slices"
)

// updateStatus observes the owner once; projection determines whether failures
// block setup or remain nonfatal infrastructure diagnostics.
func (b *Bridge) updateStatus(ctx context.Context, policy projectionPolicy) (UpdateStatusResult, error) {
	var status updates.CurrentState
	var err error
	if b.cfg.Updates.Enabled && b.cfg.Updates.Service != nil {
		status, err = b.cfg.Updates.Service.GetStatus(ctx)
		if err == nil {
			status = sanitizeUpdateStatus(status)
		}
	}
	return projectUpdateStatus(status, err, b.cfg.Updates.Enabled, b.cfg.Updates.Service != nil, policy)
}

func (b *Bridge) safeUpdateStatus(ctx context.Context) UpdateStatusResult {
	result, _ := b.updateStatus(ctx, infrastructureProjection)
	return result
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
	status.Issues = slices.Clone(status.Issues)
	for i, issue := range status.Issues {
		status.Issues[i] = relay.RelayIssue{Code: sanitizeIdentifier(issue.Code), Message: sanitizeSummary(issue.Message, "relay is degraded"), Blocking: false}
	}
	return status
}
