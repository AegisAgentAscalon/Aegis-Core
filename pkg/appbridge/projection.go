package appbridge

import (
	"github.com/AegisAgentAscalon/aegis-core/pkg/auth"
	"github.com/AegisAgentAscalon/aegis-core/pkg/devicelink"
	"github.com/AegisAgentAscalon/aegis-core/pkg/profilemesh"
	"github.com/AegisAgentAscalon/aegis-core/pkg/profilesync"
	"github.com/AegisAgentAscalon/aegis-core/pkg/relay"
	"github.com/AegisAgentAscalon/aegis-core/pkg/securityposture"
	"github.com/AegisAgentAscalon/aegis-core/pkg/setupstate"
	"github.com/AegisAgentAscalon/aegis-core/pkg/updates"
)

// projectionPolicy preserves the distinction between setup admission and diagnostics.
type projectionPolicy uint8

const (
	setupProjection projectionPolicy = iota
	infrastructureProjection
)

func projectUpdateStatus(status updates.CurrentState, err error, enabled, provider bool, policy projectionPolicy) (UpdateStatusResult, error) {
	if !enabled {
		if policy == setupProjection {
			return UpdateStatusResult{}, ErrDisabled
		}
		status := updates.CurrentState{Configured: false, Message: "updates are disabled"}
		return UpdateStatusResult{Status: status, Card: SetupCapabilityCard{Capability: setupstate.CapabilityUpdates, Enabled: false, Ready: true, State: setupstate.StateDisabled, Summary: "updates disabled"}}, nil
	}
	if !provider {
		if policy == setupProjection {
			return UpdateStatusResult{Card: SetupCapabilityCard{Capability: setupstate.CapabilityUpdates, Enabled: true, State: setupstate.StateBlocked, Summary: "update service is not configured"}}, nil
		}
		status := updates.CurrentState{Configured: false, Message: "update status provider is not configured"}
		card := SetupCapabilityCard{Capability: setupstate.CapabilityUpdates, Enabled: true, Ready: true, State: setupstate.StateWarning, Summary: "update status provider is not configured", Issues: []SetupIssue{{Capability: setupstate.CapabilityUpdates, Code: "update_status_provider_missing", Message: "update status provider is not configured", Blocking: false}}}
		return UpdateStatusResult{Status: status, Card: card}, nil
	}
	if err != nil {
		if policy == setupProjection {
			return UpdateStatusResult{}, err
		}
		status = updates.CurrentState{Configured: true, LastError: "update status is unavailable", Message: "updates are degraded"}
		card := SetupCapabilityCard{Capability: setupstate.CapabilityUpdates, Enabled: true, Ready: true, State: setupstate.StateWarning, Summary: "updates are degraded", Issues: []SetupIssue{{Capability: setupstate.CapabilityUpdates, Code: "update_status_unavailable", Message: "updates are degraded", Blocking: false}}}
		return UpdateStatusResult{Status: status, Card: card}, nil
	}
	card := SetupCapabilityCard{Capability: setupstate.CapabilityUpdates, Enabled: true, Ready: true, State: setupstate.StateReady, Summary: "updates ready"}
	if !status.Configured {
		card.State = setupstate.StateWarning
		if policy == setupProjection {
			card.Ready = false
			card.State = setupstate.StateBlocked
		}
		card.Summary = "updates are not configured"
	} else if status.UpdateAvailable {
		card.State = setupstate.StateWarning
		card.Summary = "update is available"
	} else if policy == infrastructureProjection && status.LastError != "" {
		card.State = setupstate.StateWarning
		card.Summary = sanitizeSummary(status.Message, "updates are degraded")
		card.Issues = append(card.Issues, SetupIssue{Capability: setupstate.CapabilityUpdates, Code: "update_status_degraded", Message: card.Summary, Blocking: false})
	}
	return UpdateStatusResult{Status: status, Card: card}, nil
}

func relayCard(status relay.RelayStatus) SetupCapabilityCard {
	card := SetupCapabilityCard{Capability: setupstate.CapabilityRelay, Enabled: true, Ready: true, State: setupstate.StateWarning, Summary: sanitizeSummary(status.Summary, "relay is degraded")}
	if status.Available {
		card.State = setupstate.StateReady
		card.Summary = sanitizeSummary(status.Summary, "relay provider is available")
	}
	for _, issue := range status.Issues {
		card.Issues = append(card.Issues, SetupIssue{Capability: setupstate.CapabilityRelay, Code: sanitizeIdentifier(issue.Code), Message: sanitizeSummary(issue.Message, "relay is degraded"), Blocking: false})
	}
	return card
}

func authCapabilityStatus(status auth.AuthStatus) setupstate.CapabilityStatus {
	if !status.Configured {
		return setupstate.CapabilityStatus{Capability: setupstate.CapabilityAuth, Enabled: true, Ready: false, State: setupstate.StateBlocked, Summary: "auth is not configured"}
	}
	if !status.SignedIn || status.NeedsReconnect {
		return setupstate.CapabilityStatus{Capability: setupstate.CapabilityAuth, Enabled: true, Ready: false, State: setupstate.StateBlocked, Summary: "auth sign-in is required"}
	}
	return setupstate.CapabilityStatus{Capability: setupstate.CapabilityAuth, Enabled: true, Ready: true, State: setupstate.StateReady, Summary: "auth ready"}
}

func fromSetupStateOverview(in setupstate.SetupOverview, capabilities []setupstate.Capability) SetupOverview {
	out := SetupOverview{AppID: in.AppID, DisplayName: in.DisplayName, Ready: in.Ready}
	statusByCapability := map[setupstate.Capability]setupstate.CapabilityStatus{}
	for _, status := range in.Capabilities {
		statusByCapability[status.Capability] = status
	}
	for _, capability := range capabilities {
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
	case securityposture.PostureDegraded, securityposture.PostureReviewRequired, securityposture.PostureOutOfScope:
		card.State = setupstate.StateWarning
		card.Summary = "security posture requires review"
	default:
		card.Ready = false
		card.State = setupstate.StateWarning
		card.Summary = "security posture is unknown; review required"
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
