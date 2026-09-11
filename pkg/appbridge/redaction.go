package appbridge

import (
	"context"
	"slices"
	"strings"

	"github.com/AegisAgentAscalon/aegis-core/pkg/auth"
	"github.com/AegisAgentAscalon/aegis-core/pkg/profilemesh"
	"github.com/AegisAgentAscalon/aegis-core/pkg/profilesync"
	"github.com/AegisAgentAscalon/aegis-core/pkg/relay"
	"github.com/AegisAgentAscalon/aegis-core/pkg/securityposture"
	"github.com/AegisAgentAscalon/aegis-core/pkg/setupstate"
	"github.com/AegisAgentAscalon/aegis-core/pkg/updates"
)

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
	status.Issues = slices.Clone(status.Issues)
	for i, issue := range status.Issues {
		status.Issues[i] = relay.RelayIssue{Code: sanitizeIdentifier(issue.Code), Message: sanitizeSummary(issue.Message, "relay is degraded"), Blocking: false}
	}
	return status
}

func sanitizeAuthStatus(status auth.AuthStatus) auth.AuthStatus {
	status.Scopes = slices.Clone(status.Scopes)
	status.LastError = sanitizeSummary(status.LastError, "")
	status.DisplayName = sanitizeSummary(status.DisplayName, status.AppID)
	status.AppID = sanitizeIdentifier(status.AppID)
	status.TokenNamespace = sanitizeIdentifier(status.TokenNamespace)
	status.ClientIDFingerprint = sanitizeIdentifier(status.ClientIDFingerprint)
	status.Profile.DisplayName = sanitizeSummary(status.Profile.DisplayName, "")
	return status
}

func sanitizeUpdateStatus(status updates.CurrentState) updates.CurrentState {
	if status.LatestRelease != nil {
		release := *status.LatestRelease
		status.LatestRelease = &release
	}
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
	switch summary.Posture {
	case securityposture.PostureReady, securityposture.PostureBlocked, securityposture.PostureDegraded, securityposture.PostureReviewRequired, securityposture.PostureOutOfScope, securityposture.PostureUnknown:
	default:
		summary.Posture = securityposture.PostureUnknown
	}
	summary.Issues = slices.Clone(summary.Issues)
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
	status.Issues = slices.Clone(status.Issues)
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
	overview.Issues = slices.Clone(overview.Issues)
	for i, issue := range overview.Issues {
		overview.Issues[i] = profilemesh.ProfileMeshIssue{Code: sanitizeIdentifier(issue.Code), Message: sanitizeSummary(issue.Message, "profile mesh issue"), Blocking: issue.Blocking}
	}
	overview.Warnings = slices.Clone(overview.Warnings)
	for i, warning := range overview.Warnings {
		overview.Warnings[i] = profilemesh.ProfileMeshIssue{Code: sanitizeIdentifier(warning.Code), Message: sanitizeSummary(warning.Message, "profile mesh warning"), Blocking: false}
	}
	return overview
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
