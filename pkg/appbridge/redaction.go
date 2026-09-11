package appbridge

import (
	"github.com/AegisAgentAscalon/aegis-core/pkg/auth"
	"github.com/AegisAgentAscalon/aegis-core/pkg/profilemesh"
	"github.com/AegisAgentAscalon/aegis-core/pkg/profilesync"
	"github.com/AegisAgentAscalon/aegis-core/pkg/securityposture"
	"github.com/AegisAgentAscalon/aegis-core/pkg/updates"
	"slices"
	"strings"
)

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
