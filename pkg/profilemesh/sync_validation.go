package profilemesh

import (
	"regexp"
	"strings"
	"time"
)

var profileSyncFingerprintPattern = regexp.MustCompile(`^[a-fA-F0-9]{16,128}$`)

func BuildProfileFreshnessSummary(metadata ProfileSnapshotMetadata, now time.Time) ProfileFreshnessSummary {
	now = normalizeProfileSyncNow(now)
	updatedAt := metadata.UpdatedAt.UTC()
	if updatedAt.IsZero() {
		updatedAt = metadata.CreatedAt.UTC()
	}
	age := now.Sub(updatedAt)
	if age < 0 {
		age = 0
	}
	futureDated := metadata.CreatedAt.After(now.Add(DefaultSnapshotClockSkew)) ||
		metadata.UpdatedAt.After(now.Add(DefaultSnapshotClockSkew))
	stale := false
	if !metadata.ExpiresAt.IsZero() && !metadata.ExpiresAt.After(now.Add(-DefaultSnapshotClockSkew)) {
		stale = true
	}
	if !updatedAt.IsZero() && now.Sub(updatedAt) > DefaultSnapshotFreshnessWindow {
		stale = true
	}
	message := "profile snapshot metadata is fresh"
	if futureDated {
		message = "profile snapshot metadata is future dated"
	} else if stale {
		message = "profile snapshot metadata is stale"
	}
	return ProfileFreshnessSummary{
		ProfileNamespace: metadata.ProfileNamespace,
		SnapshotID:       metadata.SnapshotID,
		Fresh:            !stale && !futureDated,
		Stale:            stale,
		FutureDated:      futureDated,
		AgeSeconds:       int64(age.Seconds()),
		ObservedAt:       now,
		ExpiresAt:        metadata.ExpiresAt,
		Message:          message,
	}
}

func ValidateSignedProfileSnapshot(snapshot SignedProfileSnapshot, now time.Time) SnapshotValidationResult {
	now = normalizeProfileSyncNow(now)
	issues := validateSnapshotMetadata(snapshot.Metadata, now)
	if !validProfileSyncID(snapshot.Signature.SignerDeviceID) {
		issues = append(issues, syncIssue("invalid_signer_device_id", ErrInvalidSignerDeviceID.Error(), true))
	}
	if snapshot.Signature.SignerKeyFingerprint != "" && !validProfileSyncFingerprint(snapshot.Signature.SignerKeyFingerprint) {
		issues = append(issues, syncIssue("invalid_signer_key_fingerprint", "invalid signer key fingerprint", true))
	}
	if snapshot.Signature.SignatureFingerprint != "" && !validProfileSyncFingerprint(snapshot.Signature.SignatureFingerprint) {
		issues = append(issues, syncIssue("invalid_signature_fingerprint", "invalid signature fingerprint", true))
	}
	if !snapshot.Signature.SignedAt.IsZero() && snapshot.Signature.SignedAt.After(now.Add(DefaultSnapshotClockSkew)) {
		issues = append(issues, syncIssue("future_dated_signature", ErrSnapshotMetadataFutureDated.Error(), true))
	}
	freshness := BuildProfileFreshnessSummary(snapshot.Metadata, now)
	return SnapshotValidationResult{Valid: noBlockingProfileSyncIssues(issues), Freshness: freshness, Issues: issues}
}

func ValidateProfileChangeProposal(proposal ProfileChangeProposal, now time.Time) ProposalValidationResult {
	now = normalizeProfileSyncNow(now)
	status := proposal.Status
	if status == "" {
		status = ProposalStatusDraft
	}
	issues := []ProfileSyncIssue{}
	if !validProfileSyncID(proposal.ProposalID) {
		issues = append(issues, syncIssue("invalid_proposal_id", ErrInvalidProfileProposalID.Error(), true))
	}
	if !validProfileSyncNamespace(proposal.ProfileNamespace) {
		issues = append(issues, syncIssue("invalid_profile_namespace", ErrInvalidProfileNamespace.Error(), true))
	}
	if !validProfileSyncID(proposal.ProfileID) || !validProfileSyncID(proposal.BaseSnapshotID) || !validProfileSyncID(proposal.ProposedSnapshotID) {
		issues = append(issues, syncIssue("invalid_snapshot_ref", ErrInvalidSnapshotID.Error(), true))
	}
	if !validProfileSyncID(proposal.SourceBranchID) {
		issues = append(issues, syncIssue("invalid_source_branch_id", ErrInvalidOfflineBranchID.Error(), true))
	}
	if proposal.TargetBranchID != "" && !validProfileSyncID(proposal.TargetBranchID) {
		issues = append(issues, syncIssue("invalid_target_branch_id", ErrInvalidOfflineBranchID.Error(), true))
	}
	if !validProfileSyncID(proposal.AuthorDeviceID) {
		issues = append(issues, syncIssue("invalid_author_device_id", ErrInvalidSignerDeviceID.Error(), true))
	}
	if !validProposalStatus(status) {
		issues = append(issues, syncIssue("invalid_proposal_status", ErrInvalidProfileSyncContract.Error(), true))
	}
	if proposal.RequestedHostingMode == HostingMultiProfileDevices {
		issues = append(issues, syncIssue("multi_host_unsupported", ErrProfileSyncModeUnsupported.Error(), true))
	}
	if proposal.RequestedHostingMode != "" && proposal.RequestedHostingMode != HostingSingleProfileDevice && proposal.RequestedHostingMode != HostingMultiProfileDevices {
		issues = append(issues, syncIssue("invalid_hosting_mode", ErrInvalidProfileSyncContract.Error(), true))
	}
	if proposal.CreatedAt.IsZero() || proposal.UpdatedAt.IsZero() || proposal.UpdatedAt.Before(proposal.CreatedAt.Add(-DefaultSnapshotClockSkew)) {
		issues = append(issues, syncIssue("invalid_proposal_timestamps", ErrInvalidProfileSyncContract.Error(), true))
	}
	if proposal.CreatedAt.After(now.Add(DefaultSnapshotClockSkew)) || proposal.UpdatedAt.After(now.Add(DefaultSnapshotClockSkew)) {
		issues = append(issues, syncIssue("future_dated_proposal", ErrSnapshotMetadataFutureDated.Error(), true))
	}
	conflicts, conflictIssues := sanitizeAndValidateConflicts(proposal.Conflicts)
	issues = append(issues, conflictIssues...)
	requiresReview := proposal.RequiresUserReview || proposal.MergePlan.RequiresUserReview || len(conflicts) > 0
	if len(conflicts) > 0 && !proposal.RequiresUserReview {
		issues = append(issues, syncIssue("conflict_requires_user_review", ErrProfileConflictNeedsReview.Error(), true))
	}
	if unsafeProfileSyncDetail(proposal.MergePlan.Summary) || unsafeProfileSyncDetail(proposal.MergePlan.Strategy) || unsafeProfileSyncDetail(proposal.MergePlan.Status) {
		issues = append(issues, syncIssue("unsafe_merge_plan_summary", "merge plan summary contains unsafe details", true))
	}
	if proposal.MergePlan.PlanID != "" && !validProfileSyncID(proposal.MergePlan.PlanID) {
		issues = append(issues, syncIssue("invalid_merge_plan_id", ErrInvalidProfileSyncContract.Error(), true))
	}
	return ProposalValidationResult{Valid: noBlockingProfileSyncIssues(issues), Status: status, RequiresUserReview: requiresReview, Conflicts: conflicts, Issues: issues}
}

func ValidateOfflineProfileBranches(branches []OfflineProfileBranch) ProposalValidationResult {
	issues := []ProfileSyncIssue{}
	seen := map[string]bool{}
	var conflicts []ConflictSummary
	for _, branch := range branches {
		if !validProfileSyncID(branch.BranchID) {
			issues = append(issues, syncIssue("invalid_branch_id", ErrInvalidOfflineBranchID.Error(), true))
		} else if seen[branch.BranchID] {
			issues = append(issues, syncIssue("duplicate_branch_id", "offline branch id collision", true))
			conflicts = append(conflicts, ConflictSummary{ConflictID: "duplicate-" + branch.BranchID, Summary: "offline branch id collision", RequiresUserReview: true, SafeFailureCode: "duplicate_branch"})
		}
		seen[branch.BranchID] = true
		if !validProfileSyncNamespace(branch.ProfileNamespace) {
			issues = append(issues, syncIssue("invalid_profile_namespace", ErrInvalidProfileNamespace.Error(), true))
		}
		if !validProfileSyncID(branch.ProfileID) || !validProfileSyncID(branch.BaseSnapshotID) || !validProfileSyncID(branch.HeadSnapshotID) {
			issues = append(issues, syncIssue("invalid_branch_snapshot_ref", ErrInvalidSnapshotID.Error(), true))
		}
		if !validProfileSyncID(branch.OwnerDeviceID) {
			issues = append(issues, syncIssue("invalid_branch_owner_device_id", ErrInvalidSignerDeviceID.Error(), true))
		}
		if branch.CreatedAt.IsZero() || branch.UpdatedAt.IsZero() || branch.UpdatedAt.Before(branch.CreatedAt.Add(-DefaultSnapshotClockSkew)) {
			issues = append(issues, syncIssue("invalid_branch_timestamps", ErrInvalidProfileSyncContract.Error(), true))
		}
		if unsafeProfileSyncDetail(branch.Status) {
			issues = append(issues, syncIssue("unsafe_branch_status", "offline branch status contains unsafe details", true))
		}
	}
	return ProposalValidationResult{Valid: noBlockingProfileSyncIssues(issues), Status: ProposalStatusPendingReview, RequiresUserReview: len(conflicts) > 0, Conflicts: conflicts, Issues: issues}
}

func validateSnapshotMetadata(metadata ProfileSnapshotMetadata, now time.Time) []ProfileSyncIssue {
	issues := []ProfileSyncIssue{}
	if !validProfileSyncNamespace(metadata.ProfileNamespace) {
		issues = append(issues, syncIssue("invalid_profile_namespace", ErrInvalidProfileNamespace.Error(), true))
	}
	if !validProfileSyncID(metadata.ProfileID) || !validProfileSyncID(metadata.SnapshotID) {
		issues = append(issues, syncIssue("invalid_snapshot_id", ErrInvalidSnapshotID.Error(), true))
	}
	if metadata.ParentSnapshotID != "" && !validProfileSyncID(metadata.ParentSnapshotID) {
		issues = append(issues, syncIssue("invalid_parent_snapshot_id", ErrInvalidSnapshotID.Error(), true))
	}
	if !validProfileSyncFingerprint(metadata.SnapshotFingerprint) {
		issues = append(issues, syncIssue("invalid_snapshot_fingerprint", ErrInvalidSnapshotFingerprint.Error(), true))
	}
	if !validProfileSyncID(metadata.SourceDeviceID) {
		issues = append(issues, syncIssue("invalid_source_device_id", ErrInvalidSignerDeviceID.Error(), true))
	}
	if metadata.HostingMode == HostingMultiProfileDevices {
		issues = append(issues, syncIssue("multi_host_unsupported", ErrProfileSyncModeUnsupported.Error(), true))
	}
	if metadata.HostingMode != "" && metadata.HostingMode != HostingSingleProfileDevice && metadata.HostingMode != HostingMultiProfileDevices {
		issues = append(issues, syncIssue("invalid_hosting_mode", ErrInvalidProfileSyncContract.Error(), true))
	}
	if metadata.CreatedAt.IsZero() || metadata.UpdatedAt.IsZero() || metadata.UpdatedAt.Before(metadata.CreatedAt.Add(-DefaultSnapshotClockSkew)) {
		issues = append(issues, syncIssue("invalid_snapshot_timestamps", ErrInvalidProfileSyncContract.Error(), true))
	}
	freshness := BuildProfileFreshnessSummary(metadata, now)
	if freshness.FutureDated {
		issues = append(issues, syncIssue("future_dated_snapshot", ErrSnapshotMetadataFutureDated.Error(), true))
	}
	if freshness.Stale {
		issues = append(issues, syncIssue("stale_snapshot", ErrSnapshotMetadataStale.Error(), false))
	}
	return issues
}

func sanitizeAndValidateConflicts(in []ConflictSummary) ([]ConflictSummary, []ProfileSyncIssue) {
	conflicts := make([]ConflictSummary, 0, len(in))
	issues := []ProfileSyncIssue{}
	seen := map[string]bool{}
	for _, conflict := range in {
		out := conflict
		out.RequiresUserReview = true
		if !validProfileSyncID(conflict.ConflictID) {
			issues = append(issues, syncIssue("invalid_conflict_id", ErrInvalidProfileSyncContract.Error(), true))
			out.ConflictID = ""
		} else if seen[conflict.ConflictID] {
			issues = append(issues, syncIssue("duplicate_conflict_id", ErrInvalidProfileSyncContract.Error(), true))
		}
		seen[conflict.ConflictID] = true
		if conflict.ResourceID != "" && !validProfileSyncID(conflict.ResourceID) {
			issues = append(issues, syncIssue("invalid_conflict_resource_id", ErrInvalidProfileSyncContract.Error(), true))
			out.ResourceID = ""
		}
		if unsafeProfileSyncDetail(conflict.ResourceType) {
			issues = append(issues, syncIssue("unsafe_conflict_resource_type", "conflict resource type contains unsafe details", true))
			out.ResourceType = ""
		}
		if unsafeProfileSyncDetail(conflict.Summary) {
			issues = append(issues, syncIssue("unsafe_conflict_summary", "conflict summary contains unsafe details", true))
			out.Summary = "conflict details require app-owned review"
			out.SafeFailureCode = "unsafe_conflict_detail"
		}
		if unsafeProfileSyncDetail(conflict.SafeFailureCode) {
			issues = append(issues, syncIssue("unsafe_conflict_code", "conflict code contains unsafe details", true))
			out.SafeFailureCode = "unsafe_conflict_detail"
		}
		conflicts = append(conflicts, out)
	}
	return conflicts, issues
}

func validProposalStatus(status ProposalStatus) bool {
	switch status {
	case ProposalStatusDraft, ProposalStatusPendingReview, ProposalStatusNeedsUserMerge, ProposalStatusAccepted, ProposalStatusRejected, ProposalStatusDeferred:
		return true
	default:
		return false
	}
}

func validProfileSyncNamespace(s string) bool {
	s = strings.TrimSpace(s)
	return safeNamePattern.MatchString(s) && !strings.Contains(s, "..") && !strings.ContainsAny(s, `/\`) && !reservedDeviceName(s) && !unsafeProfileSyncDetail(s)
}

func validProfileSyncID(s string) bool {
	return validID(s) && !unsafeProfileSyncDetail(s)
}

func validProfileSyncFingerprint(s string) bool {
	s = strings.TrimSpace(s)
	return profileSyncFingerprintPattern.MatchString(s) && !unsafeProfileSyncDetail(s)
}

func unsafeProfileSyncDetail(s string) bool {
	lower := strings.ToLower(strings.TrimSpace(s))
	if lower == "" {
		return false
	}
	for _, marker := range []string{"client_secret", "refresh_token", "access_token", "id_token", "auth_code", "pkce", "verifier", "private_key", "begin private key", "github_pat", "ghp_", "token=", "password=", "secret=", "secret"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	for _, marker := range []string{`:\`, `/users/`, `/home/`, `/tmp/`, `\\`, `appdata`, `downloads`, `desktop`} {
		if strings.Contains(lower, strings.ToLower(marker)) {
			return true
		}
	}
	return false
}

func syncIssue(code, message string, blocking bool) ProfileSyncIssue {
	if unsafeProfileSyncDetail(message) {
		message = ErrInvalidProfileSyncContract.Error()
	}
	return ProfileSyncIssue{Code: code, Message: message, Blocking: blocking}
}

func noBlockingProfileSyncIssues(issues []ProfileSyncIssue) bool {
	for _, issue := range issues {
		if issue.Blocking {
			return false
		}
	}
	return true
}

func normalizeProfileSyncNow(now time.Time) time.Time {
	if now.IsZero() {
		return time.Now().UTC()
	}
	return now.UTC()
}
