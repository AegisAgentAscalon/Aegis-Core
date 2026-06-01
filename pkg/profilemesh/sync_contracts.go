package profilemesh

import (
	"errors"
	"regexp"
	"strings"
	"time"
)

const (
	DefaultSnapshotFreshnessWindow = 24 * time.Hour
	DefaultSnapshotClockSkew       = 2 * time.Minute
)

var (
	ErrInvalidProfileSyncContract  = errors.New("invalid profile sync contract")
	ErrInvalidProfileNamespace     = errors.New("invalid profile namespace")
	ErrInvalidSnapshotID           = errors.New("invalid profile snapshot id")
	ErrInvalidSnapshotFingerprint  = errors.New("invalid profile snapshot fingerprint")
	ErrInvalidSignerDeviceID       = errors.New("invalid profile snapshot signer device id")
	ErrInvalidOfflineBranchID      = errors.New("invalid offline profile branch id")
	ErrInvalidProfileProposalID    = errors.New("invalid profile change proposal id")
	ErrSnapshotMetadataStale       = errors.New("profile snapshot metadata is stale")
	ErrSnapshotMetadataFutureDated = errors.New("profile snapshot metadata is future dated")
	ErrProfileSyncModeUnsupported  = errors.New("profile sync mode is unsupported")
	ErrProfileConflictNeedsReview  = errors.New("profile conflict requires future user review")
)

var (
	profileSyncNamePattern        = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$`)
	profileSyncIDPattern          = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,127}$`)
	profileSyncFingerprintPattern = regexp.MustCompile(`^[a-fA-F0-9]{16,128}$`)
)

type ProposalStatus string

const (
	ProposalStatusDraft          ProposalStatus = "draft"
	ProposalStatusPendingReview  ProposalStatus = "pending_review"
	ProposalStatusNeedsUserMerge ProposalStatus = "needs_user_merge"
	ProposalStatusAccepted       ProposalStatus = "accepted"
	ProposalStatusRejected       ProposalStatus = "rejected"
	ProposalStatusDeferred       ProposalStatus = "deferred"
)

type SignedProfileSnapshot struct {
	Metadata  ProfileSnapshotMetadata  `json:"metadata"`
	Signature SnapshotSignatureSummary `json:"signature"`
}

type ProfileSnapshotMetadata struct {
	SchemaVersion       int                `json:"schema_version"`
	ProfileNamespace    string             `json:"profile_namespace"`
	ProfileID           string             `json:"profile_id"`
	SnapshotID          string             `json:"snapshot_id"`
	SnapshotFingerprint string             `json:"snapshot_fingerprint"`
	ParentSnapshotID    string             `json:"parent_snapshot_id,omitempty"`
	SourceDeviceID      string             `json:"source_device_id"`
	HostingMode         ProfileHostingMode `json:"hosting_mode"`
	CreatedAt           time.Time          `json:"created_at"`
	UpdatedAt           time.Time          `json:"updated_at"`
	ExpiresAt           time.Time          `json:"expires_at,omitempty"`
	MetadataVersion     int                `json:"metadata_version"`
}

type ProfileFreshnessSummary struct {
	ProfileNamespace string    `json:"profile_namespace"`
	SnapshotID       string    `json:"snapshot_id"`
	Fresh            bool      `json:"fresh"`
	Stale            bool      `json:"stale"`
	FutureDated      bool      `json:"future_dated"`
	AgeSeconds       int64     `json:"age_seconds"`
	ObservedAt       time.Time `json:"observed_at"`
	ExpiresAt        time.Time `json:"expires_at,omitempty"`
	Message          string    `json:"message,omitempty"`
}

type OfflineProfileBranch struct {
	BranchID         string    `json:"branch_id"`
	ProfileNamespace string    `json:"profile_namespace"`
	ProfileID        string    `json:"profile_id"`
	BaseSnapshotID   string    `json:"base_snapshot_id"`
	HeadSnapshotID   string    `json:"head_snapshot_id"`
	OwnerDeviceID    string    `json:"owner_device_id"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
	Status           string    `json:"status,omitempty"`
}

type ProfileChangeProposal struct {
	ProposalID           string             `json:"proposal_id"`
	ProfileNamespace     string             `json:"profile_namespace"`
	ProfileID            string             `json:"profile_id"`
	BaseSnapshotID       string             `json:"base_snapshot_id"`
	ProposedSnapshotID   string             `json:"proposed_snapshot_id"`
	SourceBranchID       string             `json:"source_branch_id"`
	TargetBranchID       string             `json:"target_branch_id,omitempty"`
	AuthorDeviceID       string             `json:"author_device_id"`
	Status               ProposalStatus     `json:"status"`
	RequestedHostingMode ProfileHostingMode `json:"requested_hosting_mode,omitempty"`
	CreatedAt            time.Time          `json:"created_at"`
	UpdatedAt            time.Time          `json:"updated_at"`
	RequiresUserReview   bool               `json:"requires_user_review"`
	Conflicts            []ConflictSummary  `json:"conflicts,omitempty"`
	MergePlan            MergePlan          `json:"merge_plan,omitempty"`
}

type ConflictSummary struct {
	ConflictID         string `json:"conflict_id"`
	ResourceID         string `json:"resource_id,omitempty"`
	ResourceType       string `json:"resource_type,omitempty"`
	Summary            string `json:"summary,omitempty"`
	RequiresUserReview bool   `json:"requires_user_review"`
	SafeFailureCode    string `json:"safe_failure_code,omitempty"`
}

type MergePlan struct {
	PlanID             string `json:"plan_id,omitempty"`
	Strategy           string `json:"strategy,omitempty"`
	Status             string `json:"status,omitempty"`
	FutureOnly         bool   `json:"future_only"`
	RequiresUserReview bool   `json:"requires_user_review"`
	Summary            string `json:"summary,omitempty"`
}

type SnapshotSignatureSummary struct {
	SignerDeviceID             string    `json:"signer_device_id"`
	SignerKeyFingerprint       string    `json:"signer_key_fingerprint,omitempty"`
	SignatureFingerprint       string    `json:"signature_fingerprint,omitempty"`
	Algorithm                  string    `json:"algorithm,omitempty"`
	SignedAt                   time.Time `json:"signed_at,omitempty"`
	DeviceTrustValidationState string    `json:"device_trust_validation_state,omitempty"`
}

type SnapshotValidationResult struct {
	Valid     bool                    `json:"valid"`
	Freshness ProfileFreshnessSummary `json:"freshness"`
	Issues    []ProfileSyncIssue      `json:"issues,omitempty"`
}

type ProposalValidationResult struct {
	Valid              bool               `json:"valid"`
	Status             ProposalStatus     `json:"status"`
	RequiresUserReview bool               `json:"requires_user_review"`
	Conflicts          []ConflictSummary  `json:"conflicts,omitempty"`
	Issues             []ProfileSyncIssue `json:"issues,omitempty"`
}

type ProfileSyncIssue struct {
	Code     string `json:"code"`
	Message  string `json:"message"`
	Blocking bool   `json:"blocking"`
}

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
	if !metadata.ExpiresAt.IsZero() && metadata.ExpiresAt.Before(now.Add(-DefaultSnapshotClockSkew)) {
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
	if !validProfileSyncDeviceID(snapshot.Signature.SignerDeviceID) {
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
	if !validProfileSyncDeviceID(proposal.AuthorDeviceID) {
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
		if !validProfileSyncDeviceID(branch.OwnerDeviceID) {
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
	if !validProfileSyncDeviceID(metadata.SourceDeviceID) {
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
	return profileSyncNamePattern.MatchString(s) && !strings.Contains(s, "..") && !strings.ContainsAny(s, `/\`) && !profileSyncReservedName(s) && !unsafeProfileSyncDetail(s)
}

func validProfileSyncDeviceID(s string) bool {
	return validProfileSyncID(s)
}

func validProfileSyncID(s string) bool {
	s = strings.TrimSpace(s)
	return profileSyncIDPattern.MatchString(s) && !strings.Contains(s, "..") && !strings.ContainsAny(s, `/\`) && !unsafeProfileSyncDetail(s)
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

func profileSyncReservedName(s string) bool {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9":
		return true
	default:
		return false
	}
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
