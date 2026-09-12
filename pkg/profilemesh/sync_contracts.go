package profilemesh

import (
	"errors"
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
