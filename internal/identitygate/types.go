package identitygate

import (
	"context"
	"time"
)

type AssuranceLevel string

const (
	AssuranceAnonymous         AssuranceLevel = "anonymous"
	AssuranceClaimed           AssuranceLevel = "claimed"
	AssuranceRecognizedProfile AssuranceLevel = "recognized_profile"
	AssuranceKnownDevice       AssuranceLevel = "known_device"
	AssuranceVerified          AssuranceLevel = "verified"
	AssuranceFreshVerified     AssuranceLevel = "fresh_verified"
	AssuranceLocked            AssuranceLevel = "locked"
)

type OperatorAssurance string

const (
	OperatorUnknown       OperatorAssurance = "operator_unknown"
	OperatorClaimed       OperatorAssurance = "operator_claimed"
	OperatorRecognized    OperatorAssurance = "operator_recognized"
	OperatorKnownDevice   OperatorAssurance = "operator_known_device"
	OperatorVerified      OperatorAssurance = "operator_verified"
	OperatorFreshVerified OperatorAssurance = "operator_fresh_verified"
	OperatorLocked        OperatorAssurance = "operator_locked"
)

type Scope string

const (
	ScopePublic                    Scope = "public"
	ScopePublicChat                Scope = "public_chat"
	ScopeProfileLight              Scope = "profile_light"
	ScopeUserPrivateMemory         Scope = "user_private_memory"
	ScopePrivateMemoryRead         Scope = "private_memory_read"
	ScopeProjectPrivate            Scope = "project_private"
	ScopePrivateMemoryWrite        Scope = "private_memory_write"
	ScopeRelationshipPrivate       Scope = "relationship_private"
	ScopeAgentIdentityVault        Scope = "agent_identity_vault"
	ScopeIdentityContinuityPrivate Scope = "identity_continuity_private"
	ScopeIntimatePrivate           Scope = "intimate_private"
	ScopeSecurityAdmin             Scope = "security_admin"
	ScopeModelForge                Scope = "model_forge"
	ScopeTrainingLineage           Scope = "training_lineage"
	ScopeVaultExport               Scope = "vault_export"
	ScopePrivateMemoryExport       Scope = "private_memory_export"
)

type PromptSourceClass string

const (
	SourceSystemPolicy       PromptSourceClass = "system_policy"
	SourceDeveloperPolicy    PromptSourceClass = "developer_policy"
	SourceAegisCorePolicy    PromptSourceClass = "aegis_core_policy"
	SourceVerifiedOperator   PromptSourceClass = "verified_operator"
	SourceCurrentUserMessage PromptSourceClass = "current_user_message"
	SourceTrustedMemory      PromptSourceClass = "trusted_memory"
	SourceUntrustedMemory    PromptSourceClass = "untrusted_memory"
	SourceRetrievedDocument  PromptSourceClass = "retrieved_document"
	SourceWebContent         PromptSourceClass = "web_content"
	SourceEmail              PromptSourceClass = "email"
	SourceToolOutput         PromptSourceClass = "tool_output"
	SourceModelOutput        PromptSourceClass = "model_output"
	SourceUnknown            PromptSourceClass = "unknown"
)

type SourceTrustLevel string

const (
	SourceTrustTrusted   SourceTrustLevel = "trusted"
	SourceTrustBounded   SourceTrustLevel = "bounded"
	SourceTrustUntrusted SourceTrustLevel = "untrusted"
)

type RecognitionFeatures struct {
	Aliases      []string          `json:"aliases,omitempty"`
	Topics       []string          `json:"topics,omitempty"`
	StyleSummary string            `json:"style_summary,omitempty"`
	SafeMetadata map[string]string `json:"safe_metadata,omitempty"`
}

type UserProfile struct {
	UserID              string              `json:"user_id"`
	DisplayName         string              `json:"display_name"`
	RecognitionFeatures RecognitionFeatures `json:"recognition_features,omitempty"`
}

type VerificationCadencePolicy struct {
	VerifiedWindow             time.Duration
	FreshWindow                time.Duration
	IdleTimeout                time.Duration
	MaxVerifiedWindow          time.Duration
	MaxFreshWindow             time.Duration
	PublicChatRequiresAuth     bool
	ProfileLightRequiresAuth   bool
	SlidingVerifiedWindow      bool
	SlidingFreshWindow         bool
	BurnFreshAfterSensitiveUse bool
}

type IdentitySession struct {
	SessionID              string
	AccountUserID          string
	ClaimedUserID          string
	RecognizedUserID       string
	VerifiedUserID         string
	VerifiedOperatorUserID string
	AssuranceLevel         AssuranceLevel
	OperatorAssurance      OperatorAssurance
	AccountAuthenticated   bool
	TrustedDevice          bool
	ReauthRequired         bool
	VerifiedAt             time.Time
	VerifiedUntil          time.Time
	FreshVerifiedAt        time.Time
	FreshUntil             time.Time
	LastActiveAt           time.Time
	IdleTimeoutAt          time.Time
	VerificationEpoch      uint64
	ReauthReason           string
	AllowedScopes          []Scope
	LockReason             string
}

type RecognitionResult struct {
	CandidateUserID      string
	Confidence           float64
	MatchedSignals       []string
	RiskFlags            []string
	RequiresVerification bool
	Explanation          string
}

// VerificationResult is the legacy provider result.
//
// Deprecated: providers should return VerificationReceipt instead.
type VerificationResult struct {
	UserID     string
	Verified   bool
	Fresh      bool
	VerifiedAt time.Time
	ExpiresAt  time.Time
	Provider   string
}

// VerificationRequest is the safe, session-bound challenge sent to a receipt
// provider. It intentionally carries no captured material or provider payload.
type VerificationRequest struct {
	AttemptID         string    `json:"attempt_id"`
	AssertionID       string    `json:"assertion_id"`
	SessionID         string    `json:"session_id"`
	VerificationEpoch uint64    `json:"verification_epoch"`
	SubjectUserID     string    `json:"subject_user_id"`
	Reason            string    `json:"reason,omitempty"`
	FreshRequired     bool      `json:"fresh_required"`
	RequestedAt       time.Time `json:"requested_at"`
	ExpiresAt         time.Time `json:"expires_at"`
}

// VerificationReceipt is the safe result accepted from a configured provider.
// Identifiers are opaque references only; raw evidence must remain provider-side.
type VerificationReceipt struct {
	ReceiptID     string    `json:"receipt_id"`
	AttemptID     string    `json:"attempt_id"`
	AssertionID   string    `json:"assertion_id"`
	SessionID     string    `json:"session_id"`
	SubjectUserID string    `json:"subject_user_id"`
	Provider      string    `json:"provider"`
	Verified      bool      `json:"verified"`
	Fresh         bool      `json:"fresh"`
	VerifiedAt    time.Time `json:"verified_at"`
	ExpiresAt     time.Time `json:"expires_at"`
}

type SessionSignals struct {
	ClaimedUserID string
	Aliases       []string
	Topics        []string
	DeviceKnown   bool
	AccountUserID string
}

type PromptFragment struct {
	FragmentID           string
	SourceClass          PromptSourceClass
	SourceTrust          SourceTrustLevel
	OperatorVerified     bool
	AllowedAsInstruction bool
	AllowedAsData        bool
	RequestedScopes      []Scope
	GrantedScopes        []Scope
	CreatedAt            time.Time
	ExpiresAt            time.Time
	Content              string
	SafetyLabels         []string
	ProvenanceSummary    string
}

type ModelIdentityPacket struct {
	AssuranceLevel            AssuranceLevel
	OperatorAssurance         OperatorAssurance
	VerifiedUserID            string
	RecognizedUserID          string
	AllowedScopes             []Scope
	ReauthRequired            bool
	ReauthReason              string
	VerificationAgeSeconds    int64
	FreshAgeSeconds           int64
	IdentityPolicySummary     string
	PromptSourcePolicySummary string
	UntrustedSourcesPresent   bool
}

type AuditEvent struct {
	Kind      string
	Summary   string
	CreatedAt time.Time
}

type Clock interface{ Now() time.Time }

type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }

// IdentityVerificationProvider is the legacy verification contract.
//
// Deprecated: implement VerificationReceiptProvider for new integrations.
type IdentityVerificationProvider interface {
	CanVerify(context.Context, string) bool
	RequestVerification(context.Context, string, string) (VerificationResult, error)
	RequestFreshVerification(context.Context, string, string) (VerificationResult, error)
	ProviderName() string
}

// VerificationReceiptProvider performs provider-owned verification and returns
// only an opaque, session-bound receipt. Implementations must keep all captured
// evidence and credentials outside these request and receipt values.
type VerificationReceiptProvider interface {
	Verify(context.Context, VerificationRequest) (VerificationReceipt, error)
	ProviderName() string
}

type AuditSink interface {
	Record(context.Context, AuditEvent) error
}

type Config struct {
	SessionID       string
	CadencePolicy   VerificationCadencePolicy
	ReceiptProvider VerificationReceiptProvider
	// VerificationProvider preserves the original provider integration surface.
	// Deprecated: use ReceiptProvider.
	VerificationProvider IdentityVerificationProvider
	Clock                Clock
	AuditSink            AuditSink
}
