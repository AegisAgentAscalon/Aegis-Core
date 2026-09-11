package profilesync

import (
	"context"
	"errors"
	"regexp"
	"time"

	"github.com/AegisAgentAscalon/aegis-core/pkg/profilemesh"
	"github.com/AegisAgentAscalon/aegis-core/pkg/relay"
)

const (
	EnvelopeSchemaVersion      = 1
	DefaultEnvelopeTTL         = 5 * time.Minute
	defaultClockSkew           = 2 * time.Minute
	deterministicMailboxDomain = "aegis.profilesync.mailbox.v1"
)

var (
	ErrDisabled             = errors.New("profile sync is disabled")
	ErrInvalidConfig        = errors.New("invalid profile sync config")
	ErrNoRelayProvider      = errors.New("profile sync relay transport is not configured")
	ErrTransportUnavailable = errors.New("profile sync transport unavailable")
	ErrStoreUnavailable     = errors.New("profile sync store unavailable")
	ErrInvalidSyncEnvelope  = errors.New("invalid profile sync envelope")
	ErrSnapshotRejected     = errors.New("profile snapshot metadata rejected")
	ErrProposalRejected     = errors.New("profile proposal metadata rejected")
	ErrDuplicateSnapshot    = errors.New("duplicate profile snapshot metadata")
	ErrDuplicateProposal    = errors.New("duplicate profile proposal metadata")
	ErrTrustVerification    = errors.New("profile sync trust verification required")
	ErrConflictReview       = errors.New("profile sync conflict requires review")
	ErrMultiHostUnsupported = errors.New("profile sync multi-host merge is unsupported")
	ErrLocalStoreCorrupt    = errors.New("profile sync local metadata store is corrupt")
	ErrLocalStoreNotFound   = errors.New("profile sync local metadata record is not available")
	ErrReceiveOnlyTransport = errors.New("profile sync relay transport is receive-only")
)

var syncNamePattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$`)

var syncIDPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,127}$`)

type Clock interface {
	Now() time.Time
}

type SyncConfig struct {
	Enabled          bool
	ProfileNamespace string
	LocalDeviceID    string
}

type EnvelopeKind string

const (
	EnvelopeKindSnapshot EnvelopeKind = "profile_snapshot_metadata"
	EnvelopeKindProposal EnvelopeKind = "profile_proposal_metadata"
)

type TrustState string

const (
	TrustPending   TrustState = "pending"
	TrustTrusted   TrustState = "trusted"
	TrustUntrusted TrustState = "untrusted"
)

type SyncIssue struct {
	Code     string `json:"code"`
	Message  string `json:"message"`
	Blocking bool   `json:"blocking"`
}

type SyncStatus struct {
	Enabled             bool        `json:"enabled"`
	Available           bool        `json:"available"`
	ProfileNamespace    string      `json:"profile_namespace,omitempty"`
	LocalSnapshotID     string      `json:"local_snapshot_id,omitempty"`
	RemoteSnapshotCount int         `json:"remote_snapshot_count"`
	RemoteProposalCount int         `json:"remote_proposal_count"`
	ReviewRequired      bool        `json:"review_required"`
	LastExchangeAt      time.Time   `json:"last_exchange_at,omitempty"`
	Summary             string      `json:"summary,omitempty"`
	Issues              []SyncIssue `json:"issues,omitempty"`
}

type SyncPlan struct {
	Enabled              bool        `json:"enabled"`
	ProfileNamespace     string      `json:"profile_namespace,omitempty"`
	LocalSnapshotID      string      `json:"local_snapshot_id,omitempty"`
	LocalProposalCount   int         `json:"local_proposal_count"`
	RemoteSnapshotCount  int         `json:"remote_snapshot_count"`
	RemoteProposalCount  int         `json:"remote_proposal_count"`
	TransportAvailable   bool        `json:"transport_available"`
	ConflictReviewNeeded bool        `json:"conflict_review_needed"`
	PlannedAt            time.Time   `json:"planned_at"`
	Issues               []SyncIssue `json:"issues,omitempty"`
}

type SyncSession struct {
	SessionID        string    `json:"session_id"`
	ProfileNamespace string    `json:"profile_namespace"`
	LocalDeviceID    string    `json:"local_device_id"`
	StartedAt        time.Time `json:"started_at"`
	CompletedAt      time.Time `json:"completed_at,omitempty"`
	ReviewRequired   bool      `json:"review_required"`
}

type PushResult struct {
	PushedSnapshots int                     `json:"pushed_snapshots"`
	PushedProposals int                     `json:"pushed_proposals"`
	Receipts        []relay.DeliveryReceipt `json:"receipts,omitempty"`
	Issues          []SyncIssue             `json:"issues,omitempty"`
}

type PullResult struct {
	ReceivedSnapshots int         `json:"received_snapshots"`
	ReceivedProposals int         `json:"received_proposals"`
	Rejected          int         `json:"rejected"`
	ReviewRequired    bool        `json:"review_required"`
	Issues            []SyncIssue `json:"issues,omitempty"`
}

type ExchangeResult struct {
	Session        SyncSession `json:"session"`
	Push           PushResult  `json:"push"`
	Pull           PullResult  `json:"pull"`
	Status         SyncStatus  `json:"status"`
	ReviewRequired bool        `json:"review_required"`
	Issues         []SyncIssue `json:"issues,omitempty"`
}

type LocalSnapshotRecord struct {
	Snapshot   profilemesh.SignedProfileSnapshot `json:"snapshot"`
	ExportedAt time.Time                         `json:"exported_at"`
}

type RemoteSnapshotRecord struct {
	Snapshot       profilemesh.SignedProfileSnapshot   `json:"snapshot"`
	ReceivedAt     time.Time                           `json:"received_at"`
	TrustState     TrustState                          `json:"trust_state"`
	RequiresReview bool                                `json:"requires_review"`
	Freshness      profilemesh.ProfileFreshnessSummary `json:"freshness"`
}

type RemoteProposalRecord struct {
	Proposal       profilemesh.ProfileChangeProposal `json:"proposal"`
	ReceivedAt     time.Time                         `json:"received_at"`
	TrustState     TrustState                        `json:"trust_state"`
	RequiresReview bool                              `json:"requires_review"`
}

type SnapshotStore interface {
	LoadLocalSnapshot(ctx context.Context) (profilemesh.SignedProfileSnapshot, error)
	SaveRemoteSnapshot(ctx context.Context, record RemoteSnapshotRecord) error
	ListRemoteSnapshots(ctx context.Context) ([]RemoteSnapshotRecord, error)
}

type ProposalStore interface {
	LoadLocalProposals(ctx context.Context) ([]profilemesh.ProfileChangeProposal, error)
	SaveRemoteProposal(ctx context.Context, record RemoteProposalRecord) error
	ListRemoteProposals(ctx context.Context) ([]RemoteProposalRecord, error)
}

type TrustVerifier interface {
	VerifySigner(ctx context.Context, signerDeviceID, signerKeyFingerprint string) TrustDecision
}

type TrustDecision struct {
	Trusted bool
	Pending bool
	Code    string
	Message string
}

type SyncTransport interface {
	GetStatus(ctx context.Context) SyncTransportStatus
	PushEnvelope(ctx context.Context, envelope SyncEnvelope) (relay.DeliveryReceipt, error)
	PullEnvelopes(ctx context.Context) ([]SyncEnvelope, error)
}

type SyncTransportStatus struct {
	Available         bool        `json:"available"`
	ProviderAvailable bool        `json:"provider_available"`
	PushAvailable     bool        `json:"push_available"`
	PullAvailable     bool        `json:"pull_available"`
	ProviderID        string      `json:"provider_id,omitempty"`
	Summary           string      `json:"summary,omitempty"`
	Issues            []SyncIssue `json:"issues,omitempty"`
}

// RelaySyncDiagnostics is a redacted capability view of a relay-backed Profile
// Sync transport. It intentionally omits namespace, device, mailbox, target,
// credential, payload, and signature values.
type RelaySyncDiagnostics struct {
	Available               bool        `json:"available"`
	ProviderAvailable       bool        `json:"provider_available"`
	SendConfigured          bool        `json:"send_configured"`
	ReceiveConfigured       bool        `json:"receive_configured"`
	SendAvailable           bool        `json:"send_available"`
	ReceiveAvailable        bool        `json:"receive_available"`
	ReceiveOnly             bool        `json:"receive_only"`
	ProviderID              string      `json:"provider_id,omitempty"`
	MailboxExpiresAtRFC3339 string      `json:"mailbox_expires_at_rfc3339,omitempty"`
	MessageTTLSeconds       int64       `json:"message_ttl_seconds,omitempty"`
	MaximumPayloadBytes     int         `json:"maximum_payload_bytes"`
	Summary                 string      `json:"summary,omitempty"`
	Issues                  []SyncIssue `json:"issues,omitempty"`
}

type SyncEnvelope struct {
	SchemaVersion    int                                `json:"schema_version"`
	Kind             EnvelopeKind                       `json:"kind"`
	ProfileNamespace string                             `json:"profile_namespace"`
	SourceDeviceID   string                             `json:"source_device_id"`
	MessageID        string                             `json:"message_id"`
	CreatedAt        time.Time                          `json:"created_at"`
	Snapshot         *profilemesh.SignedProfileSnapshot `json:"snapshot,omitempty"`
	Proposal         *profilemesh.ProfileChangeProposal `json:"proposal,omitempty"`
}

type proposalReviewClassification struct {
	duplicate      bool
	requiresReview bool
	issues         []SyncIssue
}
