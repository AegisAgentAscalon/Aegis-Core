// Package profilesync orchestrates Profile Mesh metadata snapshot/proposal
// exchange over optional untrusted transports. It does not store profile data
// content, perform cloud sync, or auto-merge profile conflicts.
package profilesync

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/AegisAgentAscalon/aegis-core/pkg/profilemesh"
	"github.com/AegisAgentAscalon/aegis-core/pkg/relay"
)

const (
	EnvelopeSchemaVersion             = 1
	DefaultEnvelopeTTL                = 5 * time.Minute
	MaxEnvelopeSignatureEvidenceBytes = 4 * 1024
	defaultClockSkew                  = 2 * time.Minute
	deterministicMailboxDomain        = "aegis.profilesync.mailbox.v1"
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

type Option func(*options)

type options struct {
	snapshots SnapshotStore
	proposals ProposalStore
	transport SyncTransport
	trust     TrustVerifier
	clock     Clock
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
	Available  bool        `json:"available"`
	ProviderID string      `json:"provider_id,omitempty"`
	Summary    string      `json:"summary,omitempty"`
	Issues     []SyncIssue `json:"issues,omitempty"`
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
	MaximumSignatureBytes   int         `json:"maximum_signature_bytes"`
	Summary                 string      `json:"summary,omitempty"`
	Issues                  []SyncIssue `json:"issues,omitempty"`
}

// EnvelopeSignatureEvidence preserves caller-owned opaque signature bytes as
// bounded metadata. Profile Sync does not verify, trust, execute, or persist it.
type EnvelopeSignatureEvidence struct {
	Algorithm string `json:"algorithm"`
	KeyID     string `json:"key_id,omitempty"`
	Signature []byte `json:"signature"`
}

type SyncEnvelope struct {
	SchemaVersion     int                                `json:"schema_version"`
	Kind              EnvelopeKind                       `json:"kind"`
	ProfileNamespace  string                             `json:"profile_namespace"`
	SourceDeviceID    string                             `json:"source_device_id"`
	MessageID         string                             `json:"message_id"`
	CreatedAt         time.Time                          `json:"created_at"`
	SignatureEvidence *EnvelopeSignatureEvidence         `json:"signature_evidence,omitempty"`
	Snapshot          *profilemesh.SignedProfileSnapshot `json:"snapshot,omitempty"`
	Proposal          *profilemesh.ProfileChangeProposal `json:"proposal,omitempty"`
}

type RelaySyncTransportConfig struct {
	Provider        relay.RelayProvider
	Namespace       string
	SourceDeviceID  string
	TargetDeviceID  string
	TargetMailboxID string
	Mailbox         relay.MailboxRef
	MessageTTL      time.Duration
	MaxPayloadBytes int
	Clock           Clock
}

type RelaySyncTransport struct {
	cfg RelaySyncTransportConfig
}

type SyncManager struct {
	cfg       SyncConfig
	snapshots SnapshotStore
	proposals ProposalStore
	transport SyncTransport
	trust     TrustVerifier
	clock     Clock
	lastMu    sync.Mutex
	last      time.Time
}

func WithSnapshotStore(store SnapshotStore) Option {
	return func(opts *options) {
		opts.snapshots = store
	}
}

func WithProposalStore(store ProposalStore) Option {
	return func(opts *options) {
		opts.proposals = store
	}
}

func WithTransport(transport SyncTransport) Option {
	return func(opts *options) {
		opts.transport = transport
	}
}

func WithTrustVerifier(verifier TrustVerifier) Option {
	return func(opts *options) {
		opts.trust = verifier
	}
}

func WithClock(clock Clock) Option {
	return func(opts *options) {
		opts.clock = clock
	}
}

func NewSyncManager(config SyncConfig, opts ...Option) (*SyncManager, error) {
	parsed := options{}
	for _, opt := range opts {
		if opt != nil {
			opt(&parsed)
		}
	}
	if config.Enabled && !validSyncName(config.ProfileNamespace) {
		return nil, ErrInvalidConfig
	}
	if config.Enabled && !validSyncID(config.LocalDeviceID) {
		return nil, ErrInvalidConfig
	}
	return &SyncManager{cfg: config, snapshots: parsed.snapshots, proposals: parsed.proposals, transport: parsed.transport, trust: parsed.trust, clock: parsed.clock}, nil
}

func NewRelaySyncTransport(config RelaySyncTransportConfig) (*RelaySyncTransport, error) {
	if config.Provider == nil {
		return nil, ErrNoRelayProvider
	}
	if !validExactSyncName(config.Namespace) || !validExactSyncID(config.SourceDeviceID) {
		return nil, ErrInvalidConfig
	}
	hasSendTarget := config.TargetDeviceID != "" || config.TargetMailboxID != ""
	hasReceiveMailbox := config.Mailbox.MailboxID != ""
	if !hasSendTarget && !hasReceiveMailbox {
		return nil, ErrInvalidConfig
	}
	if config.TargetDeviceID != "" && !validExactSyncID(config.TargetDeviceID) {
		return nil, ErrInvalidConfig
	}
	if config.TargetMailboxID != "" && relay.ValidateMailboxID(config.TargetMailboxID) != nil {
		return nil, ErrInvalidConfig
	}
	if hasReceiveMailbox {
		if err := relay.ValidateMailboxRef(config.Mailbox); err != nil {
			return nil, ErrInvalidConfig
		}
		if config.Mailbox.Namespace != config.Namespace || config.Mailbox.OwnerDeviceID != config.SourceDeviceID {
			return nil, ErrInvalidConfig
		}
	}
	return &RelaySyncTransport{cfg: config}, nil
}

// NewReceiveOnlyRelaySyncTransport constructs a mailbox-backed transport that
// can pull Profile Sync envelopes without requiring a placeholder send target.
func NewReceiveOnlyRelaySyncTransport(config RelaySyncTransportConfig) (*RelaySyncTransport, error) {
	if config.TargetDeviceID != "" || config.TargetMailboxID != "" || config.Mailbox.MailboxID == "" {
		return nil, ErrInvalidConfig
	}
	return NewRelaySyncTransport(config)
}

// DeterministicRelayMailboxID returns a stable, domain-separated mailbox ID.
// The digest isolates namespaces and owner devices without exposing either one.
func DeterministicRelayMailboxID(namespace, ownerDeviceID string) (string, error) {
	if !validExactSyncName(namespace) || !validExactSyncID(ownerDeviceID) {
		return "", ErrInvalidConfig
	}
	sum := sha256.Sum256([]byte(deterministicMailboxDomain + "\x00" + namespace + "\x00" + ownerDeviceID))
	mailboxID := "profilesync-" + hex.EncodeToString(sum[:])
	if err := relay.ValidateMailboxID(mailboxID); err != nil {
		return "", ErrInvalidConfig
	}
	return mailboxID, nil
}

// FormatStatusTimeRFC3339 converts a status timestamp to a browser-safe UTC
// RFC 3339 string. Zero timestamps remain absent.
func FormatStatusTimeRFC3339(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.UTC().Format(time.RFC3339Nano)
}

func (m *SyncManager) BuildStatus(ctx context.Context) SyncStatus {
	if m == nil || !m.cfg.Enabled {
		return SyncStatus{Enabled: false, Available: false, Summary: "profile sync is disabled"}
	}
	status := SyncStatus{Enabled: true, ProfileNamespace: m.cfg.ProfileNamespace, Available: true, Summary: "profile sync metadata orchestration is available", LastExchangeAt: m.lastExchangeAt()}
	if !validSyncName(m.cfg.ProfileNamespace) || !validSyncID(m.cfg.LocalDeviceID) {
		status.Available = false
		status.Issues = append(status.Issues, syncIssue("invalid_config", ErrInvalidConfig.Error(), true))
	}
	if m.snapshots == nil {
		status.Available = false
		status.Issues = append(status.Issues, syncIssue("snapshot_store_missing", ErrStoreUnavailable.Error(), true))
	} else {
		if local, err := m.snapshots.LoadLocalSnapshot(ctx); err != nil {
			status.Available = false
			status.Issues = append(status.Issues, syncIssue("snapshot_store_unavailable", ErrStoreUnavailable.Error(), true))
		} else {
			status.LocalSnapshotID = local.Metadata.SnapshotID
			issues, reviewRequired, blocking := classifyLocalSnapshot(local, m.now())
			status.Issues = append(status.Issues, issues...)
			if reviewRequired {
				status.ReviewRequired = true
			}
			if blocking {
				status.Available = false
			}
		}
		if remotes, err := m.snapshots.ListRemoteSnapshots(ctx); err != nil {
			status.Available = false
			status.Issues = append(status.Issues, syncIssue("remote_snapshot_store_unavailable", ErrStoreUnavailable.Error(), true))
		} else {
			status.RemoteSnapshotCount = len(remotes)
			for _, record := range remotes {
				if record.RequiresReview {
					status.ReviewRequired = true
				}
			}
		}
	}
	if m.proposals != nil {
		if proposals, err := m.proposals.ListRemoteProposals(ctx); err != nil {
			status.Available = false
			status.Issues = append(status.Issues, syncIssue("remote_proposal_store_unavailable", ErrStoreUnavailable.Error(), true))
		} else {
			status.RemoteProposalCount = len(proposals)
			for _, record := range proposals {
				if record.RequiresReview {
					status.ReviewRequired = true
				}
			}
		}
	}
	if m.transport == nil {
		status.Available = false
		status.Issues = append(status.Issues, syncIssue("transport_missing", ErrNoRelayProvider.Error(), false))
	} else {
		transportStatus := m.transport.GetStatus(ctx)
		if !transportStatus.Available {
			status.Available = false
			status.Issues = append(status.Issues, syncIssue("transport_unavailable", ErrTransportUnavailable.Error(), false))
		}
	}
	if status.ReviewRequired {
		status.Issues = append(status.Issues, syncIssue("conflict_review_required", ErrConflictReview.Error(), false))
	}
	if !status.Available {
		status.Summary = "profile sync metadata orchestration is degraded"
	} else if status.ReviewRequired {
		status.Summary = "profile sync metadata orchestration requires review"
	}
	return status
}

func (m *SyncManager) BuildSyncPlan(ctx context.Context) (SyncPlan, error) {
	if m == nil || !m.cfg.Enabled {
		return SyncPlan{Enabled: false, PlannedAt: time.Now().UTC(), Issues: []SyncIssue{syncIssue("sync_disabled", ErrDisabled.Error(), false)}}, nil
	}
	now := m.now()
	plan := SyncPlan{Enabled: true, ProfileNamespace: m.cfg.ProfileNamespace, PlannedAt: now}
	if err := m.ensureReadyForStoreOnly(); err != nil {
		plan.Issues = append(plan.Issues, syncIssue("invalid_config", err.Error(), true))
		return plan, err
	}
	local, err := m.snapshots.LoadLocalSnapshot(ctx)
	if err != nil {
		plan.Issues = append(plan.Issues, syncIssue("snapshot_store_unavailable", ErrStoreUnavailable.Error(), true))
		return plan, ErrStoreUnavailable
	}
	plan.LocalSnapshotID = local.Metadata.SnapshotID
	issues, reviewRequired, blocking := classifyLocalSnapshot(local, now)
	plan.Issues = append(plan.Issues, issues...)
	if reviewRequired {
		plan.ConflictReviewNeeded = true
	}
	if blocking {
		return plan, ErrSnapshotRejected
	}
	if m.proposals != nil {
		proposals, err := m.proposals.LoadLocalProposals(ctx)
		if err != nil {
			plan.Issues = append(plan.Issues, syncIssue("proposal_store_unavailable", ErrStoreUnavailable.Error(), true))
			return plan, ErrStoreUnavailable
		}
		plan.LocalProposalCount = len(proposals)
	}
	remotes, err := m.snapshots.ListRemoteSnapshots(ctx)
	if err != nil {
		plan.Issues = append(plan.Issues, syncIssue("remote_snapshot_store_unavailable", ErrStoreUnavailable.Error(), true))
		return plan, ErrStoreUnavailable
	}
	plan.RemoteSnapshotCount = len(remotes)
	for _, record := range remotes {
		if record.RequiresReview {
			plan.ConflictReviewNeeded = true
		}
	}
	if m.proposals != nil {
		remoteProposals, err := m.proposals.ListRemoteProposals(ctx)
		if err != nil {
			plan.Issues = append(plan.Issues, syncIssue("remote_proposal_store_unavailable", ErrStoreUnavailable.Error(), true))
			return plan, ErrStoreUnavailable
		}
		plan.RemoteProposalCount = len(remoteProposals)
		for _, record := range remoteProposals {
			if record.RequiresReview {
				plan.ConflictReviewNeeded = true
			}
		}
	}
	if m.transport == nil {
		plan.Issues = append(plan.Issues, syncIssue("offline_transport_missing", ErrNoRelayProvider.Error(), false))
	} else {
		transportStatus := m.transport.GetStatus(ctx)
		plan.TransportAvailable = transportStatus.Available
		if !transportStatus.Available {
			plan.Issues = append(plan.Issues, syncIssue("offline_transport_unavailable", ErrTransportUnavailable.Error(), false))
		}
	}
	if plan.ConflictReviewNeeded {
		plan.Issues = append(plan.Issues, syncIssue("conflict_review_required", ErrConflictReview.Error(), false))
	}
	return plan, nil
}

func (m *SyncManager) PushLocalSnapshot(ctx context.Context) (PushResult, error) {
	result := PushResult{}
	if err := m.ensureReadyForExchange(); err != nil {
		result.Issues = append(result.Issues, syncIssue("sync_not_ready", err.Error(), true))
		return result, err
	}
	snapshot, err := m.snapshots.LoadLocalSnapshot(ctx)
	if err != nil {
		result.Issues = append(result.Issues, syncIssue("snapshot_store_unavailable", ErrStoreUnavailable.Error(), true))
		return result, ErrStoreUnavailable
	}
	validation := profilemesh.ValidateSignedProfileSnapshot(snapshot, m.now())
	if snapshot.Metadata.ProfileNamespace != m.cfg.ProfileNamespace || !validation.Valid {
		result.Issues = append(result.Issues, fromProfileIssues(validation.Issues)...)
		if snapshot.Metadata.ProfileNamespace != m.cfg.ProfileNamespace {
			result.Issues = append(result.Issues, syncIssue("invalid_profile_namespace", profilemesh.ErrInvalidProfileNamespace.Error(), true))
		}
		return result, ErrSnapshotRejected
	}
	envelope := snapshotEnvelope(m.cfg.ProfileNamespace, m.cfg.LocalDeviceID, snapshot, m.now())
	receipt, err := m.transport.PushEnvelope(ctx, envelope)
	if err != nil {
		result.Issues = append(result.Issues, syncIssue("transport_unavailable", ErrTransportUnavailable.Error(), true))
		return result, ErrTransportUnavailable
	}
	result.PushedSnapshots = 1
	result.Receipts = append(result.Receipts, sanitizeReceipt(receipt))
	m.recordExchange()
	return result, nil
}

func (m *SyncManager) PushLocalProposals(ctx context.Context) (PushResult, error) {
	result := PushResult{}
	if err := m.ensureReadyForExchange(); err != nil {
		result.Issues = append(result.Issues, syncIssue("sync_not_ready", err.Error(), true))
		return result, err
	}
	if m.proposals == nil {
		return result, nil
	}
	proposals, err := m.proposals.LoadLocalProposals(ctx)
	if err != nil {
		result.Issues = append(result.Issues, syncIssue("proposal_store_unavailable", ErrStoreUnavailable.Error(), true))
		return result, ErrStoreUnavailable
	}
	seen := map[string]bool{}
	for _, proposal := range proposals {
		if seen[proposal.ProposalID] {
			result.Issues = append(result.Issues, syncIssue("duplicate_proposal_id", ErrDuplicateProposal.Error(), false))
			continue
		}
		seen[proposal.ProposalID] = true
		validation := profilemesh.ValidateProfileChangeProposal(proposal, m.now())
		if proposal.ProfileNamespace != m.cfg.ProfileNamespace || !validation.Valid {
			result.Issues = append(result.Issues, fromProfileIssues(validation.Issues)...)
			if proposal.ProfileNamespace != m.cfg.ProfileNamespace {
				result.Issues = append(result.Issues, syncIssue("invalid_profile_namespace", profilemesh.ErrInvalidProfileNamespace.Error(), true))
			}
			continue
		}
		receipt, err := m.transport.PushEnvelope(ctx, proposalEnvelope(m.cfg.ProfileNamespace, m.cfg.LocalDeviceID, proposal, m.now()))
		if err != nil {
			result.Issues = append(result.Issues, syncIssue("transport_unavailable", ErrTransportUnavailable.Error(), true))
			return result, ErrTransportUnavailable
		}
		result.PushedProposals++
		result.Receipts = append(result.Receipts, sanitizeReceipt(receipt))
	}
	m.recordExchange()
	return result, nil
}

func (m *SyncManager) PullRemote(ctx context.Context) (PullResult, error) {
	result := PullResult{}
	if err := m.ensureReadyForExchange(); err != nil {
		result.Issues = append(result.Issues, syncIssue("sync_not_ready", err.Error(), true))
		return result, err
	}
	envelopes, err := m.transport.PullEnvelopes(ctx)
	if err != nil {
		if errors.Is(err, ErrInvalidSyncEnvelope) {
			result.Issues = append(result.Issues, syncIssue("invalid_envelope", ErrInvalidSyncEnvelope.Error(), true))
			return result, ErrInvalidSyncEnvelope
		}
		result.Issues = append(result.Issues, syncIssue("transport_unavailable", ErrTransportUnavailable.Error(), true))
		return result, ErrTransportUnavailable
	}
	local, localErr := m.snapshots.LoadLocalSnapshot(ctx)
	if localErr != nil {
		result.Issues = append(result.Issues, syncIssue("snapshot_store_unavailable", ErrStoreUnavailable.Error(), true))
		return result, ErrStoreUnavailable
	}
	for _, envelope := range envelopes {
		if err := validateEnvelopeHeaderAt(envelope, m.cfg.ProfileNamespace, m.now()); err != nil {
			result.Rejected++
			result.Issues = append(result.Issues, syncIssue("invalid_envelope", ErrInvalidSyncEnvelope.Error(), true))
			continue
		}
		var handleErr error
		switch envelope.Kind {
		case EnvelopeKindSnapshot:
			handleErr = m.pullSnapshot(ctx, envelope, local, &result)
		case EnvelopeKindProposal:
			handleErr = m.pullProposal(ctx, envelope, local, &result)
		default:
			result.Rejected++
			result.Issues = append(result.Issues, syncIssue("invalid_envelope_kind", ErrInvalidSyncEnvelope.Error(), true))
		}
		if handleErr != nil {
			m.recordExchange()
			return result, handleErr
		}
	}
	m.recordExchange()
	return result, nil
}

func (m *SyncManager) Exchange(ctx context.Context) (ExchangeResult, error) {
	started := m.now()
	result := ExchangeResult{Session: SyncSession{SessionID: "sync-" + started.Format("20060102150405"), ProfileNamespace: m.cfg.ProfileNamespace, LocalDeviceID: m.cfg.LocalDeviceID, StartedAt: started}}
	pushSnapshot, pushErr := m.PushLocalSnapshot(ctx)
	result.Push = mergePushResults(result.Push, pushSnapshot)
	if pushErr != nil {
		result.Issues = append(result.Issues, pushSnapshot.Issues...)
		result.Status = m.BuildStatus(ctx)
		result.Session.CompletedAt = m.now()
		return result, pushErr
	}
	pushProposals, proposalErr := m.PushLocalProposals(ctx)
	result.Push = mergePushResults(result.Push, pushProposals)
	if proposalErr != nil {
		result.Issues = append(result.Issues, pushProposals.Issues...)
		result.Status = m.BuildStatus(ctx)
		result.Session.CompletedAt = m.now()
		return result, proposalErr
	}
	pull, pullErr := m.PullRemote(ctx)
	result.Pull = pull
	result.ReviewRequired = pull.ReviewRequired
	result.Session.ReviewRequired = pull.ReviewRequired
	result.Session.CompletedAt = m.now()
	result.Status = m.BuildStatus(ctx)
	result.Issues = append(result.Issues, result.Push.Issues...)
	result.Issues = append(result.Issues, pull.Issues...)
	if pullErr != nil {
		return result, pullErr
	}
	return result, nil
}

func (m *SyncManager) pullSnapshot(ctx context.Context, envelope SyncEnvelope, local profilemesh.SignedProfileSnapshot, result *PullResult) error {
	if envelope.Snapshot == nil {
		result.Rejected++
		result.Issues = append(result.Issues, syncIssue("missing_snapshot", ErrSnapshotRejected.Error(), true))
		return nil
	}
	snapshot := *envelope.Snapshot
	validation := profilemesh.ValidateSignedProfileSnapshot(snapshot, m.now())
	if snapshot.Metadata.ProfileNamespace != m.cfg.ProfileNamespace || !validation.Valid {
		result.Rejected++
		result.Issues = append(result.Issues, fromProfileIssues(validation.Issues)...)
		if snapshot.Metadata.ProfileNamespace != m.cfg.ProfileNamespace {
			result.Issues = append(result.Issues, syncIssue("invalid_profile_namespace", profilemesh.ErrInvalidProfileNamespace.Error(), true))
		}
		return nil
	}
	duplicate, err := duplicateSnapshot(ctx, m.snapshots, snapshot.Metadata.SnapshotID)
	if err != nil {
		result.Rejected++
		result.Issues = append(result.Issues, syncIssue("remote_snapshot_store_unavailable", ErrStoreUnavailable.Error(), true))
		return ErrStoreUnavailable
	}
	if duplicate {
		result.Rejected++
		result.ReviewRequired = true
		result.Issues = append(result.Issues, syncIssue("duplicate_snapshot_id", ErrDuplicateSnapshot.Error(), false))
		return nil
	}
	trustState, trustIssue := m.verifySnapshotSigner(ctx, snapshot)
	if trustIssue.Code != "" {
		result.Issues = append(result.Issues, trustIssue)
	}
	requiresReview := trustState != TrustTrusted || snapshotConflict(local, snapshot) || validation.Freshness.Stale
	if snapshot.Metadata.HostingMode == profilemesh.HostingMultiProfileDevices {
		requiresReview = true
		result.Issues = append(result.Issues, syncIssue("multi_host_unsupported", ErrMultiHostUnsupported.Error(), true))
	}
	if snapshotConflict(local, snapshot) {
		result.Issues = append(result.Issues, syncIssue("conflict_review_required", ErrConflictReview.Error(), false))
	}
	if err := m.snapshots.SaveRemoteSnapshot(ctx, RemoteSnapshotRecord{Snapshot: snapshot, ReceivedAt: m.now(), TrustState: trustState, RequiresReview: requiresReview, Freshness: validation.Freshness}); err != nil {
		result.Rejected++
		result.Issues = append(result.Issues, syncIssue("snapshot_store_unavailable", ErrStoreUnavailable.Error(), true))
		return ErrStoreUnavailable
	}
	result.ReceivedSnapshots++
	if requiresReview {
		result.ReviewRequired = true
	}
	return nil
}

func (m *SyncManager) pullProposal(ctx context.Context, envelope SyncEnvelope, local profilemesh.SignedProfileSnapshot, result *PullResult) error {
	if envelope.Proposal == nil {
		result.Rejected++
		result.Issues = append(result.Issues, syncIssue("missing_proposal", ErrProposalRejected.Error(), true))
		return nil
	}
	if m.proposals == nil {
		result.Rejected++
		result.Issues = append(result.Issues, syncIssue("proposal_store_missing", ErrStoreUnavailable.Error(), true))
		return ErrStoreUnavailable
	}
	proposal := *envelope.Proposal
	validation := profilemesh.ValidateProfileChangeProposal(proposal, m.now())
	if proposal.ProfileNamespace != m.cfg.ProfileNamespace || !validation.Valid {
		result.Rejected++
		result.Issues = append(result.Issues, fromProfileIssues(validation.Issues)...)
		if proposal.ProfileNamespace != m.cfg.ProfileNamespace {
			result.Issues = append(result.Issues, syncIssue("invalid_profile_namespace", profilemesh.ErrInvalidProfileNamespace.Error(), true))
		}
		return nil
	}
	review, err := classifyRemoteProposal(ctx, m.proposals, proposal, local.Metadata.SnapshotID)
	if err != nil {
		result.Rejected++
		result.Issues = append(result.Issues, syncIssue("remote_proposal_store_unavailable", ErrStoreUnavailable.Error(), true))
		return ErrStoreUnavailable
	}
	if review.duplicate {
		result.Rejected++
		result.ReviewRequired = true
		result.Issues = append(result.Issues, review.issues...)
		return nil
	}
	trustState, trustIssue := m.verifyProposalSigner(ctx, proposal)
	if trustIssue.Code != "" {
		result.Issues = append(result.Issues, trustIssue)
	}
	requiresReview := trustState != TrustTrusted || validation.RequiresUserReview || review.requiresReview
	if validation.RequiresUserReview {
		result.Issues = append(result.Issues, syncIssue("conflict_review_required", ErrConflictReview.Error(), false))
	}
	result.Issues = append(result.Issues, review.issues...)
	if err := m.proposals.SaveRemoteProposal(ctx, RemoteProposalRecord{Proposal: proposal, ReceivedAt: m.now(), TrustState: trustState, RequiresReview: requiresReview}); err != nil {
		result.Rejected++
		result.Issues = append(result.Issues, syncIssue("proposal_store_unavailable", ErrStoreUnavailable.Error(), true))
		return ErrStoreUnavailable
	}
	result.ReceivedProposals++
	if requiresReview {
		result.ReviewRequired = true
	}
	return nil
}

func (m *SyncManager) ensureReadyForStoreOnly() error {
	if m == nil || !m.cfg.Enabled {
		return ErrDisabled
	}
	if !validSyncName(m.cfg.ProfileNamespace) || !validSyncID(m.cfg.LocalDeviceID) {
		return ErrInvalidConfig
	}
	if m.snapshots == nil {
		return ErrStoreUnavailable
	}
	return nil
}

func (m *SyncManager) ensureReadyForExchange() error {
	if err := m.ensureReadyForStoreOnly(); err != nil {
		return err
	}
	if m.transport == nil {
		return ErrNoRelayProvider
	}
	return nil
}

func (m *SyncManager) verifySnapshotSigner(ctx context.Context, snapshot profilemesh.SignedProfileSnapshot) (TrustState, SyncIssue) {
	if m.trust == nil {
		return TrustPending, syncIssue("trust_verifier_missing", ErrTrustVerification.Error(), false)
	}
	decision := m.trust.VerifySigner(ctx, snapshot.Signature.SignerDeviceID, snapshot.Signature.SignerKeyFingerprint)
	return trustStateFromDecision(decision), trustIssueFromDecision(decision)
}

func (m *SyncManager) verifyProposalSigner(ctx context.Context, proposal profilemesh.ProfileChangeProposal) (TrustState, SyncIssue) {
	if m.trust == nil {
		return TrustPending, syncIssue("trust_verifier_missing", ErrTrustVerification.Error(), false)
	}
	decision := m.trust.VerifySigner(ctx, proposal.AuthorDeviceID, "")
	return trustStateFromDecision(decision), trustIssueFromDecision(decision)
}

func (m *SyncManager) now() time.Time {
	if m != nil && m.clock != nil {
		return m.clock.Now().UTC()
	}
	return time.Now().UTC()
}

func (m *SyncManager) recordExchange() {
	m.lastMu.Lock()
	defer m.lastMu.Unlock()
	m.last = m.now()
}

func (m *SyncManager) lastExchangeAt() time.Time {
	m.lastMu.Lock()
	defer m.lastMu.Unlock()
	return m.last
}

func classifyLocalSnapshot(snapshot profilemesh.SignedProfileSnapshot, now time.Time) ([]SyncIssue, bool, bool) {
	validation := profilemesh.ValidateSignedProfileSnapshot(snapshot, now)
	issues := make([]SyncIssue, 0, len(validation.Issues))
	reviewRequired := false
	blocking := false
	for _, issue := range validation.Issues {
		code := safeID(issue.Code)
		if code == "stale_snapshot" {
			code = "local_snapshot_stale"
			reviewRequired = true
		}
		if code == "future_dated_snapshot" {
			code = "local_snapshot_future_dated"
		}
		if issue.Blocking {
			blocking = true
		}
		issues = append(issues, syncIssue(code, issue.Message, issue.Blocking))
	}
	if validation.Freshness.Stale && !containsSyncIssueCode(issues, "local_snapshot_stale") {
		issues = append(issues, syncIssue("local_snapshot_stale", profilemesh.ErrSnapshotMetadataStale.Error(), false))
		reviewRequired = true
	}
	if validation.Freshness.FutureDated {
		blocking = true
	}
	return issues, reviewRequired, blocking
}

func containsSyncIssueCode(issues []SyncIssue, code string) bool {
	for _, issue := range issues {
		if issue.Code == code {
			return true
		}
	}
	return false
}

func (t *RelaySyncTransport) GetStatus(ctx context.Context) SyncTransportStatus {
	if t == nil || t.cfg.Provider == nil {
		return SyncTransportStatus{Available: false, Summary: ErrNoRelayProvider.Error(), Issues: []SyncIssue{syncIssue("relay_missing", ErrNoRelayProvider.Error(), false)}}
	}
	status := t.cfg.Provider.GetStatus(ctx)
	out := SyncTransportStatus{Available: status.Available, ProviderID: safeID(status.ProviderID), Summary: safeSummary(status.Summary, "relay transport is unavailable")}
	for _, issue := range status.Issues {
		out.Issues = append(out.Issues, syncIssue(safeID(issue.Code), safeSummary(issue.Message, ErrTransportUnavailable.Error()), false))
	}
	if !out.Available && len(out.Issues) == 0 {
		out.Issues = append(out.Issues, syncIssue("relay_unavailable", ErrTransportUnavailable.Error(), false))
	}
	return out
}

// BuildDiagnostics reports safe relay capabilities without exposing routing
// identifiers, caller signature evidence, payloads, or provider error details.
func (t *RelaySyncTransport) BuildDiagnostics(ctx context.Context) RelaySyncDiagnostics {
	status := t.GetStatus(ctx)
	diagnostics := RelaySyncDiagnostics{
		ProviderAvailable:     status.Available,
		ProviderID:            status.ProviderID,
		Summary:               status.Summary,
		Issues:                append([]SyncIssue(nil), status.Issues...),
		MaximumPayloadBytes:   relay.DefaultMaxPayloadSize,
		MaximumSignatureBytes: MaxEnvelopeSignatureEvidenceBytes,
	}
	if t == nil {
		return diagnostics
	}
	diagnostics.SendConfigured = t.cfg.TargetDeviceID != "" || t.cfg.TargetMailboxID != ""
	diagnostics.ReceiveConfigured = t.cfg.Mailbox.MailboxID != ""
	diagnostics.ReceiveOnly = diagnostics.ReceiveConfigured && !diagnostics.SendConfigured
	diagnostics.SendAvailable = diagnostics.ProviderAvailable && diagnostics.SendConfigured
	diagnostics.ReceiveAvailable = diagnostics.ProviderAvailable && diagnostics.ReceiveConfigured
	if t.cfg.MaxPayloadBytes > 0 {
		diagnostics.MaximumPayloadBytes = t.cfg.MaxPayloadBytes
	}
	if diagnostics.SendConfigured {
		ttl := t.cfg.MessageTTL
		if ttl <= 0 {
			ttl = DefaultEnvelopeTTL
		}
		diagnostics.MessageTTLSeconds = int64(ttl / time.Second)
	}
	if diagnostics.ReceiveConfigured {
		diagnostics.MailboxExpiresAtRFC3339 = FormatStatusTimeRFC3339(t.cfg.Mailbox.ExpiresAt)
		if !t.cfg.Mailbox.ExpiresAt.IsZero() && !t.cfg.Mailbox.ExpiresAt.After(t.now()) {
			diagnostics.ReceiveAvailable = false
			diagnostics.Issues = append(diagnostics.Issues, syncIssue("relay_mailbox_expired", relay.ErrMailboxExpired.Error(), false))
		}
	}
	diagnostics.Available = diagnostics.SendAvailable || diagnostics.ReceiveAvailable
	if diagnostics.ProviderAvailable {
		switch {
		case diagnostics.SendAvailable && diagnostics.ReceiveAvailable:
			diagnostics.Summary = "profile sync relay send and receive are available"
		case diagnostics.ReceiveAvailable:
			diagnostics.Summary = "profile sync relay receive is available"
		case diagnostics.SendAvailable:
			diagnostics.Summary = "profile sync relay send is available"
		default:
			diagnostics.Summary = "profile sync relay transport is not configured for an available operation"
		}
	}
	return diagnostics
}

func (t *RelaySyncTransport) PushEnvelope(ctx context.Context, envelope SyncEnvelope) (relay.DeliveryReceipt, error) {
	if t == nil || t.cfg.Provider == nil {
		return relay.DeliveryReceipt{}, ErrNoRelayProvider
	}
	if t.cfg.TargetDeviceID == "" && t.cfg.TargetMailboxID == "" {
		return relay.DeliveryReceipt{}, ErrReceiveOnlyTransport
	}
	if err := validateEnvelopeHeaderAt(envelope, t.cfg.Namespace, t.now()); err != nil {
		return relay.DeliveryReceipt{}, err
	}
	payload, err := json.Marshal(envelope)
	if err != nil {
		return relay.DeliveryReceipt{}, ErrInvalidSyncEnvelope
	}
	now := t.now()
	ttl := t.cfg.MessageTTL
	if ttl <= 0 {
		ttl = DefaultEnvelopeTTL
	}
	targetMailboxID := t.cfg.TargetMailboxID
	targetDeviceID := t.cfg.TargetDeviceID
	rEnvelope := relay.RelayEnvelope{
		RelayEnvelopeMetadata: relay.RelayEnvelopeMetadata{
			ProtocolVersion: relay.ProtocolVersion,
			Namespace:       t.cfg.Namespace,
			SourceDeviceID:  t.cfg.SourceDeviceID,
			TargetDeviceID:  targetDeviceID,
			TargetMailboxID: targetMailboxID,
			MessageKind:     relay.MessageKindOpaque,
			CreatedAt:       now,
			ExpiresAt:       now.Add(ttl),
			MessageID:       envelope.MessageID,
			PayloadHash:     relay.PayloadSHA256(payload),
			Metadata:        map[string]string{"aegis_profile_sync_kind": string(envelope.Kind)},
		},
		Payload: payload,
	}
	receipt, err := t.cfg.Provider.SendEnvelope(ctx, rEnvelope)
	if err != nil {
		if errors.Is(err, relay.ErrDuplicateEnvelope) {
			return relay.DeliveryReceipt{MessageID: envelope.MessageID, Accepted: true, Delivered: false, ReceivedAt: now, Summary: "profile sync envelope was already accepted"}, nil
		}
		return relay.DeliveryReceipt{}, ErrTransportUnavailable
	}
	return sanitizeReceipt(receipt), nil
}

func (t *RelaySyncTransport) PullEnvelopes(ctx context.Context) ([]SyncEnvelope, error) {
	if t == nil || t.cfg.Provider == nil {
		return nil, ErrNoRelayProvider
	}
	if t.cfg.Mailbox.MailboxID == "" {
		return nil, ErrInvalidConfig
	}
	envelopes, err := t.cfg.Provider.ReceiveEnvelopes(ctx, t.cfg.Mailbox)
	if err != nil {
		return nil, ErrTransportUnavailable
	}
	out := make([]SyncEnvelope, 0, len(envelopes))
	for _, envelope := range envelopes {
		if err := validateRelayCarrierEnvelope(envelope, t.cfg); err != nil {
			return nil, ErrInvalidSyncEnvelope
		}
		var decoded SyncEnvelope
		if err := json.Unmarshal(envelope.Payload, &decoded); err != nil {
			return nil, ErrInvalidSyncEnvelope
		}
		if kind := envelope.Metadata["aegis_profile_sync_kind"]; kind != "" && kind != string(decoded.Kind) {
			return nil, ErrInvalidSyncEnvelope
		}
		if err := validateEnvelopeHeaderAt(decoded, t.cfg.Namespace, t.now()); err != nil {
			return nil, err
		}
		out = append(out, decoded)
	}
	return out, nil
}

func (t *RelaySyncTransport) now() time.Time {
	if t != nil && t.cfg.Clock != nil {
		return t.cfg.Clock.Now().UTC()
	}
	return time.Now().UTC()
}

func validateRelayCarrierEnvelope(envelope relay.RelayEnvelope, cfg RelaySyncTransportConfig) error {
	limit := cfg.MaxPayloadBytes
	if limit <= 0 {
		limit = relay.DefaultMaxPayloadSize
	}
	if err := relay.ValidateEnvelopeWithLimit(envelope, limit); err != nil {
		return err
	}
	if envelope.Namespace != cfg.Namespace || envelope.MessageKind != relay.MessageKindOpaque {
		return ErrInvalidSyncEnvelope
	}
	if cfg.Mailbox.MailboxID != "" && envelope.TargetMailboxID != "" && envelope.TargetMailboxID != cfg.Mailbox.MailboxID {
		return ErrInvalidSyncEnvelope
	}
	return nil
}

type MemoryMetadataStore struct {
	mu              sync.Mutex
	err             error
	localSnapshot   profilemesh.SignedProfileSnapshot
	localProposals  []profilemesh.ProfileChangeProposal
	remoteSnapshots map[string]RemoteSnapshotRecord
	remoteProposals map[string]RemoteProposalRecord
}

func NewMemoryMetadataStore() *MemoryMetadataStore {
	return &MemoryMetadataStore{remoteSnapshots: map[string]RemoteSnapshotRecord{}, remoteProposals: map[string]RemoteProposalRecord{}}
}

func (s *MemoryMetadataStore) SetError(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.err = err
}

func (s *MemoryMetadataStore) SetLocalSnapshot(snapshot profilemesh.SignedProfileSnapshot) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.localSnapshot = snapshot
}

func (s *MemoryMetadataStore) AddLocalProposal(proposal profilemesh.ProfileChangeProposal) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.localProposals = append(s.localProposals, proposal)
}

func (s *MemoryMetadataStore) LoadLocalSnapshot(ctx context.Context) (profilemesh.SignedProfileSnapshot, error) {
	if err := storeContextError(ctx); err != nil {
		return profilemesh.SignedProfileSnapshot{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return profilemesh.SignedProfileSnapshot{}, s.err
	}
	return s.localSnapshot, nil
}

func (s *MemoryMetadataStore) SaveRemoteSnapshot(ctx context.Context, record RemoteSnapshotRecord) error {
	if err := storeContextError(ctx); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return s.err
	}
	if s.remoteSnapshots == nil {
		s.remoteSnapshots = map[string]RemoteSnapshotRecord{}
	}
	s.remoteSnapshots[record.Snapshot.Metadata.SnapshotID] = record
	return nil
}

func (s *MemoryMetadataStore) ListRemoteSnapshots(ctx context.Context) ([]RemoteSnapshotRecord, error) {
	if err := storeContextError(ctx); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return nil, s.err
	}
	out := make([]RemoteSnapshotRecord, 0, len(s.remoteSnapshots))
	for _, record := range s.remoteSnapshots {
		out = append(out, record)
	}
	return out, nil
}

func (s *MemoryMetadataStore) LoadLocalProposals(ctx context.Context) ([]profilemesh.ProfileChangeProposal, error) {
	if err := storeContextError(ctx); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return nil, s.err
	}
	return append([]profilemesh.ProfileChangeProposal{}, s.localProposals...), nil
}

func (s *MemoryMetadataStore) SaveRemoteProposal(ctx context.Context, record RemoteProposalRecord) error {
	if err := storeContextError(ctx); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return s.err
	}
	if s.remoteProposals == nil {
		s.remoteProposals = map[string]RemoteProposalRecord{}
	}
	s.remoteProposals[record.Proposal.ProposalID] = record
	return nil
}

func (s *MemoryMetadataStore) ListRemoteProposals(ctx context.Context) ([]RemoteProposalRecord, error) {
	if err := storeContextError(ctx); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return nil, s.err
	}
	out := make([]RemoteProposalRecord, 0, len(s.remoteProposals))
	for _, record := range s.remoteProposals {
		out = append(out, record)
	}
	return out, nil
}

func storeContextError(ctx context.Context) error {
	if ctx == nil {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return ErrStoreUnavailable
	}
	return nil
}

func snapshotEnvelope(namespace, deviceID string, snapshot profilemesh.SignedProfileSnapshot, now time.Time) SyncEnvelope {
	return SyncEnvelope{SchemaVersion: EnvelopeSchemaVersion, Kind: EnvelopeKindSnapshot, ProfileNamespace: namespace, SourceDeviceID: deviceID, MessageID: "snapshot-" + snapshot.Metadata.SnapshotID, CreatedAt: now, Snapshot: &snapshot}
}

func proposalEnvelope(namespace, deviceID string, proposal profilemesh.ProfileChangeProposal, now time.Time) SyncEnvelope {
	return SyncEnvelope{SchemaVersion: EnvelopeSchemaVersion, Kind: EnvelopeKindProposal, ProfileNamespace: namespace, SourceDeviceID: deviceID, MessageID: "proposal-" + proposal.ProposalID, CreatedAt: now, Proposal: &proposal}
}

func validateEnvelopeHeader(envelope SyncEnvelope, namespace string) error {
	return validateEnvelopeHeaderAt(envelope, namespace, time.Now().UTC())
}

func validateEnvelopeHeaderAt(envelope SyncEnvelope, namespace string, now time.Time) error {
	if envelope.SchemaVersion != EnvelopeSchemaVersion || !validSyncName(envelope.ProfileNamespace) || envelope.ProfileNamespace != namespace || !validSyncID(envelope.SourceDeviceID) || !validSyncID(envelope.MessageID) || envelope.CreatedAt.IsZero() {
		return ErrInvalidSyncEnvelope
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if envelope.CreatedAt.After(now.Add(defaultClockSkew)) {
		return ErrInvalidSyncEnvelope
	}
	if !validEnvelopeSignatureEvidence(envelope.SignatureEvidence) {
		return ErrInvalidSyncEnvelope
	}
	switch envelope.Kind {
	case EnvelopeKindSnapshot:
		if envelope.Snapshot == nil {
			return ErrInvalidSyncEnvelope
		}
	case EnvelopeKindProposal:
		if envelope.Proposal == nil {
			return ErrInvalidSyncEnvelope
		}
	default:
		return ErrInvalidSyncEnvelope
	}
	return nil
}

func validEnvelopeSignatureEvidence(evidence *EnvelopeSignatureEvidence) bool {
	if evidence == nil {
		return true
	}
	if !validExactSyncName(evidence.Algorithm) {
		return false
	}
	if evidence.KeyID != "" && !validExactSyncID(evidence.KeyID) {
		return false
	}
	return len(evidence.Signature) > 0 && len(evidence.Signature) <= MaxEnvelopeSignatureEvidenceBytes
}

func duplicateSnapshot(ctx context.Context, store SnapshotStore, snapshotID string) (bool, error) {
	records, err := store.ListRemoteSnapshots(ctx)
	if err != nil {
		return false, err
	}
	for _, record := range records {
		if record.Snapshot.Metadata.SnapshotID == snapshotID {
			return true, nil
		}
	}
	return false, nil
}

type proposalReviewClassification struct {
	duplicate      bool
	requiresReview bool
	issues         []SyncIssue
}

func classifyRemoteProposal(ctx context.Context, store ProposalStore, proposal profilemesh.ProfileChangeProposal, localSnapshotID string) (proposalReviewClassification, error) {
	records, err := store.ListRemoteProposals(ctx)
	if err != nil {
		return proposalReviewClassification{}, err
	}
	out := proposalReviewClassification{}
	if proposal.BaseSnapshotID != localSnapshotID {
		out.requiresReview = true
		out.issues = append(out.issues, syncIssue("conflict_review_required", ErrConflictReview.Error(), false))
	}
	for _, record := range records {
		existing := record.Proposal
		if existing.ProposalID == proposal.ProposalID {
			out.duplicate = true
			out.requiresReview = true
			out.issues = append(out.issues, syncIssue("duplicate_proposal_id", ErrDuplicateProposal.Error(), false))
			return out, nil
		}
		if competingProposal(existing, proposal) {
			out.requiresReview = true
			out.issues = append(out.issues, syncIssue("competing_proposal_review_required", ErrConflictReview.Error(), false))
		}
		if supersededProposal(existing, proposal) {
			out.requiresReview = true
			out.issues = append(out.issues, syncIssue("superseded_proposal_review_required", ErrConflictReview.Error(), false))
		}
	}
	return out, nil
}

func competingProposal(a, b profilemesh.ProfileChangeProposal) bool {
	if a.ProfileNamespace != b.ProfileNamespace || a.ProfileID != b.ProfileID {
		return false
	}
	if a.ProposalID == "" || b.ProposalID == "" || a.ProposalID == b.ProposalID {
		return false
	}
	return a.BaseSnapshotID != "" && a.BaseSnapshotID == b.BaseSnapshotID
}

func supersededProposal(a, b profilemesh.ProfileChangeProposal) bool {
	if a.ProfileNamespace != b.ProfileNamespace || a.ProfileID != b.ProfileID {
		return false
	}
	if a.ProposalID == "" || b.ProposalID == "" || a.ProposalID == b.ProposalID {
		return false
	}
	return (a.ProposedSnapshotID != "" && a.ProposedSnapshotID == b.BaseSnapshotID) ||
		(b.ProposedSnapshotID != "" && b.ProposedSnapshotID == a.BaseSnapshotID)
}

func snapshotConflict(local, remote profilemesh.SignedProfileSnapshot) bool {
	if local.Metadata.ProfileNamespace != remote.Metadata.ProfileNamespace || local.Metadata.ProfileID != remote.Metadata.ProfileID {
		return false
	}
	if local.Metadata.SnapshotID == "" || remote.Metadata.SnapshotID == "" || local.Metadata.SnapshotID == remote.Metadata.SnapshotID {
		return false
	}
	if remote.Metadata.ParentSnapshotID == local.Metadata.SnapshotID || local.Metadata.ParentSnapshotID == remote.Metadata.SnapshotID {
		return false
	}
	if local.Metadata.MetadataVersion == remote.Metadata.MetadataVersion {
		return true
	}
	return remote.Metadata.ParentSnapshotID != "" && remote.Metadata.ParentSnapshotID != local.Metadata.SnapshotID
}

func trustStateFromDecision(decision TrustDecision) TrustState {
	if decision.Trusted {
		return TrustTrusted
	}
	if decision.Pending {
		return TrustPending
	}
	return TrustUntrusted
}

func trustIssueFromDecision(decision TrustDecision) SyncIssue {
	if decision.Trusted {
		return SyncIssue{}
	}
	if decision.Pending {
		return syncIssue(safeID(decision.Code), safeSummary(decision.Message, ErrTrustVerification.Error()), false)
	}
	return syncIssue(safeID(decision.Code), safeSummary(decision.Message, ErrTrustVerification.Error()), false)
}

func fromProfileIssues(issues []profilemesh.ProfileSyncIssue) []SyncIssue {
	out := make([]SyncIssue, 0, len(issues))
	for _, issue := range issues {
		out = append(out, syncIssue(safeID(issue.Code), safeSummary(issue.Message, ErrSnapshotRejected.Error()), issue.Blocking))
	}
	return out
}

func mergePushResults(a, b PushResult) PushResult {
	a.PushedSnapshots += b.PushedSnapshots
	a.PushedProposals += b.PushedProposals
	a.Receipts = append(a.Receipts, b.Receipts...)
	a.Issues = append(a.Issues, b.Issues...)
	return a
}

func sanitizeReceipt(receipt relay.DeliveryReceipt) relay.DeliveryReceipt {
	receipt.MessageID = safeID(receipt.MessageID)
	receipt.Summary = safeSummary(receipt.Summary, "relay accepted envelope metadata")
	return receipt
}

func syncIssue(code, message string, blocking bool) SyncIssue {
	code = safeID(code)
	if code == "" {
		code = "profile_sync_issue"
	}
	return SyncIssue{Code: code, Message: safeSummary(message, "profile sync issue"), Blocking: blocking}
}

func safeID(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || unsafeSyncText(value) {
		return ""
	}
	return value
}

func safeSummary(value, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" || unsafeSyncText(value) {
		return fallback
	}
	return value
}

func validSyncName(value string) bool {
	value = strings.TrimSpace(value)
	return syncNamePattern.MatchString(value) && !strings.Contains(value, "..") && !strings.ContainsAny(value, `/\`) && !reservedName(value) && !unsafeSyncText(value)
}

func validExactSyncName(value string) bool {
	return value == strings.TrimSpace(value) && validSyncName(value)
}

func validSyncID(value string) bool {
	value = strings.TrimSpace(value)
	return syncIDPattern.MatchString(value) && !strings.Contains(value, "..") && !strings.ContainsAny(value, `/\`) && !unsafeSyncText(value)
}

func validExactSyncID(value string) bool {
	return value == strings.TrimSpace(value) && validSyncID(value)
}

func unsafeSyncText(value string) bool {
	lower := strings.ToLower(strings.TrimSpace(value))
	if lower == "" {
		return false
	}
	for _, marker := range []string{"client_secret", "refresh_token", "access_token", "id_token", "auth_code", "pkce", "verifier", "private_key", "begin private key", "github_pat", "ghp_", "api_key", "apikey", "access_key", "secret_key", "authorization:", "authorization=", "bearer ", "x-api-key", "token=", "password=", "secret=", `:\`, `/users/`, `/home/`, `/tmp/`, `\\`, "appdata", "downloads", "desktop"} {
		if strings.Contains(lower, strings.ToLower(marker)) {
			return true
		}
	}
	return false
}

func reservedName(value string) bool {
	switch strings.ToUpper(strings.TrimSpace(value)) {
	case "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9":
		return true
	default:
		return false
	}
}
