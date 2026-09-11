package profilesync

import (
	"context"
	"errors"
	"time"

	"github.com/AegisAgentAscalon/aegis-core/pkg/profilemesh"
)

// LocalExchangeRecordSchemaVersion is the strict exchange-record format.
// LoadLastExchange continues to accept legacy schema 1 records.
const LocalExchangeRecordSchemaVersion = 2

const (
	localMetadataStoreSchemaVersion   = 1
	legacyExchangeRecordSchemaVersion = 1
	maxLocalJSONFileBytes             = 8 * 1024 * 1024
)

type LocalExchangeRecord struct {
	SchemaVersion     int         `json:"schema_version"`
	ProfileNamespace  string      `json:"profile_namespace"`
	Session           SyncSession `json:"session"`
	PushedSnapshots   int         `json:"pushed_snapshots"`
	PushedProposals   int         `json:"pushed_proposals"`
	ReceivedSnapshots int         `json:"received_snapshots"`
	ReceivedProposals int         `json:"received_proposals"`
	Rejected          int         `json:"rejected"`
	ReviewRequired    bool        `json:"review_required"`
	Issues            []SyncIssue `json:"issues,omitempty"`
	StatusSummary     string      `json:"status_summary,omitempty"`
	RecordedAt        time.Time   `json:"recorded_at"`
}

type localStoreMetadataFile struct {
	SchemaVersion    int       `json:"schema_version"`
	ProfileNamespace string    `json:"profile_namespace"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
}

type localSnapshotFile struct {
	SchemaVersion    int                 `json:"schema_version"`
	ProfileNamespace string              `json:"profile_namespace"`
	Record           LocalSnapshotRecord `json:"record"`
}

type remoteSnapshotFile struct {
	SchemaVersion    int                  `json:"schema_version"`
	ProfileNamespace string               `json:"profile_namespace"`
	Record           RemoteSnapshotRecord `json:"record"`
}

type localProposalFile struct {
	SchemaVersion    int                               `json:"schema_version"`
	ProfileNamespace string                            `json:"profile_namespace"`
	Proposal         profilemesh.ProfileChangeProposal `json:"proposal"`
}

type remoteProposalFile struct {
	SchemaVersion    int                  `json:"schema_version"`
	ProfileNamespace string               `json:"profile_namespace"`
	Record           RemoteProposalRecord `json:"record"`
}

// PersistExchangeResult records a completed Profile Sync exchange in the local
// metadata store after confirming the result belongs to that store namespace.
func PersistExchangeResult(ctx context.Context, store *LocalMetadataStore, result ExchangeResult) error {
	if store == nil {
		return ErrStoreUnavailable
	}
	return store.SaveLastExchange(ctx, result)
}

func validateStoredExchangeRecord(namespace string, record LocalExchangeRecord) error {
	if record.ProfileNamespace != namespace {
		return ErrLocalStoreCorrupt
	}
	switch record.SchemaVersion {
	case legacyExchangeRecordSchemaVersion:
		// Schema 1 records were written before strict session and counter
		// validation. Preserve their original read contract.
		if !validSyncID(record.Session.SessionID) {
			return ErrLocalStoreCorrupt
		}
		return nil
	case LocalExchangeRecordSchemaVersion:
		if err := validateExchangeSession(namespace, record.Session); err != nil ||
			record.PushedSnapshots < 0 || record.PushedProposals < 0 ||
			record.ReceivedSnapshots < 0 || record.ReceivedProposals < 0 || record.Rejected < 0 ||
			record.RecordedAt.IsZero() {
			return ErrLocalStoreCorrupt
		}
		return nil
	default:
		return ErrLocalStoreCorrupt
	}
}

func validateExchangeResultForStore(namespace string, result ExchangeResult) error {
	if err := validateExchangeSession(namespace, result.Session); err != nil {
		return err
	}
	if result.Push.PushedSnapshots < 0 || result.Push.PushedProposals < 0 || result.Pull.ReceivedSnapshots < 0 || result.Pull.ReceivedProposals < 0 || result.Pull.Rejected < 0 {
		return ErrInvalidConfig
	}
	return nil
}

func validateExchangeSession(namespace string, session SyncSession) error {
	if !validExactSyncName(namespace) || session.ProfileNamespace != namespace || !validExactSyncID(session.SessionID) || !validExactSyncID(session.LocalDeviceID) {
		return ErrInvalidConfig
	}
	if session.StartedAt.IsZero() || session.CompletedAt.IsZero() || session.CompletedAt.Before(session.StartedAt) {
		return ErrInvalidConfig
	}
	return nil
}

func validateStoreSnapshot(namespace string, snapshot profilemesh.SignedProfileSnapshot, now time.Time) (profilemesh.SignedProfileSnapshot, error) {
	validation := profilemesh.ValidateSignedProfileSnapshot(snapshot, now)
	if snapshot.Metadata.ProfileNamespace != namespace || !validation.Valid {
		return profilemesh.SignedProfileSnapshot{}, ErrSnapshotRejected
	}
	return snapshot, nil
}

func validateRemoteSnapshotRecord(namespace string, record RemoteSnapshotRecord, now time.Time) (RemoteSnapshotRecord, error) {
	snapshot, err := validateStoreSnapshot(namespace, record.Snapshot, now)
	if err != nil {
		return RemoteSnapshotRecord{}, err
	}
	if record.TrustState == "" {
		record.TrustState = TrustPending
	}
	if !validTrustState(record.TrustState) {
		return RemoteSnapshotRecord{}, ErrSnapshotRejected
	}
	record.Snapshot = snapshot
	record.Freshness = profilemesh.BuildProfileFreshnessSummary(snapshot.Metadata, now)
	if record.TrustState != TrustTrusted || record.Freshness.Stale {
		record.RequiresReview = true
	}
	return record, nil
}

func validateStoreProposal(namespace string, proposal profilemesh.ProfileChangeProposal, now time.Time) (profilemesh.ProfileChangeProposal, error) {
	validation := profilemesh.ValidateProfileChangeProposal(proposal, now)
	if proposal.ProfileNamespace != namespace || !validation.Valid {
		return profilemesh.ProfileChangeProposal{}, ErrProposalRejected
	}
	proposal.Status = validation.Status
	proposal.Conflicts = validation.Conflicts
	if len(proposal.Conflicts) > 0 {
		proposal.RequiresUserReview = true
	}
	return proposal, nil
}

func validateRemoteProposalRecord(namespace string, record RemoteProposalRecord, now time.Time) (RemoteProposalRecord, error) {
	proposal, err := validateStoreProposal(namespace, record.Proposal, now)
	if err != nil {
		return RemoteProposalRecord{}, err
	}
	if record.TrustState == "" {
		record.TrustState = TrustPending
	}
	if !validTrustState(record.TrustState) {
		return RemoteProposalRecord{}, ErrProposalRejected
	}
	record.Proposal = proposal
	if record.TrustState != TrustTrusted || proposal.RequiresUserReview {
		record.RequiresReview = true
	}
	return record, nil
}

func validTrustState(state TrustState) bool {
	switch state {
	case TrustPending, TrustTrusted, TrustUntrusted:
		return true
	default:
		return false
	}
}

func localStoreIssue(err error) SyncIssue {
	switch {
	case errors.Is(err, ErrLocalStoreCorrupt):
		return syncIssue("local_store_corrupt", ErrLocalStoreCorrupt.Error(), true)
	case errors.Is(err, ErrLocalStoreNotFound):
		return syncIssue("local_store_missing", ErrLocalStoreNotFound.Error(), false)
	case errors.Is(err, ErrInvalidConfig):
		return syncIssue("local_store_invalid_config", ErrInvalidConfig.Error(), true)
	default:
		return syncIssue("local_store_unavailable", ErrStoreUnavailable.Error(), true)
	}
}

var _ SnapshotStore = (*LocalMetadataStore)(nil)

var _ ProposalStore = (*LocalMetadataStore)(nil)
