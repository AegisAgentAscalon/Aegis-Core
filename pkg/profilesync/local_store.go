package profilesync

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/AegisAgentAscalon/aegis-core/pkg/profilemesh"
)

type LocalMetadataStoreConfig struct {
	RootDir          string
	ProfileNamespace string
	Clock            Clock
}

type LocalMetadataStoreStatus struct {
	Available               bool        `json:"available"`
	ProfileNamespace        string      `json:"profile_namespace,omitempty"`
	SchemaVersion           int         `json:"schema_version,omitempty"`
	StoreLabel              string      `json:"store_label,omitempty"`
	LocalSnapshotConfigured bool        `json:"local_snapshot_configured"`
	LocalProposalCount      int         `json:"local_proposal_count"`
	RemoteSnapshotCount     int         `json:"remote_snapshot_count"`
	RemoteProposalCount     int         `json:"remote_proposal_count"`
	LastExchangeAt          time.Time   `json:"last_exchange_at,omitempty"`
	Summary                 string      `json:"summary,omitempty"`
	Issues                  []SyncIssue `json:"issues,omitempty"`
}

type LocalMetadataStore struct {
	mu        sync.Mutex
	root      string
	namespace string
	clock     Clock
}

func NewLocalMetadataStore(config LocalMetadataStoreConfig) (*LocalMetadataStore, error) {
	root := strings.TrimSpace(config.RootDir)
	if root == "" || !validSyncName(config.ProfileNamespace) {
		return nil, ErrInvalidConfig
	}
	store := &LocalMetadataStore{root: filepath.Clean(root), namespace: config.ProfileNamespace, clock: config.Clock}
	if err := store.ensureInitialized(context.Background()); err != nil {
		return nil, err
	}
	return store, nil
}

func (s *LocalMetadataStore) BuildStatus(ctx context.Context) LocalMetadataStoreStatus {
	if s == nil {
		return LocalMetadataStoreStatus{Available: false, Summary: ErrStoreUnavailable.Error(), Issues: []SyncIssue{syncIssue("local_store_missing", ErrStoreUnavailable.Error(), false)}}
	}
	status := LocalMetadataStoreStatus{
		Available:        true,
		ProfileNamespace: s.namespace,
		SchemaVersion:    localMetadataStoreSchemaVersion,
		StoreLabel:       safeSummary(filepath.Base(s.root), "local_metadata_store"),
		Summary:          "profile sync local metadata store is available",
	}
	if err := s.ensureInitialized(ctx); err != nil {
		status.Available = false
		status.Summary = "profile sync local metadata store is degraded"
		status.Issues = append(status.Issues, localStoreIssue(err))
		return status
	}
	if _, err := s.LoadLocalSnapshot(ctx); err == nil {
		status.LocalSnapshotConfigured = true
		snapshot, loadErr := s.LoadLocalSnapshot(ctx)
		if loadErr == nil {
			issues, _, blocking := classifyLocalSnapshot(snapshot, s.now())
			status.Issues = append(status.Issues, issues...)
			if blocking {
				status.Available = false
			}
		}
	} else if !errors.Is(err, ErrLocalStoreNotFound) {
		status.Available = false
		status.Issues = append(status.Issues, localStoreIssue(err))
	}
	if proposals, err := s.LoadLocalProposals(ctx); err != nil {
		status.Available = false
		status.Issues = append(status.Issues, localStoreIssue(err))
	} else {
		status.LocalProposalCount = len(proposals)
	}
	if snapshots, err := s.ListRemoteSnapshots(ctx); err != nil {
		status.Available = false
		status.Issues = append(status.Issues, localStoreIssue(err))
	} else {
		status.RemoteSnapshotCount = len(snapshots)
	}
	if proposals, err := s.ListRemoteProposals(ctx); err != nil {
		status.Available = false
		status.Issues = append(status.Issues, localStoreIssue(err))
	} else {
		status.RemoteProposalCount = len(proposals)
	}
	if exchange, err := s.LoadLastExchange(ctx); err == nil {
		status.LastExchangeAt = exchange.RecordedAt
	} else if !errors.Is(err, ErrLocalStoreNotFound) {
		status.Available = false
		status.Issues = append(status.Issues, localStoreIssue(err))
	}
	if !status.Available {
		status.Summary = "profile sync local metadata store is degraded"
	}
	return status
}

func (s *LocalMetadataStore) SaveLocalSnapshot(ctx context.Context, snapshot profilemesh.SignedProfileSnapshot) error {
	if s == nil {
		return ErrStoreUnavailable
	}
	snapshot, err := validateStoreSnapshot(s.namespace, snapshot, s.now())
	if err != nil {
		return err
	}
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureInitializedLocked(ctx, now); err != nil {
		return err
	}
	file := localSnapshotFile{
		SchemaVersion:    localMetadataStoreSchemaVersion,
		ProfileNamespace: s.namespace,
		Record:           LocalSnapshotRecord{Snapshot: snapshot, ExportedAt: now},
	}
	return writeJSONAtomic(ctx, s.localSnapshotPath(), file)
}

func (s *LocalMetadataStore) LoadLocalSnapshot(ctx context.Context) (profilemesh.SignedProfileSnapshot, error) {
	if s == nil {
		return profilemesh.SignedProfileSnapshot{}, ErrStoreUnavailable
	}
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureInitializedLocked(ctx, now); err != nil {
		return profilemesh.SignedProfileSnapshot{}, err
	}
	var file localSnapshotFile
	if err := readJSONFile(ctx, s.localSnapshotPath(), &file); err != nil {
		return profilemesh.SignedProfileSnapshot{}, err
	}
	if file.SchemaVersion != localMetadataStoreSchemaVersion || file.ProfileNamespace != s.namespace {
		return profilemesh.SignedProfileSnapshot{}, ErrLocalStoreCorrupt
	}
	snapshot, err := validateStoreSnapshot(s.namespace, file.Record.Snapshot, now)
	if err != nil {
		return profilemesh.SignedProfileSnapshot{}, ErrLocalStoreCorrupt
	}
	return snapshot, nil
}

func (s *LocalMetadataStore) SaveRemoteSnapshot(ctx context.Context, record RemoteSnapshotRecord) error {
	if s == nil {
		return ErrStoreUnavailable
	}
	record, err := validateRemoteSnapshotRecord(s.namespace, record, s.now())
	if err != nil {
		return err
	}
	path, err := s.snapshotRecordPath(record.Snapshot.Metadata.SnapshotID)
	if err != nil {
		return err
	}
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureInitializedLocked(ctx, now); err != nil {
		return err
	}
	file := remoteSnapshotFile{SchemaVersion: localMetadataStoreSchemaVersion, ProfileNamespace: s.namespace, Record: record}
	return writeJSONAtomic(ctx, path, file)
}

func (s *LocalMetadataStore) LoadRemoteSnapshot(ctx context.Context, snapshotID string) (RemoteSnapshotRecord, error) {
	if s == nil {
		return RemoteSnapshotRecord{}, ErrStoreUnavailable
	}
	path, err := s.snapshotRecordPath(snapshotID)
	if err != nil {
		return RemoteSnapshotRecord{}, err
	}
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureInitializedLocked(ctx, now); err != nil {
		return RemoteSnapshotRecord{}, err
	}
	return s.readRemoteSnapshotLocked(ctx, path, now)
}

func (s *LocalMetadataStore) ListRemoteSnapshots(ctx context.Context) ([]RemoteSnapshotRecord, error) {
	if s == nil {
		return nil, ErrStoreUnavailable
	}
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureInitializedLocked(ctx, now); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(s.remoteSnapshotsDir())
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, ErrStoreUnavailable
	}
	out := make([]RemoteSnapshotRecord, 0, len(entries))
	for _, entry := range entries {
		if skipStoreDataFile(entry) {
			continue
		}
		record, err := s.readRemoteSnapshotLocked(ctx, filepath.Join(s.remoteSnapshotsDir(), entry.Name()), now)
		if err != nil {
			return nil, err
		}
		out = append(out, record)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Snapshot.Metadata.SnapshotID < out[j].Snapshot.Metadata.SnapshotID
	})
	return out, nil
}

func (s *LocalMetadataStore) SaveLocalProposal(ctx context.Context, proposal profilemesh.ProfileChangeProposal) error {
	if s == nil {
		return ErrStoreUnavailable
	}
	proposal, err := validateStoreProposal(s.namespace, proposal, s.now())
	if err != nil {
		return err
	}
	path, err := s.localProposalPath(proposal.ProposalID)
	if err != nil {
		return err
	}
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureInitializedLocked(ctx, now); err != nil {
		return err
	}
	file := localProposalFile{SchemaVersion: localMetadataStoreSchemaVersion, ProfileNamespace: s.namespace, Proposal: proposal}
	return writeJSONAtomic(ctx, path, file)
}

func (s *LocalMetadataStore) LoadLocalProposals(ctx context.Context) ([]profilemesh.ProfileChangeProposal, error) {
	if s == nil {
		return nil, ErrStoreUnavailable
	}
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureInitializedLocked(ctx, now); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(s.localProposalsDir())
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, ErrStoreUnavailable
	}
	out := make([]profilemesh.ProfileChangeProposal, 0, len(entries))
	for _, entry := range entries {
		if skipStoreDataFile(entry) {
			continue
		}
		var file localProposalFile
		if err := readJSONFile(ctx, filepath.Join(s.localProposalsDir(), entry.Name()), &file); err != nil {
			return nil, err
		}
		if file.SchemaVersion != localMetadataStoreSchemaVersion || file.ProfileNamespace != s.namespace {
			return nil, ErrLocalStoreCorrupt
		}
		proposal, err := validateStoreProposal(s.namespace, file.Proposal, now)
		if err != nil {
			return nil, ErrLocalStoreCorrupt
		}
		out = append(out, proposal)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].ProposalID < out[j].ProposalID
	})
	return out, nil
}

func (s *LocalMetadataStore) SaveRemoteProposal(ctx context.Context, record RemoteProposalRecord) error {
	if s == nil {
		return ErrStoreUnavailable
	}
	record, err := validateRemoteProposalRecord(s.namespace, record, s.now())
	if err != nil {
		return err
	}
	path, err := s.remoteProposalPath(record.Proposal.ProposalID)
	if err != nil {
		return err
	}
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureInitializedLocked(ctx, now); err != nil {
		return err
	}
	file := remoteProposalFile{SchemaVersion: localMetadataStoreSchemaVersion, ProfileNamespace: s.namespace, Record: record}
	return writeJSONAtomic(ctx, path, file)
}

func (s *LocalMetadataStore) LoadRemoteProposal(ctx context.Context, proposalID string) (RemoteProposalRecord, error) {
	if s == nil {
		return RemoteProposalRecord{}, ErrStoreUnavailable
	}
	path, err := s.remoteProposalPath(proposalID)
	if err != nil {
		return RemoteProposalRecord{}, err
	}
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureInitializedLocked(ctx, now); err != nil {
		return RemoteProposalRecord{}, err
	}
	return s.readRemoteProposalLocked(ctx, path, now)
}

func (s *LocalMetadataStore) ListRemoteProposals(ctx context.Context) ([]RemoteProposalRecord, error) {
	if s == nil {
		return nil, ErrStoreUnavailable
	}
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureInitializedLocked(ctx, now); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(s.remoteProposalsDir())
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, ErrStoreUnavailable
	}
	out := make([]RemoteProposalRecord, 0, len(entries))
	for _, entry := range entries {
		if skipStoreDataFile(entry) {
			continue
		}
		record, err := s.readRemoteProposalLocked(ctx, filepath.Join(s.remoteProposalsDir(), entry.Name()), now)
		if err != nil {
			return nil, err
		}
		out = append(out, record)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Proposal.ProposalID < out[j].Proposal.ProposalID
	})
	return out, nil
}

func (s *LocalMetadataStore) SaveLastExchange(ctx context.Context, result ExchangeResult) error {
	if s == nil {
		return ErrStoreUnavailable
	}
	if err := validateExchangeResultForStore(s.namespace, result); err != nil {
		return err
	}
	record := LocalExchangeRecord{
		SchemaVersion:     LocalExchangeRecordSchemaVersion,
		ProfileNamespace:  s.namespace,
		Session:           result.Session,
		PushedSnapshots:   result.Push.PushedSnapshots,
		PushedProposals:   result.Push.PushedProposals,
		ReceivedSnapshots: result.Pull.ReceivedSnapshots,
		ReceivedProposals: result.Pull.ReceivedProposals,
		Rejected:          result.Pull.Rejected,
		ReviewRequired:    result.ReviewRequired || result.Session.ReviewRequired || result.Pull.ReviewRequired,
		StatusSummary:     safeSummary(result.Status.Summary, "profile sync exchange status"),
		RecordedAt:        s.now(),
	}
	for _, issue := range append(result.Issues, append(result.Push.Issues, result.Pull.Issues...)...) {
		record.Issues = append(record.Issues, syncIssue(issue.Code, issue.Message, issue.Blocking))
	}
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureInitializedLocked(ctx, now); err != nil {
		return err
	}
	return writeJSONAtomic(ctx, s.lastExchangePath(), record)
}

func (s *LocalMetadataStore) LoadLastExchange(ctx context.Context) (LocalExchangeRecord, error) {
	if s == nil {
		return LocalExchangeRecord{}, ErrStoreUnavailable
	}
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureInitializedLocked(ctx, now); err != nil {
		return LocalExchangeRecord{}, err
	}
	var record LocalExchangeRecord
	if err := readJSONFile(ctx, s.lastExchangePath(), &record); err != nil {
		return LocalExchangeRecord{}, err
	}
	if err := validateStoredExchangeRecord(s.namespace, record); err != nil {
		return LocalExchangeRecord{}, ErrLocalStoreCorrupt
	}
	record.StatusSummary = safeSummary(record.StatusSummary, "profile sync exchange status")
	for i, issue := range record.Issues {
		record.Issues[i] = syncIssue(issue.Code, issue.Message, issue.Blocking)
	}
	return record, nil
}
