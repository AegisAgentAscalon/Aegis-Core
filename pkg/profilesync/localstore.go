package profilesync

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
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

type LocalMetadataStore struct {
	mu        sync.Mutex
	root      string
	namespace string
	clock     Clock
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
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureInitializedLocked(ctx); err != nil {
		return err
	}
	file := localSnapshotFile{
		SchemaVersion:    localMetadataStoreSchemaVersion,
		ProfileNamespace: s.namespace,
		Record:           LocalSnapshotRecord{Snapshot: snapshot, ExportedAt: s.now()},
	}
	return writeJSONAtomic(s.localSnapshotPath(), file)
}

func (s *LocalMetadataStore) LoadLocalSnapshot(ctx context.Context) (profilemesh.SignedProfileSnapshot, error) {
	if s == nil {
		return profilemesh.SignedProfileSnapshot{}, ErrStoreUnavailable
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureInitializedLocked(ctx); err != nil {
		return profilemesh.SignedProfileSnapshot{}, err
	}
	var file localSnapshotFile
	if err := readJSONFile(s.localSnapshotPath(), &file); err != nil {
		return profilemesh.SignedProfileSnapshot{}, err
	}
	if file.SchemaVersion != localMetadataStoreSchemaVersion || file.ProfileNamespace != s.namespace {
		return profilemesh.SignedProfileSnapshot{}, ErrLocalStoreCorrupt
	}
	snapshot, err := validateStoreSnapshot(s.namespace, file.Record.Snapshot, s.now())
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
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureInitializedLocked(ctx); err != nil {
		return err
	}
	file := remoteSnapshotFile{SchemaVersion: localMetadataStoreSchemaVersion, ProfileNamespace: s.namespace, Record: record}
	return writeJSONAtomic(path, file)
}

func (s *LocalMetadataStore) LoadRemoteSnapshot(ctx context.Context, snapshotID string) (RemoteSnapshotRecord, error) {
	if s == nil {
		return RemoteSnapshotRecord{}, ErrStoreUnavailable
	}
	path, err := s.snapshotRecordPath(snapshotID)
	if err != nil {
		return RemoteSnapshotRecord{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureInitializedLocked(ctx); err != nil {
		return RemoteSnapshotRecord{}, err
	}
	return s.readRemoteSnapshotLocked(path)
}

func (s *LocalMetadataStore) ListRemoteSnapshots(ctx context.Context) ([]RemoteSnapshotRecord, error) {
	if s == nil {
		return nil, ErrStoreUnavailable
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureInitializedLocked(ctx); err != nil {
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
		record, err := s.readRemoteSnapshotLocked(filepath.Join(s.remoteSnapshotsDir(), entry.Name()))
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
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureInitializedLocked(ctx); err != nil {
		return err
	}
	file := localProposalFile{SchemaVersion: localMetadataStoreSchemaVersion, ProfileNamespace: s.namespace, Proposal: proposal}
	return writeJSONAtomic(path, file)
}

func (s *LocalMetadataStore) LoadLocalProposals(ctx context.Context) ([]profilemesh.ProfileChangeProposal, error) {
	if s == nil {
		return nil, ErrStoreUnavailable
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureInitializedLocked(ctx); err != nil {
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
		if err := readJSONFile(filepath.Join(s.localProposalsDir(), entry.Name()), &file); err != nil {
			return nil, err
		}
		if file.SchemaVersion != localMetadataStoreSchemaVersion || file.ProfileNamespace != s.namespace {
			return nil, ErrLocalStoreCorrupt
		}
		proposal, err := validateStoreProposal(s.namespace, file.Proposal, s.now())
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
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureInitializedLocked(ctx); err != nil {
		return err
	}
	file := remoteProposalFile{SchemaVersion: localMetadataStoreSchemaVersion, ProfileNamespace: s.namespace, Record: record}
	return writeJSONAtomic(path, file)
}

func (s *LocalMetadataStore) LoadRemoteProposal(ctx context.Context, proposalID string) (RemoteProposalRecord, error) {
	if s == nil {
		return RemoteProposalRecord{}, ErrStoreUnavailable
	}
	path, err := s.remoteProposalPath(proposalID)
	if err != nil {
		return RemoteProposalRecord{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureInitializedLocked(ctx); err != nil {
		return RemoteProposalRecord{}, err
	}
	return s.readRemoteProposalLocked(path)
}

func (s *LocalMetadataStore) ListRemoteProposals(ctx context.Context) ([]RemoteProposalRecord, error) {
	if s == nil {
		return nil, ErrStoreUnavailable
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureInitializedLocked(ctx); err != nil {
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
		record, err := s.readRemoteProposalLocked(filepath.Join(s.remoteProposalsDir(), entry.Name()))
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

// PersistExchangeResult records a completed Profile Sync exchange in the local
// metadata store after confirming the result belongs to that store namespace.
func PersistExchangeResult(ctx context.Context, store *LocalMetadataStore, result ExchangeResult) error {
	if store == nil {
		return ErrStoreUnavailable
	}
	return store.SaveLastExchange(ctx, result)
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
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureInitializedLocked(ctx); err != nil {
		return err
	}
	return writeJSONAtomic(s.lastExchangePath(), record)
}

func (s *LocalMetadataStore) LoadLastExchange(ctx context.Context) (LocalExchangeRecord, error) {
	if s == nil {
		return LocalExchangeRecord{}, ErrStoreUnavailable
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureInitializedLocked(ctx); err != nil {
		return LocalExchangeRecord{}, err
	}
	var record LocalExchangeRecord
	if err := readJSONFile(s.lastExchangePath(), &record); err != nil {
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

func (s *LocalMetadataStore) ensureInitialized(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ensureInitializedLocked(ctx)
}

func (s *LocalMetadataStore) ensureInitializedLocked(ctx context.Context) error {
	if err := storeContextError(ctx); err != nil {
		return err
	}
	if !validSyncName(s.namespace) || strings.TrimSpace(s.root) == "" {
		return ErrInvalidConfig
	}
	for _, dir := range []string{s.namespaceRoot(), s.remoteSnapshotsDir(), s.localProposalsDir(), s.remoteProposalsDir(), s.exchangesDir()} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return ErrStoreUnavailable
		}
	}
	metaPath := s.metadataPath()
	var meta localStoreMetadataFile
	if err := readJSONFile(metaPath, &meta); err != nil {
		if errors.Is(err, ErrLocalStoreNotFound) {
			now := s.now()
			meta = localStoreMetadataFile{SchemaVersion: localMetadataStoreSchemaVersion, ProfileNamespace: s.namespace, CreatedAt: now, UpdatedAt: now}
			return writeJSONAtomic(metaPath, meta)
		}
		return err
	}
	if meta.SchemaVersion != localMetadataStoreSchemaVersion || meta.ProfileNamespace != s.namespace {
		return ErrLocalStoreCorrupt
	}
	return nil
}

func (s *LocalMetadataStore) readRemoteSnapshotLocked(path string) (RemoteSnapshotRecord, error) {
	var file remoteSnapshotFile
	if err := readJSONFile(path, &file); err != nil {
		return RemoteSnapshotRecord{}, err
	}
	if file.SchemaVersion != localMetadataStoreSchemaVersion || file.ProfileNamespace != s.namespace {
		return RemoteSnapshotRecord{}, ErrLocalStoreCorrupt
	}
	record, err := validateRemoteSnapshotRecord(s.namespace, file.Record, s.now())
	if err != nil {
		return RemoteSnapshotRecord{}, ErrLocalStoreCorrupt
	}
	return record, nil
}

func (s *LocalMetadataStore) readRemoteProposalLocked(path string) (RemoteProposalRecord, error) {
	var file remoteProposalFile
	if err := readJSONFile(path, &file); err != nil {
		return RemoteProposalRecord{}, err
	}
	if file.SchemaVersion != localMetadataStoreSchemaVersion || file.ProfileNamespace != s.namespace {
		return RemoteProposalRecord{}, ErrLocalStoreCorrupt
	}
	record, err := validateRemoteProposalRecord(s.namespace, file.Record, s.now())
	if err != nil {
		return RemoteProposalRecord{}, ErrLocalStoreCorrupt
	}
	return record, nil
}

func (s *LocalMetadataStore) now() time.Time {
	if s != nil && s.clock != nil {
		return s.clock.Now().UTC()
	}
	return time.Now().UTC()
}

func (s *LocalMetadataStore) namespaceRoot() string {
	return filepath.Join(s.root, s.namespace)
}

func (s *LocalMetadataStore) metadataPath() string {
	return filepath.Join(s.namespaceRoot(), "store_meta.json")
}

func (s *LocalMetadataStore) localSnapshotPath() string {
	return filepath.Join(s.namespaceRoot(), "snapshots", "local.json")
}

func (s *LocalMetadataStore) remoteSnapshotsDir() string {
	return filepath.Join(s.namespaceRoot(), "snapshots", "remote")
}

func (s *LocalMetadataStore) snapshotRecordPath(snapshotID string) (string, error) {
	name, err := localStoreFileName(snapshotID, ErrSnapshotRejected)
	if err != nil {
		return "", err
	}
	return filepath.Join(s.remoteSnapshotsDir(), name), nil
}

func (s *LocalMetadataStore) localProposalsDir() string {
	return filepath.Join(s.namespaceRoot(), "proposals", "local")
}

func (s *LocalMetadataStore) localProposalPath(proposalID string) (string, error) {
	name, err := localStoreFileName(proposalID, ErrProposalRejected)
	if err != nil {
		return "", err
	}
	return filepath.Join(s.localProposalsDir(), name), nil
}

func (s *LocalMetadataStore) remoteProposalsDir() string {
	return filepath.Join(s.namespaceRoot(), "proposals", "remote")
}

func (s *LocalMetadataStore) remoteProposalPath(proposalID string) (string, error) {
	name, err := localStoreFileName(proposalID, ErrProposalRejected)
	if err != nil {
		return "", err
	}
	return filepath.Join(s.remoteProposalsDir(), name), nil
}

func (s *LocalMetadataStore) exchangesDir() string {
	return filepath.Join(s.namespaceRoot(), "exchanges")
}

func (s *LocalMetadataStore) lastExchangePath() string {
	return filepath.Join(s.exchangesDir(), "last_exchange.json")
}

func localStoreFileName(id string, invalidErr error) (string, error) {
	id = strings.TrimSpace(id)
	if !validSyncID(id) {
		return "", invalidErr
	}
	var b strings.Builder
	for _, r := range id {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '_', r == '-':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	sum := sha256.Sum256([]byte(id))
	stem := strings.Trim(b.String(), ". ")
	if stem == "" {
		stem = "record"
	}
	return fmt.Sprintf("%s-%s.json", stem, hex.EncodeToString(sum[:6])), nil
}

func skipStoreDataFile(entry os.DirEntry) bool {
	name := entry.Name()
	return entry.IsDir() || strings.HasPrefix(name, ".tmp-") || !strings.HasSuffix(name, ".json")
}

func readJSONFile(path string, out any) error {
	file, err := os.Open(path)
	if os.IsNotExist(err) {
		return ErrLocalStoreNotFound
	}
	if err != nil {
		return ErrStoreUnavailable
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, maxLocalJSONFileBytes+1))
	if err != nil {
		return ErrStoreUnavailable
	}
	if len(raw) == 0 || len(raw) > maxLocalJSONFileBytes {
		return ErrLocalStoreCorrupt
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return ErrLocalStoreCorrupt
	}
	return nil
}

func writeJSONAtomic(path string, value any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return ErrStoreUnavailable
	}
	tmp := filepath.Join(filepath.Dir(path), fmt.Sprintf(".tmp-%s-%d", filepath.Base(path), time.Now().UnixNano()))
	file, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return ErrStoreUnavailable
	}
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	encodeErr := encoder.Encode(value)
	syncErr := file.Sync()
	closeErr := file.Close()
	if encodeErr != nil || syncErr != nil || closeErr != nil {
		_ = os.Remove(tmp)
		return ErrStoreUnavailable
	}
	if err := os.Rename(tmp, path); err != nil {
		if removeErr := os.Remove(path); removeErr != nil && !os.IsNotExist(removeErr) {
			_ = os.Remove(tmp)
			return ErrStoreUnavailable
		}
		if err := os.Rename(tmp, path); err != nil {
			_ = os.Remove(tmp)
			return ErrStoreUnavailable
		}
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
