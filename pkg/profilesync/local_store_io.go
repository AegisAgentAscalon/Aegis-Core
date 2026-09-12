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
	"strings"
	"time"

	"github.com/AegisAgentAscalon/aegis-core/internal/filepersist"
)

func (s *LocalMetadataStore) ensureInitialized(ctx context.Context) error {
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ensureInitializedLocked(ctx, now)
}

// Locked helpers receive an operation time sampled before taking the mutex.
// Host clock callbacks may reenter the store; they must never run under its lock.
func (s *LocalMetadataStore) ensureInitializedLocked(ctx context.Context, now time.Time) error {
	if err := storeContextError(ctx); err != nil {
		return err
	}
	if !validSyncName(s.namespace) || strings.TrimSpace(s.root) == "" {
		return ErrInvalidConfig
	}
	for _, dir := range []string{s.namespaceRoot(), s.remoteSnapshotsDir(), s.localProposalsDir(), s.remoteProposalsDir(), s.exchangesDir()} {
		if err := filepersist.EnsureDir(ctx, dir); err != nil {
			return ErrStoreUnavailable
		}
	}
	metaPath := s.metadataPath()
	var meta localStoreMetadataFile
	if err := readJSONFile(ctx, metaPath, &meta); err != nil {
		if errors.Is(err, ErrLocalStoreNotFound) {
			meta = localStoreMetadataFile{SchemaVersion: localMetadataStoreSchemaVersion, ProfileNamespace: s.namespace, CreatedAt: now, UpdatedAt: now}
			return writeJSONAtomic(ctx, metaPath, meta)
		}
		return err
	}
	if meta.SchemaVersion != localMetadataStoreSchemaVersion || meta.ProfileNamespace != s.namespace {
		return ErrLocalStoreCorrupt
	}
	return nil
}

func (s *LocalMetadataStore) readRemoteSnapshotLocked(ctx context.Context, path string, now time.Time) (RemoteSnapshotRecord, error) {
	var file remoteSnapshotFile
	if err := readJSONFile(ctx, path, &file); err != nil {
		return RemoteSnapshotRecord{}, err
	}
	if file.SchemaVersion != localMetadataStoreSchemaVersion || file.ProfileNamespace != s.namespace {
		return RemoteSnapshotRecord{}, ErrLocalStoreCorrupt
	}
	record, err := validateRemoteSnapshotRecord(s.namespace, file.Record, now)
	if err != nil {
		return RemoteSnapshotRecord{}, ErrLocalStoreCorrupt
	}
	return record, nil
}

func (s *LocalMetadataStore) readRemoteProposalLocked(ctx context.Context, path string, now time.Time) (RemoteProposalRecord, error) {
	var file remoteProposalFile
	if err := readJSONFile(ctx, path, &file); err != nil {
		return RemoteProposalRecord{}, err
	}
	if file.SchemaVersion != localMetadataStoreSchemaVersion || file.ProfileNamespace != s.namespace {
		return RemoteProposalRecord{}, ErrLocalStoreCorrupt
	}
	record, err := validateRemoteProposalRecord(s.namespace, file.Record, now)
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

func readJSONFile(ctx context.Context, path string, out any) error {
	err := filepersist.ReadJSON(ctx, path, maxLocalJSONFileBytes, out)
	if os.IsNotExist(err) {
		return ErrLocalStoreNotFound
	}
	if errors.Is(err, filepersist.ErrTooLarge) || errors.Is(err, filepersist.ErrInvalidJSON) {
		return ErrLocalStoreCorrupt
	}
	if err != nil {
		return ErrStoreUnavailable
	}
	return nil
}

func writeJSONAtomic(ctx context.Context, path string, value any) error {
	err := filepersist.Write(ctx, path, 0600, maxLocalJSONFileBytes, func(w io.Writer) error {
		encoder := json.NewEncoder(w)
		encoder.SetIndent("", "  ")
		return encoder.Encode(value)
	})
	if err != nil {
		return ErrStoreUnavailable
	}
	return nil
}
