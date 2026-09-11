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
)

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
