package updates

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/AegisAgentAscalon/aegis-core/internal/filepersist"
)

type store struct {
	dir string
}

type selectedUpdate struct {
	SchemaVersion int       `json:"schema_version"`
	SourceKey     string    `json:"source_key"`
	PolicyKey     string    `json:"policy_key"`
	Manifest      Manifest  `json:"manifest"`
	Artifact      Artifact  `json:"artifact"`
	UpdatedAt     time.Time `json:"updated_at"`
}

type downloadedUpdate struct {
	SchemaVersion int       `json:"schema_version"`
	SourceKey     string    `json:"source_key"`
	PolicyKey     string    `json:"policy_key"`
	Manifest      Manifest  `json:"manifest"`
	Artifact      Artifact  `json:"artifact"`
	ArtifactPath  string    `json:"artifact_path"`
	BytesWritten  int64     `json:"bytes_written"`
	DownloadedAt  time.Time `json:"downloaded_at"`
}

type verifiedUpdate struct {
	SchemaVersion int              `json:"schema_version"`
	Downloaded    downloadedUpdate `json:"downloaded"`
	VerifiedAt    time.Time        `json:"verified_at"`
}

// stagedUpdateRecord keeps lane provenance in private persisted metadata while
// the public StagedUpdate contract remains free of storage and policy keys.
type stagedUpdateRecord struct {
	StagedUpdate
	Manifest  *Manifest `json:"manifest,omitempty"`
	SourceKey string    `json:"source_key"`
	PolicyKey string    `json:"policy_key"`
}

func newStore(cfg AppConfig) (*store, error) {
	dir := filepath.Join(cfg.StagingDir, cfg.AppID, cfg.Namespace, "updates")
	if scope := stateScopeKey(cfg); scope != "" {
		dir = filepath.Join(dir, scope)
	}
	if err := secureMkdirAll(dir); err != nil {
		return nil, ErrStorageUnavailable
	}
	return &store{dir: dir}, nil
}

func (s *store) selectedPath() string   { return filepath.Join(s.dir, "selected_update.json") }
func (s *store) downloadedPath() string { return filepath.Join(s.dir, "downloaded_update.json") }
func (s *store) verifiedPath() string   { return filepath.Join(s.dir, "verified_update.json") }
func (s *store) stagedMetaPath() string { return filepath.Join(s.stagedDir(), "staged_update.json") }
func (s *store) lifecyclePath() string {
	return filepath.Join(s.stagedDir(), "lifecycle_envelope.json")
}
func (s *store) downloadsDir() string { return filepath.Join(s.dir, "downloads") }
func (s *store) stagedDir() string    { return filepath.Join(s.dir, "staged") }

func (s *store) readSelected(ctx context.Context) (selectedUpdate, error) {
	var out selectedUpdate
	err := readJSON(ctx, s.selectedPath(), &out)
	return out, err
}

func (s *store) writeSelected(ctx context.Context, v selectedUpdate) error {
	v.SchemaVersion = schemaVersion
	return writeJSON(ctx, s.selectedPath(), v)
}

func (s *store) readDownloaded(ctx context.Context) (downloadedUpdate, error) {
	var out downloadedUpdate
	err := readJSON(ctx, s.downloadedPath(), &out)
	return out, err
}

func (s *store) writeDownloaded(ctx context.Context, v downloadedUpdate) error {
	v.SchemaVersion = schemaVersion
	return writeJSON(ctx, s.downloadedPath(), v)
}

func (s *store) readVerified(ctx context.Context) (verifiedUpdate, error) {
	var out verifiedUpdate
	err := readJSON(ctx, s.verifiedPath(), &out)
	return out, err
}

func (s *store) writeVerified(ctx context.Context, v verifiedUpdate) error {
	v.SchemaVersion = schemaVersion
	return writeJSON(ctx, s.verifiedPath(), v)
}

func (s *store) readStaged(ctx context.Context) (stagedUpdateRecord, error) {
	var record stagedUpdateRecord
	err := readJSON(ctx, s.stagedMetaPath(), &record)
	if err != nil {
		return stagedUpdateRecord{}, err
	}
	out := record.StagedUpdate
	if out.ArtifactPath == "" && out.ArtifactName != "" {
		out.ArtifactPath = filepath.Join(s.stagedDir(), out.ArtifactName)
	}
	record.StagedUpdate = out
	return record, nil
}

func (s *store) writeStaged(ctx context.Context, v stagedUpdateRecord) error {
	return writeJSON(ctx, s.stagedMetaPath(), v)
}

func (s *store) readLifecycle(ctx context.Context) (lifecycleRecord, error) {
	var out lifecycleRecord
	err := readJSON(ctx, s.lifecyclePath(), &out)
	return out, err
}

func (s *store) writeLifecycle(ctx context.Context, v lifecycleRecord) error {
	v.SchemaVersion = lifecycleSchemaVersion
	return writeJSON(ctx, s.lifecyclePath(), v)
}

func (s *store) clearCandidateState() error {
	if err := removeFiles(s.selectedPath(), s.downloadedPath(), s.verifiedPath()); err != nil {
		return err
	}
	if err := os.RemoveAll(s.downloadsDir()); err != nil {
		return ErrStorageUnavailable
	}
	return nil
}

func (s *store) clearDownloadedState() error {
	if err := removeFiles(s.downloadedPath(), s.verifiedPath()); err != nil {
		return err
	}
	if err := os.RemoveAll(s.downloadsDir()); err != nil {
		return ErrStorageUnavailable
	}
	return nil
}

func removeFiles(paths ...string) error {
	for _, path := range paths {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return ErrStorageUnavailable
		}
	}
	return nil
}

// Bound metadata reads with headroom for indented 4 MiB manifests and envelopes.
const maxMetadataBytes = 64 << 20

func readJSON(ctx context.Context, path string, out any) error {
	err := filepersist.ReadJSON(ctx, path, maxMetadataBytes, out)
	if errors.Is(err, os.ErrNotExist) {
		return err
	}
	return persistenceError(err)
}

func writeJSON(ctx context.Context, path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return ErrStorageUnavailable
	}
	return writeFileAtomic(ctx, path, b, 0600)
}

func writeFileAtomic(ctx context.Context, path string, data []byte, perm os.FileMode) error {
	return persistenceError(filepersist.Write(ctx, path, perm, maxMetadataBytes, func(w io.Writer) error { _, err := w.Write(data); return err }))
}

func secureMkdirAll(dir string) error {
	return persistenceError(filepersist.EnsureDir(context.Background(), dir))
}

func persistenceError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return ErrContextCanceled
	}
	return ErrStorageUnavailable
}
