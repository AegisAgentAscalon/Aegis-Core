package updates

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"time"

	"github.com/AegisAgentAscalon/aegis-core/internal/filelock"
	"github.com/AegisAgentAscalon/aegis-core/internal/filepersist"
	"github.com/AegisAgentAscalon/aegis-core/internal/generation"
)

type store struct {
	dir         string
	generations *generation.Store
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
	blobID        string
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
	blobID string
	StagedUpdate
	Manifest  *Manifest `json:"manifest,omitempty"`
	SourceKey string    `json:"source_key"`
	PolicyKey string    `json:"policy_key"`
}

type lifecycleRecord struct {
	SchemaVersion int                          `json:"schema_version"`
	Envelope      LifecycleEnvelope            `json:"envelope"`
	Idempotency   []lifecycleIdempotencyRecord `json:"idempotency"`
}

type lifecycleIdempotencyRecord struct {
	Key         string `json:"key"`
	Fingerprint string `json:"fingerprint"`
}

func newStore(cfg AppConfig) (*store, error) {
	dir := filepath.Join(cfg.StagingDir, cfg.AppID, cfg.Namespace, "updates")
	scope := stateScopeKey(cfg)
	if scope != "" {
		dir = filepath.Join(dir, scope)
	}
	owner := strings.Join([]string{"updates", cfg.AppID, cfg.Namespace, filepath.ToSlash(scope)}, "\x00")
	generations, err := generation.New(dir, owner)
	if err != nil {
		return nil, persistenceError(err)
	}
	dir, err = filepath.Abs(dir)
	if err != nil {
		return nil, ErrStorageUnavailable
	}
	st := &store{dir: dir, generations: generations}
	// Creating the sentinel must not briefly claim that an apply is executing.
	// This checked open neither takes a gate nor changes an existing file.
	sentinel, err := filepersist.OpenOrCreateRegular(context.Background(), st.applyPath())
	if err != nil {
		return nil, persistenceError(err)
	}
	if err := sentinel.Close(); err != nil {
		return nil, persistenceError(err)
	}
	return st, nil
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
func (s *store) blobDir() string      { return filepath.Join(s.dir, ".updates-blobs") }
func (s *store) applyPath() string    { return filepath.Join(s.dir, ".apply.lock") }

func (s *store) tryApply(ctx context.Context) (*filelock.Lock, error) {
	gate, err := filelock.TryAcquire(ctx, s.applyPath())
	if errors.Is(err, filelock.ErrBusy) {
		return nil, ErrApplyInProgress
	}
	return gate, persistenceError(err)
}

// Bound metadata reads with headroom for indented 4 MiB manifests and envelopes.
const maxMetadataBytes = 64 << 20

func persistenceError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, ErrContextCanceled) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return ErrContextCanceled
	}
	return ErrStorageUnavailable
}
