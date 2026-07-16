package updates

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"
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

func (s *store) readSelected() (selectedUpdate, error) {
	var out selectedUpdate
	err := readJSON(s.selectedPath(), &out)
	return out, err
}

func (s *store) writeSelected(v selectedUpdate) error {
	v.SchemaVersion = SchemaVersion
	return writeJSON(s.selectedPath(), v)
}

func (s *store) readDownloaded() (downloadedUpdate, error) {
	var out downloadedUpdate
	err := readJSON(s.downloadedPath(), &out)
	return out, err
}

func (s *store) writeDownloaded(v downloadedUpdate) error {
	v.SchemaVersion = SchemaVersion
	return writeJSON(s.downloadedPath(), v)
}

func (s *store) readVerified() (verifiedUpdate, error) {
	var out verifiedUpdate
	err := readJSON(s.verifiedPath(), &out)
	return out, err
}

func (s *store) writeVerified(v verifiedUpdate) error {
	v.SchemaVersion = SchemaVersion
	return writeJSON(s.verifiedPath(), v)
}

func (s *store) readStaged() (StagedUpdate, error) {
	var out StagedUpdate
	err := readJSON(s.stagedMetaPath(), &out)
	if err != nil {
		return StagedUpdate{}, err
	}
	if out.ArtifactPath == "" && out.ArtifactName != "" {
		out.ArtifactPath = filepath.Join(s.stagedDir(), out.ArtifactName)
	}
	return out, nil
}

func (s *store) writeStaged(v StagedUpdate) error {
	return writeJSON(s.stagedMetaPath(), v)
}

func (s *store) readLifecycle() (lifecycleRecord, error) {
	var out lifecycleRecord
	err := readJSON(s.lifecyclePath(), &out)
	return out, err
}

func (s *store) writeLifecycle(v lifecycleRecord) error {
	v.SchemaVersion = lifecycleSchemaVersion
	return writeJSON(s.lifecyclePath(), v)
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

func readJSON(path string, out any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return err
		}
		return ErrStorageUnavailable
	}
	if err := json.Unmarshal(b, out); err != nil {
		return ErrStorageUnavailable
	}
	return nil
}

func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return ErrStorageUnavailable
	}
	return writeFileAtomic(path, b, 0o600)
}

func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if err := secureMkdirAll(dir); err != nil {
		return ErrStorageUnavailable
	}
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return ErrStorageUnavailable
	}
	name := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(name)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return ErrStorageUnavailable
	}
	if err := tmp.Close(); err != nil {
		return ErrStorageUnavailable
	}
	if err := os.Chmod(name, perm); err != nil {
		return ErrStorageUnavailable
	}
	if err := replaceFile(name, path); err != nil {
		return ErrStorageUnavailable
	}
	cleanup = false
	return nil
}

func secureMkdirAll(dir string) error {
	absolute, err := filepath.Abs(dir)
	if err != nil {
		return ErrStorageUnavailable
	}
	volume := filepath.VolumeName(absolute)
	rest := strings.TrimPrefix(absolute, volume)
	parts := strings.FieldsFunc(rest, func(r rune) bool { return r == '/' || r == '\\' })
	current := volume + string(filepath.Separator)
	if volume == "" {
		current = string(filepath.Separator)
	}
	firstMissing := len(parts)
	for index, part := range parts {
		current = filepath.Join(current, part)
		info, statErr := os.Lstat(current)
		if errors.Is(statErr, os.ErrNotExist) {
			firstMissing = index
			break
		}
		if statErr != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return ErrStorageUnavailable
		}
	}
	if err := os.MkdirAll(absolute, 0o700); err != nil {
		return ErrStorageUnavailable
	}
	current = volume + string(filepath.Separator)
	if volume == "" {
		current = string(filepath.Separator)
	}
	for index, part := range parts {
		current = filepath.Join(current, part)
		info, statErr := os.Lstat(current)
		if statErr != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return ErrStorageUnavailable
		}
		// Repair only package-created directories (and the requested final
		// directory), never caller-owned ancestors such as /tmp or a home dir.
		if index >= firstMissing || index == len(parts)-1 {
			if err := os.Chmod(current, 0o700); err != nil {
				return ErrStorageUnavailable
			}
		}
	}
	return nil
}
