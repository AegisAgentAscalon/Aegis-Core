// Artifact download orchestration and candidate metadata.
package updates

import (
	"context"
	"os"
	"path/filepath"
	"time"
)

func (s *Service) DownloadUpdate(ctx context.Context, version string) (DownloadResult, error) {
	ctx = normalizeContext(ctx)
	if err := contextError(ctx); err != nil {
		return DownloadResult{}, err
	}
	s.workflowMu.Lock()
	defer s.workflowMu.Unlock()
	snapshot, err := s.operationSnapshot()
	if err != nil {
		return DownloadResult{}, err
	}
	selected, err := s.selectionForSnapshot(ctx, snapshot, version)
	if err != nil {
		return DownloadResult{}, err
	}
	artifact := selected.Artifact
	if err := validateArtifact(snapshot.cfg, artifact); err != nil {
		return DownloadResult{}, err
	}
	if err := secureMkdirAll(snapshot.store.downloadsDir()); err != nil {
		return DownloadResult{}, ErrStorageUnavailable
	}
	temp, err := os.CreateTemp(snapshot.store.downloadsDir(), ".download-*")
	if err != nil {
		return DownloadResult{}, ErrStorageUnavailable
	}
	tmpPath := temp.Name()
	defer os.Remove(tmpPath)
	if err := temp.Close(); err != nil {
		return DownloadResult{}, ErrStorageUnavailable
	}
	finalPath := filepath.Join(snapshot.store.downloadsDir(), artifact.Filename)
	n, err := downloadArtifactFor(ctx, snapshot.cfg, snapshot.client, artifact, tmpPath)
	if err != nil {
		return DownloadResult{}, err
	}
	if (artifact.Size > 0 && n != artifact.Size) || (snapshot.cfg.Policy.MaximumArtifactSize > 0 && n > snapshot.cfg.Policy.MaximumArtifactSize) {
		return DownloadResult{}, ErrDownloadFailed
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.applyInProgress {
		return DownloadResult{}, ErrApplyInProgress
	}
	if !s.currentLocked(snapshot) {
		return DownloadResult{}, ErrUpdateStateChanged
	}
	if err := replaceFile(ctx, tmpPath, finalPath); err != nil {
		return DownloadResult{}, err
	}
	meta := downloadedUpdate{
		SchemaVersion: schemaVersion, SourceKey: selected.SourceKey, PolicyKey: selected.PolicyKey,
		Manifest: selected.Manifest, Artifact: artifact, ArtifactPath: finalPath,
		BytesWritten: n, DownloadedAt: time.Now().UTC(),
	}
	if err := snapshot.store.writeDownloaded(ctx, meta); err != nil {
		return DownloadResult{}, err
	}
	return DownloadResult{Version: selected.Manifest.Version, ArtifactName: artifact.Filename, BytesWritten: n, Message: "update downloaded"}, nil
}
