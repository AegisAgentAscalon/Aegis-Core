// Artifact download orchestration and candidate metadata.
package updates

import (
	"context"
	"time"
)

func (s *Service) DownloadUpdate(ctx context.Context, version string) (DownloadResult, error) {
	ctx = normalizeContext(ctx)
	if err := contextError(ctx); err != nil {
		return DownloadResult{}, err
	}
	s.workflowMu.Lock()
	defer s.workflowMu.Unlock()
	snapshot, err := s.beginOperation(ctx, true)
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
	id, target, err := snapshot.store.beginBlob(ctx, artifact.Filename)
	if err != nil {
		return DownloadResult{}, err
	}
	committed := false
	defer func() {
		if !committed {
			snapshot.store.discardPrepared([]string{id})
		}
	}()
	n, err := downloadArtifactFor(ctx, snapshot.cfg, snapshot.client, artifact, target)
	if err != nil {
		return DownloadResult{}, err
	}
	if (artifact.Size > 0 && n != artifact.Size) || (snapshot.cfg.Policy.MaximumArtifactSize > 0 && n > snapshot.cfg.Policy.MaximumArtifactSize) {
		return DownloadResult{}, ErrDownloadFailed
	}
	blob, err := snapshot.store.finishBlob(ctx, id, artifact.Filename, "download")
	if err != nil {
		return DownloadResult{}, err
	}
	if blob.Size != n {
		return DownloadResult{}, ErrDownloadFailed
	}
	snapshot.view.blobs[id] = blob
	snapshot.view.downloaded = stored(downloadedUpdate{blobID: id, SchemaVersion: schemaVersion, SourceKey: selected.SourceKey, PolicyKey: selected.PolicyKey,
		Manifest: selected.Manifest, Artifact: artifact, ArtifactPath: target, BytesWritten: n, DownloadedAt: time.Now().UTC()})
	if verified := snapshot.view.verified.value; verified != nil && samePath(verified.Downloaded.Artifact.Filename, artifact.Filename) {
		snapshot.view.verified = recordSlot[verifiedUpdate]{}
	}
	if err := s.publishOperation(ctx, snapshot); err != nil {
		return DownloadResult{}, err
	}
	committed = true
	return DownloadResult{Version: selected.Manifest.Version, ArtifactName: artifact.Filename, BytesWritten: n, Message: "update downloaded"}, nil
}
