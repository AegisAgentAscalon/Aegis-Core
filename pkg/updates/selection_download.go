// Manifest selection and artifact download orchestration.
package updates

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func (s *Service) CheckForUpdates(ctx context.Context) (CheckResult, error) {
	ctx = normalizeContext(ctx)
	if err := contextError(ctx); err != nil {
		return CheckResult{}, err
	}
	s.workflowMu.Lock()
	defer s.workflowMu.Unlock()
	for attempt := 0; attempt < 4; attempt++ {
		snapshot, err := s.operationSnapshot()
		if err != nil {
			return CheckResult{}, err
		}
		result, err := s.checkForUpdatesSnapshot(ctx, snapshot)
		if !errors.Is(err, ErrUpdateStateChanged) || snapshot.cfg.Source.SourceID != "" {
			return result, err
		}
	}
	// Legacy callers did not opt into explicit source identity. A concurrent
	// source change supersedes the check without becoming a fatal error.
	return CheckResult{Message: "update check superseded by source change"}, nil
}

func (s *Service) checkForUpdatesSnapshot(ctx context.Context, snapshot serviceSnapshot) (CheckResult, error) {
	manifest, err := snapshot.provider.LoadManifest(ctx)
	if err != nil {
		return CheckResult{}, sanitizeProviderError(err)
	}
	artifact, err := selectArtifactForConfig(snapshot.cfg, manifest)
	if err != nil {
		if errors.Is(err, ErrNoUpdateAvailable) || errors.Is(err, ErrNoCompatibleArtifact) {
			s.mu.Lock()
			defer s.mu.Unlock()
			if !s.currentLocked(snapshot) {
				return CheckResult{}, ErrUpdateStateChanged
			}
			if clearErr := snapshot.store.clearCandidateState(); clearErr != nil {
				return CheckResult{}, clearErr
			}
		}
		return CheckResult{}, err
	}
	release := releaseFromSelection(manifest, artifact, time.Now().UTC(), sourceSummary(snapshot.cfg.Source))
	available := compareVersions(manifest.Version, snapshot.cfg.CurrentVersion) > 0
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.applyInProgress {
		return CheckResult{}, ErrApplyInProgress
	}
	if !s.currentLocked(snapshot) {
		return CheckResult{}, ErrUpdateStateChanged
	}
	if !available {
		if err := snapshot.store.clearCandidateState(); err != nil {
			return CheckResult{}, err
		}
		return CheckResult{UpdateAvailable: false, LatestRelease: &release, Message: "no update available"}, nil
	}
	selected := selectedUpdate{
		SchemaVersion: schemaVersion,
		SourceKey:     sourceKey(snapshot.cfg.Source), PolicyKey: policyKey(snapshot.cfg.Policy),
		Manifest: manifest, Artifact: artifact, UpdatedAt: time.Now().UTC(),
	}
	if previous, readErr := snapshot.store.readSelected(ctx); readErr == nil {
		if !sameSelectedUpdate(previous, selected) {
			if err := snapshot.store.clearDownloadedState(); err != nil {
				return CheckResult{}, err
			}
		}
	} else if !errors.Is(readErr, os.ErrNotExist) {
		if err := snapshot.store.clearCandidateState(); err != nil {
			return CheckResult{}, err
		}
	}
	if err := snapshot.store.writeSelected(ctx, selected); err != nil {
		return CheckResult{}, err
	}
	return CheckResult{UpdateAvailable: true, LatestRelease: &release, Message: "update available"}, nil
}

func (s *Service) selectionForSnapshot(ctx context.Context, snapshot serviceSnapshot, version string) (selectedUpdate, error) {
	version = strings.TrimSpace(version)
	selected, err := snapshot.store.readSelected(ctx)
	if err == nil && (version == "" || selected.Manifest.Version == version) && validateSelectedUpdate(snapshot.cfg, selected) == nil {
		return selected, nil
	}
	if _, err := s.checkForUpdatesSnapshot(ctx, snapshot); err != nil {
		return selectedUpdate{}, err
	}
	selected, err = snapshot.store.readSelected(ctx)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return selectedUpdate{}, ErrNoUpdateAvailable
		}
		return selectedUpdate{}, err
	}
	if version != "" && selected.Manifest.Version != version {
		return selectedUpdate{}, ErrNoUpdateAvailable
	}
	if err := validateSelectedUpdate(snapshot.cfg, selected); err != nil {
		return selectedUpdate{}, err
	}
	return selected, nil
}

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
		_ = os.Remove(tmpPath)
		return DownloadResult{}, err
	}
	if (artifact.Size > 0 && n != artifact.Size) || (snapshot.cfg.Policy.MaximumArtifactSize > 0 && n > snapshot.cfg.Policy.MaximumArtifactSize) {
		_ = os.Remove(tmpPath)
		return DownloadResult{}, ErrDownloadFailed
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.applyInProgress {
		_ = os.Remove(tmpPath)
		return DownloadResult{}, ErrApplyInProgress
	}
	if !s.currentLocked(snapshot) {
		_ = os.Remove(tmpPath)
		return DownloadResult{}, ErrUpdateStateChanged
	}
	if err := replaceFile(ctx, tmpPath, finalPath); err != nil {
		_ = os.Remove(tmpPath)
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

func (s *Service) VerifyUpdate(ctx context.Context, version string) (VerifyResult, error) {
	ctx = normalizeContext(ctx)
	if err := contextError(ctx); err != nil {
		return VerifyResult{}, err
	}
	s.workflowMu.Lock()
	defer s.workflowMu.Unlock()
	snapshot, err := s.operationSnapshot()
	if err != nil {
		return VerifyResult{}, err
	}
	return s.verifyUpdateSnapshot(snapshot, version)
}

func (s *Service) verifyUpdateSnapshot(snapshot serviceSnapshot, version string) (VerifyResult, error) {
	downloaded, err := snapshot.store.readDownloaded(context.Background())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return VerifyResult{}, ErrVerificationFailed
		}
		return VerifyResult{}, err
	}
	if version != "" && downloaded.Manifest.Version != strings.TrimSpace(version) {
		return VerifyResult{}, ErrVerificationFailed
	}
	if err := validateDownloadedUpdateFor(snapshot.cfg, snapshot.store, downloaded); err != nil {
		return VerifyResult{}, err
	}
	got, err := fileSHA256(downloaded.ArtifactPath)
	if err != nil || !strings.EqualFold(got, downloaded.Artifact.SHA256) {
		return VerifyResult{}, ErrVerificationFailed
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.applyInProgress {
		return VerifyResult{}, ErrApplyInProgress
	}
	if !s.currentLocked(snapshot) {
		return VerifyResult{}, ErrUpdateStateChanged
	}
	verified := verifiedUpdate{SchemaVersion: schemaVersion, Downloaded: downloaded, VerifiedAt: time.Now().UTC()}
	if err := snapshot.store.writeVerified(context.Background(), verified); err != nil {
		return VerifyResult{}, err
	}
	return VerifyResult{Version: downloaded.Manifest.Version, ArtifactName: downloaded.Artifact.Filename, OK: true, Message: "update verified"}, nil
}
