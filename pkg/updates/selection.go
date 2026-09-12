// Manifest selection and cached candidate orchestration.
package updates

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
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
	if err := contextError(ctx); err != nil {
		return CheckResult{}, err
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
	} else if errors.Is(readErr, ErrContextCanceled) {
		// Cancellation says nothing about the validity of the stored candidate.
		return CheckResult{}, readErr
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

func (s *Service) selectArtifact(manifest Manifest) (Artifact, error) {
	s.mu.Lock()
	cfg := cloneConfig(s.cfg)
	s.mu.Unlock()
	return selectArtifactForConfig(cfg, manifest)
}

func selectArtifactForConfig(cfg AppConfig, manifest Manifest) (Artifact, error) {
	if err := validateManifest(cfg, manifest); err != nil {
		return Artifact{}, err
	}
	for _, artifact := range sortedArtifacts(manifest.Artifacts) {
		if artifact.Platform != cfg.Platform || artifact.Architecture != cfg.Architecture {
			continue
		}
		if err := validateArtifact(cfg, artifact); err != nil {
			return Artifact{}, err
		}
		return artifact, nil
	}
	return Artifact{}, ErrNoCompatibleArtifact
}

func sameSelectedUpdate(a, b selectedUpdate) bool {
	if a.SourceKey != b.SourceKey || a.PolicyKey != b.PolicyKey {
		return false
	}
	left, leftErr := json.Marshal(struct {
		Manifest Manifest `json:"manifest"`
		Artifact Artifact `json:"artifact"`
	}{Manifest: a.Manifest, Artifact: a.Artifact})
	right, rightErr := json.Marshal(struct {
		Manifest Manifest `json:"manifest"`
		Artifact Artifact `json:"artifact"`
	}{Manifest: b.Manifest, Artifact: b.Artifact})
	return leftErr == nil && rightErr == nil && bytes.Equal(left, right)
}
