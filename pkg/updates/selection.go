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
	if err := s.lockWorkflow(ctx); err != nil {
		return CheckResult{}, err
	}
	defer s.unlockWorkflow()
	for attempt := 0; attempt < 4; attempt++ {
		snapshot, err := s.beginOperation(ctx, true)
		if err != nil {
			return CheckResult{}, err
		}
		result, err := s.checkForUpdatesSnapshot(ctx, snapshot)
		if !errors.Is(err, ErrUpdateStateChanged) || snapshot.cfg.Source.SourceID != "" {
			return result, err
		}
		s.mu.Lock()
		current := s.currentLocked(snapshot)
		s.mu.Unlock()
		// Legacy retries follow a local configuration change only. Another
		// owner's committed state must never be overwritten by stale work.
		if current {
			return result, err
		}
	}
	return CheckResult{Message: "update check superseded by source change"}, nil
}

func (s *Service) checkForUpdatesSnapshot(ctx context.Context, snapshot serviceSnapshot) (CheckResult, error) {
	manifest, err := snapshot.provider.LoadManifest(ctx)
	if err != nil {
		if canceled := contextError(ctx); canceled != nil {
			return CheckResult{}, canceled
		}
		return CheckResult{}, sanitizeProviderError(err)
	}
	if err := contextError(ctx); err != nil {
		return CheckResult{}, err
	}
	artifact, err := selectArtifactForConfig(snapshot.cfg, manifest)
	if err != nil {
		if errors.Is(err, ErrNoUpdateAvailable) || errors.Is(err, ErrNoCompatibleArtifact) {
			// Historical valid candidates are cleared on these selection errors.
			// Invalid/quarantined candidates require a successful fresh result:
			// a failed check cannot repair their fault or activate a legacy root.
			invalid, inspectErr := snapshot.store.candidateProblem(ctx, snapshot.view)
			if invalid || inspectErr != nil || snapshot.view.fatal != nil {
				return CheckResult{}, err
			}
			snapshot.view.clearCandidate()
			if commitErr := s.publishOperation(ctx, snapshot); commitErr != nil {
				return CheckResult{}, commitErr
			}
		}
		return CheckResult{}, err
	}
	release := releaseFromSelection(manifest, artifact, time.Now().UTC(), sourceSummary(snapshot.cfg.Source))
	if compareVersions(manifest.Version, snapshot.cfg.CurrentVersion) <= 0 {
		snapshot.view.clearCandidate()
		if err := s.publishOperation(ctx, snapshot); err != nil {
			return CheckResult{}, err
		}
		return CheckResult{UpdateAvailable: false, LatestRelease: &release, Message: "no update available"}, nil
	}
	selected := selectedUpdate{SchemaVersion: schemaVersion, SourceKey: sourceKey(snapshot.cfg.Source), PolicyKey: policyKey(snapshot.cfg.Policy),
		Manifest: manifest, Artifact: artifact, UpdatedAt: time.Now().UTC()}
	invalid, inspectErr := snapshot.store.candidateProblem(ctx, snapshot.view)
	if inspectErr != nil {
		return CheckResult{}, inspectErr
	}
	previous, readErr := snapshot.view.selected.read()
	if invalid || readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
		snapshot.view.clearCandidate()
	}
	if readErr == nil && !sameSelectedUpdate(previous, selected) {
		snapshot.view.clearTransfers()
	}
	snapshot.view.candidateFault = false
	snapshot.view.selected = stored(selected)
	if err := s.publishOperation(ctx, snapshot); err != nil {
		return CheckResult{}, err
	}
	return CheckResult{UpdateAvailable: true, LatestRelease: &release, Message: "update available"}, nil
}

func (s *Service) selectionForSnapshot(ctx context.Context, snapshot serviceSnapshot, version string) (selectedUpdate, error) {
	version = strings.TrimSpace(version)
	selected, err := snapshot.view.selected.read()
	if err == nil && !snapshot.view.candidateFault && (version == "" || selected.Manifest.Version == version) && validateSelectedUpdate(snapshot.cfg, selected) == nil {
		return selected, nil
	}
	if _, err := s.checkForUpdatesSnapshot(ctx, snapshot); err != nil {
		return selectedUpdate{}, err
	}
	selected, err = snapshot.view.selected.read()
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
