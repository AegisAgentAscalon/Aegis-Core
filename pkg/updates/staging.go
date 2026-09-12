// Staging and app-owned handoff planning.
package updates

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func (s *Service) StageUpdate(ctx context.Context, version string) (StageResult, error) {
	ctx = normalizeContext(ctx)
	if err := contextError(ctx); err != nil {
		return StageResult{}, err
	}
	s.workflowMu.Lock()
	defer s.workflowMu.Unlock()
	snapshot, err := s.operationSnapshot()
	if err != nil {
		return StageResult{}, err
	}
	verified, err := snapshot.store.readVerified(ctx)
	if err != nil {
		if _, verifyErr := s.verifyUpdateSnapshot(snapshot, version); verifyErr != nil {
			return StageResult{}, verifyErr
		}
		verified, err = snapshot.store.readVerified(ctx)
	}
	if err != nil {
		return StageResult{}, err
	}
	if version != "" && verified.Downloaded.Manifest.Version != strings.TrimSpace(version) {
		return StageResult{}, ErrVerificationFailed
	}
	if verified.SchemaVersion != schemaVersion || verified.VerifiedAt.IsZero() {
		return StageResult{}, ErrStorageUnavailable
	}
	if err := validateDownloadedUpdateFor(snapshot.cfg, snapshot.store, verified.Downloaded); err != nil {
		return StageResult{}, err
	}
	got, err := fileSHA256(verified.Downloaded.ArtifactPath)
	if err != nil || !strings.EqualFold(got, verified.Downloaded.Artifact.SHA256) {
		return StageResult{}, ErrVerificationFailed
	}
	target := filepath.Join(snapshot.store.stagedDir(), verified.Downloaded.Artifact.Filename)
	staged := stagedUpdateRecord{
		StagedUpdate: StagedUpdate{
			Source: sourceSummary(snapshot.cfg.Source),
			AppID:  snapshot.cfg.AppID, Version: verified.Downloaded.Manifest.Version,
			Channel: verified.Downloaded.Manifest.Channel, Platform: verified.Downloaded.Artifact.Platform,
			Architecture: verified.Downloaded.Artifact.Architecture, ArtifactName: verified.Downloaded.Artifact.Filename,
			ArtifactPath: target, SHA256: verified.Downloaded.Artifact.SHA256, Size: verified.Downloaded.BytesWritten,
			StagedAt: time.Now().UTC(), RequiredRestart: verified.Downloaded.Manifest.RequiredRestart,
			ApplyBehavior: verified.Downloaded.Manifest.ApplyBehavior,
		},
		Manifest:  &verified.Downloaded.Manifest,
		SourceKey: sourceKey(snapshot.cfg.Source), PolicyKey: policyKey(snapshot.cfg.Policy),
	}
	if existing, handled, err := s.checkLifecycleBeforeRestage(ctx, snapshot.cfg, snapshot.store, staged, time.Now().UTC()); err != nil {
		return StageResult{}, err
	} else if handled {
		return existing, nil
	}
	if err := secureMkdirAll(snapshot.store.stagedDir()); err != nil {
		return StageResult{}, ErrStorageUnavailable
	}
	pendingFile, err := os.CreateTemp(snapshot.store.stagedDir(), ".pending-*")
	if err != nil {
		return StageResult{}, ErrStorageUnavailable
	}
	pending := pendingFile.Name()
	defer os.Remove(pending)
	if err := pendingFile.Close(); err != nil {
		return StageResult{}, ErrStorageUnavailable
	}
	if err := copyFileAtomic(ctx, verified.Downloaded.ArtifactPath, pending); err != nil {
		return StageResult{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.applyInProgress {
		return StageResult{}, ErrApplyInProgress
	}
	if !s.currentLocked(snapshot) {
		return StageResult{}, ErrUpdateStateChanged
	}
	if err := contextError(ctx); err != nil {
		return StageResult{}, err
	}
	if existing, handled, err := s.checkLifecycleBeforeRestage(ctx, snapshot.cfg, snapshot.store, staged, time.Now().UTC()); err != nil {
		return StageResult{}, err
	} else if handled {
		return existing, nil
	}
	if err := replaceFile(ctx, pending, target); err != nil {
		return StageResult{}, err
	}
	if err := validateStagedUpdateReadyFor(ctx, snapshot.cfg, snapshot.store, staged, time.Now().UTC()); err != nil {
		_ = os.Remove(target)
		return StageResult{}, err
	}
	if err := snapshot.store.writeStaged(ctx, staged); err != nil {
		return StageResult{}, err
	}
	if err := snapshot.store.writeLifecycle(ctx, newLifecycleRecord(staged.StagedUpdate, time.Now().UTC())); err != nil {
		return StageResult{}, err
	}
	return StageResult{Version: staged.Version, ArtifactName: staged.ArtifactName, Staged: true, Message: "update staged"}, nil
}

func (s *Service) DescribeStagedUpdate(ctx context.Context) (StagedUpdateSummary, error) {
	ctx = normalizeContext(ctx)
	if err := contextError(ctx); err != nil {
		return StagedUpdateSummary{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	stagedRecord, err := s.store.readStaged(ctx)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return StagedUpdateSummary{}, ErrStagedUpdateNotFound
		}
		return StagedUpdateSummary{}, ErrStorageUnavailable
	}
	if err := validateStagedUpdateReadyFor(ctx, s.cfg, s.store, stagedRecord, time.Now().UTC()); err != nil {
		return StagedUpdateSummary{}, err
	}
	return stagedSummaryFrom(stagedRecord.StagedUpdate), nil
}

func (s *Service) BuildApplyPlan(ctx context.Context) (ApplyPlan, error) {
	ctx = normalizeContext(ctx)
	if err := contextError(ctx); err != nil {
		return ApplyPlan{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	stagedRecord, err := s.store.readStaged(ctx)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return ApplyPlan{}, ErrStagedUpdateNotFound
		}
		return ApplyPlan{}, ErrStorageUnavailable
	}
	if err := validateStagedUpdateReadyFor(ctx, s.cfg, s.store, stagedRecord, time.Now().UTC()); err != nil {
		return ApplyPlan{}, err
	}
	staged := stagedRecord.StagedUpdate
	return ApplyPlan{
		Source: staged.Source, Version: staged.Version, ArtifactName: staged.ArtifactName,
		RequiredRestart: staged.RequiredRestart, ApplyBehavior: staged.ApplyBehavior, AppOwnedApply: true,
		Summary: "staged update is ready for app-owned apply",
		Steps:   []string{"consumer app reviews the staged update", "consumer app runs its own apply strategy", "consumer app handles shutdown, restart, and rollback policy"},
	}, nil
}

func (s *Service) ClearStagedUpdate(ctx context.Context) (ClearResult, error) {
	ctx = normalizeContext(ctx)
	if err := contextError(ctx); err != nil {
		return ClearResult{}, err
	}
	s.workflowMu.Lock()
	defer s.workflowMu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.applyInProgress {
		return ClearResult{}, ErrApplyInProgress
	}
	if err := os.RemoveAll(s.store.stagedDir()); err != nil {
		return ClearResult{}, ErrStorageUnavailable
	}
	if err := secureMkdirAll(s.store.stagedDir()); err != nil {
		return ClearResult{}, ErrStorageUnavailable
	}
	if err := removeFiles(s.store.verifiedPath()); err != nil {
		return ClearResult{}, err
	}
	return ClearResult{Cleared: true, Message: "staged update cleared"}, nil
}
