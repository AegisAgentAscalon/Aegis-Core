// Staging and app-owned handoff planning.
package updates

import (
	"context"
	"errors"
	"os"
	"strings"
	"time"
)

func (s *Service) StageUpdate(ctx context.Context, version string) (StageResult, error) {
	ctx = normalizeContext(ctx)
	if err := contextError(ctx); err != nil {
		return StageResult{}, err
	}
	if err := s.lockWorkflow(ctx); err != nil {
		return StageResult{}, err
	}
	defer s.unlockWorkflow()
	snapshot, err := s.beginOperation(ctx, true)
	if err != nil {
		return StageResult{}, err
	}
	if err := candidateAdmission(ctx, snapshot); err != nil {
		return StageResult{}, err
	}
	if snapshot.view.token == "" {
		if err := snapshot.store.resolveLegacyStage(ctx, snapshot.cfg, snapshot.view); err != nil {
			return StageResult{}, err
		}
	}
	verified, err := snapshot.view.verified.read()
	if err != nil {
		if _, err := verifyUpdateSnapshot(ctx, snapshot, version); err != nil {
			return StageResult{}, err
		}
		verified, err = snapshot.view.verified.read()
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
	got, err := hashFile(ctx, verified.Downloaded.ArtifactPath)
	if errors.Is(err, ErrContextCanceled) {
		return StageResult{}, err
	}
	if err != nil || !strings.EqualFold(got, verified.Downloaded.Artifact.SHA256) {
		return StageResult{}, ErrVerificationFailed
	}
	staged := stagedUpdateRecord{
		StagedUpdate: StagedUpdate{
			Source: sourceSummary(snapshot.cfg.Source), AppID: snapshot.cfg.AppID, Version: verified.Downloaded.Manifest.Version,
			Channel: verified.Downloaded.Manifest.Channel, Platform: verified.Downloaded.Artifact.Platform,
			Architecture: verified.Downloaded.Artifact.Architecture, ArtifactName: verified.Downloaded.Artifact.Filename,
			SHA256: verified.Downloaded.Artifact.SHA256, Size: verified.Downloaded.BytesWritten,
			StagedAt: time.Now().UTC(), RequiredRestart: verified.Downloaded.Manifest.RequiredRestart, ApplyBehavior: verified.Downloaded.Manifest.ApplyBehavior,
		},
		Manifest: &verified.Downloaded.Manifest, SourceKey: sourceKey(snapshot.cfg.Source), PolicyKey: policyKey(snapshot.cfg.Policy),
	}
	if existing, handled, err := checkLifecycleBeforeRestage(ctx, snapshot, staged, time.Now().UTC()); err != nil {
		return StageResult{}, err
	} else if handled {
		return existing, nil
	}
	prepared := []string{}
	committed := false
	defer func() {
		if !committed {
			snapshot.store.discardPrepared(prepared)
		}
	}()
	id, blob, err := snapshot.store.copyBlob(ctx, verified.Downloaded.ArtifactPath, staged.ArtifactName, "staged", &prepared)
	if err != nil {
		return StageResult{}, err
	}
	staged.blobID, staged.ArtifactPath = id, snapshot.store.blobPath(id, staged.ArtifactName)
	snapshot.view.blobs[id] = blob
	op, err := s.lockOperation(ctx, snapshot, true)
	if err != nil {
		return StageResult{}, err
	}
	defer op.close()
	if existing, handled, err := checkLifecycleBeforeRestage(ctx, snapshot, staged, time.Now().UTC()); err != nil {
		return StageResult{}, err
	} else if handled {
		return existing, nil
	}
	if err := validateStagedUpdateReadyFor(ctx, snapshot.cfg, snapshot.store, staged, time.Now().UTC()); err != nil {
		return StageResult{}, err
	}
	snapshot.view.staged = stored(staged)
	snapshot.view.lifecycle = stored(newLifecycleRecord(staged.StagedUpdate, time.Now().UTC()))
	if err := snapshot.store.publish(ctx, op.guard, snapshot.cfg, snapshot.view, false); err != nil {
		return StageResult{}, err
	}
	committed = true
	return StageResult{Version: staged.Version, ArtifactName: staged.ArtifactName, Staged: true, Message: "update staged"}, nil
}

func readyStaged(ctx context.Context, snapshot serviceSnapshot, now time.Time) (stagedUpdateRecord, error) {
	staged, err := stagedForSnapshot(snapshot)
	if err != nil {
		return stagedUpdateRecord{}, err
	}
	if err := validateStagedUpdateReadyFor(ctx, snapshot.cfg, snapshot.store, staged, now); err != nil {
		return stagedUpdateRecord{}, err
	}
	return staged, nil
}

func stagedForSnapshot(snapshot serviceSnapshot) (stagedUpdateRecord, error) {
	if _, err := snapshot.view.staged.read(); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return stagedUpdateRecord{}, ErrStagedUpdateNotFound
		}
		return stagedUpdateRecord{}, ErrStorageUnavailable
	}
	return snapshot.view.stagedFor(snapshot.cfg)
}

func (s *Service) DescribeStagedUpdate(ctx context.Context) (StagedUpdateSummary, error) {
	ctx = normalizeContext(ctx)
	snapshot, err := s.beginOperation(ctx, false)
	if err != nil {
		return StagedUpdateSummary{}, err
	}
	staged, err := readyStaged(ctx, snapshot, time.Now().UTC())
	if err != nil {
		return StagedUpdateSummary{}, err
	}
	return stagedSummaryFrom(staged.StagedUpdate), nil
}

func (s *Service) BuildApplyPlan(ctx context.Context) (ApplyPlan, error) {
	ctx = normalizeContext(ctx)
	snapshot, err := s.beginOperation(ctx, false)
	if err != nil {
		return ApplyPlan{}, err
	}
	stagedRecord, err := readyStaged(ctx, snapshot, time.Now().UTC())
	if err != nil {
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
	if err := s.lockWorkflow(ctx); err != nil {
		return ClearResult{}, err
	}
	defer s.unlockWorkflow()
	snapshot, err := s.beginOperation(ctx, true)
	if err != nil {
		return ClearResult{}, err
	}
	snapshot.view.clearStaged()
	if err := s.publishOperation(ctx, snapshot); err != nil {
		return ClearResult{}, err
	}
	return ClearResult{Cleared: true, Message: "staged update cleared"}, nil
}
