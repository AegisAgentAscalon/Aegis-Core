package updates

import (
	"context"
	"errors"
	"os"
	"strings"
	"time"
)

func (s *Service) GetLifecycleEnvelope(ctx context.Context) (LifecycleEnvelope, error) {
	ctx = normalizeContext(ctx)
	if err := contextError(ctx); err != nil {
		return LifecycleEnvelope{}, err
	}
	s.workflowMu.Lock()
	defer s.workflowMu.Unlock()
	op, err := s.beginLocked(ctx, false)
	if err != nil {
		return LifecycleEnvelope{}, err
	}
	defer op.close()
	snapshot := op.snapshot
	record, _, missing, err := lifecycleFor(ctx, snapshot, time.Now().UTC())
	if err != nil {
		return LifecycleEnvelope{}, err
	}
	if missing {
		snapshot.view.lifecycle = stored(record)
		if err := snapshot.store.publish(ctx, op.guard, snapshot.cfg, snapshot.view, false); err != nil {
			return LifecycleEnvelope{}, err
		}
	}
	return cloneLifecycleEnvelope(record.Envelope), nil
}

// RecordPackageHandoff records a consumer handoff and reveals no path until the
// staged bytes have been rehashed immediately before the atomic record write.
func (s *Service) RecordPackageHandoff(ctx context.Context, request PackageHandoffRequest) (PackageHandoff, error) {
	ctx = normalizeContext(ctx)
	if err := contextError(ctx); err != nil {
		return PackageHandoff{}, err
	}
	if err := validateHandoffRequest(request); err != nil {
		return PackageHandoff{}, err
	}
	s.workflowMu.Lock()
	defer s.workflowMu.Unlock()
	op, err := s.beginLocked(ctx, false)
	if err != nil {
		return PackageHandoff{}, err
	}
	defer op.close()
	snapshot := op.snapshot

	now := time.Now().UTC()
	record, staged, _, err := lifecycleFor(ctx, snapshot, now)
	if err != nil {
		return PackageHandoff{}, err
	}
	fingerprint := lifecycleFingerprint("handoff", request.ConsumerID)
	if duplicate, err := lifecycleDuplicate(record, request.IdempotencyKey, fingerprint); err != nil {
		return PackageHandoff{}, err
	} else if duplicate {
		return PackageHandoff{Envelope: cloneLifecycleEnvelope(record.Envelope), ArtifactPath: staged.ArtifactPath}, nil
	}
	if request.ExpectedRevision != record.Envelope.Revision {
		return PackageHandoff{}, ErrLifecycleRevisionStale
	}
	if record.Envelope.Phase != LifecyclePhaseStaged {
		return PackageHandoff{}, ErrLifecycleTransition
	}

	at := lifecycleTimestamp(now)
	record.Envelope.Revision++
	record.Envelope.Phase = LifecyclePhaseHandoffRecorded
	record.Envelope.Route.ConsumerID = request.ConsumerID
	record.Envelope.Validation.RehashedAtHandoff = true
	record.Envelope.Validation.HandoffRehashedAt = at
	record.Envelope.Steps.Handoff = LifecycleStep{Status: LifecycleStepCompleted, At: at}
	record.Envelope.UpdatedAt = at
	appendLifecycleHistory(&record.Envelope, ActionHistoryEntry{
		Revision: record.Envelope.Revision, Event: LifecycleEventHandoff,
		Status: string(LifecycleStepCompleted), At: at, ConsumerID: request.ConsumerID,
	})
	rememberLifecycleIdempotency(&record, request.IdempotencyKey, fingerprint)
	snapshot.view.lifecycle = stored(record)
	if err := snapshot.store.publish(ctx, op.guard, snapshot.cfg, snapshot.view, true); err != nil {
		return PackageHandoff{}, err
	}
	return PackageHandoff{Envelope: cloneLifecycleEnvelope(record.Envelope), ArtifactPath: snapshot.view.staged.value.ArtifactPath}, nil
}

// ReportExternalAction records consumer-reported work; it never performs that work.
func (s *Service) ReportExternalAction(ctx context.Context, report ExternalActionReport) (LifecycleEnvelope, error) {
	ctx = normalizeContext(ctx)
	if err := contextError(ctx); err != nil {
		return LifecycleEnvelope{}, err
	}
	if err := validateExternalActionReport(report); err != nil {
		return LifecycleEnvelope{}, err
	}
	s.workflowMu.Lock()
	defer s.workflowMu.Unlock()
	op, err := s.beginLocked(ctx, false)
	if err != nil {
		return LifecycleEnvelope{}, err
	}
	defer op.close()
	snapshot := op.snapshot

	now := time.Now().UTC()
	record, _, _, err := lifecycleFor(ctx, snapshot, now)
	if err != nil {
		return LifecycleEnvelope{}, err
	}
	fingerprint := lifecycleFingerprint("external-action", report.ConsumerID, string(report.Action), string(report.Status))
	if duplicate, err := lifecycleDuplicate(record, report.IdempotencyKey, fingerprint); err != nil {
		return LifecycleEnvelope{}, err
	} else if duplicate {
		return cloneLifecycleEnvelope(record.Envelope), nil
	}
	if report.ExpectedRevision != record.Envelope.Revision {
		return LifecycleEnvelope{}, ErrLifecycleRevisionStale
	}
	if record.Envelope.Phase != LifecyclePhaseHandoffRecorded && record.Envelope.Phase != LifecyclePhaseExternalActionReported {
		return LifecycleEnvelope{}, ErrLifecycleTransition
	}
	if report.ConsumerID != record.Envelope.Route.ConsumerID {
		return LifecycleEnvelope{}, ErrInvalidLifecycleRequest
	}

	at := lifecycleTimestamp(now)
	record.Envelope.Revision++
	record.Envelope.Phase = LifecyclePhaseExternalActionReported
	record.Envelope.Steps.ExternalAction = LifecycleStep{Status: LifecycleStepReported, At: at}
	record.Envelope.UpdatedAt = at
	appendLifecycleHistory(&record.Envelope, ActionHistoryEntry{
		Revision: record.Envelope.Revision, Event: LifecycleEventExternalAction, Action: report.Action,
		Status: string(report.Status), At: at, ConsumerID: report.ConsumerID,
	})
	rememberLifecycleIdempotency(&record, report.IdempotencyKey, fingerprint)
	snapshot.view.lifecycle = stored(record)
	if err := snapshot.store.publish(ctx, op.guard, snapshot.cfg, snapshot.view, false); err != nil {
		return LifecycleEnvelope{}, err
	}
	return cloneLifecycleEnvelope(record.Envelope), nil
}

// ReportExternalCompletion records a consumer-owned final outcome.
func (s *Service) ReportExternalCompletion(ctx context.Context, report ExternalCompletionReport) (LifecycleEnvelope, error) {
	ctx = normalizeContext(ctx)
	if err := contextError(ctx); err != nil {
		return LifecycleEnvelope{}, err
	}
	if err := validateExternalCompletionReport(report); err != nil {
		return LifecycleEnvelope{}, err
	}
	s.workflowMu.Lock()
	defer s.workflowMu.Unlock()
	op, err := s.beginLocked(ctx, false)
	if err != nil {
		return LifecycleEnvelope{}, err
	}
	defer op.close()
	snapshot := op.snapshot

	now := time.Now().UTC()
	record, _, _, err := lifecycleFor(ctx, snapshot, now)
	if err != nil {
		return LifecycleEnvelope{}, err
	}
	fingerprint := lifecycleFingerprint("completion", report.ConsumerID, string(report.Outcome))
	if duplicate, err := lifecycleDuplicate(record, report.IdempotencyKey, fingerprint); err != nil {
		return LifecycleEnvelope{}, err
	} else if duplicate {
		return cloneLifecycleEnvelope(record.Envelope), nil
	}
	if report.ExpectedRevision != record.Envelope.Revision {
		return LifecycleEnvelope{}, ErrLifecycleRevisionStale
	}
	if record.Envelope.Phase != LifecyclePhaseExternalActionReported {
		return LifecycleEnvelope{}, ErrLifecycleTransition
	}
	if report.ConsumerID != record.Envelope.Route.ConsumerID {
		return LifecycleEnvelope{}, ErrInvalidLifecycleRequest
	}

	at := lifecycleTimestamp(now)
	record.Envelope.Revision++
	record.Envelope.Phase = LifecyclePhaseCompleted
	record.Envelope.Steps.Completion = LifecycleStep{Status: completionStepStatus(report.Outcome), At: at}
	record.Envelope.UpdatedAt = at
	appendLifecycleHistory(&record.Envelope, ActionHistoryEntry{
		Revision: record.Envelope.Revision, Event: LifecycleEventCompletion,
		Status: string(report.Outcome), At: at, ConsumerID: report.ConsumerID,
	})
	rememberLifecycleIdempotency(&record, report.IdempotencyKey, fingerprint)
	snapshot.view.lifecycle = stored(record)
	if err := snapshot.store.publish(ctx, op.guard, snapshot.cfg, snapshot.view, false); err != nil {
		return LifecycleEnvelope{}, err
	}
	return cloneLifecycleEnvelope(record.Envelope), nil
}

func lifecycleFor(ctx context.Context, snapshot serviceSnapshot, now time.Time) (lifecycleRecord, StagedUpdate, bool, error) {
	stagedRecord, err := readyStaged(ctx, snapshot, now)
	if err != nil {
		return lifecycleRecord{}, StagedUpdate{}, false, err
	}
	staged := stagedRecord.StagedUpdate
	record, err := snapshot.view.lifecycle.read()
	if errors.Is(err, os.ErrNotExist) {
		return newLifecycleRecord(staged, now), staged, true, nil
	}
	if err != nil || validateLifecycleRecord(record, staged) != nil {
		return lifecycleRecord{}, StagedUpdate{}, false, ErrStorageUnavailable
	}
	return record, staged, false, nil
}

func checkLifecycleBeforeRestage(ctx context.Context, snapshot serviceSnapshot, candidate stagedUpdateRecord, now time.Time) (StageResult, bool, error) {
	record, err := snapshot.view.lifecycle.read()
	if errors.Is(err, os.ErrNotExist) {
		return StageResult{}, false, nil
	}
	if err != nil {
		return StageResult{}, false, ErrStorageUnavailable
	}
	existing, err := snapshot.view.stagedFor(snapshot.cfg)
	if err != nil || validateLifecycleRecord(record, existing.StagedUpdate) != nil {
		return StageResult{}, false, ErrStorageUnavailable
	}
	if record.Envelope.Phase != LifecyclePhaseStaged || !sameStagedPackage(existing, candidate) {
		return StageResult{}, false, ErrLifecycleRestageConflict
	}
	if err := validateStagedUpdateReadyFor(ctx, snapshot.cfg, snapshot.store, existing, now); err != nil {
		return StageResult{}, false, err
	}
	return StageResult{Version: existing.Version, ArtifactName: existing.ArtifactName, Staged: true, Message: "update already staged"}, true, nil
}

func sameStagedPackage(left, right stagedUpdateRecord) bool {
	l, r := left.StagedUpdate, right.StagedUpdate
	return l.Source == r.Source && left.SourceKey == right.SourceKey && left.PolicyKey == right.PolicyKey &&
		l.AppID == r.AppID && l.Version == r.Version && l.Channel == r.Channel &&
		l.Platform == r.Platform && l.Architecture == r.Architecture &&
		l.ArtifactName == r.ArtifactName && strings.EqualFold(l.SHA256, r.SHA256) &&
		l.Size == r.Size && l.RequiredRestart == r.RequiredRestart &&
		l.ApplyBehavior == r.ApplyBehavior
}

func newLifecycleRecord(staged StagedUpdate, now time.Time) lifecycleRecord {
	stagedAt := lifecycleTimestamp(staged.StagedAt)
	validatedAt := lifecycleTimestamp(now)
	packageID := lifecyclePackageID(staged)
	envelope := LifecycleEnvelope{
		LifecycleID: lifecycleID(packageID, stagedAt),
		Revision:    1,
		Phase:       LifecyclePhaseStaged,
		Package: PackageSummary{
			ID: packageID, Source: staged.Source, AppID: staged.AppID, Version: staged.Version,
			Channel: staged.Channel, Platform: staged.Platform, Architecture: staged.Architecture,
			ArtifactName: staged.ArtifactName, SHA256: strings.ToLower(staged.SHA256), Size: staged.Size,
			StagedAt: stagedAt, RequiresRestart: staged.RequiredRestart,
		},
		Route:        RouteSummary{Mode: "record_only", Owner: "consumer", ArtifactAccess: "explicit_verified_handoff"},
		Validation:   ValidationSummary{SHA256Verified: true, SizeVerified: true, ValidatedAt: validatedAt},
		Capabilities: recordOnlyCapabilities(),
		Steps: LifecycleSteps{
			Staged:         LifecycleStep{Status: LifecycleStepCompleted, At: stagedAt},
			Validated:      LifecycleStep{Status: LifecycleStepCompleted, At: validatedAt},
			Handoff:        LifecycleStep{Status: LifecycleStepPending},
			ExternalAction: LifecycleStep{Status: LifecycleStepPending},
			Completion:     LifecycleStep{Status: LifecycleStepPending},
		},
		UpdatedAt: validatedAt,
	}
	envelope.History = []ActionHistoryEntry{
		{Revision: 1, Event: LifecycleEventStaged, Status: string(LifecycleStepCompleted), At: stagedAt},
		{Revision: 1, Event: LifecycleEventValidated, Status: string(LifecycleStepCompleted), At: validatedAt},
	}
	return lifecycleRecord{SchemaVersion: lifecycleSchemaVersion, Envelope: envelope}
}
