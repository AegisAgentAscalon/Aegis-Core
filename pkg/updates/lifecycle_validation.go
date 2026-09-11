package updates

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"
)

func validateLifecycleRecord(record lifecycleRecord, staged StagedUpdate) error {
	envelope := record.Envelope
	if record.SchemaVersion != lifecycleSchemaVersion || envelope.Revision == 0 || envelope.Package.ID != lifecyclePackageID(staged) {
		return ErrStorageUnavailable
	}
	if envelope.LifecycleID != lifecycleID(envelope.Package.ID, envelope.Package.StagedAt) || envelope.Capabilities != recordOnlyCapabilities() {
		return ErrStorageUnavailable
	}
	if envelope.Route.Mode != "record_only" || envelope.Route.Owner != "consumer" || envelope.Route.ArtifactAccess != "explicit_verified_handoff" {
		return ErrStorageUnavailable
	}
	if envelope.Package.AppID != staged.AppID || envelope.Package.Version != staged.Version || envelope.Package.Channel != staged.Channel ||
		envelope.Package.Platform != staged.Platform || envelope.Package.Architecture != staged.Architecture ||
		envelope.Package.ArtifactName != staged.ArtifactName || !strings.EqualFold(envelope.Package.SHA256, staged.SHA256) ||
		envelope.Package.Size != staged.Size || envelope.Package.StagedAt != lifecycleTimestamp(staged.StagedAt) ||
		envelope.Package.RequiresRestart != staged.RequiredRestart || envelope.Package.Source != staged.Source {
		return ErrStorageUnavailable
	}
	if !validLifecyclePhase(envelope.Phase) || !validLifecycleSteps(envelope) ||
		!envelope.Validation.SHA256Verified || !envelope.Validation.SizeVerified ||
		len(envelope.History) > LifecycleHistoryLimit || len(record.Idempotency) > lifecycleIdempotencyLimit {
		return ErrStorageUnavailable
	}
	if _, err := time.Parse(time.RFC3339Nano, envelope.Package.StagedAt); err != nil {
		return ErrStorageUnavailable
	}
	if _, err := time.Parse(time.RFC3339Nano, envelope.Validation.ValidatedAt); err != nil {
		return ErrStorageUnavailable
	}
	if envelope.Validation.RehashedAtHandoff {
		if _, err := time.Parse(time.RFC3339Nano, envelope.Validation.HandoffRehashedAt); err != nil {
			return ErrStorageUnavailable
		}
	} else if envelope.Validation.HandoffRehashedAt != "" {
		return ErrStorageUnavailable
	}
	if _, err := time.Parse(time.RFC3339Nano, envelope.UpdatedAt); err != nil {
		return ErrStorageUnavailable
	}
	if envelope.Route.ConsumerID != "" && !validLifecycleIdentifier(envelope.Route.ConsumerID) {
		return ErrStorageUnavailable
	}
	var priorRevision uint64
	for _, entry := range envelope.History {
		if entry.Revision == 0 || entry.Revision > envelope.Revision || entry.Revision < priorRevision || !validLifecycleHistoryEntry(entry) {
			return ErrStorageUnavailable
		}
		if (entry.Event == LifecycleEventStaged || entry.Event == LifecycleEventValidated) && entry.ConsumerID != "" {
			return ErrStorageUnavailable
		}
		if entry.Event != LifecycleEventStaged && entry.Event != LifecycleEventValidated && entry.ConsumerID != envelope.Route.ConsumerID {
			return ErrStorageUnavailable
		}
		priorRevision = entry.Revision
		if _, err := time.Parse(time.RFC3339Nano, entry.At); err != nil {
			return ErrStorageUnavailable
		}
		if entry.ConsumerID != "" && !validLifecycleIdentifier(entry.ConsumerID) {
			return ErrStorageUnavailable
		}
	}
	for _, item := range record.Idempotency {
		if !validLifecycleIdentifier(item.Key) || !sha256Pattern.MatchString(item.Fingerprint) {
			return ErrStorageUnavailable
		}
	}
	return nil
}

func validateHandoffRequest(request PackageHandoffRequest) error {
	if request.ExpectedRevision == 0 || !validLifecycleIdentifier(request.IdempotencyKey) || !validLifecycleIdentifier(request.ConsumerID) {
		return ErrInvalidLifecycleRequest
	}
	return nil
}

func validateExternalActionReport(report ExternalActionReport) error {
	if report.ExpectedRevision == 0 || !validLifecycleIdentifier(report.IdempotencyKey) || !validLifecycleIdentifier(report.ConsumerID) {
		return ErrInvalidLifecycleRequest
	}
	if !validExternalAction(report.Action) || !validExternalActionStatus(report.Status) {
		return ErrInvalidLifecycleRequest
	}
	return nil
}

func validateExternalCompletionReport(report ExternalCompletionReport) error {
	if report.ExpectedRevision == 0 || !validLifecycleIdentifier(report.IdempotencyKey) || !validLifecycleIdentifier(report.ConsumerID) {
		return ErrInvalidLifecycleRequest
	}
	switch report.Outcome {
	case CompletionSucceeded, CompletionFailed, CompletionCanceled:
		return nil
	default:
		return ErrInvalidLifecycleRequest
	}
}

func validLifecycleIdentifier(value string) bool {
	return value == strings.TrimSpace(value) && validSafeName(value) && !unsafeUpdateDetail(value)
}

func validLifecyclePhase(phase LifecyclePhase) bool {
	switch phase {
	case LifecyclePhaseStaged, LifecyclePhaseHandoffRecorded, LifecyclePhaseExternalActionReported, LifecyclePhaseCompleted:
		return true
	default:
		return false
	}
}

func validLifecycleEvent(event LifecycleEvent) bool {
	switch event {
	case LifecycleEventStaged, LifecycleEventValidated, LifecycleEventHandoff, LifecycleEventExternalAction, LifecycleEventCompletion:
		return true
	default:
		return false
	}
}

func validLifecycleSteps(envelope LifecycleEnvelope) bool {
	if envelope.Steps.Staged.Status != LifecycleStepCompleted || envelope.Steps.Staged.At != envelope.Package.StagedAt ||
		envelope.Steps.Validated.Status != LifecycleStepCompleted || envelope.Steps.Validated.At != envelope.Validation.ValidatedAt {
		return false
	}
	if !validLifecycleStep(envelope.Steps.Handoff) || !validLifecycleStep(envelope.Steps.ExternalAction) || !validLifecycleStep(envelope.Steps.Completion) {
		return false
	}
	switch envelope.Phase {
	case LifecyclePhaseStaged:
		return envelope.Route.ConsumerID == "" && !envelope.Validation.RehashedAtHandoff && envelope.Steps.Handoff.Status == LifecycleStepPending &&
			envelope.Steps.ExternalAction.Status == LifecycleStepPending && envelope.Steps.Completion.Status == LifecycleStepPending
	case LifecyclePhaseHandoffRecorded:
		return envelope.Route.ConsumerID != "" && envelope.Validation.RehashedAtHandoff &&
			envelope.Steps.Handoff.Status == LifecycleStepCompleted && envelope.Steps.ExternalAction.Status == LifecycleStepPending &&
			envelope.Steps.Completion.Status == LifecycleStepPending
	case LifecyclePhaseExternalActionReported:
		return envelope.Route.ConsumerID != "" && envelope.Validation.RehashedAtHandoff &&
			envelope.Steps.Handoff.Status == LifecycleStepCompleted && envelope.Steps.ExternalAction.Status == LifecycleStepReported &&
			envelope.Steps.Completion.Status == LifecycleStepPending
	case LifecyclePhaseCompleted:
		return envelope.Route.ConsumerID != "" && envelope.Validation.RehashedAtHandoff &&
			envelope.Steps.Handoff.Status == LifecycleStepCompleted && envelope.Steps.ExternalAction.Status == LifecycleStepReported &&
			(envelope.Steps.Completion.Status == LifecycleStepSucceeded || envelope.Steps.Completion.Status == LifecycleStepFailed || envelope.Steps.Completion.Status == LifecycleStepCanceled)
	default:
		return false
	}
}

func validLifecycleStep(step LifecycleStep) bool {
	if step.Status == LifecycleStepPending {
		return step.At == ""
	}
	switch step.Status {
	case LifecycleStepCompleted, LifecycleStepReported, LifecycleStepSucceeded, LifecycleStepFailed, LifecycleStepCanceled:
		_, err := time.Parse(time.RFC3339Nano, step.At)
		return err == nil
	default:
		return false
	}
}

func validLifecycleHistoryEntry(entry ActionHistoryEntry) bool {
	if !validLifecycleEvent(entry.Event) || entry.Status == "" || unsafeUpdateDetail(entry.Status) {
		return false
	}
	switch entry.Event {
	case LifecycleEventStaged, LifecycleEventValidated, LifecycleEventHandoff:
		return entry.Action == "" && entry.Status == string(LifecycleStepCompleted)
	case LifecycleEventExternalAction:
		return validExternalAction(entry.Action) && validExternalActionStatus(ExternalActionStatus(entry.Status))
	case LifecycleEventCompletion:
		if entry.Action != "" {
			return false
		}
		switch CompletionOutcome(entry.Status) {
		case CompletionSucceeded, CompletionFailed, CompletionCanceled:
			return true
		default:
			return false
		}
	default:
		return false
	}
}

func validExternalAction(action ExternalActionKind) bool {
	switch action {
	case ExternalActionInstaller, ExternalActionExtract, ExternalActionRestart, ExternalActionRollback:
		return true
	default:
		return false
	}
}

func validExternalActionStatus(status ExternalActionStatus) bool {
	switch status {
	case ExternalActionStarted, ExternalActionSucceeded, ExternalActionFailed:
		return true
	default:
		return false
	}
}

func completionStepStatus(outcome CompletionOutcome) LifecycleStepStatus {
	switch outcome {
	case CompletionSucceeded:
		return LifecycleStepSucceeded
	case CompletionCanceled:
		return LifecycleStepCanceled
	default:
		return LifecycleStepFailed
	}
}

func lifecycleDuplicate(record lifecycleRecord, key, fingerprint string) (bool, error) {
	for _, item := range record.Idempotency {
		if item.Key != key {
			continue
		}
		if item.Fingerprint != fingerprint {
			return false, ErrLifecycleIdempotencyConflict
		}
		return true, nil
	}
	return false, nil
}

func rememberLifecycleIdempotency(record *lifecycleRecord, key, fingerprint string) {
	record.Idempotency = append(record.Idempotency, lifecycleIdempotencyRecord{Key: key, Fingerprint: fingerprint})
	if len(record.Idempotency) > lifecycleIdempotencyLimit {
		record.Idempotency = append([]lifecycleIdempotencyRecord(nil), record.Idempotency[len(record.Idempotency)-lifecycleIdempotencyLimit:]...)
	}
}

func appendLifecycleHistory(envelope *LifecycleEnvelope, entry ActionHistoryEntry) {
	envelope.History = append(envelope.History, entry)
	if len(envelope.History) > LifecycleHistoryLimit {
		envelope.History = append([]ActionHistoryEntry(nil), envelope.History[len(envelope.History)-LifecycleHistoryLimit:]...)
	}
}

func lifecycleFingerprint(parts ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(sum[:])
}

func lifecyclePackageID(staged StagedUpdate) string {
	return lifecycleFingerprint(staged.AppID, staged.Version, string(staged.Channel), staged.Platform, staged.Architecture, staged.ArtifactName, strings.ToLower(staged.SHA256))[:32]
}

func lifecycleID(packageID, stagedAt string) string {
	return lifecycleFingerprint(packageID, stagedAt)[:32]
}

func lifecycleTimestamp(value time.Time) string {
	return value.UTC().Format(time.RFC3339Nano)
}

func recordOnlyCapabilities() ExecutionCapabilities {
	return ExecutionCapabilities{CanRevealVerifiedPackage: true, CanRecordExternalReports: true}
}

func cloneLifecycleEnvelope(envelope LifecycleEnvelope) LifecycleEnvelope {
	envelope.History = append([]ActionHistoryEntry(nil), envelope.History...)
	return envelope
}
