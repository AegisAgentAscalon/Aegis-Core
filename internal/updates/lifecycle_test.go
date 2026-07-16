package updates

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

func TestRecordOnlyLifecycleTransitionsRevisionIdempotencyAndCapabilities(t *testing.T) {
	ctx := context.Background()
	svc, staged := stageInternalRecordOnlyUpdate(t, "1.2.0")

	envelope, err := svc.GetLifecycleEnvelope(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if envelope.Revision != 1 || envelope.Phase != LifecyclePhaseStaged {
		t.Fatalf("initial lifecycle = %+v", envelope)
	}
	assertFalseExecutionCapabilities(t, envelope.Capabilities)
	assertLifecycleRFC3339(t, envelope)
	assertUpdateJSONSafe(t, envelope)
	if _, err := svc.ApplyUpdate(ctx); !errors.Is(err, ErrLegacyExecutionDisabled) {
		t.Fatalf("record-only ApplyUpdate error = %v, want disabled", err)
	}

	if _, err := svc.ReportExternalAction(ctx, ExternalActionReport{
		ExpectedRevision: envelope.Revision, IdempotencyKey: "early-action", ConsumerID: "consumer-host",
		Action: ExternalActionInstaller, Status: ExternalActionStarted,
	}); !errors.Is(err, ErrLifecycleTransition) {
		t.Fatalf("action before handoff error = %v, want transition error", err)
	}
	if _, err := svc.ReportExternalCompletion(ctx, ExternalCompletionReport{
		ExpectedRevision: envelope.Revision, IdempotencyKey: "early-completion", ConsumerID: "consumer-host", Outcome: CompletionSucceeded,
	}); !errors.Is(err, ErrLifecycleTransition) {
		t.Fatalf("completion before action error = %v, want transition error", err)
	}

	handoffRequest := PackageHandoffRequest{
		ExpectedRevision: envelope.Revision,
		IdempotencyKey:   "handoff-1",
		ConsumerID:       "consumer-host",
	}
	handoff, err := svc.RecordPackageHandoff(ctx, handoffRequest)
	if err != nil {
		t.Fatal(err)
	}
	if handoff.ArtifactPath != staged.ArtifactPath || handoff.Envelope.Revision != 2 || handoff.Envelope.Phase != LifecyclePhaseHandoffRecorded {
		t.Fatalf("handoff = %+v", handoff)
	}
	if !handoff.Envelope.Validation.RehashedAtHandoff || handoff.Envelope.Route.ConsumerID != "consumer-host" {
		t.Fatalf("handoff validation/route = %+v %+v", handoff.Envelope.Validation, handoff.Envelope.Route)
	}
	assertFalseExecutionCapabilities(t, handoff.Envelope.Capabilities)
	assertLifecycleRFC3339(t, handoff.Envelope)
	assertUpdateJSONSafe(t, handoff)

	duplicate, err := svc.RecordPackageHandoff(ctx, handoffRequest)
	if err != nil || duplicate.Envelope.Revision != handoff.Envelope.Revision || duplicate.ArtifactPath != staged.ArtifactPath {
		t.Fatalf("idempotent handoff = %+v, %v", duplicate, err)
	}
	if _, err := svc.RecordPackageHandoff(ctx, PackageHandoffRequest{
		ExpectedRevision: handoff.Envelope.Revision,
		IdempotencyKey:   handoffRequest.IdempotencyKey,
		ConsumerID:       "other-host",
	}); !errors.Is(err, ErrLifecycleIdempotencyConflict) {
		t.Fatalf("conflicting idempotency error = %v", err)
	}
	if _, err := svc.RecordPackageHandoff(ctx, PackageHandoffRequest{
		ExpectedRevision: envelope.Revision,
		IdempotencyKey:   "handoff-stale",
		ConsumerID:       "consumer-host",
	}); !errors.Is(err, ErrLifecycleRevisionStale) {
		t.Fatalf("stale handoff error = %v", err)
	}

	actionReport := ExternalActionReport{
		ExpectedRevision: handoff.Envelope.Revision,
		IdempotencyKey:   "action-1",
		ConsumerID:       "consumer-host",
		Action:           ExternalActionInstaller,
		Status:           ExternalActionSucceeded,
	}
	action, err := svc.ReportExternalAction(ctx, actionReport)
	if err != nil {
		t.Fatal(err)
	}
	if action.Revision != 3 || action.Phase != LifecyclePhaseExternalActionReported || action.Steps.ExternalAction.Status != LifecycleStepReported {
		t.Fatalf("external action lifecycle = %+v", action)
	}
	duplicateAction, err := svc.ReportExternalAction(ctx, actionReport)
	if err != nil || duplicateAction.Revision != action.Revision {
		t.Fatalf("idempotent external action = %+v, %v", duplicateAction, err)
	}
	if _, err := svc.ReportExternalAction(ctx, ExternalActionReport{
		ExpectedRevision: handoff.Envelope.Revision,
		IdempotencyKey:   "action-stale",
		ConsumerID:       "consumer-host",
		Action:           ExternalActionRestart,
		Status:           ExternalActionStarted,
	}); !errors.Is(err, ErrLifecycleRevisionStale) {
		t.Fatalf("stale action error = %v", err)
	}

	completionReport := ExternalCompletionReport{
		ExpectedRevision: action.Revision,
		IdempotencyKey:   "completion-1",
		ConsumerID:       "consumer-host",
		Outcome:          CompletionSucceeded,
	}
	completed, err := svc.ReportExternalCompletion(ctx, completionReport)
	if err != nil {
		t.Fatal(err)
	}
	if completed.Revision != 4 || completed.Phase != LifecyclePhaseCompleted || completed.Steps.Completion.Status != LifecycleStepSucceeded {
		t.Fatalf("completed lifecycle = %+v", completed)
	}
	duplicateCompletion, err := svc.ReportExternalCompletion(ctx, completionReport)
	if err != nil || duplicateCompletion.Revision != completed.Revision {
		t.Fatalf("idempotent completion = %+v, %v", duplicateCompletion, err)
	}
	if _, err := svc.ReportExternalAction(ctx, ExternalActionReport{
		ExpectedRevision: completed.Revision,
		IdempotencyKey:   "late-action",
		ConsumerID:       "consumer-host",
		Action:           ExternalActionRollback,
		Status:           ExternalActionStarted,
	}); !errors.Is(err, ErrLifecycleTransition) {
		t.Fatalf("action after completion error = %v", err)
	}
}

func TestPackageHandoffRehashesBeforeEveryPathReveal(t *testing.T) {
	ctx := context.Background()
	tamperedService, tamperedStaged := stageInternalRecordOnlyUpdate(t, "1.2.0")
	tamperedEnvelope, err := tamperedService.GetLifecycleEnvelope(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tamperedStaged.ArtifactPath, []byte("tampered before handoff"), 0o600); err != nil {
		t.Fatal(err)
	}
	blocked, err := tamperedService.RecordPackageHandoff(ctx, PackageHandoffRequest{
		ExpectedRevision: tamperedEnvelope.Revision, IdempotencyKey: "blocked-handoff", ConsumerID: "consumer-host",
	})
	if !errors.Is(err, ErrVerificationFailed) {
		t.Fatalf("initial reveal after tamper error = %v", err)
	}
	if blocked.ArtifactPath != "" {
		t.Fatalf("tampered package path was revealed before handoff: %q", blocked.ArtifactPath)
	}

	svc, staged := stageInternalRecordOnlyUpdate(t, "1.2.0")
	envelope, err := svc.GetLifecycleEnvelope(ctx)
	if err != nil {
		t.Fatal(err)
	}
	request := PackageHandoffRequest{ExpectedRevision: envelope.Revision, IdempotencyKey: "handoff-rehash", ConsumerID: "consumer-host"}
	handoff, err := svc.RecordPackageHandoff(ctx, request)
	if err != nil || handoff.ArtifactPath == "" {
		t.Fatalf("initial handoff = %+v, %v", handoff, err)
	}
	if err := os.WriteFile(staged.ArtifactPath, []byte("tampered after handoff"), 0o600); err != nil {
		t.Fatal(err)
	}
	retry, err := svc.RecordPackageHandoff(ctx, request)
	if !errors.Is(err, ErrVerificationFailed) {
		t.Fatalf("duplicate reveal after tamper error = %v", err)
	}
	if retry.ArtifactPath != "" {
		t.Fatalf("tampered package path was revealed: %q", retry.ArtifactPath)
	}
}

func TestLifecycleRequestsRejectSensitiveDetailsAndHistoryIsBounded(t *testing.T) {
	ctx := context.Background()
	svc, _ := stageInternalRecordOnlyUpdate(t, "1.2.0")
	envelope, err := svc.GetLifecycleEnvelope(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.RecordPackageHandoff(ctx, PackageHandoffRequest{
		ExpectedRevision: envelope.Revision,
		IdempotencyKey:   "token=bad",
		ConsumerID:       `C:\Users\person\Desktop`,
	}); !errors.Is(err, ErrInvalidLifecycleRequest) {
		t.Fatalf("sensitive handoff request error = %v", err)
	}

	handoff, err := svc.RecordPackageHandoff(ctx, PackageHandoffRequest{
		ExpectedRevision: envelope.Revision, IdempotencyKey: "bounded-handoff", ConsumerID: "consumer-host",
	})
	if err != nil {
		t.Fatal(err)
	}
	envelope = handoff.Envelope
	for index := 0; index < LifecycleHistoryLimit+12; index++ {
		envelope, err = svc.ReportExternalAction(ctx, ExternalActionReport{
			ExpectedRevision: envelope.Revision,
			IdempotencyKey:   "bounded-action-" + twoDigits(index),
			ConsumerID:       "consumer-host",
			Action:           ExternalActionExtract,
			Status:           ExternalActionSucceeded,
		})
		if err != nil {
			t.Fatalf("external action %d: %v", index, err)
		}
	}
	if len(envelope.History) != LifecycleHistoryLimit {
		t.Fatalf("history length = %d, want %d", len(envelope.History), LifecycleHistoryLimit)
	}
	assertUpdateJSONSafe(t, envelope)
}

func TestLifecycleMethodsNeverInvokeLegacyApplyCallback(t *testing.T) {
	ctx := context.Background()
	apply := &countingLifecycleApply{}
	svc, _ := stageInternalUpdate(t, "1.2.0", apply)
	envelope, err := svc.GetLifecycleEnvelope(ctx)
	if err != nil {
		t.Fatal(err)
	}
	handoff, err := svc.RecordPackageHandoff(ctx, PackageHandoffRequest{
		ExpectedRevision: envelope.Revision, IdempotencyKey: "no-callback-handoff", ConsumerID: "consumer-host",
	})
	if err != nil {
		t.Fatal(err)
	}
	action, err := svc.ReportExternalAction(ctx, ExternalActionReport{
		ExpectedRevision: handoff.Envelope.Revision, IdempotencyKey: "no-callback-action", ConsumerID: "consumer-host",
		Action: ExternalActionInstaller, Status: ExternalActionSucceeded,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ReportExternalCompletion(ctx, ExternalCompletionReport{
		ExpectedRevision: action.Revision, IdempotencyKey: "no-callback-completion", ConsumerID: "consumer-host", Outcome: CompletionSucceeded,
	}); err != nil {
		t.Fatal(err)
	}
	if apply.calls != 0 {
		t.Fatalf("lifecycle methods invoked legacy apply callback %d times", apply.calls)
	}
}

type countingLifecycleApply struct {
	calls int
}

func (a *countingLifecycleApply) Apply(context.Context, StagedUpdate) (ApplyResult, error) {
	a.calls++
	return ApplyResult{OK: true}, nil
}

func stageInternalRecordOnlyUpdate(t *testing.T, version string) (*Service, StagedUpdate) {
	t.Helper()
	ctx := context.Background()
	cfg, artifactPath, artifactHash := testUpdateFiles(t, version)
	writeManifest(t, cfg.Source.ManifestPath, testManifest(cfg, version, artifactPath, artifactHash))
	svc, err := NewRecordOnlyService(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CheckForUpdates(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.DownloadUpdate(ctx, version); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.VerifyUpdate(ctx, version); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.StageUpdate(ctx, version); err != nil {
		t.Fatal(err)
	}
	staged, err := svc.store.readStaged()
	if err != nil {
		t.Fatal(err)
	}
	return svc, staged
}

func assertFalseExecutionCapabilities(t *testing.T, capabilities ExecutionCapabilities) {
	t.Helper()
	if !capabilities.CanRevealVerifiedPackage || !capabilities.CanRecordExternalReports {
		t.Fatalf("record-only capabilities missing: %+v", capabilities)
	}
	if capabilities.CanExecuteInstaller || capabilities.CanExtractPackage || capabilities.CanRestartApplication || capabilities.CanRollbackApplication {
		t.Fatalf("execution capability reported true: %+v", capabilities)
	}
}

func assertLifecycleRFC3339(t *testing.T, envelope LifecycleEnvelope) {
	t.Helper()
	values := []string{envelope.Package.StagedAt, envelope.Validation.ValidatedAt, envelope.UpdatedAt}
	if envelope.Validation.HandoffRehashedAt != "" {
		values = append(values, envelope.Validation.HandoffRehashedAt)
	}
	for _, step := range []LifecycleStep{envelope.Steps.Staged, envelope.Steps.Validated, envelope.Steps.Handoff, envelope.Steps.ExternalAction, envelope.Steps.Completion} {
		if step.At != "" {
			values = append(values, step.At)
		}
	}
	for _, entry := range envelope.History {
		values = append(values, entry.At)
	}
	for _, value := range values {
		if _, err := time.Parse(time.RFC3339Nano, value); err != nil {
			t.Fatalf("timestamp %q is not RFC3339: %v", value, err)
		}
	}
}

func twoDigits(value int) string {
	const digits = "0123456789"
	return string([]byte{digits[(value/10)%10], digits[value%10]})
}

func TestPackageHandoffJSONOmitsArtifactPath(t *testing.T) {
	handoff := PackageHandoff{ArtifactPath: `C:\Users\person\Desktop\secret.zip`}
	raw, err := json.Marshal(handoff)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "secret.zip") || strings.Contains(string(raw), "artifact_path") {
		t.Fatalf("handoff JSON exposed artifact path: %s", raw)
	}
}
