package updates

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPublicRecordOnlyLifecycleContract(t *testing.T) {
	ctx := context.Background()
	cfg := publicLifecycleFixture(t, "1.2.0")
	svc, err := NewRecordOnlyService(cfg)
	if err != nil {
		t.Fatal(err)
	}
	stagePublicLifecycle(t, svc, "1.2.0")

	envelope, err := svc.GetLifecycleEnvelope(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if envelope.Revision != 1 || envelope.Phase != LifecyclePhaseStaged {
		t.Fatalf("initial envelope = %+v", envelope)
	}
	if !envelope.Capabilities.CanRevealVerifiedPackage || !envelope.Capabilities.CanRecordExternalReports ||
		envelope.Capabilities.CanExecuteInstaller || envelope.Capabilities.CanExtractPackage ||
		envelope.Capabilities.CanRestartApplication || envelope.Capabilities.CanRollbackApplication {
		t.Fatalf("untruthful capabilities: %+v", envelope.Capabilities)
	}
	for _, value := range []string{envelope.Package.StagedAt, envelope.Validation.ValidatedAt, envelope.UpdatedAt} {
		if _, err := time.Parse(time.RFC3339Nano, value); err != nil {
			t.Fatalf("non-RFC3339 lifecycle time %q: %v", value, err)
		}
	}
	if _, err := svc.ApplyUpdate(ctx); !errors.Is(err, ErrLegacyExecutionDisabled) {
		t.Fatalf("record-only ApplyUpdate error = %v", err)
	}
	if _, err := svc.RecordPackageHandoff(ctx, PackageHandoffRequest{
		ExpectedRevision: envelope.Revision, IdempotencyKey: "token=bad", ConsumerID: "consumer-host",
	}); !errors.Is(err, ErrInvalidLifecycleRequest) {
		t.Fatalf("sensitive idempotency key error = %v", err)
	}

	handoff, err := svc.RecordPackageHandoff(ctx, PackageHandoffRequest{
		ExpectedRevision: envelope.Revision, IdempotencyKey: "public-handoff", ConsumerID: "consumer-host",
	})
	if err != nil {
		t.Fatal(err)
	}
	if handoff.ArtifactPath == "" || !handoff.Envelope.Validation.RehashedAtHandoff || handoff.Envelope.Validation.HandoffRehashedAt == "" || handoff.Envelope.Revision != 2 {
		t.Fatalf("handoff = %+v", handoff)
	}
	assertPublicUpdateJSONSafe(t, handoff, cfg.StagingDir)
	if _, err := svc.ReportExternalAction(ctx, ExternalActionReport{
		ExpectedRevision: envelope.Revision,
		IdempotencyKey:   "public-stale-action",
		ConsumerID:       "consumer-host",
		Action:           ExternalActionInstaller,
		Status:           ExternalActionStarted,
	}); !errors.Is(err, ErrLifecycleRevisionStale) {
		t.Fatalf("stale public action error = %v", err)
	}
	action, err := svc.ReportExternalAction(ctx, ExternalActionReport{
		ExpectedRevision: handoff.Envelope.Revision,
		IdempotencyKey:   "public-action",
		ConsumerID:       "consumer-host",
		Action:           ExternalActionInstaller,
		Status:           ExternalActionSucceeded,
	})
	if err != nil {
		t.Fatal(err)
	}
	completed, err := svc.ReportExternalCompletion(ctx, ExternalCompletionReport{
		ExpectedRevision: action.Revision,
		IdempotencyKey:   "public-completion",
		ConsumerID:       "consumer-host",
		Outcome:          CompletionSucceeded,
	})
	if err != nil {
		t.Fatal(err)
	}
	if completed.Phase != LifecyclePhaseCompleted || completed.Steps.Completion.Status != LifecycleStepSucceeded {
		t.Fatalf("completed public lifecycle = %+v", completed)
	}
	assertPublicUpdateJSONSafe(t, completed, cfg.StagingDir)
}

func TestPublicLifecycleMethodsDoNotInvokeLegacyStrategy(t *testing.T) {
	ctx := context.Background()
	cfg := publicLifecycleFixture(t, "1.2.0")
	strategy := &publicCountingLifecycleApply{}
	svc, err := NewService(cfg, strategy)
	if err != nil {
		t.Fatal(err)
	}
	stagePublicLifecycle(t, svc, "1.2.0")
	envelope, err := svc.GetLifecycleEnvelope(ctx)
	if err != nil {
		t.Fatal(err)
	}
	handoff, err := svc.RecordPackageHandoff(ctx, PackageHandoffRequest{
		ExpectedRevision: envelope.Revision, IdempotencyKey: "public-no-callback-handoff", ConsumerID: "consumer-host",
	})
	if err != nil {
		t.Fatal(err)
	}
	action, err := svc.ReportExternalAction(ctx, ExternalActionReport{
		ExpectedRevision: handoff.Envelope.Revision, IdempotencyKey: "public-no-callback-action", ConsumerID: "consumer-host",
		Action: ExternalActionExtract, Status: ExternalActionSucceeded,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ReportExternalCompletion(ctx, ExternalCompletionReport{
		ExpectedRevision: action.Revision, IdempotencyKey: "public-no-callback-completion", ConsumerID: "consumer-host", Outcome: CompletionSucceeded,
	}); err != nil {
		t.Fatal(err)
	}
	if strategy.calls != 0 {
		t.Fatalf("public lifecycle methods invoked legacy callback %d times", strategy.calls)
	}
}

type publicCountingLifecycleApply struct {
	calls int
}

func (a *publicCountingLifecycleApply) Apply(context.Context, StagedUpdate) (ApplyResult, error) {
	a.calls++
	return ApplyResult{OK: true}, nil
}

func publicLifecycleFixture(t *testing.T, version string) AppConfig {
	t.Helper()
	dir := t.TempDir()
	artifact := []byte("public lifecycle artifact " + version)
	sum := sha256.Sum256(artifact)
	artifactPath := filepath.Join(dir, "artifact.zip")
	if err := os.WriteFile(artifactPath, artifact, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := AppConfig{
		AppID: "aegis-test", DisplayName: "Aegis Test", CurrentVersion: "1.0.0",
		Channel: ChannelStable, Platform: "windows", Architecture: "amd64", Namespace: "lifecycle-test",
		StateDir: filepath.Join(dir, "state"), StagingDir: filepath.Join(dir, "stage"), CacheDir: filepath.Join(dir, "cache"),
		Source: SourceConfig{Provider: ProviderFileManifest, ManifestPath: filepath.Join(dir, "manifest.json")},
	}
	writePublicManifest(t, cfg.Source.ManifestPath, Manifest{
		SchemaVersion: 1, AppID: cfg.AppID, Channel: cfg.Channel, Version: version, RequiredRestart: true,
		Artifacts: []Artifact{{
			Platform: cfg.Platform, Architecture: cfg.Architecture, Filename: "artifact.zip",
			DownloadURL: artifactPath, Size: int64(len(artifact)), SHA256: hex.EncodeToString(sum[:]),
		}},
	})
	return cfg
}

func stagePublicLifecycle(t *testing.T, svc *Service, version string) {
	t.Helper()
	ctx := context.Background()
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
}
