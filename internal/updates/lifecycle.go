package updates

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"time"
)

const (
	lifecycleSchemaVersion    = 1
	LifecycleHistoryLimit     = 32
	lifecycleIdempotencyLimit = 64
)

var (
	ErrLifecycleRevisionStale       = errors.New("update lifecycle revision is stale")
	ErrLifecycleIdempotencyConflict = errors.New("update lifecycle idempotency conflict")
	ErrLifecycleTransition          = errors.New("illegal update lifecycle transition")
	ErrInvalidLifecycleRequest      = errors.New("invalid update lifecycle request")
	ErrLegacyExecutionDisabled      = errors.New("legacy update execution is disabled")
)

type LifecyclePhase string

const (
	LifecyclePhaseStaged                 LifecyclePhase = "staged"
	LifecyclePhaseHandoffRecorded        LifecyclePhase = "handoff_recorded"
	LifecyclePhaseExternalActionReported LifecyclePhase = "external_action_reported"
	LifecyclePhaseCompleted              LifecyclePhase = "completed"
)

type LifecycleStepStatus string

const (
	LifecycleStepPending   LifecycleStepStatus = "pending"
	LifecycleStepCompleted LifecycleStepStatus = "completed"
	LifecycleStepReported  LifecycleStepStatus = "reported"
	LifecycleStepSucceeded LifecycleStepStatus = "succeeded"
	LifecycleStepFailed    LifecycleStepStatus = "failed"
	LifecycleStepCanceled  LifecycleStepStatus = "canceled"
)

type ExternalActionKind string

const (
	ExternalActionInstaller ExternalActionKind = "installer"
	ExternalActionExtract   ExternalActionKind = "extract"
	ExternalActionRestart   ExternalActionKind = "restart"
	ExternalActionRollback  ExternalActionKind = "rollback"
)

type ExternalActionStatus string

const (
	ExternalActionStarted   ExternalActionStatus = "started"
	ExternalActionSucceeded ExternalActionStatus = "succeeded"
	ExternalActionFailed    ExternalActionStatus = "failed"
)

type CompletionOutcome string

const (
	CompletionSucceeded CompletionOutcome = "succeeded"
	CompletionFailed    CompletionOutcome = "failed"
	CompletionCanceled  CompletionOutcome = "canceled"
)

type LifecycleEvent string

const (
	LifecycleEventStaged         LifecycleEvent = "staged"
	LifecycleEventValidated      LifecycleEvent = "validated"
	LifecycleEventHandoff        LifecycleEvent = "handoff"
	LifecycleEventExternalAction LifecycleEvent = "external_action"
	LifecycleEventCompletion     LifecycleEvent = "completion"
)

// PackageSummary is safe staged-package metadata and never includes a path.
type PackageSummary struct {
	ID              string        `json:"id"`
	Source          SourceSummary `json:"source"`
	AppID           string        `json:"app_id"`
	Version         string        `json:"version"`
	Channel         Channel       `json:"channel"`
	Platform        string        `json:"platform"`
	Architecture    string        `json:"architecture"`
	ArtifactName    string        `json:"artifact_name"`
	SHA256          string        `json:"sha256"`
	Size            int64         `json:"size"`
	StagedAt        string        `json:"staged_at"`
	RequiresRestart bool          `json:"requires_restart"`
}

// RouteSummary describes the explicit consumer-owned handoff route.
type RouteSummary struct {
	Mode           string `json:"mode"`
	Owner          string `json:"owner"`
	ArtifactAccess string `json:"artifact_access"`
	ConsumerID     string `json:"consumer_id,omitempty"`
}

// ValidationSummary reports checks performed by Core without exposing paths.
type ValidationSummary struct {
	SHA256Verified    bool   `json:"sha256_verified"`
	SizeVerified      bool   `json:"size_verified"`
	ValidatedAt       string `json:"validated_at"`
	RehashedAtHandoff bool   `json:"rehashed_at_handoff"`
	HandoffRehashedAt string `json:"handoff_rehashed_at,omitempty"`
}

// ExecutionCapabilities truthfully separates Core records from app execution.
type ExecutionCapabilities struct {
	CanRevealVerifiedPackage bool `json:"can_reveal_verified_package"`
	CanRecordExternalReports bool `json:"can_record_external_reports"`
	CanExecuteInstaller      bool `json:"can_execute_installer"`
	CanExtractPackage        bool `json:"can_extract_package"`
	CanRestartApplication    bool `json:"can_restart_application"`
	CanRollbackApplication   bool `json:"can_rollback_application"`
}

type LifecycleStep struct {
	Status LifecycleStepStatus `json:"status"`
	At     string              `json:"at,omitempty"`
}

type LifecycleSteps struct {
	Staged         LifecycleStep `json:"staged"`
	Validated      LifecycleStep `json:"validated"`
	Handoff        LifecycleStep `json:"handoff"`
	ExternalAction LifecycleStep `json:"external_action"`
	Completion     LifecycleStep `json:"completion"`
}

type ActionHistoryEntry struct {
	Revision   uint64             `json:"revision"`
	Event      LifecycleEvent     `json:"event"`
	Action     ExternalActionKind `json:"action,omitempty"`
	Status     string             `json:"status"`
	At         string             `json:"at"`
	ConsumerID string             `json:"consumer_id,omitempty"`
}

// LifecycleEnvelope is the single atomic, safe record of package lifecycle state.
type LifecycleEnvelope struct {
	LifecycleID  string                `json:"lifecycle_id"`
	Revision     uint64                `json:"revision"`
	Phase        LifecyclePhase        `json:"phase"`
	Package      PackageSummary        `json:"package"`
	Route        RouteSummary          `json:"route"`
	Validation   ValidationSummary     `json:"validation"`
	Capabilities ExecutionCapabilities `json:"capabilities"`
	Steps        LifecycleSteps        `json:"steps"`
	History      []ActionHistoryEntry  `json:"history"`
	UpdatedAt    string                `json:"updated_at"`
}

type PackageHandoffRequest struct {
	ExpectedRevision uint64 `json:"expected_revision"`
	IdempotencyKey   string `json:"idempotency_key"`
	ConsumerID       string `json:"consumer_id"`
}

// PackageHandoff returns a freshly rehashed local path only to the direct Go caller.
type PackageHandoff struct {
	Envelope     LifecycleEnvelope `json:"envelope"`
	ArtifactPath string            `json:"-"`
}

type ExternalActionReport struct {
	ExpectedRevision uint64               `json:"expected_revision"`
	IdempotencyKey   string               `json:"idempotency_key"`
	ConsumerID       string               `json:"consumer_id"`
	Action           ExternalActionKind   `json:"action"`
	Status           ExternalActionStatus `json:"status"`
}

type ExternalCompletionReport struct {
	ExpectedRevision uint64            `json:"expected_revision"`
	IdempotencyKey   string            `json:"idempotency_key"`
	ConsumerID       string            `json:"consumer_id"`
	Outcome          CompletionOutcome `json:"outcome"`
}

type lifecycleRecord struct {
	SchemaVersion int                          `json:"schema_version"`
	Envelope      LifecycleEnvelope            `json:"envelope"`
	Idempotency   []lifecycleIdempotencyRecord `json:"idempotency"`
}

type lifecycleIdempotencyRecord struct {
	Key         string `json:"key"`
	Fingerprint string `json:"fingerprint"`
}

func (s *Service) GetLifecycleEnvelope(ctx context.Context) (LifecycleEnvelope, error) {
	ctx = normalizeContext(ctx)
	if err := contextError(ctx); err != nil {
		return LifecycleEnvelope{}, err
	}
	s.workflowMu.Lock()
	defer s.workflowMu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	record, _, err := s.lifecycleRecordLocked(time.Now().UTC())
	if err != nil {
		return LifecycleEnvelope{}, err
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
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()
	record, staged, err := s.lifecycleRecordLocked(now)
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
	if err := s.store.writeLifecycle(record); err != nil {
		return PackageHandoff{}, err
	}
	return PackageHandoff{Envelope: cloneLifecycleEnvelope(record.Envelope), ArtifactPath: staged.ArtifactPath}, nil
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
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()
	record, _, err := s.lifecycleRecordLocked(now)
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
	if err := s.store.writeLifecycle(record); err != nil {
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
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()
	record, _, err := s.lifecycleRecordLocked(now)
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
	if err := s.store.writeLifecycle(record); err != nil {
		return LifecycleEnvelope{}, err
	}
	return cloneLifecycleEnvelope(record.Envelope), nil
}

func (s *Service) lifecycleRecordLocked(now time.Time) (lifecycleRecord, StagedUpdate, error) {
	staged, err := s.store.readStaged()
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return lifecycleRecord{}, StagedUpdate{}, ErrStagedUpdateNotFound
		}
		return lifecycleRecord{}, StagedUpdate{}, ErrStorageUnavailable
	}
	if err := validateStagedUpdateReadyFor(s.cfg, s.store, staged, now); err != nil {
		return lifecycleRecord{}, StagedUpdate{}, err
	}
	info, err := os.Lstat(staged.ArtifactPath)
	if err != nil || info.Size() != staged.Size {
		return lifecycleRecord{}, StagedUpdate{}, ErrVerificationFailed
	}

	record, err := s.store.readLifecycle()
	if errors.Is(err, os.ErrNotExist) {
		record = newLifecycleRecord(staged, now)
		if err := s.store.writeLifecycle(record); err != nil {
			return lifecycleRecord{}, StagedUpdate{}, err
		}
		return record, staged, nil
	}
	if err != nil || validateLifecycleRecord(record, staged) != nil {
		return lifecycleRecord{}, StagedUpdate{}, ErrStorageUnavailable
	}
	return record, staged, nil
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
