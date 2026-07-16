package updates

import (
	"context"

	internal "github.com/AegisAgentAscalon/aegis-core/internal/updates"
)

const LifecycleHistoryLimit = internal.LifecycleHistoryLimit

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

// ExecutionCapabilities is explicit: Core can reveal and record, but cannot
// install, extract, restart, or roll back an application.
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

// LifecycleEnvelope is one atomic, safe summary separate from Manifest v1.
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

// PackageHandoff exposes ArtifactPath only to the direct Go caller. JSON and
// safe summaries omit it.
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

// GetLifecycleEnvelope returns the safe record-only lifecycle state.
func (s *Service) GetLifecycleEnvelope(ctx context.Context) (LifecycleEnvelope, error) {
	envelope, err := s.svc.GetLifecycleEnvelope(ctx)
	if err != nil {
		return LifecycleEnvelope{}, err
	}
	return fromInternalLifecycleEnvelope(envelope), nil
}

// RecordPackageHandoff records a handoff and reveals freshly rehashed package
// bytes without invoking callbacks, processes, shells, or installers.
func (s *Service) RecordPackageHandoff(ctx context.Context, request PackageHandoffRequest) (PackageHandoff, error) {
	handoff, err := s.svc.RecordPackageHandoff(ctx, internal.PackageHandoffRequest{
		ExpectedRevision: request.ExpectedRevision,
		IdempotencyKey:   request.IdempotencyKey,
		ConsumerID:       request.ConsumerID,
	})
	if err != nil {
		return PackageHandoff{}, err
	}
	return PackageHandoff{Envelope: fromInternalLifecycleEnvelope(handoff.Envelope), ArtifactPath: handoff.ArtifactPath}, nil
}

// ReportExternalAction records consumer-reported work and never performs it.
func (s *Service) ReportExternalAction(ctx context.Context, report ExternalActionReport) (LifecycleEnvelope, error) {
	envelope, err := s.svc.ReportExternalAction(ctx, internal.ExternalActionReport{
		ExpectedRevision: report.ExpectedRevision,
		IdempotencyKey:   report.IdempotencyKey,
		ConsumerID:       report.ConsumerID,
		Action:           internal.ExternalActionKind(report.Action),
		Status:           internal.ExternalActionStatus(report.Status),
	})
	if err != nil {
		return LifecycleEnvelope{}, err
	}
	return fromInternalLifecycleEnvelope(envelope), nil
}

// ReportExternalCompletion records a consumer-owned final outcome.
func (s *Service) ReportExternalCompletion(ctx context.Context, report ExternalCompletionReport) (LifecycleEnvelope, error) {
	envelope, err := s.svc.ReportExternalCompletion(ctx, internal.ExternalCompletionReport{
		ExpectedRevision: report.ExpectedRevision,
		IdempotencyKey:   report.IdempotencyKey,
		ConsumerID:       report.ConsumerID,
		Outcome:          internal.CompletionOutcome(report.Outcome),
	})
	if err != nil {
		return LifecycleEnvelope{}, err
	}
	return fromInternalLifecycleEnvelope(envelope), nil
}

func fromInternalLifecycleEnvelope(envelope internal.LifecycleEnvelope) LifecycleEnvelope {
	history := make([]ActionHistoryEntry, 0, len(envelope.History))
	for _, entry := range envelope.History {
		history = append(history, ActionHistoryEntry{
			Revision: entry.Revision, Event: LifecycleEvent(entry.Event), Action: ExternalActionKind(entry.Action),
			Status: entry.Status, At: entry.At, ConsumerID: entry.ConsumerID,
		})
	}
	return LifecycleEnvelope{
		LifecycleID: envelope.LifecycleID,
		Revision:    envelope.Revision,
		Phase:       LifecyclePhase(envelope.Phase),
		Package: PackageSummary{
			ID: envelope.Package.ID, Source: fromInternalSourceSummary(envelope.Package.Source), AppID: envelope.Package.AppID,
			Version: envelope.Package.Version, Channel: Channel(envelope.Package.Channel), Platform: envelope.Package.Platform,
			Architecture: envelope.Package.Architecture, ArtifactName: envelope.Package.ArtifactName,
			SHA256: envelope.Package.SHA256, Size: envelope.Package.Size, StagedAt: envelope.Package.StagedAt,
			RequiresRestart: envelope.Package.RequiresRestart,
		},
		Route: RouteSummary{
			Mode: envelope.Route.Mode, Owner: envelope.Route.Owner,
			ArtifactAccess: envelope.Route.ArtifactAccess, ConsumerID: envelope.Route.ConsumerID,
		},
		Validation: ValidationSummary{
			SHA256Verified: envelope.Validation.SHA256Verified, SizeVerified: envelope.Validation.SizeVerified,
			ValidatedAt: envelope.Validation.ValidatedAt, RehashedAtHandoff: envelope.Validation.RehashedAtHandoff,
			HandoffRehashedAt: envelope.Validation.HandoffRehashedAt,
		},
		Capabilities: ExecutionCapabilities{
			CanRevealVerifiedPackage: envelope.Capabilities.CanRevealVerifiedPackage,
			CanRecordExternalReports: envelope.Capabilities.CanRecordExternalReports,
			CanExecuteInstaller:      envelope.Capabilities.CanExecuteInstaller,
			CanExtractPackage:        envelope.Capabilities.CanExtractPackage,
			CanRestartApplication:    envelope.Capabilities.CanRestartApplication,
			CanRollbackApplication:   envelope.Capabilities.CanRollbackApplication,
		},
		Steps: LifecycleSteps{
			Staged:         fromInternalLifecycleStep(envelope.Steps.Staged),
			Validated:      fromInternalLifecycleStep(envelope.Steps.Validated),
			Handoff:        fromInternalLifecycleStep(envelope.Steps.Handoff),
			ExternalAction: fromInternalLifecycleStep(envelope.Steps.ExternalAction),
			Completion:     fromInternalLifecycleStep(envelope.Steps.Completion),
		},
		History: history, UpdatedAt: envelope.UpdatedAt,
	}
}

func fromInternalLifecycleStep(step internal.LifecycleStep) LifecycleStep {
	return LifecycleStep{Status: LifecycleStepStatus(step.Status), At: step.At}
}
