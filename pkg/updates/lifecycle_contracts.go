package updates

import (
	"errors"
)

const (
	lifecycleSchemaVersion    = 1
	LifecycleHistoryLimit     = 32
	lifecycleIdempotencyLimit = 64
)

var (
	ErrLifecycleRevisionStale       = errors.New("update lifecycle revision is stale")
	ErrLifecycleIdempotencyConflict = errors.New("update lifecycle idempotency conflict")
	ErrLifecycleRestageConflict     = errors.New("active update lifecycle conflicts with restaging")
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
