package updates

import (
	"time"
)

type Release struct {
	Source                  SourceSummary `json:"source"`
	AppID                   string        `json:"app_id"`
	Version                 string        `json:"version"`
	Channel                 Channel       `json:"channel"`
	Platform                string        `json:"platform"`
	Architecture            string        `json:"architecture"`
	PublishedAt             string        `json:"published_at,omitempty"`
	ReleaseNotesURL         string        `json:"release_notes_url,omitempty"`
	ReleaseNotesText        string        `json:"release_notes_text,omitempty"`
	MinimumSupportedVersion string        `json:"minimum_supported_version,omitempty"`
	RequiredRestart         bool          `json:"required_restart,omitempty"`
	ApplyBehavior           string        `json:"apply_behavior,omitempty"`
	ArtifactName            string        `json:"artifact_name,omitempty"`
	ArtifactSHA256          string        `json:"artifact_sha256,omitempty"`
	ArtifactSize            int64         `json:"artifact_size,omitempty"`
	CheckedAt               time.Time     `json:"checked_at,omitempty"`
}

type CurrentState struct {
	Source            SourceSummary `json:"source"`
	AppID             string        `json:"app_id"`
	DisplayName       string        `json:"display_name"`
	CurrentVersion    string        `json:"current_version"`
	Channel           Channel       `json:"channel"`
	Platform          string        `json:"platform"`
	Architecture      string        `json:"architecture"`
	Provider          ProviderKind  `json:"provider"`
	Configured        bool          `json:"configured"`
	UpdateAvailable   bool          `json:"update_available"`
	LatestRelease     *Release      `json:"latest_release,omitempty"`
	StagedVersion     string        `json:"staged_version,omitempty"`
	Verified          bool          `json:"verified"`
	RollbackAvailable bool          `json:"rollback_available"`
	Message           string        `json:"message,omitempty"`
	LastError         string        `json:"last_error,omitempty"`
}

type CheckResult struct {
	UpdateAvailable bool     `json:"update_available"`
	LatestRelease   *Release `json:"latest_release,omitempty"`
	Message         string   `json:"message"`
}

type DownloadResult struct {
	Version      string `json:"version"`
	ArtifactName string `json:"artifact_name,omitempty"`
	BytesWritten int64  `json:"bytes_written,omitempty"`
	Message      string `json:"message"`
}

type VerifyResult struct {
	Version      string `json:"version"`
	ArtifactName string `json:"artifact_name,omitempty"`
	OK           bool   `json:"ok"`
	Message      string `json:"message"`
}

type StageResult struct {
	Version      string `json:"version"`
	ArtifactName string `json:"artifact_name,omitempty"`
	Staged       bool   `json:"staged"`
	Message      string `json:"message"`
}

type ApplyResult struct {
	Version string `json:"version"`
	OK      bool   `json:"ok"`
	Message string `json:"message"`
}

type ClearResult struct {
	Cleared bool   `json:"cleared"`
	Message string `json:"message"`
}

type StagedUpdate struct {
	Source          SourceSummary `json:"source"`
	AppID           string        `json:"app_id"`
	Version         string        `json:"version"`
	Channel         Channel       `json:"channel"`
	Platform        string        `json:"platform"`
	Architecture    string        `json:"architecture"`
	ArtifactName    string        `json:"artifact_name"`
	ArtifactPath    string        `json:"-"`
	SHA256          string        `json:"sha256"`
	Size            int64         `json:"size,omitempty"`
	StagedAt        time.Time     `json:"staged_at"`
	RequiredRestart bool          `json:"required_restart,omitempty"`
	ApplyBehavior   string        `json:"apply_behavior,omitempty"`
}

type StagedUpdateSummary struct {
	Source          SourceSummary `json:"source"`
	AppID           string        `json:"app_id"`
	Version         string        `json:"version"`
	Channel         Channel       `json:"channel"`
	Platform        string        `json:"platform"`
	Architecture    string        `json:"architecture"`
	ArtifactName    string        `json:"artifact_name"`
	SHA256          string        `json:"sha256"`
	Size            int64         `json:"size,omitempty"`
	StagedAt        time.Time     `json:"staged_at"`
	RequiredRestart bool          `json:"required_restart,omitempty"`
	ApplyBehavior   string        `json:"apply_behavior,omitempty"`
	Message         string        `json:"message,omitempty"`
}

type ApplyPlan struct {
	Source          SourceSummary `json:"source"`
	Version         string        `json:"version"`
	ArtifactName    string        `json:"artifact_name,omitempty"`
	RequiredRestart bool          `json:"required_restart,omitempty"`
	ApplyBehavior   string        `json:"apply_behavior,omitempty"`
	AppOwnedApply   bool          `json:"app_owned_apply"`
	Summary         string        `json:"summary"`
	Steps           []string      `json:"steps,omitempty"`
}
