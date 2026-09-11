// Package updates exposes the public, app-agnostic Aegis Update Framework.
package updates

import (
	"context"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	schemaVersion      = 1
	defaultHTTPTimeout = 15 * time.Second
	maxManifestBytes   = 4 * 1024 * 1024

	manifestSignatureKindEd25519 = "ed25519"
)

var (
	ErrNotConfigured        = errors.New("updates are not configured")
	ErrInvalidConfig        = errors.New("invalid update configuration")
	ErrInvalidProvider      = errors.New("invalid update provider")
	ErrProviderUnavailable  = errors.New("update provider unavailable")
	ErrInvalidManifest      = errors.New("invalid update manifest")
	ErrNoUpdateAvailable    = errors.New("no update available")
	ErrNoCompatibleArtifact = errors.New("no compatible update artifact")
	ErrDownloadFailed       = errors.New("update download failed")
	ErrVerificationFailed   = errors.New("update verification failed")
	ErrUpdateBlocked        = errors.New("update blocked by policy")
	ErrManifestStale        = errors.New("update manifest stale")
	ErrManifestFutureDated  = errors.New("update manifest future dated")
	ErrRollbackRisk         = errors.New("update rollback risk")
	ErrStagedUpdateStale    = errors.New("staged update stale")
	ErrStagedUpdateNotFound = errors.New("staged update is not available")
	ErrApplyFailed          = errors.New("update apply failed")
	ErrStorageUnavailable   = errors.New("update storage unavailable")
	ErrContextCanceled      = errors.New("update operation canceled")
	ErrUpdateStateChanged   = errors.New("update source or policy changed during operation")
	ErrApplyInProgress      = errors.New("update apply is already in progress")
)

var (
	safeNamePattern     = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$`)
	safeFilenamePattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,180}$`)
	versionPattern      = regexp.MustCompile(`^v?[0-9]+(\.[0-9]+){0,3}(-[A-Za-z0-9._-]+)?$`)
	sha256Pattern       = regexp.MustCompile(`^[a-fA-F0-9]{64}$`)
)

type Channel string

const (
	ChannelStable    Channel = "stable"
	ChannelPreview   Channel = "preview"
	ChannelDev       Channel = "dev"
	ChannelLocalTest Channel = "local-test"
)

type ProviderKind string

const (
	ProviderFileManifest      ProviderKind = "file_manifest"
	ProviderHTTPManifest      ProviderKind = "http_manifest"
	ProviderGitHubRawManifest ProviderKind = "github_raw_manifest"
	ProviderGitHubManifest    ProviderKind = "github_manifest"
)

type AppConfig struct {
	AppID          string
	DisplayName    string
	AppName        string
	CurrentVersion string
	Channel        Channel
	Platform       string
	Architecture   string
	Namespace      string
	Source         SourceConfig
	Policy         Policy
	StagingDir     string
	StateDir       string
	CacheDir       string
	HTTPTimeout    time.Duration
}

type SourceConfig struct {
	Provider           ProviderKind
	ManifestPath       string
	ManifestURL        string
	Feed               string
	GitHubOwner        string
	GitHubRepo         string
	GitHubRef          string
	GitHubManifestPath string
	// SourceID is a non-secret stable lane identity used for safe provenance
	// and isolated persisted state. Authenticated sources require it.
	SourceID              string
	Access                SourceAccess
	RequiredManifestKeyID string
	AllowedHTTPHosts      []string
}

type Policy struct {
	// RequireSHA256 is always enforced; normalization sets it to true even
	// when callers leave it false.
	RequireSHA256            bool
	AllowPrerelease          bool
	MinimumVersion           string
	MaximumArtifactSize      int64
	RequireManifestSignature bool
	ManifestVerificationKeys map[string]string
	FreezeUpdates            bool
	RejectRollbackCandidates bool
	MaximumManifestAge       time.Duration
	MaximumFutureSkew        time.Duration
	MaximumStagedAge         time.Duration
}

type Manifest struct {
	SchemaVersion           int                 `json:"schema_version"`
	AppID                   string              `json:"app_id"`
	Channel                 Channel             `json:"channel"`
	Version                 string              `json:"version"`
	ReleaseNotesURL         string              `json:"release_notes_url,omitempty"`
	ReleaseNotesText        string              `json:"release_notes_text,omitempty"`
	PublishedAt             string              `json:"published_at,omitempty"`
	MinimumSupportedVersion string              `json:"minimum_supported_version,omitempty"`
	RequiredRestart         bool                `json:"required_restart,omitempty"`
	ApplyBehavior           string              `json:"apply_behavior,omitempty"`
	Artifacts               []Artifact          `json:"artifacts"`
	Signature               *SignatureMetadata  `json:"signature,omitempty"`
	Metadata                map[string]string   `json:"metadata,omitempty"`
	Future                  map[string][]string `json:"future,omitempty"`
}

type Artifact struct {
	Platform     string             `json:"platform"`
	Architecture string             `json:"architecture"`
	Filename     string             `json:"filename"`
	DownloadURL  string             `json:"download_url"`
	Size         int64              `json:"size,omitempty"`
	SHA256       string             `json:"sha256"`
	Signature    *SignatureMetadata `json:"signature,omitempty"`
}

type SignatureMetadata struct {
	Kind      string `json:"kind,omitempty"`
	KeyID     string `json:"key_id,omitempty"`
	Signature string `json:"signature,omitempty"`
}

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

type ApplyStrategy interface {
	Apply(ctx context.Context, staged StagedUpdate) (ApplyResult, error)
}

type ApplyAdapter interface {
	ApplyUpdate(ctx context.Context, stagedPath string, release Release) (ApplyResult, error)
}

type ManualApplyStrategy struct {
	Message string
}

func (m ManualApplyStrategy) Apply(ctx context.Context, staged StagedUpdate) (ApplyResult, error) {
	if err := contextError(ctx); err != nil {
		return ApplyResult{}, err
	}
	message := strings.TrimSpace(m.Message)
	if message == "" {
		message = "update is staged for app-owned manual apply"
	}
	return ApplyResult{Version: staged.Version, OK: true, Message: message}, nil
}

type Provider interface {
	LoadManifest(ctx context.Context) (Manifest, error)
}

// Service is the public update service handle. Its private state is shared when
// a Service value is copied, matching the historical facade's pointer-owner
// semantics while keeping implementation details out of the public contract.
type Service struct {
	*serviceState
}

type serviceState struct {
	cfg                AppConfig
	store              *store
	provider           Provider
	apply              ApplyStrategy
	client             *http.Client
	options            ServiceOptions
	revision           uint64
	legacyApplyEnabled bool

	mu              sync.Mutex
	workflowMu      sync.Mutex
	applyInProgress bool
}
