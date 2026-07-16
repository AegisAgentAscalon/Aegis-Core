// Package updates exposes the public, app-agnostic Aegis Update Framework.
package updates

import (
	"context"
	"net/http"
	"strings"
	"time"

	internal "github.com/AegisAgentAscalon/aegis-core/internal/updates"
)

var (
	ErrNotConfigured                = internal.ErrNotConfigured
	ErrInvalidConfig                = internal.ErrInvalidConfig
	ErrInvalidProvider              = internal.ErrInvalidProvider
	ErrProviderUnavailable          = internal.ErrProviderUnavailable
	ErrInvalidManifest              = internal.ErrInvalidManifest
	ErrNoUpdateAvailable            = internal.ErrNoUpdateAvailable
	ErrNoCompatibleArtifact         = internal.ErrNoCompatibleArtifact
	ErrDownloadFailed               = internal.ErrDownloadFailed
	ErrVerificationFailed           = internal.ErrVerificationFailed
	ErrUpdateBlocked                = internal.ErrUpdateBlocked
	ErrManifestStale                = internal.ErrManifestStale
	ErrManifestFutureDated          = internal.ErrManifestFutureDated
	ErrRollbackRisk                 = internal.ErrRollbackRisk
	ErrStagedUpdateStale            = internal.ErrStagedUpdateStale
	ErrStagedUpdateNotFound         = internal.ErrStagedUpdateNotFound
	ErrApplyFailed                  = internal.ErrApplyFailed
	ErrStorageUnavailable           = internal.ErrStorageUnavailable
	ErrContextCanceled              = internal.ErrContextCanceled
	ErrUpdateStateChanged           = internal.ErrUpdateStateChanged
	ErrApplyInProgress              = internal.ErrApplyInProgress
	ErrLifecycleRevisionStale       = internal.ErrLifecycleRevisionStale
	ErrLifecycleIdempotencyConflict = internal.ErrLifecycleIdempotencyConflict
	ErrLifecycleTransition          = internal.ErrLifecycleTransition
	ErrInvalidLifecycleRequest      = internal.ErrInvalidLifecycleRequest
	ErrLegacyExecutionDisabled      = internal.ErrLegacyExecutionDisabled
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

type SourceAccess string

const (
	SourceAccessLocal                 SourceAccess = "local"
	SourceAccessPublic                SourceAccess = "public"
	SourceAccessAppOwnedAuthenticated SourceAccess = "app_owned_authenticated"
)

// SourceSummary is safe provenance. It never contains URLs or credentials.
type SourceSummary struct {
	ID            string       `json:"id,omitempty"`
	Access        SourceAccess `json:"access"`
	Provider      ProviderKind `json:"provider"`
	Authenticated bool         `json:"authenticated"`
}

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
	// SourceID is a non-secret, stable lane identifier. A non-empty value opts
	// into source-, channel-, and policy-scoped persistence.
	SourceID string
	// Access selects local, public, or app-owned authenticated transport.
	Access SourceAccess
	// RequiredManifestKeyID optionally pins this source to one configured
	// manifest verification key; authenticated sources require it.
	RequiredManifestKeyID string
	// AllowedHTTPHosts contains exact authorities. Authenticated sources require
	// at least one; entries without a port mean HTTPS/443.
	AllowedHTTPHosts []string
}

type Policy struct {
	// RequireSHA256 is always enforced by the service; callers cannot disable
	// artifact SHA-256 validation through this field.
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

// LaneConfig atomically switches source, channel and optionally trust policy.
type LaneConfig struct {
	Channel Channel
	Source  SourceConfig
	Policy  *Policy
}

// ServiceOptions keeps public and credential-scoped transports separate.
type ServiceOptions struct {
	HTTPClient              *http.Client
	AuthenticatedHTTPClient *http.Client
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

// ApplyStrategy permits arbitrary app callback execution.
//
// Deprecated: use NewRecordOnlyService and the lifecycle reporting APIs.
type ApplyStrategy interface {
	Apply(ctx context.Context, staged StagedUpdate) (ApplyResult, error)
}

// ApplyAdapter permits arbitrary app callback execution.
//
// Deprecated: use NewRecordOnlyService and the lifecycle reporting APIs.
type ApplyAdapter interface {
	ApplyUpdate(ctx context.Context, stagedPath string, release Release) (ApplyResult, error)
}

// Deprecated: use NewRecordOnlyService and the lifecycle reporting APIs.
type ManualApplyStrategy struct {
	Message string
}

func (m ManualApplyStrategy) Apply(ctx context.Context, staged StagedUpdate) (ApplyResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return ApplyResult{}, ErrContextCanceled
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

type Service struct {
	svc *internal.Service
}

// Deprecated: this compatibility constructor accepts executable callbacks. Use
// NewRecordOnlyService for the non-executing package lifecycle contract.
func NewService(cfg AppConfig, apply ApplyStrategy) (*Service, error) {
	return NewServiceWithOptions(cfg, apply, ServiceOptions{})
}

// Deprecated: this compatibility constructor accepts executable callbacks. Use
// NewRecordOnlyServiceWithOptions for the non-executing package lifecycle contract.
func NewServiceWithOptions(cfg AppConfig, apply ApplyStrategy, options ServiceOptions) (*Service, error) {
	svc, err := internal.NewServiceWithOptions(toInternalConfig(cfg), publicApplyStrategy{apply: apply}, toInternalOptions(options))
	if err != nil {
		return nil, err
	}
	return &Service{svc: svc}, nil
}

// NewRecordOnlyService creates a service whose legacy apply methods are disabled.
func NewRecordOnlyService(cfg AppConfig) (*Service, error) {
	return NewRecordOnlyServiceWithOptions(cfg, ServiceOptions{})
}

// NewRecordOnlyServiceWithOptions creates a non-executing service. Its lifecycle
// APIs only validate, reveal a verified path, and record consumer reports.
func NewRecordOnlyServiceWithOptions(cfg AppConfig, options ServiceOptions) (*Service, error) {
	svc, err := internal.NewRecordOnlyServiceWithOptions(toInternalConfig(cfg), toInternalOptions(options))
	if err != nil {
		return nil, err
	}
	return &Service{svc: svc}, nil
}

// Deprecated: use NewRecordOnlyService and the lifecycle reporting APIs.
func NewServiceWithAdapter(cfg AppConfig, apply ApplyAdapter) (*Service, error) {
	return NewServiceWithAdapterOptions(cfg, apply, ServiceOptions{})
}

// Deprecated: use NewRecordOnlyServiceWithOptions and the lifecycle reporting APIs.
func NewServiceWithAdapterOptions(cfg AppConfig, apply ApplyAdapter, options ServiceOptions) (*Service, error) {
	var strategy ApplyStrategy
	if apply != nil {
		strategy = publicApplyAdapter{adapter: apply}
	}
	return NewServiceWithOptions(cfg, strategy, options)
}

func (s *Service) ValidateConfig() error { return s.svc.ValidateConfig() }

func (s *Service) GetStatus(ctx context.Context) (CurrentState, error) {
	st, err := s.svc.GetStatus(ctx)
	if err != nil {
		return CurrentState{}, err
	}
	return fromInternalState(st), nil
}

func (s *Service) ConfigureSource(ctx context.Context, source SourceConfig) (CurrentState, error) {
	st, err := s.svc.ConfigureSource(ctx, toInternalSource(source))
	if err != nil {
		return CurrentState{}, err
	}
	return fromInternalState(st), nil
}

func (s *Service) SetChannel(ctx context.Context, channel Channel) (CurrentState, error) {
	st, err := s.svc.SetChannel(ctx, internal.Channel(channel))
	if err != nil {
		return CurrentState{}, err
	}
	return fromInternalState(st), nil
}

func (s *Service) ConfigureLane(ctx context.Context, lane LaneConfig) (CurrentState, error) {
	var policy *internal.Policy
	if lane.Policy != nil {
		converted := toInternalPolicy(*lane.Policy)
		policy = &converted
	}
	st, err := s.svc.ConfigureLane(ctx, internal.LaneConfig{
		Channel: internal.Channel(lane.Channel), Source: toInternalSource(lane.Source), Policy: policy,
	})
	if err != nil {
		return CurrentState{}, err
	}
	return fromInternalState(st), nil
}

func (s *Service) CheckForUpdates(ctx context.Context) (CheckResult, error) {
	res, err := s.svc.CheckForUpdates(ctx)
	if err != nil {
		return CheckResult{}, err
	}
	return fromInternalCheck(res), nil
}

func (s *Service) DownloadUpdate(ctx context.Context, version string) (DownloadResult, error) {
	res, err := s.svc.DownloadUpdate(ctx, version)
	return DownloadResult(res), err
}

func (s *Service) VerifyUpdate(ctx context.Context, version string) (VerifyResult, error) {
	res, err := s.svc.VerifyUpdate(ctx, version)
	return VerifyResult(res), err
}

func (s *Service) StageUpdate(ctx context.Context, version string) (StageResult, error) {
	res, err := s.svc.StageUpdate(ctx, version)
	return StageResult(res), err
}

func (s *Service) DescribeStagedUpdate(ctx context.Context) (StagedUpdateSummary, error) {
	res, err := s.svc.DescribeStagedUpdate(ctx)
	if err != nil {
		return StagedUpdateSummary{}, err
	}
	return fromInternalStagedSummary(res), nil
}

func (s *Service) BuildApplyPlan(ctx context.Context) (ApplyPlan, error) {
	res, err := s.svc.BuildApplyPlan(ctx)
	if err != nil {
		return ApplyPlan{}, err
	}
	return fromInternalApplyPlan(res), nil
}

// ApplyUpdate invokes the legacy callback strategy.
//
// Deprecated: use RecordPackageHandoff and consumer-reported lifecycle methods.
func (s *Service) ApplyUpdate(ctx context.Context) (ApplyResult, error) {
	res, err := s.svc.ApplyUpdate(ctx)
	return ApplyResult(res), err
}

func (s *Service) ClearStagedUpdate(ctx context.Context) (ClearResult, error) {
	res, err := s.svc.ClearStagedUpdate(ctx)
	return ClearResult(res), err
}

func (s *Service) State(ctx context.Context) (CurrentState, error) { return s.GetStatus(ctx) }
func (s *Service) Check(ctx context.Context) (CheckResult, error)  { return s.CheckForUpdates(ctx) }
func (s *Service) Download(ctx context.Context, version string) (DownloadResult, error) {
	return s.DownloadUpdate(ctx, version)
}
func (s *Service) Verify(ctx context.Context, version string) (VerifyResult, error) {
	return s.VerifyUpdate(ctx, version)
}
func (s *Service) Stage(ctx context.Context, version string) (StageResult, error) {
	return s.StageUpdate(ctx, version)
}
func (s *Service) Describe(ctx context.Context) (StagedUpdateSummary, error) {
	return s.DescribeStagedUpdate(ctx)
}
func (s *Service) PlanApply(ctx context.Context) (ApplyPlan, error) { return s.BuildApplyPlan(ctx) }

// Apply invokes the legacy callback strategy for a matching version.
//
// Deprecated: use RecordPackageHandoff and consumer-reported lifecycle methods.
func (s *Service) Apply(ctx context.Context, version string) (ApplyResult, error) {
	res, err := s.svc.Apply(ctx, version)
	return ApplyResult(res), err
}

type publicApplyStrategy struct{ apply ApplyStrategy }

func (p publicApplyStrategy) Apply(ctx context.Context, staged internal.StagedUpdate) (internal.ApplyResult, error) {
	if p.apply == nil {
		return internal.ManualApplyStrategy{}.Apply(ctx, staged)
	}
	res, err := p.apply.Apply(ctx, fromInternalStaged(staged))
	return internal.ApplyResult(res), err
}

type publicApplyAdapter struct{ adapter ApplyAdapter }

func (p publicApplyAdapter) Apply(ctx context.Context, staged StagedUpdate) (ApplyResult, error) {
	return p.adapter.ApplyUpdate(ctx, staged.ArtifactPath, Release{
		Source: staged.Source, AppID: staged.AppID, Version: staged.Version, Channel: staged.Channel,
		Platform: staged.Platform, Architecture: staged.Architecture, RequiredRestart: staged.RequiredRestart,
		ApplyBehavior: staged.ApplyBehavior, ArtifactName: staged.ArtifactName, ArtifactSHA256: staged.SHA256,
		ArtifactSize: staged.Size,
	})
}

func toInternalConfig(cfg AppConfig) internal.AppConfig {
	return internal.AppConfig{
		AppID: cfg.AppID, DisplayName: cfg.DisplayName, AppName: cfg.AppName, CurrentVersion: cfg.CurrentVersion,
		Channel: internal.Channel(cfg.Channel), Platform: cfg.Platform, Architecture: cfg.Architecture, Namespace: cfg.Namespace,
		Source: toInternalSource(cfg.Source), Policy: toInternalPolicy(cfg.Policy), StagingDir: cfg.StagingDir,
		StateDir: cfg.StateDir, CacheDir: cfg.CacheDir, HTTPTimeout: cfg.HTTPTimeout,
	}
}

func toInternalPolicy(policy Policy) internal.Policy {
	return internal.Policy{
		RequireSHA256: policy.RequireSHA256, AllowPrerelease: policy.AllowPrerelease,
		MinimumVersion: policy.MinimumVersion, MaximumArtifactSize: policy.MaximumArtifactSize,
		RequireManifestSignature: policy.RequireManifestSignature,
		ManifestVerificationKeys: cloneStringMap(policy.ManifestVerificationKeys), FreezeUpdates: policy.FreezeUpdates,
		RejectRollbackCandidates: policy.RejectRollbackCandidates, MaximumManifestAge: policy.MaximumManifestAge,
		MaximumFutureSkew: policy.MaximumFutureSkew, MaximumStagedAge: policy.MaximumStagedAge,
	}
}

func toInternalOptions(options ServiceOptions) internal.ServiceOptions {
	return internal.ServiceOptions{HTTPClient: options.HTTPClient, AuthenticatedHTTPClient: options.AuthenticatedHTTPClient}
}

func toInternalSource(src SourceConfig) internal.SourceConfig {
	return internal.SourceConfig{
		Provider: internal.ProviderKind(src.Provider), ManifestPath: src.ManifestPath, ManifestURL: src.ManifestURL,
		Feed: src.Feed, GitHubOwner: src.GitHubOwner, GitHubRepo: src.GitHubRepo, GitHubRef: src.GitHubRef,
		GitHubManifestPath: src.GitHubManifestPath, SourceID: src.SourceID, Access: internal.SourceAccess(src.Access),
		RequiredManifestKeyID: src.RequiredManifestKeyID, AllowedHTTPHosts: append([]string(nil), src.AllowedHTTPHosts...),
	}
}

func fromInternalState(st internal.CurrentState) CurrentState {
	var release *Release
	if st.LatestRelease != nil {
		r := fromInternalRelease(*st.LatestRelease)
		release = &r
	}
	return CurrentState{
		Source: fromInternalSourceSummary(st.Source),
		AppID:  st.AppID, DisplayName: st.DisplayName, CurrentVersion: st.CurrentVersion, Channel: Channel(st.Channel),
		Platform: st.Platform, Architecture: st.Architecture, Provider: ProviderKind(st.Provider), Configured: st.Configured,
		UpdateAvailable: st.UpdateAvailable, LatestRelease: release, StagedVersion: st.StagedVersion, Verified: st.Verified,
		RollbackAvailable: st.RollbackAvailable, Message: st.Message, LastError: st.LastError,
	}
}

func fromInternalCheck(res internal.CheckResult) CheckResult {
	var release *Release
	if res.LatestRelease != nil {
		r := fromInternalRelease(*res.LatestRelease)
		release = &r
	}
	return CheckResult{UpdateAvailable: res.UpdateAvailable, LatestRelease: release, Message: res.Message}
}

func fromInternalRelease(r internal.Release) Release {
	return Release{
		Source: fromInternalSourceSummary(r.Source),
		AppID:  r.AppID, Version: r.Version, Channel: Channel(r.Channel), Platform: r.Platform, Architecture: r.Architecture,
		PublishedAt: r.PublishedAt, ReleaseNotesURL: r.ReleaseNotesURL, ReleaseNotesText: r.ReleaseNotesText,
		MinimumSupportedVersion: r.MinimumSupportedVersion, RequiredRestart: r.RequiredRestart, ApplyBehavior: r.ApplyBehavior,
		ArtifactName: r.ArtifactName, ArtifactSHA256: r.ArtifactSHA256, ArtifactSize: r.ArtifactSize, CheckedAt: r.CheckedAt,
	}
}

func fromInternalStaged(staged internal.StagedUpdate) StagedUpdate {
	return StagedUpdate{
		Source: fromInternalSourceSummary(staged.Source),
		AppID:  staged.AppID, Version: staged.Version, Channel: Channel(staged.Channel), Platform: staged.Platform,
		Architecture: staged.Architecture, ArtifactName: staged.ArtifactName, ArtifactPath: staged.ArtifactPath,
		SHA256: staged.SHA256, Size: staged.Size, StagedAt: staged.StagedAt, RequiredRestart: staged.RequiredRestart,
		ApplyBehavior: staged.ApplyBehavior,
	}
}

func fromInternalStagedSummary(summary internal.StagedUpdateSummary) StagedUpdateSummary {
	return StagedUpdateSummary{
		Source: fromInternalSourceSummary(summary.Source),
		AppID:  summary.AppID, Version: summary.Version, Channel: Channel(summary.Channel), Platform: summary.Platform,
		Architecture: summary.Architecture, ArtifactName: summary.ArtifactName, SHA256: summary.SHA256, Size: summary.Size,
		StagedAt: summary.StagedAt, RequiredRestart: summary.RequiredRestart, ApplyBehavior: summary.ApplyBehavior, Message: summary.Message,
	}
}

func fromInternalApplyPlan(plan internal.ApplyPlan) ApplyPlan {
	return ApplyPlan{
		Source:  fromInternalSourceSummary(plan.Source),
		Version: plan.Version, ArtifactName: plan.ArtifactName, RequiredRestart: plan.RequiredRestart,
		ApplyBehavior: plan.ApplyBehavior, AppOwnedApply: plan.AppOwnedApply, Summary: plan.Summary,
		Steps: append([]string{}, plan.Steps...),
	}
}

func fromInternalSourceSummary(summary internal.SourceSummary) SourceSummary {
	return SourceSummary{ID: summary.ID, Access: SourceAccess(summary.Access), Provider: ProviderKind(summary.Provider), Authenticated: summary.Authenticated}
}

func cloneStringMap(in map[string]string) map[string]string {
	if in == nil {
		return nil
	}
	out := make(map[string]string, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}
