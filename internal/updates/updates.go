// Package updates contains the private implementation for the Aegis Update Framework.
package updates

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	SchemaVersion      = 1
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
}

type Policy struct {
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
	AppID                   string    `json:"app_id"`
	Version                 string    `json:"version"`
	Channel                 Channel   `json:"channel"`
	Platform                string    `json:"platform"`
	Architecture            string    `json:"architecture"`
	PublishedAt             string    `json:"published_at,omitempty"`
	ReleaseNotesURL         string    `json:"release_notes_url,omitempty"`
	ReleaseNotesText        string    `json:"release_notes_text,omitempty"`
	MinimumSupportedVersion string    `json:"minimum_supported_version,omitempty"`
	RequiredRestart         bool      `json:"required_restart,omitempty"`
	ApplyBehavior           string    `json:"apply_behavior,omitempty"`
	ArtifactName            string    `json:"artifact_name,omitempty"`
	ArtifactSHA256          string    `json:"artifact_sha256,omitempty"`
	ArtifactSize            int64     `json:"artifact_size,omitempty"`
	CheckedAt               time.Time `json:"checked_at,omitempty"`
}

type CurrentState struct {
	AppID             string       `json:"app_id"`
	DisplayName       string       `json:"display_name"`
	CurrentVersion    string       `json:"current_version"`
	Channel           Channel      `json:"channel"`
	Platform          string       `json:"platform"`
	Architecture      string       `json:"architecture"`
	Provider          ProviderKind `json:"provider"`
	Configured        bool         `json:"configured"`
	UpdateAvailable   bool         `json:"update_available"`
	LatestRelease     *Release     `json:"latest_release,omitempty"`
	StagedVersion     string       `json:"staged_version,omitempty"`
	Verified          bool         `json:"verified"`
	RollbackAvailable bool         `json:"rollback_available"`
	Message           string       `json:"message,omitempty"`
	LastError         string       `json:"last_error,omitempty"`
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
	AppID           string    `json:"app_id"`
	Version         string    `json:"version"`
	Channel         Channel   `json:"channel"`
	Platform        string    `json:"platform"`
	Architecture    string    `json:"architecture"`
	ArtifactName    string    `json:"artifact_name"`
	ArtifactPath    string    `json:"-"`
	SHA256          string    `json:"sha256"`
	Size            int64     `json:"size,omitempty"`
	StagedAt        time.Time `json:"staged_at"`
	RequiredRestart bool      `json:"required_restart,omitempty"`
	ApplyBehavior   string    `json:"apply_behavior,omitempty"`
}

type StagedUpdateSummary struct {
	AppID           string    `json:"app_id"`
	Version         string    `json:"version"`
	Channel         Channel   `json:"channel"`
	Platform        string    `json:"platform"`
	Architecture    string    `json:"architecture"`
	ArtifactName    string    `json:"artifact_name"`
	SHA256          string    `json:"sha256"`
	Size            int64     `json:"size,omitempty"`
	StagedAt        time.Time `json:"staged_at"`
	RequiredRestart bool      `json:"required_restart,omitempty"`
	ApplyBehavior   string    `json:"apply_behavior,omitempty"`
	Message         string    `json:"message,omitempty"`
}

type ApplyPlan struct {
	Version         string   `json:"version"`
	ArtifactName    string   `json:"artifact_name,omitempty"`
	RequiredRestart bool     `json:"required_restart,omitempty"`
	ApplyBehavior   string   `json:"apply_behavior,omitempty"`
	AppOwnedApply   bool     `json:"app_owned_apply"`
	Summary         string   `json:"summary"`
	Steps           []string `json:"steps,omitempty"`
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

type Service struct {
	cfg      AppConfig
	store    *store
	provider Provider
	apply    ApplyStrategy
	client   *http.Client
	mu       sync.Mutex
}

func NewService(cfg AppConfig, apply ApplyStrategy) (*Service, error) {
	cfg = normalizeConfig(cfg)
	if err := validateConfig(cfg); err != nil {
		return nil, err
	}
	st, err := newStore(cfg)
	if err != nil {
		return nil, err
	}
	provider, err := newProvider(cfg)
	if err != nil {
		return nil, err
	}
	if apply == nil {
		apply = ManualApplyStrategy{}
	}
	timeout := cfg.HTTPTimeout
	if timeout <= 0 {
		timeout = defaultHTTPTimeout
	}
	return &Service{cfg: cfg, store: st, provider: provider, apply: apply, client: &http.Client{Timeout: timeout}}, nil
}

func NewServiceWithAdapter(cfg AppConfig, adapter ApplyAdapter) (*Service, error) {
	var strategy ApplyStrategy
	if adapter != nil {
		strategy = applyAdapterStrategy{adapter: adapter}
	}
	return NewService(cfg, strategy)
}

func (s *Service) ValidateConfig() error {
	return validateConfig(s.cfg)
}

func (s *Service) GetStatus(ctx context.Context) (CurrentState, error) {
	if err := contextError(ctx); err != nil {
		return CurrentState{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	state := CurrentState{
		AppID:          s.cfg.AppID,
		DisplayName:    s.cfg.DisplayName,
		CurrentVersion: s.cfg.CurrentVersion,
		Channel:        s.cfg.Channel,
		Platform:       s.cfg.Platform,
		Architecture:   s.cfg.Architecture,
		Provider:       s.cfg.Source.Provider,
		Configured:     true,
		Message:        "updates configured",
	}
	if cached, err := s.store.readSelected(); err == nil {
		if err := validateSelectedUpdate(s.cfg, cached); err == nil {
			release := releaseFromSelection(cached.Manifest, cached.Artifact, time.Time{})
			state.LatestRelease = &release
			state.UpdateAvailable = compareVersions(cached.Manifest.Version, s.cfg.CurrentVersion) > 0
		} else {
			state.LastError = safeStatusMessage(err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		state.LastError = "stored update metadata is invalid"
	}
	if staged, err := s.store.readStaged(); err == nil {
		if err := validateStagedUpdateReady(s.cfg, staged, time.Now().UTC()); err == nil {
			state.StagedVersion = staged.Version
			state.Verified = true
		} else {
			state.LastError = safeStatusMessage(err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		state.LastError = "staged update metadata is invalid"
	}
	return state, nil
}

func (s *Service) ConfigureSource(ctx context.Context, source SourceConfig) (CurrentState, error) {
	if err := contextError(ctx); err != nil {
		return CurrentState{}, err
	}
	s.mu.Lock()
	next := s.cfg
	next.Source = normalizeSource(source)
	if err := validateSource(next.Source); err != nil {
		s.mu.Unlock()
		return CurrentState{}, err
	}
	provider, err := newProvider(next)
	if err != nil {
		s.mu.Unlock()
		return CurrentState{}, err
	}
	s.cfg = next
	s.provider = provider
	s.mu.Unlock()
	return s.GetStatus(ctx)
}

func (s *Service) SetChannel(ctx context.Context, channel Channel) (CurrentState, error) {
	if err := contextError(ctx); err != nil {
		return CurrentState{}, err
	}
	channel = Channel(strings.TrimSpace(string(channel)))
	if channel == "" || !validSafeName(string(channel)) {
		return CurrentState{}, ErrInvalidConfig
	}
	s.mu.Lock()
	s.cfg.Channel = channel
	s.mu.Unlock()
	return s.GetStatus(ctx)
}

func (s *Service) CheckForUpdates(ctx context.Context) (CheckResult, error) {
	if err := contextError(ctx); err != nil {
		return CheckResult{}, err
	}
	manifest, err := s.provider.LoadManifest(ctx)
	if err != nil {
		return CheckResult{}, sanitizeProviderError(err)
	}
	artifact, err := s.selectArtifact(manifest)
	if err != nil {
		return CheckResult{}, err
	}
	release := releaseFromSelection(manifest, artifact, time.Now().UTC())
	available := compareVersions(manifest.Version, s.cfg.CurrentVersion) > 0
	if !available {
		return CheckResult{UpdateAvailable: false, LatestRelease: &release, Message: "no update available"}, nil
	}
	if err := s.store.writeSelected(selectedUpdate{SchemaVersion: SchemaVersion, Manifest: manifest, Artifact: artifact, UpdatedAt: time.Now().UTC()}); err != nil {
		return CheckResult{}, err
	}
	return CheckResult{UpdateAvailable: true, LatestRelease: &release, Message: "update available"}, nil
}

func (s *Service) DownloadUpdate(ctx context.Context, version string) (DownloadResult, error) {
	if err := contextError(ctx); err != nil {
		return DownloadResult{}, err
	}
	selected, err := s.selectionForVersion(ctx, version)
	if err != nil {
		return DownloadResult{}, err
	}
	artifact := selected.Artifact
	if err := validateArtifact(s.cfg, artifact); err != nil {
		return DownloadResult{}, err
	}
	if err := os.MkdirAll(s.store.downloadsDir(), 0o700); err != nil {
		return DownloadResult{}, ErrStorageUnavailable
	}
	tmpPath := filepath.Join(s.store.downloadsDir(), artifact.Filename+".tmp")
	finalPath := filepath.Join(s.store.downloadsDir(), artifact.Filename)
	n, err := s.downloadArtifact(ctx, artifact, tmpPath)
	if err != nil {
		_ = os.Remove(tmpPath)
		return DownloadResult{}, err
	}
	if artifact.Size > 0 && n != artifact.Size {
		_ = os.Remove(tmpPath)
		return DownloadResult{}, ErrDownloadFailed
	}
	if s.cfg.Policy.MaximumArtifactSize > 0 && n > s.cfg.Policy.MaximumArtifactSize {
		_ = os.Remove(tmpPath)
		return DownloadResult{}, ErrDownloadFailed
	}
	if err := os.Rename(tmpPath, finalPath); err != nil {
		_ = os.Remove(tmpPath)
		return DownloadResult{}, ErrStorageUnavailable
	}
	meta := downloadedUpdate{SchemaVersion: SchemaVersion, Manifest: selected.Manifest, Artifact: artifact, ArtifactPath: finalPath, BytesWritten: n, DownloadedAt: time.Now().UTC()}
	if err := s.store.writeDownloaded(meta); err != nil {
		return DownloadResult{}, err
	}
	return DownloadResult{Version: selected.Manifest.Version, ArtifactName: artifact.Filename, BytesWritten: n, Message: "update downloaded"}, nil
}

func (s *Service) VerifyUpdate(ctx context.Context, version string) (VerifyResult, error) {
	if err := contextError(ctx); err != nil {
		return VerifyResult{}, err
	}
	downloaded, err := s.store.readDownloaded()
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return VerifyResult{}, ErrVerificationFailed
		}
		return VerifyResult{}, err
	}
	if version != "" && downloaded.Manifest.Version != version {
		return VerifyResult{}, ErrVerificationFailed
	}
	if err := validateManifest(s.cfg, downloaded.Manifest); err != nil {
		return VerifyResult{}, err
	}
	if err := validateArtifact(s.cfg, downloaded.Artifact); err != nil {
		return VerifyResult{}, err
	}
	got, err := fileSHA256(downloaded.ArtifactPath)
	if err != nil {
		return VerifyResult{}, ErrVerificationFailed
	}
	if !strings.EqualFold(got, downloaded.Artifact.SHA256) {
		return VerifyResult{}, ErrVerificationFailed
	}
	verified := verifiedUpdate{SchemaVersion: SchemaVersion, Downloaded: downloaded, VerifiedAt: time.Now().UTC()}
	if err := s.store.writeVerified(verified); err != nil {
		return VerifyResult{}, err
	}
	return VerifyResult{Version: downloaded.Manifest.Version, ArtifactName: downloaded.Artifact.Filename, OK: true, Message: "update verified"}, nil
}

func (s *Service) StageUpdate(ctx context.Context, version string) (StageResult, error) {
	if err := contextError(ctx); err != nil {
		return StageResult{}, err
	}
	verified, err := s.store.readVerified()
	if err != nil {
		if _, verifyErr := s.VerifyUpdate(ctx, version); verifyErr != nil {
			return StageResult{}, verifyErr
		}
		verified, err = s.store.readVerified()
	}
	if err != nil {
		return StageResult{}, err
	}
	if version != "" && verified.Downloaded.Manifest.Version != version {
		return StageResult{}, ErrVerificationFailed
	}
	if err := validateManifest(s.cfg, verified.Downloaded.Manifest); err != nil {
		return StageResult{}, err
	}
	if err := validateArtifact(s.cfg, verified.Downloaded.Artifact); err != nil {
		return StageResult{}, err
	}
	got, err := fileSHA256(verified.Downloaded.ArtifactPath)
	if err != nil || !strings.EqualFold(got, verified.Downloaded.Artifact.SHA256) {
		return StageResult{}, ErrVerificationFailed
	}
	if err := os.MkdirAll(s.store.stagedDir(), 0o700); err != nil {
		return StageResult{}, ErrStorageUnavailable
	}
	target := filepath.Join(s.store.stagedDir(), verified.Downloaded.Artifact.Filename)
	if err := copyFileAtomic(verified.Downloaded.ArtifactPath, target); err != nil {
		return StageResult{}, err
	}
	staged := StagedUpdate{
		AppID:           s.cfg.AppID,
		Version:         verified.Downloaded.Manifest.Version,
		Channel:         verified.Downloaded.Manifest.Channel,
		Platform:        verified.Downloaded.Artifact.Platform,
		Architecture:    verified.Downloaded.Artifact.Architecture,
		ArtifactName:    verified.Downloaded.Artifact.Filename,
		ArtifactPath:    target,
		SHA256:          verified.Downloaded.Artifact.SHA256,
		Size:            verified.Downloaded.BytesWritten,
		StagedAt:        time.Now().UTC(),
		RequiredRestart: verified.Downloaded.Manifest.RequiredRestart,
		ApplyBehavior:   verified.Downloaded.Manifest.ApplyBehavior,
	}
	if err := validateStagedUpdateReady(s.cfg, staged, time.Now().UTC()); err != nil {
		_ = os.Remove(target)
		return StageResult{}, err
	}
	if err := s.store.writeStaged(staged); err != nil {
		return StageResult{}, err
	}
	return StageResult{Version: staged.Version, ArtifactName: staged.ArtifactName, Staged: true, Message: "update staged"}, nil
}

func (s *Service) DescribeStagedUpdate(ctx context.Context) (StagedUpdateSummary, error) {
	if err := contextError(ctx); err != nil {
		return StagedUpdateSummary{}, err
	}
	staged, err := s.store.readStaged()
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return StagedUpdateSummary{}, ErrStagedUpdateNotFound
		}
		return StagedUpdateSummary{}, ErrStorageUnavailable
	}
	if err := validateStagedUpdateReady(s.cfg, staged, time.Now().UTC()); err != nil {
		return StagedUpdateSummary{}, err
	}
	return stagedSummaryFrom(staged), nil
}

func (s *Service) BuildApplyPlan(ctx context.Context) (ApplyPlan, error) {
	if err := contextError(ctx); err != nil {
		return ApplyPlan{}, err
	}
	staged, err := s.store.readStaged()
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return ApplyPlan{}, ErrStagedUpdateNotFound
		}
		return ApplyPlan{}, ErrStorageUnavailable
	}
	if err := validateStagedUpdateReady(s.cfg, staged, time.Now().UTC()); err != nil {
		return ApplyPlan{}, err
	}
	return ApplyPlan{
		Version:         staged.Version,
		ArtifactName:    staged.ArtifactName,
		RequiredRestart: staged.RequiredRestart,
		ApplyBehavior:   staged.ApplyBehavior,
		AppOwnedApply:   true,
		Summary:         "staged update is ready for app-owned apply",
		Steps: []string{
			"consumer app reviews the staged update",
			"consumer app runs its own apply strategy",
			"consumer app handles shutdown, restart, and rollback policy",
		},
	}, nil
}

func (s *Service) ApplyUpdate(ctx context.Context) (ApplyResult, error) {
	if err := contextError(ctx); err != nil {
		return ApplyResult{}, err
	}
	staged, err := s.store.readStaged()
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return ApplyResult{}, ErrStagedUpdateNotFound
		}
		return ApplyResult{}, err
	}
	if err := validateStagedUpdateReady(s.cfg, staged, time.Now().UTC()); err != nil {
		return ApplyResult{}, err
	}
	result, err := s.apply.Apply(ctx, staged)
	if err != nil {
		return ApplyResult{}, ErrApplyFailed
	}
	result.Version = staged.Version
	if result.Message == "" || unsafeUpdateDetail(result.Message) {
		result.Message = "apply strategy completed"
	}
	return result, nil
}

func (s *Service) ClearStagedUpdate(ctx context.Context) (ClearResult, error) {
	if err := contextError(ctx); err != nil {
		return ClearResult{}, err
	}
	if err := os.RemoveAll(s.store.stagedDir()); err != nil {
		return ClearResult{}, ErrStorageUnavailable
	}
	if err := os.MkdirAll(s.store.stagedDir(), 0o700); err != nil {
		return ClearResult{}, ErrStorageUnavailable
	}
	_ = os.Remove(s.store.verifiedPath())
	return ClearResult{Cleared: true, Message: "staged update cleared"}, nil
}

func (s *Service) State(ctx context.Context) (CurrentState, error) { return s.GetStatus(ctx) }

func (s *Service) Check(ctx context.Context) (CheckResult, error) { return s.CheckForUpdates(ctx) }

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

func (s *Service) PlanApply(ctx context.Context) (ApplyPlan, error) {
	return s.BuildApplyPlan(ctx)
}

func (s *Service) Apply(ctx context.Context, version string) (ApplyResult, error) {
	_ = version
	return s.ApplyUpdate(ctx)
}

func (s *Service) selectionForVersion(ctx context.Context, version string) (selectedUpdate, error) {
	selected, err := s.store.readSelected()
	if err == nil && (version == "" || selected.Manifest.Version == version) {
		if err := validateSelectedUpdate(s.cfg, selected); err == nil {
			return selected, nil
		}
	}
	check, err := s.CheckForUpdates(ctx)
	if err != nil {
		return selectedUpdate{}, err
	}
	if !check.UpdateAvailable && (version == "" || check.LatestRelease == nil || check.LatestRelease.Version != version) {
		return selectedUpdate{}, ErrNoUpdateAvailable
	}
	selected, err = s.store.readSelected()
	if err != nil {
		return selectedUpdate{}, err
	}
	if version != "" && selected.Manifest.Version != version {
		return selectedUpdate{}, ErrNoUpdateAvailable
	}
	return selected, nil
}

func (s *Service) selectArtifact(manifest Manifest) (Artifact, error) {
	if err := validateManifest(s.cfg, manifest); err != nil {
		return Artifact{}, err
	}
	for _, artifact := range manifest.Artifacts {
		if artifact.Platform != s.cfg.Platform || artifact.Architecture != s.cfg.Architecture {
			continue
		}
		if err := validateArtifact(s.cfg, artifact); err != nil {
			return Artifact{}, err
		}
		return artifact, nil
	}
	return Artifact{}, ErrNoCompatibleArtifact
}

func (s *Service) downloadArtifact(ctx context.Context, artifact Artifact, target string) (int64, error) {
	if filepath.IsAbs(artifact.DownloadURL) {
		src, err := os.Open(artifact.DownloadURL)
		if err != nil {
			return 0, ErrDownloadFailed
		}
		defer src.Close()
		return writeStreamToFile(ctx, src, target, s.cfg.Policy.MaximumArtifactSize)
	}
	u, err := url.Parse(artifact.DownloadURL)
	if err != nil || artifact.DownloadURL == "" {
		return 0, ErrInvalidManifest
	}
	switch u.Scheme {
	case "", "file":
		path := artifact.DownloadURL
		if u.Scheme == "file" {
			path = u.Path
			if runtime.GOOS == "windows" && strings.HasPrefix(path, "/") && len(path) > 2 && path[2] == ':' {
				path = strings.TrimPrefix(path, "/")
			}
		}
		src, err := os.Open(path)
		if err != nil {
			return 0, ErrDownloadFailed
		}
		defer src.Close()
		return writeStreamToFile(ctx, src, target, s.cfg.Policy.MaximumArtifactSize)
	case "http", "https":
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, artifact.DownloadURL, nil)
		if err != nil {
			return 0, ErrInvalidManifest
		}
		resp, err := s.client.Do(req)
		if err != nil {
			if contextError(ctx) != nil {
				return 0, ErrContextCanceled
			}
			return 0, ErrDownloadFailed
		}
		defer resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode > 299 {
			return 0, ErrDownloadFailed
		}
		if s.cfg.Policy.MaximumArtifactSize > 0 && resp.ContentLength > s.cfg.Policy.MaximumArtifactSize {
			return 0, ErrDownloadFailed
		}
		return writeStreamToFile(ctx, resp.Body, target, s.cfg.Policy.MaximumArtifactSize)
	default:
		return 0, ErrInvalidManifest
	}
}

type applyAdapterStrategy struct {
	adapter ApplyAdapter
}

func (s applyAdapterStrategy) Apply(ctx context.Context, staged StagedUpdate) (ApplyResult, error) {
	release := Release{
		AppID:          staged.AppID,
		Version:        staged.Version,
		Channel:        staged.Channel,
		Platform:       staged.Platform,
		Architecture:   staged.Architecture,
		ArtifactName:   staged.ArtifactName,
		ArtifactSHA256: staged.SHA256,
		ArtifactSize:   staged.Size,
	}
	return s.adapter.ApplyUpdate(ctx, staged.ArtifactPath, release)
}

func normalizeConfig(cfg AppConfig) AppConfig {
	cfg.AppID = strings.TrimSpace(cfg.AppID)
	cfg.DisplayName = strings.TrimSpace(cfg.DisplayName)
	cfg.AppName = strings.TrimSpace(cfg.AppName)
	if cfg.DisplayName == "" {
		cfg.DisplayName = cfg.AppName
	}
	cfg.CurrentVersion = strings.TrimSpace(cfg.CurrentVersion)
	cfg.Platform = strings.TrimSpace(cfg.Platform)
	cfg.Architecture = strings.TrimSpace(cfg.Architecture)
	cfg.Namespace = strings.TrimSpace(cfg.Namespace)
	if cfg.Namespace == "" {
		cfg.Namespace = cfg.AppID
	}
	if cfg.Platform == "" {
		cfg.Platform = runtime.GOOS
	}
	if cfg.Architecture == "" {
		cfg.Architecture = runtime.GOARCH
	}
	if cfg.StagingDir == "" {
		if cfg.CacheDir != "" {
			cfg.StagingDir = cfg.CacheDir
		} else {
			cfg.StagingDir = cfg.StateDir
		}
	}
	cfg.Source = normalizeSource(cfg.Source)
	if !cfg.Policy.RequireSHA256 {
		cfg.Policy.RequireSHA256 = true
	}
	return cfg
}

func normalizeSource(src SourceConfig) SourceConfig {
	src.ManifestPath = strings.TrimSpace(src.ManifestPath)
	src.ManifestURL = strings.TrimSpace(src.ManifestURL)
	src.Feed = strings.TrimSpace(src.Feed)
	src.GitHubOwner = strings.TrimSpace(src.GitHubOwner)
	src.GitHubRepo = strings.TrimSpace(src.GitHubRepo)
	src.GitHubRef = strings.TrimSpace(src.GitHubRef)
	src.GitHubManifestPath = strings.TrimSpace(src.GitHubManifestPath)
	if src.ManifestPath == "" && src.Provider == ProviderFileManifest {
		src.ManifestPath = src.Feed
	}
	if src.ManifestURL == "" && src.Provider == ProviderHTTPManifest {
		src.ManifestURL = src.Feed
	}
	if src.GitHubRef == "" {
		src.GitHubRef = "main"
	}
	return src
}

func validateConfig(cfg AppConfig) error {
	switch {
	case cfg.AppID == "", cfg.DisplayName == "", cfg.CurrentVersion == "", cfg.Channel == "", cfg.Platform == "", cfg.Architecture == "", cfg.Namespace == "", cfg.StagingDir == "":
		return ErrInvalidConfig
	case !validSafeName(cfg.AppID), !validSafeName(cfg.Namespace), !validSafeName(string(cfg.Channel)):
		return ErrInvalidConfig
	case !validVersion(cfg.CurrentVersion):
		return ErrInvalidConfig
	case cfg.Policy.MinimumVersion != "" && !validVersion(cfg.Policy.MinimumVersion):
		return ErrInvalidConfig
	case cfg.Policy.MaximumManifestAge < 0:
		return ErrInvalidConfig
	case cfg.Policy.MaximumFutureSkew < 0:
		return ErrInvalidConfig
	case cfg.Policy.MaximumStagedAge < 0:
		return ErrInvalidConfig
	}
	if err := validateManifestVerificationKeys(cfg.Policy.ManifestVerificationKeys); err != nil {
		return err
	}
	if cfg.Policy.RequireManifestSignature && len(cfg.Policy.ManifestVerificationKeys) == 0 {
		return ErrInvalidConfig
	}
	return validateSource(cfg.Source)
}

func validateSource(src SourceConfig) error {
	switch src.Provider {
	case ProviderFileManifest:
		if src.ManifestPath == "" || hasPathTraversal(src.ManifestPath) {
			return ErrInvalidProvider
		}
	case ProviderHTTPManifest:
		if src.ManifestURL == "" || !validHTTPURL(src.ManifestURL) {
			return ErrInvalidProvider
		}
	case ProviderGitHubRawManifest, ProviderGitHubManifest:
		if !validSafeName(src.GitHubOwner) || !validSafeName(src.GitHubRepo) || !validSafeName(src.GitHubRef) || !validManifestPath(src.GitHubManifestPath) {
			return ErrInvalidProvider
		}
	default:
		return ErrInvalidProvider
	}
	return nil
}

func validateManifest(cfg AppConfig, manifest Manifest) error {
	if manifest.SchemaVersion == 0 {
		manifest.SchemaVersion = SchemaVersion
	}
	switch {
	case manifest.SchemaVersion != SchemaVersion:
		return ErrInvalidManifest
	case manifest.AppID != cfg.AppID:
		return ErrInvalidManifest
	case manifest.Channel != cfg.Channel:
		return ErrInvalidManifest
	case !validVersion(manifest.Version):
		return ErrInvalidManifest
	case manifest.MinimumSupportedVersion != "" && !validVersion(manifest.MinimumSupportedVersion):
		return ErrInvalidManifest
	case manifest.MinimumSupportedVersion != "" && compareVersions(cfg.CurrentVersion, manifest.MinimumSupportedVersion) < 0:
		return ErrInvalidManifest
	case len(manifest.Artifacts) == 0:
		return ErrNoCompatibleArtifact
	}
	if err := validateManifestText(manifest); err != nil {
		return err
	}
	if err := verifyManifestSignature(cfg.Policy, manifest); err != nil {
		return err
	}
	if err := classifyRollbackFreezePolicy(cfg, manifest); err != nil {
		return err
	}
	if err := classifyManifestFreshness(cfg, manifest, time.Now().UTC()); err != nil {
		return err
	}
	switch {
	case !cfg.Policy.AllowPrerelease && strings.Contains(manifest.Version, "-"):
		return ErrNoUpdateAvailable
	}
	return nil
}

func validateSelectedUpdate(cfg AppConfig, selected selectedUpdate) error {
	if err := validateManifest(cfg, selected.Manifest); err != nil {
		return err
	}
	return validateArtifact(cfg, selected.Artifact)
}

func classifyRollbackFreezePolicy(cfg AppConfig, manifest Manifest) error {
	if cfg.Policy.FreezeUpdates {
		return ErrUpdateBlocked
	}
	if cfg.Policy.MinimumVersion != "" && compareVersions(manifest.Version, cfg.Policy.MinimumVersion) < 0 {
		return ErrNoUpdateAvailable
	}
	if cfg.Policy.RejectRollbackCandidates && compareVersions(manifest.Version, cfg.CurrentVersion) < 0 {
		return ErrRollbackRisk
	}
	return nil
}

func classifyManifestFreshness(cfg AppConfig, manifest Manifest, now time.Time) error {
	if cfg.Policy.MaximumManifestAge <= 0 && cfg.Policy.MaximumFutureSkew <= 0 {
		return nil
	}
	publishedAt := strings.TrimSpace(manifest.PublishedAt)
	if publishedAt == "" {
		return ErrInvalidManifest
	}
	published, err := time.Parse(time.RFC3339, publishedAt)
	if err != nil {
		return ErrInvalidManifest
	}
	if cfg.Policy.MaximumFutureSkew > 0 && published.After(now.Add(cfg.Policy.MaximumFutureSkew)) {
		return ErrManifestFutureDated
	}
	if cfg.Policy.MaximumManifestAge > 0 && published.Before(now.Add(-cfg.Policy.MaximumManifestAge)) {
		return ErrManifestStale
	}
	return nil
}

func validateArtifact(cfg AppConfig, artifact Artifact) error {
	switch {
	case artifact.Platform == "", artifact.Architecture == "", artifact.DownloadURL == "", artifact.Filename == "":
		return ErrInvalidManifest
	case !validArtifactFilename(artifact.Filename):
		return ErrInvalidManifest
	case cfg.Policy.RequireSHA256 && !sha256Pattern.MatchString(artifact.SHA256):
		return ErrInvalidManifest
	case artifact.Size < 0:
		return ErrInvalidManifest
	case cfg.Policy.MaximumArtifactSize > 0 && artifact.Size > cfg.Policy.MaximumArtifactSize:
		return ErrNoCompatibleArtifact
	}
	if err := validateSignatureMetadata(artifact.Signature); err != nil {
		return err
	}
	return validateArtifactDownloadURL(cfg, artifact.DownloadURL)
}

func validateManifestText(manifest Manifest) error {
	if err := validateSignatureMetadata(manifest.Signature); err != nil {
		return err
	}
	for _, value := range []string{manifest.ReleaseNotesURL, manifest.ReleaseNotesText, manifest.PublishedAt, manifest.ApplyBehavior} {
		if unsafeUpdateDetail(value) {
			return ErrInvalidManifest
		}
	}
	for key, value := range manifest.Metadata {
		if !validSafeName(key) || unsafeUpdateDetail(value) {
			return ErrInvalidManifest
		}
	}
	for key, values := range manifest.Future {
		if !validSafeName(key) {
			return ErrInvalidManifest
		}
		for _, value := range values {
			if unsafeUpdateDetail(value) {
				return ErrInvalidManifest
			}
		}
	}
	return nil
}

func validateSignatureMetadata(signature *SignatureMetadata) error {
	if signature == nil {
		return nil
	}
	if signature.Kind != "" && !validSafeName(signature.Kind) {
		return ErrInvalidManifest
	}
	if signature.KeyID != "" && !validSafeName(signature.KeyID) {
		return ErrInvalidManifest
	}
	if len(signature.Signature) > 8192 {
		return ErrInvalidManifest
	}
	for _, value := range []string{signature.Kind, signature.KeyID, signature.Signature} {
		if unsafeUpdateDetail(value) {
			return ErrInvalidManifest
		}
	}
	return nil
}

func validateManifestVerificationKeys(keys map[string]string) error {
	for keyID, encoded := range keys {
		if !validSafeName(keyID) {
			return ErrInvalidConfig
		}
		if _, err := decodeEd25519PublicKey(encoded); err != nil {
			return ErrInvalidConfig
		}
	}
	return nil
}

func verifyManifestSignature(policy Policy, manifest Manifest) error {
	if !policy.RequireManifestSignature {
		return nil
	}
	signature := manifest.Signature
	if signature == nil || strings.TrimSpace(signature.Kind) == "" || strings.TrimSpace(signature.KeyID) == "" || strings.TrimSpace(signature.Signature) == "" {
		return ErrVerificationFailed
	}
	if signature.Kind != manifestSignatureKindEd25519 {
		return ErrVerificationFailed
	}
	encodedKey, ok := policy.ManifestVerificationKeys[signature.KeyID]
	if !ok {
		return ErrVerificationFailed
	}
	publicKey, err := decodeEd25519PublicKey(encodedKey)
	if err != nil {
		return ErrVerificationFailed
	}
	sig, err := decodeEd25519Signature(signature.Signature)
	if err != nil {
		return ErrVerificationFailed
	}
	payload, err := manifestSignaturePayload(manifest)
	if err != nil {
		return ErrInvalidManifest
	}
	if !ed25519.Verify(publicKey, payload, sig) {
		return ErrVerificationFailed
	}
	return nil
}

func manifestSignaturePayload(manifest Manifest) ([]byte, error) {
	unsigned := manifest
	unsigned.Signature = nil
	return json.Marshal(unsigned)
}

func decodeEd25519PublicKey(encoded string) (ed25519.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, ErrInvalidConfig
	}
	return ed25519.PublicKey(raw), nil
}

func decodeEd25519Signature(encoded string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil || len(raw) != ed25519.SignatureSize {
		return nil, ErrVerificationFailed
	}
	return raw, nil
}

func validateArtifactDownloadURL(cfg AppConfig, raw string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ErrInvalidManifest
	}
	if filepath.IsAbs(raw) {
		if cfg.Source.Provider != ProviderFileManifest || hasPathTraversal(raw) {
			return ErrInvalidManifest
		}
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil || u.User != nil {
		return ErrInvalidManifest
	}
	switch u.Scheme {
	case "http", "https":
		if u.Host == "" || unsafeUpdateDetail(raw) {
			return ErrInvalidManifest
		}
		return nil
	case "file":
		if cfg.Source.Provider != ProviderFileManifest || u.Host != "" {
			return ErrInvalidManifest
		}
		path := u.Path
		if runtime.GOOS == "windows" && strings.HasPrefix(path, "/") && len(path) > 2 && path[2] == ':' {
			path = strings.TrimPrefix(path, "/")
		}
		if path == "" || !filepath.IsAbs(path) || hasPathTraversal(path) {
			return ErrInvalidManifest
		}
		return nil
	default:
		return ErrInvalidManifest
	}
}

func validateStagedUpdate(cfg AppConfig, staged StagedUpdate) error {
	switch {
	case staged.AppID == "", staged.Version == "", staged.Channel == "", staged.Platform == "", staged.Architecture == "", staged.ArtifactName == "", staged.SHA256 == "":
		return ErrStorageUnavailable
	case !validSafeName(staged.AppID), !validVersion(staged.Version), !validSafeName(string(staged.Channel)), !validArtifactFilename(staged.ArtifactName), !sha256Pattern.MatchString(staged.SHA256):
		return ErrStorageUnavailable
	case staged.AppID != cfg.AppID, staged.Channel != cfg.Channel, staged.Platform != cfg.Platform, staged.Architecture != cfg.Architecture:
		return ErrStorageUnavailable
	case staged.Size < 0:
		return ErrStorageUnavailable
	case staged.StagedAt.IsZero():
		return ErrStorageUnavailable
	case unsafeUpdateDetail(staged.ApplyBehavior):
		return ErrStorageUnavailable
	case cfg.Policy.FreezeUpdates:
		return ErrUpdateBlocked
	case cfg.Policy.MinimumVersion != "" && compareVersions(staged.Version, cfg.Policy.MinimumVersion) < 0:
		return ErrNoUpdateAvailable
	case cfg.Policy.RejectRollbackCandidates && compareVersions(staged.Version, cfg.CurrentVersion) < 0:
		return ErrRollbackRisk
	}
	return nil
}

func validateStagedUpdateReady(cfg AppConfig, staged StagedUpdate, now time.Time) error {
	if err := validateStagedUpdate(cfg, staged); err != nil {
		return err
	}
	if cfg.Policy.MaximumFutureSkew > 0 && staged.StagedAt.After(now.Add(cfg.Policy.MaximumFutureSkew)) {
		return ErrManifestFutureDated
	}
	if cfg.Policy.MaximumStagedAge > 0 && staged.StagedAt.Before(now.Add(-cfg.Policy.MaximumStagedAge)) {
		return ErrStagedUpdateStale
	}
	if staged.ArtifactPath == "" || hasPathTraversal(staged.ArtifactPath) {
		return ErrStorageUnavailable
	}
	info, err := os.Stat(staged.ArtifactPath)
	if err != nil || info.IsDir() {
		return ErrVerificationFailed
	}
	if staged.Size > 0 && info.Size() != staged.Size {
		return ErrVerificationFailed
	}
	got, err := fileSHA256(staged.ArtifactPath)
	if err != nil {
		return ErrVerificationFailed
	}
	if !strings.EqualFold(got, staged.SHA256) {
		return ErrVerificationFailed
	}
	return nil
}

func safeStatusMessage(err error) string {
	switch {
	case errors.Is(err, ErrUpdateBlocked):
		return "update blocked by policy"
	case errors.Is(err, ErrManifestStale):
		return "update manifest stale"
	case errors.Is(err, ErrManifestFutureDated):
		return "update manifest future dated"
	case errors.Is(err, ErrRollbackRisk):
		return "update rollback risk"
	case errors.Is(err, ErrStagedUpdateStale):
		return "staged update stale"
	case errors.Is(err, ErrNoUpdateAvailable):
		return "no update available"
	case errors.Is(err, ErrVerificationFailed):
		return "staged update verification failed"
	default:
		return "stored update metadata is invalid"
	}
}

func newProvider(cfg AppConfig) (Provider, error) {
	switch cfg.Source.Provider {
	case ProviderFileManifest:
		return fileManifestProvider{path: cfg.Source.ManifestPath}, nil
	case ProviderHTTPManifest:
		return httpManifestProvider{url: cfg.Source.ManifestURL, timeout: cfg.HTTPTimeout}, nil
	case ProviderGitHubRawManifest, ProviderGitHubManifest:
		return httpManifestProvider{url: githubRawManifestURL(cfg.Source), timeout: cfg.HTTPTimeout}, nil
	default:
		return nil, ErrInvalidProvider
	}
}

type fileManifestProvider struct {
	path string
}

func (p fileManifestProvider) LoadManifest(ctx context.Context) (Manifest, error) {
	if err := contextError(ctx); err != nil {
		return Manifest{}, err
	}
	f, err := os.Open(p.path)
	if err != nil {
		return Manifest{}, ErrProviderUnavailable
	}
	defer f.Close()
	return readAndDecodeManifest(f)
}

type httpManifestProvider struct {
	url     string
	timeout time.Duration
}

func (p httpManifestProvider) LoadManifest(ctx context.Context) (Manifest, error) {
	if err := contextError(ctx); err != nil {
		return Manifest{}, err
	}
	timeout := p.timeout
	if timeout <= 0 {
		timeout = defaultHTTPTimeout
	}
	client := &http.Client{Timeout: timeout}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.url, nil)
	if err != nil {
		return Manifest{}, ErrInvalidProvider
	}
	resp, err := client.Do(req)
	if err != nil {
		if contextError(ctx) != nil {
			return Manifest{}, ErrContextCanceled
		}
		return Manifest{}, ErrProviderUnavailable
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return Manifest{}, ErrProviderUnavailable
	}
	return readAndDecodeManifest(resp.Body)
}

func readAndDecodeManifest(r io.Reader) (Manifest, error) {
	b, err := readManifestPayload(r)
	if err != nil {
		return Manifest{}, err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	var manifest Manifest
	if err := dec.Decode(&manifest); err != nil {
		return Manifest{}, ErrInvalidManifest
	}
	var trailing any
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Manifest{}, ErrInvalidManifest
	}
	return manifest, nil
}

func readManifestPayload(r io.Reader) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, maxManifestBytes+1))
	if err != nil {
		return nil, ErrProviderUnavailable
	}
	if len(b) == 0 || int64(len(b)) > maxManifestBytes || strings.TrimSpace(string(b)) == "" {
		return nil, ErrInvalidManifest
	}
	return b, nil
}

func releaseFromSelection(manifest Manifest, artifact Artifact, checkedAt time.Time) Release {
	return Release{
		AppID:                   manifest.AppID,
		Version:                 manifest.Version,
		Channel:                 manifest.Channel,
		Platform:                artifact.Platform,
		Architecture:            artifact.Architecture,
		PublishedAt:             manifest.PublishedAt,
		ReleaseNotesURL:         manifest.ReleaseNotesURL,
		ReleaseNotesText:        manifest.ReleaseNotesText,
		MinimumSupportedVersion: manifest.MinimumSupportedVersion,
		RequiredRestart:         manifest.RequiredRestart,
		ApplyBehavior:           manifest.ApplyBehavior,
		ArtifactName:            artifact.Filename,
		ArtifactSHA256:          artifact.SHA256,
		ArtifactSize:            artifact.Size,
		CheckedAt:               checkedAt,
	}
}

func stagedSummaryFrom(staged StagedUpdate) StagedUpdateSummary {
	return StagedUpdateSummary{
		AppID:           staged.AppID,
		Version:         staged.Version,
		Channel:         staged.Channel,
		Platform:        staged.Platform,
		Architecture:    staged.Architecture,
		ArtifactName:    staged.ArtifactName,
		SHA256:          staged.SHA256,
		Size:            staged.Size,
		StagedAt:        staged.StagedAt,
		RequiredRestart: staged.RequiredRestart,
		ApplyBehavior:   staged.ApplyBehavior,
		Message:         "update is staged for app-owned apply",
	}
}

func validSafeName(s string) bool {
	s = strings.TrimSpace(s)
	if !safeNamePattern.MatchString(s) {
		return false
	}
	if strings.Contains(s, "..") || strings.ContainsAny(s, `/\`) {
		return false
	}
	reserved := map[string]bool{"CON": true, "PRN": true, "AUX": true, "NUL": true}
	return !reserved[strings.ToUpper(s)]
}

func validArtifactFilename(name string) bool {
	name = strings.TrimSpace(name)
	return safeFilenamePattern.MatchString(name) && filepath.Base(name) == name && !strings.Contains(name, "..") && !strings.ContainsAny(name, `/\`)
}

func validManifestPath(path string) bool {
	path = strings.TrimSpace(path)
	if path == "" || strings.HasPrefix(path, "/") || strings.Contains(path, `\`) {
		return false
	}
	for _, part := range strings.Split(path, "/") {
		if !validArtifactFilename(part) {
			return false
		}
	}
	return true
}

func hasPathTraversal(path string) bool {
	normalized := strings.ReplaceAll(path, `\`, "/")
	for _, part := range strings.Split(normalized, "/") {
		if part == ".." {
			return true
		}
	}
	return false
}

func githubRawManifestURL(src SourceConfig) string {
	parts := []string{url.PathEscape(src.GitHubOwner), url.PathEscape(src.GitHubRepo), url.PathEscape(src.GitHubRef)}
	for _, part := range strings.Split(strings.Trim(src.GitHubManifestPath, "/"), "/") {
		parts = append(parts, url.PathEscape(part))
	}
	return "https://raw.githubusercontent.com/" + strings.Join(parts, "/")
}

func validVersion(v string) bool {
	return versionPattern.MatchString(strings.TrimSpace(v))
}

func validHTTPURL(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != "" && u.User == nil && !unsafeUpdateDetail(raw)
}

func unsafeUpdateDetail(value string) bool {
	lower := strings.ToLower(strings.TrimSpace(value))
	if lower == "" {
		return false
	}
	credentialMarkers := []string{
		strings.Join([]string{"client", "secret"}, "_"),
		strings.Join([]string{"refresh", "token"}, "_"),
		strings.Join([]string{"access", "token"}, "_"),
		strings.Join([]string{"id", "token"}, "_"),
		strings.Join([]string{"auth", "code"}, "_"),
		strings.Join([]string{"private", "key"}, "_"),
		"begin " + strings.Join([]string{"private", "key"}, " "),
		"github" + "_pat",
		"ghp" + "_",
		"token" + "=",
		"password" + "=",
		"secret" + "=",
	}
	for _, marker := range credentialMarkers {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	pathMarkers := []string{
		`:\`,
		"/" + "users" + "/",
		"/" + "home" + "/",
		"/" + "tmp" + "/",
		`\\`,
		"app" + "data",
		"downloads",
		"desktop",
	}
	for _, marker := range pathMarkers {
		if strings.Contains(lower, strings.ToLower(marker)) {
			return true
		}
	}
	return false
}

func compareVersions(a, b string) int {
	ap, apre := versionParts(a)
	bp, bpre := versionParts(b)
	for i := 0; i < len(ap) || i < len(bp); i++ {
		av, bv := 0, 0
		if i < len(ap) {
			av = ap[i]
		}
		if i < len(bp) {
			bv = bp[i]
		}
		if av > bv {
			return 1
		}
		if av < bv {
			return -1
		}
	}
	if apre == bpre {
		return 0
	}
	if apre == "" {
		return 1
	}
	if bpre == "" {
		return -1
	}
	return strings.Compare(apre, bpre)
}

func versionParts(v string) ([]int, string) {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	pre := ""
	if i := strings.Index(v, "-"); i >= 0 {
		pre = v[i+1:]
		v = v[:i]
	}
	raw := strings.Split(v, ".")
	out := make([]int, 0, len(raw))
	for _, item := range raw {
		n, _ := strconv.Atoi(item)
		out = append(out, n)
	}
	return out, pre
}

func sanitizeProviderError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, ErrContextCanceled) {
		return ErrContextCanceled
	}
	if errors.Is(err, ErrInvalidManifest) || errors.Is(err, ErrNoCompatibleArtifact) || errors.Is(err, ErrNoUpdateAvailable) {
		return err
	}
	return ErrProviderUnavailable
}

func contextError(ctx context.Context) error {
	if ctx != nil && ctx.Err() != nil {
		return ErrContextCanceled
	}
	return nil
}

func writeStreamToFile(ctx context.Context, r io.Reader, path string, max int64) (int64, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return 0, ErrStorageUnavailable
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return 0, ErrStorageUnavailable
	}
	defer f.Close()
	buf := make([]byte, 32*1024)
	var written int64
	for {
		if err := contextError(ctx); err != nil {
			return 0, err
		}
		n, readErr := r.Read(buf)
		if n > 0 {
			written += int64(n)
			if max > 0 && written > max {
				return 0, ErrDownloadFailed
			}
			if _, err := f.Write(buf[:n]); err != nil {
				return 0, ErrStorageUnavailable
			}
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return 0, ErrDownloadFailed
		}
	}
	if err := f.Close(); err != nil {
		return 0, ErrStorageUnavailable
	}
	return written, nil
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", ErrVerificationFailed
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", ErrVerificationFailed
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func copyFileAtomic(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return ErrVerificationFailed
	}
	defer in.Close()
	tmp := dst + ".tmp"
	if _, err := writeStreamToFile(context.Background(), in, tmp, 0); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, dst); err != nil {
		_ = os.Remove(tmp)
		return ErrStorageUnavailable
	}
	return nil
}

func sortedArtifacts(in []Artifact) []Artifact {
	out := append([]Artifact{}, in...)
	sort.Slice(out, func(i, j int) bool { return out[i].Filename < out[j].Filename })
	return out
}
