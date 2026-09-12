package updates

import (
	"context"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

func validateSelectedUpdate(cfg AppConfig, selected selectedUpdate) error {
	if selected.SchemaVersion != schemaVersion || !sourceAndPolicyMatch(cfg, selected.SourceKey, selected.PolicyKey) || selected.UpdatedAt.IsZero() {
		return ErrStorageUnavailable
	}
	return validateArtifactBinding(cfg, selected.Manifest, selected.Artifact)
}

// The manifest, not the detached cache record, authorizes artifact identity.
func validateArtifactBinding(cfg AppConfig, manifest Manifest, detached Artifact) error {
	authorized, err := selectArtifactForConfig(cfg, manifest)
	if err != nil {
		return err
	}
	if (authorized.Signature == nil) != (detached.Signature == nil) {
		return ErrVerificationFailed
	}
	if authorized.Signature != nil && *authorized.Signature != *detached.Signature {
		return ErrVerificationFailed
	}
	authorized.Signature, detached.Signature = nil, nil
	if authorized != detached {
		return ErrVerificationFailed
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
	return validateArtifactDownloadURL(cfg.Source, artifact.DownloadURL)
}

func validateArtifactDownloadURL(source SourceConfig, raw string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ErrInvalidManifest
	}
	if filepath.IsAbs(raw) {
		if source.Provider != ProviderFileManifest || hasPathTraversal(raw) {
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
		if unsafeUpdateDetail(raw) || validateSourceURL(source, raw, false) != nil {
			return ErrInvalidManifest
		}
		return nil
	case "file":
		if source.Provider != ProviderFileManifest || u.Host != "" {
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

func validateStagedUpdate(cfg AppConfig, record stagedUpdateRecord) error {
	staged := record.StagedUpdate
	if cfg.Source.SourceID != "" {
		if !sourceAndPolicyMatch(cfg, record.SourceKey, record.PolicyKey) || staged.Source != sourceSummary(cfg.Source) {
			return ErrStorageUnavailable
		}
	}
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

func validateDownloadedUpdateFor(cfg AppConfig, st *store, downloaded downloadedUpdate) error {
	if downloaded.SchemaVersion != schemaVersion || !sourceAndPolicyMatch(cfg, downloaded.SourceKey, downloaded.PolicyKey) || downloaded.DownloadedAt.IsZero() || downloaded.BytesWritten < 0 {
		return ErrStorageUnavailable
	}
	if err := validateArtifactBinding(cfg, downloaded.Manifest, downloaded.Artifact); err != nil {
		return err
	}
	expectedPath := st.downloadedPathFor(downloaded)
	if downloaded.ArtifactPath == "" || !samePath(downloaded.ArtifactPath, expectedPath) {
		return ErrStorageUnavailable
	}
	info, err := os.Lstat(expectedPath)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return ErrVerificationFailed
	}
	if info.Size() != downloaded.BytesWritten || (downloaded.Artifact.Size > 0 && info.Size() != downloaded.Artifact.Size) {
		return ErrVerificationFailed
	}
	if cfg.Policy.MaximumArtifactSize > 0 && info.Size() > cfg.Policy.MaximumArtifactSize {
		return ErrVerificationFailed
	}
	return nil
}

func validateStagedUpdateReadyFor(ctx context.Context, cfg AppConfig, st *store, record stagedUpdateRecord, now time.Time) error {
	if err := validateStagedMetadataFor(ctx, cfg, st, record, now); err != nil {
		return err
	}
	return validateStagedBytes(ctx, st, record)
}

func validateStagedMetadataFor(ctx context.Context, cfg AppConfig, st *store, record stagedUpdateRecord, now time.Time) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	staged := record.StagedUpdate
	if err := validateStagedUpdate(cfg, record); err != nil {
		return err
	}
	manifest := record.Manifest
	if manifest == nil {
		return ErrVerificationFailed
	}
	artifact, err := selectArtifactForConfig(cfg, *manifest)
	if err != nil {
		return err
	}
	if staged.Version != manifest.Version || staged.ArtifactName != artifact.Filename ||
		!strings.EqualFold(staged.SHA256, artifact.SHA256) || (artifact.Size > 0 && staged.Size != artifact.Size) ||
		staged.RequiredRestart != manifest.RequiredRestart || staged.ApplyBehavior != manifest.ApplyBehavior {
		return ErrVerificationFailed
	}
	if cfg.Policy.MaximumFutureSkew > 0 && staged.StagedAt.After(now.Add(cfg.Policy.MaximumFutureSkew)) {
		return ErrManifestFutureDated
	}
	if cfg.Policy.MaximumStagedAge > 0 && staged.StagedAt.Before(now.Add(-cfg.Policy.MaximumStagedAge)) {
		return ErrStagedUpdateStale
	}
	expectedPath := st.stagedPathFor(record)
	if staged.ArtifactPath == "" || !samePath(staged.ArtifactPath, expectedPath) {
		return ErrStorageUnavailable
	}
	return contextError(ctx)
}

func validateStagedBytes(ctx context.Context, st *store, record stagedUpdateRecord) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	staged := record.StagedUpdate
	expectedPath := st.stagedPathFor(record)
	info, err := os.Lstat(expectedPath)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return ErrVerificationFailed
	}
	if info.Size() != staged.Size {
		return ErrVerificationFailed
	}
	got, err := hashFile(ctx, expectedPath)
	if errors.Is(err, ErrContextCanceled) {
		return err
	}
	if err != nil || !strings.EqualFold(got, staged.SHA256) {
		return ErrVerificationFailed
	}
	return contextError(ctx)
}
