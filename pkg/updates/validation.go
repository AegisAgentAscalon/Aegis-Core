package updates

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

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
	cfg.Policy.ManifestVerificationKeys = cloneStringMap(cfg.Policy.ManifestVerificationKeys)
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
	return normalizeSourceAccess(src)
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
	case cfg.Policy.MaximumArtifactSize < 0:
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
	if err := validateSource(cfg.Source); err != nil {
		return err
	}
	return validateSourceAccess(cfg.Source, cfg.Policy)
}

func validateConfigWithOptions(cfg AppConfig, options ServiceOptions) error {
	if err := validateConfig(cfg); err != nil {
		return err
	}
	if cfg.Source.Access == SourceAccessAppOwnedAuthenticated && options.AuthenticatedHTTPClient == nil {
		return ErrInvalidConfig
	}
	return nil
}

func validateSource(src SourceConfig) error {
	switch src.Provider {
	case ProviderFileManifest:
		if src.ManifestPath == "" || hasPathTraversal(src.ManifestPath) {
			return ErrInvalidProvider
		}
	case ProviderHTTPManifest:
		if src.ManifestURL == "" || validateSourceURL(src, src.ManifestURL, false) != nil {
			return ErrInvalidProvider
		}
	case ProviderGitHubRawManifest, ProviderGitHubManifest:
		if !validSafeName(src.GitHubOwner) || !validSafeName(src.GitHubRepo) || !validSafeName(src.GitHubRef) || !validManifestPath(src.GitHubManifestPath) {
			return ErrInvalidProvider
		}
		if validateSourceURL(src, githubRawManifestURL(src), false) != nil {
			return ErrInvalidProvider
		}
	default:
		return ErrInvalidProvider
	}
	return nil
}

func validateManifest(cfg AppConfig, manifest Manifest) error {
	if manifest.SchemaVersion == 0 {
		manifest.SchemaVersion = schemaVersion
	}
	switch {
	case manifest.SchemaVersion != schemaVersion:
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
	if !requiredManifestKeyMatches(cfg, manifest) {
		return ErrVerificationFailed
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
	if selected.SchemaVersion != schemaVersion || !sourceAndPolicyMatch(cfg, selected.SourceKey, selected.PolicyKey) || selected.UpdatedAt.IsZero() {
		return ErrStorageUnavailable
	}
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
	return validateArtifactDownloadURL(cfg.Source, artifact.DownloadURL)
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
	if manifest.ReleaseNotesURL != "" && !validHTTPURL(manifest.ReleaseNotesURL) {
		return ErrInvalidManifest
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
	// This uses Go's JSON encoding, not a cross-language canonical JSON scheme.
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

func (s *Service) validateDownloadedUpdate(downloaded downloadedUpdate) error {
	return validateDownloadedUpdateFor(s.cfg, s.store, downloaded)
}

func validateDownloadedUpdateFor(cfg AppConfig, st *store, downloaded downloadedUpdate) error {
	if downloaded.SchemaVersion != schemaVersion || !sourceAndPolicyMatch(cfg, downloaded.SourceKey, downloaded.PolicyKey) || downloaded.DownloadedAt.IsZero() || downloaded.BytesWritten < 0 {
		return ErrStorageUnavailable
	}
	if err := validateManifest(cfg, downloaded.Manifest); err != nil {
		return err
	}
	if err := validateArtifact(cfg, downloaded.Artifact); err != nil {
		return err
	}
	expectedPath := filepath.Join(st.downloadsDir(), downloaded.Artifact.Filename)
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

func (s *Service) validateStagedUpdateReady(staged stagedUpdateRecord, now time.Time) error {
	return validateStagedUpdateReadyFor(s.cfg, s.store, staged, now)
}

func validateStagedUpdateReadyFor(cfg AppConfig, st *store, record stagedUpdateRecord, now time.Time) error {
	staged := record.StagedUpdate
	if err := validateStagedUpdate(cfg, record); err != nil {
		return err
	}
	if cfg.Policy.MaximumFutureSkew > 0 && staged.StagedAt.After(now.Add(cfg.Policy.MaximumFutureSkew)) {
		return ErrManifestFutureDated
	}
	if cfg.Policy.MaximumStagedAge > 0 && staged.StagedAt.Before(now.Add(-cfg.Policy.MaximumStagedAge)) {
		return ErrStagedUpdateStale
	}
	expectedPath := filepath.Join(st.stagedDir(), staged.ArtifactName)
	if staged.ArtifactPath == "" || !samePath(staged.ArtifactPath, expectedPath) {
		return ErrStorageUnavailable
	}
	info, err := os.Lstat(expectedPath)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return ErrVerificationFailed
	}
	if staged.Size > 0 && info.Size() != staged.Size {
		return ErrVerificationFailed
	}
	got, err := fileSHA256(expectedPath)
	if err != nil || !strings.EqualFold(got, staged.SHA256) {
		return ErrVerificationFailed
	}
	return nil
}
