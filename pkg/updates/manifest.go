package updates

import (
	"sort"
	"strings"
	"time"
)

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

func sortedArtifacts(in []Artifact) []Artifact {
	out := append([]Artifact{}, in...)
	sort.Slice(out, func(i, j int) bool { return out[i].Filename < out[j].Filename })
	return out
}
