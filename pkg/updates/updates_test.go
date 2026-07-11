package updates

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestUpdatesPublicStatusDoesNotExposeStoragePaths(t *testing.T) {
	dir := t.TempDir()
	svc, err := NewService(AppConfig{
		AppID:          "aegis-test",
		DisplayName:    "Aegis Test",
		CurrentVersion: "1.0.0",
		Channel:        ChannelStable,
		Platform:       "windows",
		Architecture:   "amd64",
		Namespace:      "updates-test",
		StateDir:       filepath.Join(dir, "state"),
		StagingDir:     filepath.Join(dir, "stage"),
		CacheDir:       filepath.Join(dir, "cache"),
		Source:         SourceConfig{Provider: ProviderFileManifest, ManifestPath: filepath.Join(dir, "missing.json")},
	}, ManualApplyStrategy{})
	if err != nil {
		t.Fatalf("NewService returned error: %v", err)
	}
	state, err := svc.GetStatus(context.Background())
	if err != nil {
		t.Fatalf("GetStatus returned error: %v", err)
	}
	raw, err := json.Marshal(state)
	if err != nil {
		t.Fatalf("marshal state: %v", err)
	}
	if strings.Contains(string(raw), dir) {
		t.Fatalf("public update state leaked local storage path: %s", raw)
	}
}

func TestUpdatesDescribeAndApplyPlanAreSafeHandoffs(t *testing.T) {
	dir := t.TempDir()
	artifact := []byte("public handoff artifact")
	sum := sha256.Sum256(artifact)
	artifactPath := filepath.Join(dir, "artifact.zip")
	if err := os.WriteFile(artifactPath, artifact, 0o600); err != nil {
		t.Fatalf("write artifact: %v", err)
	}
	manifestPath := filepath.Join(dir, "manifest.json")
	cfg := AppConfig{
		AppID:          "aegis-test",
		DisplayName:    "Aegis Test",
		CurrentVersion: "1.0.0",
		Channel:        ChannelStable,
		Platform:       "windows",
		Architecture:   "amd64",
		Namespace:      "updates-test",
		StateDir:       filepath.Join(dir, "state"),
		StagingDir:     filepath.Join(dir, "stage"),
		CacheDir:       filepath.Join(dir, "cache"),
		Source:         SourceConfig{Provider: ProviderFileManifest, ManifestPath: manifestPath},
	}
	manifest := Manifest{
		SchemaVersion:   1,
		AppID:           cfg.AppID,
		Channel:         cfg.Channel,
		Version:         "1.1.0",
		ReleaseNotesURL: "https://example.test/release",
		ApplyBehavior:   "app-owned manual apply",
		Artifacts: []Artifact{{
			Platform:     cfg.Platform,
			Architecture: cfg.Architecture,
			Filename:     "artifact.zip",
			DownloadURL:  artifactPath,
			Size:         int64(len(artifact)),
			SHA256:       hex.EncodeToString(sum[:]),
		}},
	}
	raw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	if err := os.WriteFile(manifestPath, raw, 0o600); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	svc, err := NewService(cfg, ManualApplyStrategy{})
	if err != nil {
		t.Fatalf("NewService returned error: %v", err)
	}
	if _, err := svc.CheckForUpdates(context.Background()); err != nil {
		t.Fatalf("CheckForUpdates returned error: %v", err)
	}
	if _, err := svc.DownloadUpdate(context.Background(), "1.1.0"); err != nil {
		t.Fatalf("DownloadUpdate returned error: %v", err)
	}
	if _, err := svc.StageUpdate(context.Background(), "1.1.0"); err != nil {
		t.Fatalf("StageUpdate returned error: %v", err)
	}
	summary, err := svc.DescribeStagedUpdate(context.Background())
	if err != nil || summary.Version != "1.1.0" || summary.ArtifactName != "artifact.zip" {
		t.Fatalf("DescribeStagedUpdate = %+v, %v", summary, err)
	}
	plan, err := svc.BuildApplyPlan(context.Background())
	if err != nil || !plan.AppOwnedApply || plan.Version != "1.1.0" || len(plan.Steps) == 0 {
		t.Fatalf("BuildApplyPlan = %+v, %v", plan, err)
	}
	assertPublicUpdateJSONSafe(t, summary, dir)
	assertPublicUpdateJSONSafe(t, plan, dir)
	if _, err := svc.Apply(context.Background(), "9.9.9"); err != ErrNoUpdateAvailable {
		t.Fatalf("Apply mismatched version error = %v", err)
	}
	if result, err := svc.Apply(context.Background(), "1.1.0"); err != nil || !result.OK || result.Version != "1.1.0" {
		t.Fatalf("Apply matching version = %+v, %v", result, err)
	}
	if _, err := svc.ClearStagedUpdate(context.Background()); err != nil {
		t.Fatalf("ClearStagedUpdate returned error: %v", err)
	}
	if _, err := svc.DescribeStagedUpdate(context.Background()); err != ErrStagedUpdateNotFound {
		t.Fatalf("DescribeStagedUpdate after clear error = %v", err)
	}
}

func TestUpdatesProviderErrorsAreSanitized(t *testing.T) {
	dir := t.TempDir()
	sensitiveManifest := filepath.Join(dir, "missing-secret-token.json")
	svc, err := NewService(AppConfig{
		AppID:          "aegis-test",
		DisplayName:    "Aegis Test",
		CurrentVersion: "1.0.0",
		Channel:        ChannelStable,
		Platform:       "windows",
		Architecture:   "amd64",
		Namespace:      "updates-test",
		StateDir:       filepath.Join(dir, "state"),
		StagingDir:     filepath.Join(dir, "stage"),
		CacheDir:       filepath.Join(dir, "cache"),
		Source:         SourceConfig{Provider: ProviderFileManifest, ManifestPath: sensitiveManifest},
	}, ManualApplyStrategy{})
	if err != nil {
		t.Fatalf("NewService returned error: %v", err)
	}
	_, err = svc.CheckForUpdates(context.Background())
	if err == nil {
		t.Fatal("expected missing provider manifest to fail")
	}
	if strings.Contains(err.Error(), dir) || strings.Contains(strings.ToLower(err.Error()), "secret-token") {
		t.Fatalf("provider error leaked unsafe detail: %v", err)
	}
	if _, statErr := os.Stat(sensitiveManifest); !os.IsNotExist(statErr) {
		t.Fatalf("test expected manifest to remain missing")
	}
}

func TestUpdatesSecurityPolicyViaPublicAPI(t *testing.T) {
	dir := t.TempDir()
	artifact := []byte("policy artifact")
	sum := sha256.Sum256(artifact)
	artifactPath := filepath.Join(dir, "artifact.zip")
	if err := os.WriteFile(artifactPath, artifact, 0o600); err != nil {
		t.Fatalf("write artifact: %v", err)
	}
	manifestPath := filepath.Join(dir, "manifest.json")
	cfg := AppConfig{
		AppID:          "aegis-test",
		DisplayName:    "Aegis Test",
		CurrentVersion: "1.0.0",
		Channel:        ChannelStable,
		Platform:       "windows",
		Architecture:   "amd64",
		Namespace:      "updates-test",
		StateDir:       filepath.Join(dir, "state"),
		StagingDir:     filepath.Join(dir, "stage"),
		CacheDir:       filepath.Join(dir, "cache"),
		Source:         SourceConfig{Provider: ProviderFileManifest, ManifestPath: manifestPath},
		Policy:         Policy{MinimumVersion: "1.2.0"},
	}
	manifest := Manifest{
		SchemaVersion: 1,
		AppID:         cfg.AppID,
		Channel:       cfg.Channel,
		Version:       "1.1.0",
		Artifacts: []Artifact{{
			Platform:     cfg.Platform,
			Architecture: cfg.Architecture,
			Filename:     "artifact.zip",
			DownloadURL:  artifactPath,
			Size:         int64(len(artifact)),
			SHA256:       hex.EncodeToString(sum[:]),
		}},
	}
	writePublicManifest(t, manifestPath, manifest)
	svc, err := NewService(cfg, ManualApplyStrategy{})
	if err != nil {
		t.Fatalf("NewService returned error: %v", err)
	}
	if _, err := svc.CheckForUpdates(context.Background()); err != ErrNoUpdateAvailable {
		t.Fatalf("below-floor update error = %v", err)
	} else {
		assertPublicUpdateErrorSafe(t, err)
	}

	cfg.Policy.MinimumVersion = ""
	manifest.Version = "1.2.0"
	manifest.Signature = &SignatureMetadata{Kind: "policy-note", KeyID: "release-key", Signature: "token=bad"}
	writePublicManifest(t, manifestPath, manifest)
	svc, err = NewService(cfg, ManualApplyStrategy{})
	if err != nil {
		t.Fatalf("NewService returned error: %v", err)
	}
	if _, err := svc.CheckForUpdates(context.Background()); err != ErrInvalidManifest {
		t.Fatalf("unsafe signature metadata error = %v", err)
	} else {
		assertPublicUpdateErrorSafe(t, err)
	}
}

func TestUpdatesManifestSignatureVerificationViaPublicAPI(t *testing.T) {
	dir := t.TempDir()
	signer := newPublicManifestSigner(t)
	artifact := []byte("signed policy artifact")
	sum := sha256.Sum256(artifact)
	artifactPath := filepath.Join(dir, "artifact.zip")
	if err := os.WriteFile(artifactPath, artifact, 0o600); err != nil {
		t.Fatalf("write artifact: %v", err)
	}
	manifestPath := filepath.Join(dir, "manifest.json")
	cfg := AppConfig{
		AppID:          "aegis-test",
		DisplayName:    "Aegis Test",
		CurrentVersion: "1.0.0",
		Channel:        ChannelStable,
		Platform:       "windows",
		Architecture:   "amd64",
		Namespace:      "updates-test",
		StateDir:       filepath.Join(dir, "state"),
		StagingDir:     filepath.Join(dir, "stage"),
		CacheDir:       filepath.Join(dir, "cache"),
		Source:         SourceConfig{Provider: ProviderFileManifest, ManifestPath: manifestPath},
		Policy: Policy{
			RequireManifestSignature: true,
			ManifestVerificationKeys: map[string]string{signer.keyID: signer.publicKey},
		},
	}
	manifest := Manifest{
		SchemaVersion: 1,
		AppID:         cfg.AppID,
		Channel:       cfg.Channel,
		Version:       "1.2.0",
		Artifacts: []Artifact{{
			Platform:     cfg.Platform,
			Architecture: cfg.Architecture,
			Filename:     "artifact.zip",
			DownloadURL:  artifactPath,
			Size:         int64(len(artifact)),
			SHA256:       hex.EncodeToString(sum[:]),
		}},
	}
	writePublicManifest(t, manifestPath, signer.sign(t, manifest))
	svc, err := NewService(cfg, ManualApplyStrategy{})
	if err != nil {
		t.Fatalf("NewService returned error: %v", err)
	}
	result, err := svc.CheckForUpdates(context.Background())
	if err != nil || !result.UpdateAvailable || result.LatestRelease == nil || result.LatestRelease.Version != "1.2.0" {
		t.Fatalf("signed CheckForUpdates = %+v, %v", result, err)
	}
	assertPublicUpdateJSONSafe(t, result, dir)

	tampered := signer.sign(t, manifest)
	tampered.Version = "1.2.1"
	writePublicManifest(t, manifestPath, tampered)
	if _, err := svc.CheckForUpdates(context.Background()); err != ErrVerificationFailed {
		t.Fatalf("tampered signed manifest error = %v", err)
	} else {
		assertPublicUpdateErrorSafe(t, err)
	}

	unsigned := manifest
	unsigned.Signature = nil
	writePublicManifest(t, manifestPath, unsigned)
	if _, err := svc.CheckForUpdates(context.Background()); err != ErrVerificationFailed {
		t.Fatalf("unsigned manifest with required signature error = %v", err)
	} else {
		assertPublicUpdateErrorSafe(t, err)
	}
}

func TestUpdatesRollbackFreezePolicyViaPublicAPI(t *testing.T) {
	dir := t.TempDir()
	artifact := []byte("rollback policy artifact")
	sum := sha256.Sum256(artifact)
	artifactPath := filepath.Join(dir, "artifact.zip")
	if err := os.WriteFile(artifactPath, artifact, 0o600); err != nil {
		t.Fatalf("write artifact: %v", err)
	}
	manifestPath := filepath.Join(dir, "manifest.json")
	cfg := AppConfig{
		AppID:          "aegis-test",
		DisplayName:    "Aegis Test",
		CurrentVersion: "1.0.0",
		Channel:        ChannelStable,
		Platform:       "windows",
		Architecture:   "amd64",
		Namespace:      "updates-test",
		StateDir:       filepath.Join(dir, "state"),
		StagingDir:     filepath.Join(dir, "stage"),
		CacheDir:       filepath.Join(dir, "cache"),
		Source:         SourceConfig{Provider: ProviderFileManifest, ManifestPath: manifestPath},
		Policy:         Policy{FreezeUpdates: true},
	}
	manifest := Manifest{
		SchemaVersion: 1,
		AppID:         cfg.AppID,
		Channel:       cfg.Channel,
		Version:       "1.2.0",
		Artifacts: []Artifact{{
			Platform:     cfg.Platform,
			Architecture: cfg.Architecture,
			Filename:     "artifact.zip",
			DownloadURL:  artifactPath,
			Size:         int64(len(artifact)),
			SHA256:       hex.EncodeToString(sum[:]),
		}},
	}
	writePublicManifest(t, manifestPath, manifest)
	svc, err := NewService(cfg, ManualApplyStrategy{})
	if err != nil {
		t.Fatalf("NewService returned error: %v", err)
	}
	if _, err := svc.CheckForUpdates(context.Background()); err != ErrUpdateBlocked {
		t.Fatalf("frozen update error = %v", err)
	} else {
		assertPublicUpdateErrorSafe(t, err)
	}

	cfg.Policy = Policy{MaximumManifestAge: time.Hour}
	manifest.PublishedAt = time.Now().UTC().Add(-24 * time.Hour).Format(time.RFC3339)
	writePublicManifest(t, manifestPath, manifest)
	svc, err = NewService(cfg, ManualApplyStrategy{})
	if err != nil {
		t.Fatalf("NewService returned error: %v", err)
	}
	if _, err := svc.CheckForUpdates(context.Background()); err != ErrManifestStale {
		t.Fatalf("stale update error = %v", err)
	} else {
		assertPublicUpdateErrorSafe(t, err)
	}
}

func TestUpdatesApplyResultSanitizesAppOwnedMessage(t *testing.T) {
	dir := t.TempDir()
	artifact := []byte("apply result artifact")
	sum := sha256.Sum256(artifact)
	artifactPath := filepath.Join(dir, "artifact.zip")
	if err := os.WriteFile(artifactPath, artifact, 0o600); err != nil {
		t.Fatalf("write artifact: %v", err)
	}
	manifestPath := filepath.Join(dir, "manifest.json")
	cfg := AppConfig{
		AppID:          "aegis-test",
		DisplayName:    "Aegis Test",
		CurrentVersion: "1.0.0",
		Channel:        ChannelStable,
		Platform:       "windows",
		Architecture:   "amd64",
		Namespace:      "updates-test",
		StateDir:       filepath.Join(dir, "state"),
		StagingDir:     filepath.Join(dir, "stage"),
		CacheDir:       filepath.Join(dir, "cache"),
		Source:         SourceConfig{Provider: ProviderFileManifest, ManifestPath: manifestPath},
	}
	manifest := Manifest{
		SchemaVersion: 1,
		AppID:         cfg.AppID,
		Channel:       cfg.Channel,
		Version:       "1.2.0",
		Artifacts: []Artifact{{
			Platform:     cfg.Platform,
			Architecture: cfg.Architecture,
			Filename:     "artifact.zip",
			DownloadURL:  artifactPath,
			Size:         int64(len(artifact)),
			SHA256:       hex.EncodeToString(sum[:]),
		}},
	}
	writePublicManifest(t, manifestPath, manifest)
	svc, err := NewService(cfg, unsafeSuccessfulApply{})
	if err != nil {
		t.Fatalf("NewService returned error: %v", err)
	}
	if _, err := svc.DownloadUpdate(context.Background(), "1.2.0"); err != nil {
		t.Fatalf("DownloadUpdate returned error: %v", err)
	}
	if _, err := svc.StageUpdate(context.Background(), "1.2.0"); err != nil {
		t.Fatalf("StageUpdate returned error: %v", err)
	}
	if _, err := svc.Apply(context.Background(), "9.9.9"); !errors.Is(err, ErrNoUpdateAvailable) {
		t.Fatalf("Apply with mismatched version error = %v, want no update available", err)
	}
	result, err := svc.Apply(context.Background(), "1.2.0")
	if err != nil {
		t.Fatalf("Apply returned error: %v", err)
	}
	if result.Version != "1.2.0" || !result.OK {
		t.Fatalf("unexpected apply result: %+v", result)
	}
	assertPublicUpdateJSONSafe(t, result, dir)
}

func TestUpdatesStagedArtifactRevalidationViaPublicAPI(t *testing.T) {
	dir := t.TempDir()
	artifact := []byte("public staged retention artifact")
	sum := sha256.Sum256(artifact)
	artifactPath := filepath.Join(dir, "artifact.zip")
	if err := os.WriteFile(artifactPath, artifact, 0o600); err != nil {
		t.Fatalf("write artifact: %v", err)
	}
	manifestPath := filepath.Join(dir, "manifest.json")
	cfg := AppConfig{
		AppID:          "aegis-test",
		DisplayName:    "Aegis Test",
		CurrentVersion: "1.0.0",
		Channel:        ChannelStable,
		Platform:       "windows",
		Architecture:   "amd64",
		Namespace:      "updates-test",
		StateDir:       filepath.Join(dir, "state"),
		StagingDir:     filepath.Join(dir, "stage"),
		CacheDir:       filepath.Join(dir, "cache"),
		Source:         SourceConfig{Provider: ProviderFileManifest, ManifestPath: manifestPath},
	}
	writePublicManifest(t, manifestPath, Manifest{
		SchemaVersion: 1,
		AppID:         cfg.AppID,
		Channel:       cfg.Channel,
		Version:       "1.2.0",
		Artifacts: []Artifact{{
			Platform:     cfg.Platform,
			Architecture: cfg.Architecture,
			Filename:     "artifact.zip",
			DownloadURL:  artifactPath,
			Size:         int64(len(artifact)),
			SHA256:       hex.EncodeToString(sum[:]),
		}},
	})
	svc, err := NewService(cfg, ManualApplyStrategy{})
	if err != nil {
		t.Fatalf("NewService returned error: %v", err)
	}
	if _, err := svc.DownloadUpdate(context.Background(), "1.2.0"); err != nil {
		t.Fatalf("DownloadUpdate returned error: %v", err)
	}
	if _, err := svc.StageUpdate(context.Background(), "1.2.0"); err != nil {
		t.Fatalf("StageUpdate returned error: %v", err)
	}
	removeStagedArtifactByName(t, cfg.StagingDir, "artifact.zip")
	if _, err := svc.DescribeStagedUpdate(context.Background()); err != ErrVerificationFailed {
		t.Fatalf("DescribeStagedUpdate after staged artifact removal = %v", err)
	} else {
		assertPublicUpdateErrorSafe(t, err)
	}
	if _, err := svc.BuildApplyPlan(context.Background()); err != ErrVerificationFailed {
		t.Fatalf("BuildApplyPlan after staged artifact removal = %v", err)
	} else {
		assertPublicUpdateErrorSafe(t, err)
	}
	state, err := svc.GetStatus(context.Background())
	if err != nil {
		t.Fatalf("GetStatus returned error: %v", err)
	}
	if state.Verified || state.StagedVersion != "" {
		t.Fatalf("invalid staged artifact still marked verified: %+v", state)
	}
	assertPublicUpdateJSONSafe(t, state, dir)
}

func assertPublicUpdateJSONSafe(t *testing.T, v any, privatePath string) {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal update value: %v", err)
	}
	text := strings.ToLower(string(raw))
	for _, forbidden := range []string{strings.ToLower(privatePath), "client_secret", "refresh_token", "access_token", "id_token", "auth_code", "private_key", "github_pat", "ghp_", "token=", "password=", "secret=", "artifact_path"} {
		if forbidden != "" && strings.Contains(text, forbidden) {
			t.Fatalf("unsafe update JSON detail %q in %s", forbidden, string(raw))
		}
	}
}

func removeStagedArtifactByName(t *testing.T, root, filename string) {
	t.Helper()
	removed := false
	if err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || filepath.Base(path) != filename {
			return nil
		}
		removed = true
		return os.Remove(path)
	}); err != nil {
		t.Fatalf("walk staged root: %v", err)
	}
	if !removed {
		t.Fatalf("staged artifact %q not found under test staging root", filename)
	}
}

type unsafeSuccessfulApply struct{}

func (unsafeSuccessfulApply) Apply(context.Context, StagedUpdate) (ApplyResult, error) {
	return ApplyResult{Version: `C:\Users\person\wrong-version`, OK: true, Message: `applied from C:\Users\person\AppData\token=bad`}, nil
}

func assertPublicUpdateErrorSafe(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("expected error")
	}
	text := strings.ToLower(err.Error())
	for _, forbidden := range []string{`:\`, "/users/", "/home/", "appdata", "client_secret", "refresh_token", "access_token", "id_token", "auth_code", "private_key", "github_pat", "ghp_", "token=", "password=", "secret=", "artifact_path"} {
		if forbidden != "" && strings.Contains(text, forbidden) {
			t.Fatalf("unsafe update error detail %q in %v", forbidden, err)
		}
	}
}

func writePublicManifest(t *testing.T, path string, manifest Manifest) {
	t.Helper()
	raw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
}

type publicManifestSigner struct {
	keyID     string
	publicKey string
	private   ed25519.PrivateKey
}

func newPublicManifestSigner(t *testing.T) publicManifestSigner {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(strings.NewReader(strings.Repeat("aegis-public-test-key-material-", 4)))
	if err != nil {
		t.Fatalf("generate test key: %v", err)
	}
	return publicManifestSigner{
		keyID:     "test-ed25519-key",
		publicKey: base64.StdEncoding.EncodeToString(publicKey),
		private:   privateKey,
	}
}

func (s publicManifestSigner) sign(t *testing.T, manifest Manifest) Manifest {
	t.Helper()
	unsigned := manifest
	unsigned.Signature = nil
	raw, err := json.Marshal(unsigned)
	if err != nil {
		t.Fatalf("marshal unsigned manifest: %v", err)
	}
	signed := manifest
	signed.Signature = &SignatureMetadata{
		Kind:      "ed25519",
		KeyID:     s.keyID,
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(s.private, raw)),
	}
	return signed
}
