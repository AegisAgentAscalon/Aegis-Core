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
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestConfigValidation(t *testing.T) {
	base := testConfig(t)
	cases := []AppConfig{
		func() AppConfig { c := base; c.AppID = ""; return c }(),
		func() AppConfig { c := base; c.AppID = "../bad"; return c }(),
		func() AppConfig { c := base; c.Channel = ""; return c }(),
		func() AppConfig { c := base; c.Namespace = "..\\bad"; return c }(),
		func() AppConfig { c := base; c.StagingDir = ""; c.CacheDir = ""; c.StateDir = ""; return c }(),
		func() AppConfig { c := base; c.Source.Provider = "bad"; return c }(),
		func() AppConfig { c := base; c.Source.ManifestPath = "..\\manifest.json"; return c }(),
		func() AppConfig {
			c := base
			c.Source = SourceConfig{Provider: ProviderHTTPManifest, ManifestURL: "https://user:pass@example.test/manifest.json"}
			return c
		}(),
		func() AppConfig {
			c := base
			c.Source = SourceConfig{Provider: ProviderHTTPManifest, ManifestURL: "https://example.test/manifest.json?token=bad"}
			return c
		}(),
	}
	for _, cfg := range cases {
		if _, err := NewService(cfg, nil); err == nil {
			t.Fatalf("expected config error for %+v", cfg)
		}
	}
}

func TestFileManifestFullFlow(t *testing.T) {
	ctx := context.Background()
	cfg, artifactPath, artifactHash := testUpdateFiles(t, "1.2.0")
	manifest := testManifest(cfg, "1.2.0", artifactPath, artifactHash)
	writeManifest(t, cfg.Source.ManifestPath, manifest)
	svc, err := NewService(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	check, err := svc.CheckForUpdates(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !check.UpdateAvailable || check.LatestRelease.Version != "1.2.0" {
		t.Fatalf("expected update available, got %+v", check)
	}
	download, err := svc.DownloadUpdate(ctx, "1.2.0")
	if err != nil || download.ArtifactName == "" || download.BytesWritten == 0 {
		t.Fatalf("expected download, got %+v %v", download, err)
	}
	verify, err := svc.VerifyUpdate(ctx, "1.2.0")
	if err != nil || !verify.OK {
		t.Fatalf("expected verify, got %+v %v", verify, err)
	}
	stage, err := svc.StageUpdate(ctx, "1.2.0")
	if err != nil || !stage.Staged {
		t.Fatalf("expected stage, got %+v %v", stage, err)
	}
	describe, err := svc.DescribeStagedUpdate(ctx)
	if err != nil || describe.Version != "1.2.0" || describe.ArtifactName == "" {
		t.Fatalf("expected staged summary, got %+v %v", describe, err)
	}
	plan, err := svc.BuildApplyPlan(ctx)
	if err != nil || !plan.AppOwnedApply || plan.Version != "1.2.0" || len(plan.Steps) == 0 {
		t.Fatalf("expected app-owned apply plan, got %+v %v", plan, err)
	}
	assertUpdateJSONSafe(t, describe)
	assertUpdateJSONSafe(t, plan)
	status, err := svc.GetStatus(ctx)
	if err != nil || status.StagedVersion != "1.2.0" || status.LatestRelease == nil {
		t.Fatalf("expected safe status, got %+v %v", status, err)
	}
	if strings.Contains(status.Message, cfg.StagingDir) || strings.Contains(status.StagedVersion, cfg.StagingDir) {
		t.Fatalf("status leaked staging path")
	}
	apply, err := svc.ApplyUpdate(ctx)
	if err != nil || !apply.OK {
		t.Fatalf("expected manual apply, got %+v %v", apply, err)
	}
	clear, err := svc.ClearStagedUpdate(ctx)
	if err != nil || !clear.Cleared {
		t.Fatalf("expected clear, got %+v %v", clear, err)
	}
	clear, err = svc.ClearStagedUpdate(ctx)
	if err != nil || !clear.Cleared {
		t.Fatalf("expected idempotent clear, got %+v %v", clear, err)
	}
	if _, err := svc.DescribeStagedUpdate(ctx); !errors.Is(err, ErrStagedUpdateNotFound) {
		t.Fatalf("expected missing staged update after clear, got %v", err)
	}
}

func TestManifestFailureModes(t *testing.T) {
	cfg, artifactPath, artifactHash := testUpdateFiles(t, "1.2.0")
	tests := []struct {
		name     string
		manifest Manifest
		want     error
	}{
		{name: "wrong app", manifest: func() Manifest {
			m := testManifest(cfg, "1.2.0", artifactPath, artifactHash)
			m.AppID = "other"
			return m
		}(), want: ErrInvalidManifest},
		{name: "wrong channel", manifest: func() Manifest {
			m := testManifest(cfg, "1.2.0", artifactPath, artifactHash)
			m.Channel = ChannelDev
			return m
		}(), want: ErrInvalidManifest},
		{name: "invalid version", manifest: func() Manifest { m := testManifest(cfg, "bad version", artifactPath, artifactHash); return m }(), want: ErrInvalidManifest},
		{name: "missing hash", manifest: func() Manifest { m := testManifest(cfg, "1.2.0", artifactPath, ""); return m }(), want: ErrInvalidManifest},
		{name: "unsafe filename", manifest: func() Manifest {
			m := testManifest(cfg, "1.2.0", artifactPath, artifactHash)
			m.Artifacts[0].Filename = "../evil"
			return m
		}(), want: ErrInvalidManifest},
		{name: "unsafe release notes", manifest: func() Manifest {
			m := testManifest(cfg, "1.2.0", artifactPath, artifactHash)
			m.ReleaseNotesText = `token=bad at C:\Users\person\Downloads`
			return m
		}(), want: ErrInvalidManifest},
		{name: "unsafe metadata", manifest: func() Manifest {
			m := testManifest(cfg, "1.2.0", artifactPath, artifactHash)
			m.Metadata = map[string]string{"provider": "secret=bad"}
			return m
		}(), want: ErrInvalidManifest},
		{name: "unsafe future metadata", manifest: func() Manifest {
			m := testManifest(cfg, "1.2.0", artifactPath, artifactHash)
			m.Future = map[string][]string{"notes": []string{`C:\Users\person\future`}}
			return m
		}(), want: ErrInvalidManifest},
		{name: "unsafe manifest signature metadata", manifest: func() Manifest {
			m := testManifest(cfg, "1.2.0", artifactPath, artifactHash)
			m.Signature = &SignatureMetadata{Kind: "policy-note", KeyID: "release-key", Signature: "token=bad"}
			return m
		}(), want: ErrInvalidManifest},
		{name: "unsafe artifact signature metadata", manifest: func() Manifest {
			m := testManifest(cfg, "1.2.0", artifactPath, artifactHash)
			m.Artifacts[0].Signature = &SignatureMetadata{Kind: "policy-note", KeyID: `C:\Users\person\key`, Signature: "opaque"}
			return m
		}(), want: ErrInvalidManifest},
		{name: "url credentials", manifest: func() Manifest {
			m := testManifest(cfg, "1.2.0", artifactPath, artifactHash)
			m.Artifacts[0].DownloadURL = "https://user:pass@example.test/artifact.zip"
			return m
		}(), want: ErrInvalidManifest},
		{name: "relative artifact path", manifest: func() Manifest {
			m := testManifest(cfg, "1.2.0", artifactPath, artifactHash)
			m.Artifacts[0].DownloadURL = "artifact.zip"
			return m
		}(), want: ErrInvalidManifest},
		{name: "path traversal artifact path", manifest: func() Manifest {
			m := testManifest(cfg, "1.2.0", artifactPath, artifactHash)
			m.Artifacts[0].DownloadURL = filepath.Join("..", "artifact.zip")
			return m
		}(), want: ErrInvalidManifest},
		{name: "unsupported artifact scheme", manifest: func() Manifest {
			m := testManifest(cfg, "1.2.0", artifactPath, artifactHash)
			m.Artifacts[0].DownloadURL = "ftp://example.test/artifact.zip"
			return m
		}(), want: ErrInvalidManifest},
		{name: "platform mismatch", manifest: func() Manifest {
			m := testManifest(cfg, "1.2.0", artifactPath, artifactHash)
			m.Artifacts[0].Platform = "other"
			return m
		}(), want: ErrNoCompatibleArtifact},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			writeManifest(t, cfg.Source.ManifestPath, tt.manifest)
			svc, err := NewService(cfg, nil)
			if err != nil {
				t.Fatal(err)
			}
			_, err = svc.CheckForUpdates(context.Background())
			if !errors.Is(err, tt.want) {
				t.Fatalf("expected %v, got %v", tt.want, err)
			}
		})
	}
}

func TestRemoteManifestProvidersCannotReferenceLocalArtifacts(t *testing.T) {
	cfg, artifactPath, hash := testUpdateFiles(t, "1.1.0")
	manifest := testManifest(cfg, "1.1.0", artifactPath, hash)
	cfg.Source = SourceConfig{Provider: ProviderHTTPManifest, ManifestURL: "https://example.test/manifest.json"}

	if _, err := (&Service{cfg: cfg}).selectArtifact(manifest); !errors.Is(err, ErrInvalidManifest) {
		t.Fatalf("remote provider local artifact error = %v, want invalid manifest", err)
	}

	manifest.Artifacts[0].DownloadURL = "file:///" + strings.ReplaceAll(artifactPath, `\`, `/`)
	if _, err := (&Service{cfg: cfg}).selectArtifact(manifest); !errors.Is(err, ErrInvalidManifest) {
		t.Fatalf("remote provider file URL artifact error = %v, want invalid manifest", err)
	}
}

func TestManifestProviderRejectsSuspiciousBodies(t *testing.T) {
	cfg, artifactPath, artifactHash := testUpdateFiles(t, "1.2.0")
	valid, err := json.Marshal(testManifest(cfg, "1.2.0", artifactPath, artifactHash))
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		body []byte
	}{
		{name: "empty", body: nil},
		{name: "trailing data", body: append(valid, []byte("\n{}")...)},
		{name: "oversized", body: bytes.Repeat([]byte(" "), maxManifestBytes+1)},
	}
	for _, tt := range tests {
		t.Run("file "+tt.name, func(t *testing.T) {
			if err := os.WriteFile(cfg.Source.ManifestPath, tt.body, 0o600); err != nil {
				t.Fatal(err)
			}
			svc, err := NewService(cfg, nil)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := svc.CheckForUpdates(context.Background()); !errors.Is(err, ErrInvalidManifest) {
				t.Fatalf("expected invalid manifest, got %v", err)
			} else {
				assertUpdateErrorSafe(t, err)
			}
		})
		t.Run("http "+tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write(tt.body)
			}))
			defer server.Close()
			httpCfg := cfg
			httpCfg.Source = SourceConfig{Provider: ProviderHTTPManifest, ManifestURL: server.URL + "/manifest.json"}
			svc, err := NewService(httpCfg, nil)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := svc.CheckForUpdates(context.Background()); !errors.Is(err, ErrInvalidManifest) {
				t.Fatalf("expected invalid manifest, got %v", err)
			} else {
				assertUpdateErrorSafe(t, err)
			}
		})
	}
}

func TestManifestSignatureVerification(t *testing.T) {
	cfg, artifactPath, artifactHash := testUpdateFiles(t, "1.2.0")
	keyID, publicKey, signer := testManifestSigner(t)
	cfg.Policy.RequireManifestSignature = true
	cfg.Policy.ManifestVerificationKeys = map[string]string{keyID: publicKey}

	unsigned := testManifest(cfg, "1.2.0", artifactPath, artifactHash)
	signed := signer(unsigned)
	writeManifest(t, cfg.Source.ManifestPath, signed)
	svc, err := NewService(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	check, err := svc.CheckForUpdates(context.Background())
	if err != nil || !check.UpdateAvailable {
		t.Fatalf("expected signed manifest update, got %+v %v", check, err)
	}
	assertUpdateJSONSafe(t, check)

	tampered := signedManifestCopy(signed)
	tampered.Version = "1.2.1"
	writeManifest(t, cfg.Source.ManifestPath, tampered)
	if _, err := svc.CheckForUpdates(context.Background()); !errors.Is(err, ErrVerificationFailed) {
		t.Fatalf("expected tampered manifest verification failure, got %v", err)
	} else {
		assertUpdateErrorSafe(t, err)
	}

	invalidSignature := signedManifestCopy(signed)
	invalidSignature.Signature.Signature = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, ed25519.SignatureSize))
	writeManifest(t, cfg.Source.ManifestPath, invalidSignature)
	if _, err := svc.CheckForUpdates(context.Background()); !errors.Is(err, ErrVerificationFailed) {
		t.Fatalf("expected invalid signature failure, got %v", err)
	} else {
		assertUpdateErrorSafe(t, err)
	}

	unsupported := signedManifestCopy(signed)
	unsupported.Signature.Kind = "rsa"
	writeManifest(t, cfg.Source.ManifestPath, unsupported)
	if _, err := svc.CheckForUpdates(context.Background()); !errors.Is(err, ErrVerificationFailed) {
		t.Fatalf("expected unsupported signature kind failure, got %v", err)
	} else {
		assertUpdateErrorSafe(t, err)
	}

	malformed := signedManifestCopy(signed)
	malformed.Signature.Signature = "not-base64"
	writeManifest(t, cfg.Source.ManifestPath, malformed)
	if _, err := svc.CheckForUpdates(context.Background()); !errors.Is(err, ErrVerificationFailed) {
		t.Fatalf("expected malformed signature failure, got %v", err)
	} else {
		assertUpdateErrorSafe(t, err)
	}

	unknownKey := signedManifestCopy(signed)
	unknownKey.Signature.KeyID = "other-key"
	writeManifest(t, cfg.Source.ManifestPath, unknownKey)
	if _, err := svc.CheckForUpdates(context.Background()); !errors.Is(err, ErrVerificationFailed) {
		t.Fatalf("expected missing verifier material failure, got %v", err)
	} else {
		assertUpdateErrorSafe(t, err)
	}

	writeManifest(t, cfg.Source.ManifestPath, unsigned)
	if _, err := svc.CheckForUpdates(context.Background()); !errors.Is(err, ErrVerificationFailed) {
		t.Fatalf("expected unsigned manifest failure when signature required, got %v", err)
	} else {
		assertUpdateErrorSafe(t, err)
	}

	noVerifier := cfg
	noVerifier.Policy.ManifestVerificationKeys = nil
	if _, err := NewService(noVerifier, nil); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("expected missing verifier config failure, got %v", err)
	} else {
		assertUpdateErrorSafe(t, err)
	}
}

func TestUnsignedManifestRemainsShaOnlyWhenSignatureNotRequired(t *testing.T) {
	cfg, artifactPath, artifactHash := testUpdateFiles(t, "1.2.0")
	cfg.Policy.RequireManifestSignature = false
	cfg.Policy.ManifestVerificationKeys = nil
	writeManifest(t, cfg.Source.ManifestPath, testManifest(cfg, "1.2.0", artifactPath, artifactHash))
	svc, err := NewService(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	check, err := svc.CheckForUpdates(context.Background())
	if err != nil || !check.UpdateAvailable {
		t.Fatalf("expected unsigned reference manifest to remain usable when signature is not required, got %+v %v", check, err)
	}
	assertUpdateJSONSafe(t, check)
}

func TestUpdateSecurityVersionPolicy(t *testing.T) {
	cfg, artifactPath, artifactHash := testUpdateFiles(t, "1.1.0")
	cfg.Policy.MinimumVersion = "1.2.0"
	writeManifest(t, cfg.Source.ManifestPath, testManifest(cfg, "1.1.0", artifactPath, artifactHash))
	svc, err := NewService(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	result, err := svc.CheckForUpdates(context.Background())
	if !errors.Is(err, ErrNoUpdateAvailable) {
		t.Fatalf("below-floor update error = %v, result = %+v", err, result)
	}
	assertUpdateErrorSafe(t, err)

	cfg, artifactPath, artifactHash = testUpdateFiles(t, "0.9.0")
	writeManifest(t, cfg.Source.ManifestPath, testManifest(cfg, "0.9.0", artifactPath, artifactHash))
	svc, err = NewService(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	result, err = svc.CheckForUpdates(context.Background())
	if err != nil {
		t.Fatalf("older candidate should be classified as no update, got %v", err)
	}
	if result.UpdateAvailable {
		t.Fatalf("older candidate should not be available: %+v", result)
	}
	assertUpdateJSONSafe(t, result)

	cfg, artifactPath, artifactHash = testUpdateFiles(t, "1.2.0")
	manifest := testManifest(cfg, "1.2.0", artifactPath, artifactHash)
	manifest.MinimumSupportedVersion = "2.0.0"
	writeManifest(t, cfg.Source.ManifestPath, manifest)
	svc, err = NewService(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = svc.CheckForUpdates(context.Background())
	if !errors.Is(err, ErrInvalidManifest) {
		t.Fatalf("minimum supported version error = %v", err)
	}
	assertUpdateErrorSafe(t, err)
}

func TestRollbackFreezePolicyClassification(t *testing.T) {
	t.Run("older candidate can be classified as rollback risk", func(t *testing.T) {
		cfg, artifactPath, artifactHash := testUpdateFiles(t, "0.9.0")
		cfg.Policy.RejectRollbackCandidates = true
		writeManifest(t, cfg.Source.ManifestPath, testManifest(cfg, "0.9.0", artifactPath, artifactHash))
		svc, err := NewService(cfg, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := svc.CheckForUpdates(context.Background()); !errors.Is(err, ErrRollbackRisk) {
			t.Fatalf("expected rollback-risk classification, got %v", err)
		} else {
			assertUpdateErrorSafe(t, err)
		}
	})

	t.Run("equal candidate remains no update", func(t *testing.T) {
		cfg, artifactPath, artifactHash := testUpdateFiles(t, "1.0.0")
		cfg.Policy.RejectRollbackCandidates = true
		writeManifest(t, cfg.Source.ManifestPath, testManifest(cfg, "1.0.0", artifactPath, artifactHash))
		svc, err := NewService(cfg, nil)
		if err != nil {
			t.Fatal(err)
		}
		result, err := svc.CheckForUpdates(context.Background())
		if err != nil || result.UpdateAvailable {
			t.Fatalf("expected equal candidate to be no update, got %+v %v", result, err)
		}
		assertUpdateJSONSafe(t, result)
	})

	t.Run("minimum supported equal current is allowed", func(t *testing.T) {
		cfg, artifactPath, artifactHash := testUpdateFiles(t, "1.2.0")
		manifest := testManifest(cfg, "1.2.0", artifactPath, artifactHash)
		manifest.MinimumSupportedVersion = cfg.CurrentVersion
		writeManifest(t, cfg.Source.ManifestPath, manifest)
		svc, err := NewService(cfg, nil)
		if err != nil {
			t.Fatal(err)
		}
		result, err := svc.CheckForUpdates(context.Background())
		if err != nil || !result.UpdateAvailable {
			t.Fatalf("expected equal minimum-supported version to be accepted, got %+v %v", result, err)
		}
		assertUpdateJSONSafe(t, result)
	})

	t.Run("freeze policy blocks candidate", func(t *testing.T) {
		cfg, artifactPath, artifactHash := testUpdateFiles(t, "1.2.0")
		cfg.Policy.FreezeUpdates = true
		writeManifest(t, cfg.Source.ManifestPath, testManifest(cfg, "1.2.0", artifactPath, artifactHash))
		svc, err := NewService(cfg, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := svc.CheckForUpdates(context.Background()); !errors.Is(err, ErrUpdateBlocked) {
			t.Fatalf("expected update blocked, got %v", err)
		} else {
			assertUpdateErrorSafe(t, err)
		}
	})

	t.Run("stale manifest policy fails closed", func(t *testing.T) {
		cfg, artifactPath, artifactHash := testUpdateFiles(t, "1.2.0")
		cfg.Policy.MaximumManifestAge = time.Hour
		manifest := testManifest(cfg, "1.2.0", artifactPath, artifactHash)
		manifest.PublishedAt = time.Now().UTC().Add(-48 * time.Hour).Format(time.RFC3339)
		writeManifest(t, cfg.Source.ManifestPath, manifest)
		svc, err := NewService(cfg, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := svc.CheckForUpdates(context.Background()); !errors.Is(err, ErrManifestStale) {
			t.Fatalf("expected stale manifest, got %v", err)
		} else {
			assertUpdateErrorSafe(t, err)
		}
	})

	t.Run("future-dated manifest policy fails closed", func(t *testing.T) {
		cfg, artifactPath, artifactHash := testUpdateFiles(t, "1.2.0")
		cfg.Policy.MaximumFutureSkew = time.Hour
		manifest := testManifest(cfg, "1.2.0", artifactPath, artifactHash)
		manifest.PublishedAt = time.Now().UTC().Add(48 * time.Hour).Format(time.RFC3339)
		writeManifest(t, cfg.Source.ManifestPath, manifest)
		svc, err := NewService(cfg, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := svc.CheckForUpdates(context.Background()); !errors.Is(err, ErrManifestFutureDated) {
			t.Fatalf("expected future-dated manifest, got %v", err)
		} else {
			assertUpdateErrorSafe(t, err)
		}
	})

	t.Run("freshness policy requires parseable publication time", func(t *testing.T) {
		cfg, artifactPath, artifactHash := testUpdateFiles(t, "1.2.0")
		cfg.Policy.MaximumManifestAge = time.Hour
		manifest := testManifest(cfg, "1.2.0", artifactPath, artifactHash)
		manifest.PublishedAt = "not-a-time"
		writeManifest(t, cfg.Source.ManifestPath, manifest)
		svc, err := NewService(cfg, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := svc.CheckForUpdates(context.Background()); !errors.Is(err, ErrInvalidManifest) {
			t.Fatalf("expected invalid manifest for malformed published_at, got %v", err)
		} else {
			assertUpdateErrorSafe(t, err)
		}
	})

	t.Run("negative freshness policy is invalid config", func(t *testing.T) {
		cfg := testConfig(t)
		cfg.Policy.MaximumManifestAge = -time.Second
		if _, err := NewService(cfg, nil); !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("expected invalid config for negative maximum age, got %v", err)
		}
	})
}

func TestSignedManifestStillObeysRollbackFreezePolicy(t *testing.T) {
	cfg, artifactPath, artifactHash := testUpdateFiles(t, "1.2.0")
	keyID, publicKey, signer := testManifestSigner(t)
	cfg.Policy.RequireManifestSignature = true
	cfg.Policy.ManifestVerificationKeys = map[string]string{keyID: publicKey}
	cfg.Policy.FreezeUpdates = true
	manifest := signer(testManifest(cfg, "1.2.0", artifactPath, artifactHash))
	writeManifest(t, cfg.Source.ManifestPath, manifest)
	svc, err := NewService(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CheckForUpdates(context.Background()); !errors.Is(err, ErrUpdateBlocked) {
		t.Fatalf("expected signed manifest to be blocked by freeze policy, got %v", err)
	} else {
		assertUpdateErrorSafe(t, err)
	}

	unsigned := testManifest(cfg, "1.2.0", artifactPath, artifactHash)
	writeManifest(t, cfg.Source.ManifestPath, unsigned)
	if _, err := svc.CheckForUpdates(context.Background()); !errors.Is(err, ErrVerificationFailed) {
		t.Fatalf("expected unsigned required-signature manifest to fail before policy classification, got %v", err)
	} else {
		assertUpdateErrorSafe(t, err)
	}
}

func TestCachedUpdateMetadataRevalidatedAgainstRollbackFreezePolicy(t *testing.T) {
	ctx := context.Background()
	cfg, artifactPath, artifactHash := testUpdateFiles(t, "1.2.0")
	writeManifest(t, cfg.Source.ManifestPath, testManifest(cfg, "1.2.0", artifactPath, artifactHash))
	svc, err := NewService(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CheckForUpdates(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.DownloadUpdate(ctx, "1.2.0"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.VerifyUpdate(ctx, "1.2.0"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.StageUpdate(ctx, "1.2.0"); err != nil {
		t.Fatal(err)
	}

	svc.cfg.Policy.FreezeUpdates = true
	status, err := svc.GetStatus(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if status.LastError != "update blocked by policy" || status.LatestRelease != nil || status.StagedVersion != "" || status.Verified {
		t.Fatalf("expected cached/staged status to be blocked safely, got %+v", status)
	}
	assertUpdateJSONSafe(t, status)

	if _, err := svc.DownloadUpdate(ctx, "1.2.0"); !errors.Is(err, ErrUpdateBlocked) {
		t.Fatalf("expected cached selected metadata to be blocked before download, got %v", err)
	}
	if _, err := svc.VerifyUpdate(ctx, "1.2.0"); !errors.Is(err, ErrUpdateBlocked) {
		t.Fatalf("expected downloaded metadata to be blocked before verify, got %v", err)
	}
	if _, err := svc.StageUpdate(ctx, "1.2.0"); !errors.Is(err, ErrUpdateBlocked) {
		t.Fatalf("expected verified metadata to be blocked before stage, got %v", err)
	}
	if _, err := svc.DescribeStagedUpdate(ctx); !errors.Is(err, ErrUpdateBlocked) {
		t.Fatalf("expected staged summary to be blocked, got %v", err)
	}
	if _, err := svc.BuildApplyPlan(ctx); !errors.Is(err, ErrUpdateBlocked) {
		t.Fatalf("expected apply plan to be blocked, got %v", err)
	}
	if _, err := svc.ApplyUpdate(ctx); !errors.Is(err, ErrUpdateBlocked) {
		t.Fatalf("expected app-owned apply handoff to be blocked, got %v", err)
	}
}

func TestHTTPManifestProviderLifecycle(t *testing.T) {
	ctx := context.Background()
	cfg := testConfig(t)
	artifact := []byte("network artifact")
	sum := sha256.Sum256(artifact)
	var manifestURL string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/manifest.json":
			manifest := testManifest(cfg, "1.3.0", manifestURL[:strings.LastIndex(manifestURL, "/")]+"/artifact.zip", hex.EncodeToString(sum[:]))
			manifest.Artifacts[0].Size = int64(len(artifact))
			_ = json.NewEncoder(w).Encode(manifest)
		case "/artifact.zip":
			w.Write(artifact)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	manifestURL = server.URL + "/manifest.json"
	cfg.Source = SourceConfig{Provider: ProviderHTTPManifest, ManifestURL: manifestURL}
	svc, err := NewService(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	check, err := svc.CheckForUpdates(ctx)
	if err != nil || !check.UpdateAvailable {
		t.Fatalf("expected HTTP update, got %+v %v", check, err)
	}
	if _, err := svc.DownloadUpdate(ctx, "1.3.0"); err != nil {
		t.Fatalf("HTTP download returned error: %v", err)
	}
	if verify, err := svc.VerifyUpdate(ctx, "1.3.0"); err != nil || !verify.OK {
		t.Fatalf("HTTP verify = %+v %v", verify, err)
	}
}

func TestGitHubRawManifestProviderValidation(t *testing.T) {
	cfg := testConfig(t)
	cfg.Source = SourceConfig{Provider: ProviderGitHubRawManifest, GitHubOwner: "owner", GitHubRepo: "repo", GitHubRef: "main", GitHubManifestPath: "releases/manifest.json"}
	if _, err := NewService(cfg, nil); err != nil {
		t.Fatalf("valid github raw manifest config returned error: %v", err)
	}
	if got := githubRawManifestURL(cfg.Source); got != "https://raw.githubusercontent.com/owner/repo/main/releases/manifest.json" {
		t.Fatalf("github raw URL = %q", got)
	}
	cfg.Source.GitHubRef = "../main"
	if _, err := NewService(cfg, nil); !errors.Is(err, ErrInvalidProvider) {
		t.Fatalf("unsafe github ref error = %v", err)
	}
	cfg.Source.GitHubRef = "main"
	cfg.Source.GitHubManifestPath = "../manifest.json"
	if _, err := NewService(cfg, nil); !errors.Is(err, ErrInvalidProvider) {
		t.Fatalf("unsafe github manifest path error = %v", err)
	}
}

func TestProviderAndDownloadFailuresAreSafe(t *testing.T) {
	sensitive := `{"error":"secret token C:\\Users\\person\\path"}`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, sensitive, http.StatusInternalServerError)
	}))
	defer server.Close()
	cfg := testConfig(t)
	cfg.Source = SourceConfig{Provider: ProviderHTTPManifest, ManifestURL: server.URL}
	svc, err := NewService(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CheckForUpdates(context.Background()); !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("expected provider unavailable, got %v", err)
	} else if strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "Users") {
		t.Fatalf("provider error leaked raw body: %v", err)
	}

	timeoutServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(50 * time.Millisecond)
	}))
	defer timeoutServer.Close()
	cfg.Source = SourceConfig{Provider: ProviderHTTPManifest, ManifestURL: timeoutServer.URL}
	cfg.HTTPTimeout = time.Millisecond
	svc, _ = NewService(cfg, nil)
	if _, err := svc.CheckForUpdates(context.Background()); !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("expected timeout provider failure, got %v", err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := svc.CheckForUpdates(canceled); !errors.Is(err, ErrContextCanceled) {
		t.Fatalf("expected canceled context, got %v", err)
	}
}

func TestVerifyStageAndApplyFailures(t *testing.T) {
	ctx := context.Background()
	cfg, artifactPath, artifactHash := testUpdateFiles(t, "1.2.0")
	manifest := testManifest(cfg, "1.2.0", artifactPath, artifactHash)
	writeManifest(t, cfg.Source.ManifestPath, manifest)
	svc, err := NewService(cfg, failingApply{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ApplyUpdate(ctx); !errors.Is(err, ErrStagedUpdateNotFound) {
		t.Fatalf("expected no staged update, got %v", err)
	}
	if _, err := svc.DownloadUpdate(ctx, "1.2.0"); err != nil {
		t.Fatal(err)
	}
	downloaded, err := svc.store.readDownloaded()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(downloaded.ArtifactPath, []byte("corrupt"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.VerifyUpdate(ctx, "1.2.0"); !errors.Is(err, ErrVerificationFailed) {
		t.Fatalf("expected hash mismatch, got %v", err)
	}
	if _, err := svc.DownloadUpdate(ctx, "1.2.0"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.StageUpdate(ctx, "1.2.0"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ApplyUpdate(ctx); !errors.Is(err, ErrApplyFailed) {
		t.Fatalf("expected sanitized apply failure, got %v", err)
	} else if strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), cfg.StagingDir) {
		t.Fatalf("apply error leaked raw strategy text: %v", err)
	}
}

func TestStagedUpdateArtifactRevalidationFailures(t *testing.T) {
	ctx := context.Background()
	for _, tt := range []struct {
		name   string
		mutate func(t *testing.T, svc *Service, staged StagedUpdate)
		want   error
		status string
	}{
		{
			name: "missing artifact",
			mutate: func(t *testing.T, svc *Service, staged StagedUpdate) {
				t.Helper()
				if err := os.Remove(staged.ArtifactPath); err != nil {
					t.Fatal(err)
				}
			},
			want:   ErrVerificationFailed,
			status: "staged update verification failed",
		},
		{
			name: "hash mismatch",
			mutate: func(t *testing.T, svc *Service, staged StagedUpdate) {
				t.Helper()
				if err := os.WriteFile(staged.ArtifactPath, []byte("tampered staged artifact"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
			want:   ErrVerificationFailed,
			status: "staged update verification failed",
		},
		{
			name: "metadata mismatch",
			mutate: func(t *testing.T, svc *Service, staged StagedUpdate) {
				t.Helper()
				staged.AppID = "other-app"
				if err := svc.store.writeStaged(staged); err != nil {
					t.Fatal(err)
				}
			},
			want:   ErrStorageUnavailable,
			status: "stored update metadata is invalid",
		},
		{
			name: "stale metadata",
			mutate: func(t *testing.T, svc *Service, staged StagedUpdate) {
				t.Helper()
				svc.cfg.Policy.MaximumStagedAge = time.Hour
				staged.StagedAt = time.Now().UTC().Add(-2 * time.Hour)
				if err := svc.store.writeStaged(staged); err != nil {
					t.Fatal(err)
				}
			},
			want:   ErrStagedUpdateStale,
			status: "staged update stale",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			svc, staged := stageInternalUpdate(t, "1.2.0", failingApply{})
			tt.mutate(t, svc, staged)
			if _, err := svc.DescribeStagedUpdate(ctx); !errors.Is(err, tt.want) {
				t.Fatalf("DescribeStagedUpdate error = %v, want %v", err, tt.want)
			} else {
				assertUpdateErrorSafe(t, err)
			}
			if _, err := svc.BuildApplyPlan(ctx); !errors.Is(err, tt.want) {
				t.Fatalf("BuildApplyPlan error = %v, want %v", err, tt.want)
			} else {
				assertUpdateErrorSafe(t, err)
			}
			if _, err := svc.ApplyUpdate(ctx); !errors.Is(err, tt.want) {
				t.Fatalf("ApplyUpdate error = %v, want %v", err, tt.want)
			} else {
				assertUpdateErrorSafe(t, err)
			}
			state, err := svc.GetStatus(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if state.Verified || state.StagedVersion != "" {
				t.Fatalf("unsafe staged status for invalid staged update: %+v", state)
			}
			if state.LastError != tt.status {
				t.Fatalf("status LastError = %q, want %q", state.LastError, tt.status)
			}
			assertUpdateJSONSafe(t, state)
		})
	}
}

func TestStageUpdateRevalidatesDownloadedArtifactBeforeCopy(t *testing.T) {
	ctx := context.Background()
	cfg, artifactPath, artifactHash := testUpdateFiles(t, "1.2.0")
	manifest := testManifest(cfg, "1.2.0", artifactPath, artifactHash)
	writeManifest(t, cfg.Source.ManifestPath, manifest)
	svc, err := NewService(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.DownloadUpdate(ctx, "1.2.0"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.VerifyUpdate(ctx, "1.2.0"); err != nil {
		t.Fatal(err)
	}
	verified, err := svc.store.readVerified()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(verified.Downloaded.ArtifactPath, []byte("corrupt after verify"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.StageUpdate(ctx, "1.2.0"); !errors.Is(err, ErrVerificationFailed) {
		t.Fatalf("StageUpdate error = %v, want verification failure", err)
	} else {
		assertUpdateErrorSafe(t, err)
	}
}

func TestApplyAliasRequiresMatchingVersion(t *testing.T) {
	ctx := context.Background()
	svc, _ := stageInternalUpdate(t, "1.2.0", nil)
	if _, err := svc.Apply(ctx, "9.9.9"); !errors.Is(err, ErrNoUpdateAvailable) {
		t.Fatalf("Apply with mismatched version error = %v, want no update available", err)
	}
	result, err := svc.Apply(ctx, "1.2.0")
	if err != nil {
		t.Fatalf("Apply with staged version returned error: %v", err)
	}
	if !result.OK || result.Version != "1.2.0" {
		t.Fatalf("unexpected apply result: %+v", result)
	}
}

func TestDownloadArtifactRejectsLocalPathForNonFileProvider(t *testing.T) {
	cfg, artifactPath, artifactHash := testUpdateFiles(t, "1.2.0")
	cfg.Source = SourceConfig{Provider: ProviderHTTPManifest, ManifestURL: "https://example.test/manifest.json"}
	svc, err := NewService(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	artifact := Artifact{
		Platform:     cfg.Platform,
		Architecture: cfg.Architecture,
		Filename:     "sample-1.2.0.zip",
		DownloadURL:  artifactPath,
		Size:         int64(len("artifact 1.2.0")),
		SHA256:       artifactHash,
	}
	target := filepath.Join(t.TempDir(), "download.zip")
	if _, err := svc.downloadArtifact(context.Background(), artifact, target); !errors.Is(err, ErrInvalidManifest) {
		t.Fatalf("downloadArtifact error = %v, want invalid manifest", err)
	}
	if _, err := os.Stat(target); err == nil {
		t.Fatalf("target should not be written for rejected local artifact")
	}
}

func TestSelectArtifactUsesDeterministicFilenameOrder(t *testing.T) {
	cfg, artifactPath, artifactHash := testUpdateFiles(t, "1.2.0")
	svc, err := NewService(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	manifest := testManifest(cfg, "1.2.0", artifactPath, artifactHash)
	manifest.Artifacts = []Artifact{
		{Platform: cfg.Platform, Architecture: cfg.Architecture, Filename: "b.zip", DownloadURL: artifactPath, Size: int64(len("artifact 1.2.0")), SHA256: artifactHash},
		{Platform: cfg.Platform, Architecture: cfg.Architecture, Filename: "a.zip", DownloadURL: artifactPath, Size: int64(len("artifact 1.2.0")), SHA256: artifactHash},
	}
	artifact, err := svc.selectArtifact(manifest)
	if err != nil {
		t.Fatalf("selectArtifact returned error: %v", err)
	}
	if artifact.Filename != "a.zip" {
		t.Fatalf("selected artifact = %q, want a.zip", artifact.Filename)
	}
}

func TestCorruptStagedMetadataIsClassifiedSafely(t *testing.T) {
	ctx := context.Background()
	svc, _ := stageInternalUpdate(t, "1.2.0", failingApply{})
	if err := os.WriteFile(svc.store.stagedMetaPath(), []byte("{not-json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.DescribeStagedUpdate(ctx); !errors.Is(err, ErrStorageUnavailable) {
		t.Fatalf("DescribeStagedUpdate error = %v, want storage unavailable", err)
	} else {
		assertUpdateErrorSafe(t, err)
	}
	state, err := svc.GetStatus(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if state.Verified || state.StagedVersion != "" {
		t.Fatalf("corrupt staged metadata still marked verified: %+v", state)
	}
	if state.LastError != "staged update metadata is invalid" {
		t.Fatalf("status LastError = %q", state.LastError)
	}
	assertUpdateJSONSafe(t, state)
}

func TestNoUpdateAvailable(t *testing.T) {
	cfg, artifactPath, artifactHash := testUpdateFiles(t, "1.0.0")
	writeManifest(t, cfg.Source.ManifestPath, testManifest(cfg, "1.0.0", artifactPath, artifactHash))
	svc, err := NewService(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	result, err := svc.CheckForUpdates(context.Background())
	if err != nil || result.UpdateAvailable {
		t.Fatalf("expected no update, got %+v %v", result, err)
	}
}

type failingApply struct{}

func (failingApply) Apply(context.Context, StagedUpdate) (ApplyResult, error) {
	return ApplyResult{}, errors.New("secret apply failure C:\\Users\\person\\artifact")
}

func stageInternalUpdate(t *testing.T, version string, apply ApplyStrategy) (*Service, StagedUpdate) {
	t.Helper()
	ctx := context.Background()
	cfg, artifactPath, artifactHash := testUpdateFiles(t, version)
	manifest := testManifest(cfg, version, artifactPath, artifactHash)
	writeManifest(t, cfg.Source.ManifestPath, manifest)
	svc, err := NewService(cfg, apply)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CheckForUpdates(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.DownloadUpdate(ctx, version); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.VerifyUpdate(ctx, version); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.StageUpdate(ctx, version); err != nil {
		t.Fatal(err)
	}
	staged, err := svc.store.readStaged()
	if err != nil {
		t.Fatal(err)
	}
	return svc, staged
}

func testConfig(t *testing.T) AppConfig {
	t.Helper()
	dir := t.TempDir()
	return AppConfig{
		AppID:          "sample-app",
		DisplayName:    "Sample App",
		CurrentVersion: "1.0.0",
		Channel:        ChannelStable,
		Platform:       "windows",
		Architecture:   "amd64",
		Namespace:      "default",
		StagingDir:     filepath.Join(dir, "staging"),
		Source: SourceConfig{
			Provider:     ProviderFileManifest,
			ManifestPath: filepath.Join(dir, "manifest.json"),
		},
		Policy: Policy{RequireSHA256: true, MaximumArtifactSize: 1024 * 1024},
	}
}

func testUpdateFiles(t *testing.T, version string) (AppConfig, string, string) {
	t.Helper()
	cfg := testConfig(t)
	artifactPath := filepath.Join(t.TempDir(), "sample-"+version+".zip")
	if err := os.WriteFile(artifactPath, []byte("artifact "+version), 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte("artifact " + version))
	return cfg, artifactPath, hex.EncodeToString(sum[:])
}

func testManifest(cfg AppConfig, version, artifactPath, hash string) Manifest {
	return Manifest{
		SchemaVersion:   SchemaVersion,
		AppID:           cfg.AppID,
		Channel:         cfg.Channel,
		Version:         version,
		ReleaseNotesURL: "https://example.test/release",
		Artifacts: []Artifact{{
			Platform:     cfg.Platform,
			Architecture: cfg.Architecture,
			Filename:     "sample-" + version + ".zip",
			DownloadURL:  artifactPath,
			Size:         int64(len("artifact " + version)),
			SHA256:       hash,
		}},
	}
}

func writeManifest(t *testing.T, path string, manifest Manifest) {
	t.Helper()
	b, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func testManifestSigner(t *testing.T) (string, string, func(Manifest) Manifest) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(strings.NewReader(strings.Repeat("aegis-test-key-material-", 4)))
	if err != nil {
		t.Fatal(err)
	}
	keyID := "test-ed25519-key"
	publicKeyEncoded := base64.StdEncoding.EncodeToString(publicKey)
	return keyID, publicKeyEncoded, func(manifest Manifest) Manifest {
		payload, err := manifestSignaturePayload(manifest)
		if err != nil {
			t.Fatal(err)
		}
		signature := ed25519.Sign(privateKey, payload)
		manifest.Signature = &SignatureMetadata{
			Kind:      manifestSignatureKindEd25519,
			KeyID:     keyID,
			Signature: base64.StdEncoding.EncodeToString(signature),
		}
		return manifest
	}
}

func signedManifestCopy(manifest Manifest) Manifest {
	out := manifest
	if manifest.Signature != nil {
		copied := *manifest.Signature
		out.Signature = &copied
	}
	return out
}

func assertUpdateJSONSafe(t *testing.T, v any) {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal update value: %v", err)
	}
	text := strings.ToLower(string(raw))
	for _, forbidden := range []string{"client_secret", "refresh_token", "access_token", "id_token", "auth_code", "private_key", "github_pat", "ghp_", "token=", "password=", "secret=", `c:\\users\\`, "appdata", "downloads", "artifact_path"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("unsafe update JSON detail %q in %s", forbidden, string(raw))
		}
	}
}

func assertUpdateErrorSafe(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("expected error")
	}
	text := strings.ToLower(err.Error())
	for _, forbidden := range []string{"client_secret", "refresh_token", "access_token", "id_token", "auth_code", "private_key", "github_pat", "ghp_", "token=", "password=", "secret=", `c:\\users\\`, "appdata", "downloads", "artifact_path"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("unsafe update error detail %q in %v", forbidden, err)
		}
	}
}
