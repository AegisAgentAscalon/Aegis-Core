package updates

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestRestageDoesNotLeakArtifacts(t *testing.T) {
	svc, staged := stageInternalRecordOnlyUpdate(t, "1.2.0")
	before := testBlobInventory(t, svc.store)
	for i := 0; i < 3; i++ {
		if _, err := svc.StageUpdate(context.Background(), staged.Version); err != nil {
			t.Fatal(err)
		}
	}
	if after := testBlobInventory(t, svc.store); !reflect.DeepEqual(before, after) {
		t.Fatalf("UA-02: restaging changed immutable blob inventory: before=%v after=%v", before, after)
	}
}

func signedBindingService(t *testing.T) *Service {
	t.Helper()
	cfg, path, hash := testUpdateFiles(t, "1.2.0")
	key, pub, sign := testManifestSigner(t)
	cfg.Policy.RequireManifestSignature = true
	cfg.Policy.ManifestVerificationKeys = map[string]string{key: pub}
	writeManifest(t, cfg.Source.ManifestPath, sign(testManifest(cfg, "1.2.0", path, hash)))
	s, err := NewRecordOnlyService(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.DownloadUpdate(context.Background(), "1.2.0"); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestDetachedArtifactFieldsMustMatchManifest(t *testing.T) {
	changes := map[string]func(*Artifact){
		"hash":         func(a *Artifact) { a.SHA256 = strings.Repeat("a", 64) },
		"size":         func(a *Artifact) { a.Size = 0 },
		"url":          func(a *Artifact) { a.DownloadURL += ".other" },
		"name":         func(a *Artifact) { a.Filename = "other.zip" },
		"platform":     func(a *Artifact) { a.Platform = "other" },
		"architecture": func(a *Artifact) { a.Architecture = "other" },
		"signature": func(a *Artifact) {
			a.Signature = &SignatureMetadata{Kind: "ed25519", KeyID: "detached", Signature: "unapproved"}
		},
	}
	for name, mutate := range changes {
		t.Run(name, func(t *testing.T) {
			s := legacyTestService(t, signedBindingService(t))
			selected, err := readTestSelected(t, s.store)
			if err != nil {
				t.Fatal(err)
			}
			mutate(&selected.Artifact)
			if err := validateSelectedUpdate(s.cfg, selected); err == nil {
				t.Error("altered selection accepted")
			}
			d, err := readTestDownloaded(t, s.store)
			if err != nil {
				t.Fatal(err)
			}
			mutate(&d.Artifact)
			if err := writeJSON(context.Background(), s.store.downloadedPath(), d); err != nil {
				t.Fatal(err)
			}
			if result, err := s.VerifyUpdate(context.Background(), "1.2.0"); err == nil || result.OK {
				t.Error("altered download verified")
			}
			// A forged verified record must not bypass the staging check.
			if err := writeJSON(context.Background(), s.store.verifiedPath(), verifiedUpdate{SchemaVersion: schemaVersion, Downloaded: d, VerifiedAt: d.DownloadedAt}); err != nil {
				t.Fatal(err)
			}
			if result, err := s.StageUpdate(context.Background(), "1.2.0"); err == nil || result.Staged {
				t.Error("altered verified record staged")
			}
		})
	}
}

func TestStagedRecordRetainsManifestAuthority(t *testing.T) {
	changes := map[string]func(*stagedUpdateRecord){
		"hash":         func(r *stagedUpdateRecord) { r.SHA256 = strings.Repeat("a", 64) },
		"size":         func(r *stagedUpdateRecord) { r.Size = 0 },
		"name":         func(r *stagedUpdateRecord) { r.ArtifactName = "other.zip" },
		"platform":     func(r *stagedUpdateRecord) { r.Platform = "other" },
		"architecture": func(r *stagedUpdateRecord) { r.Architecture = "other" },
		"version":      func(r *stagedUpdateRecord) { r.Version = "1.3.0" },
		"restart":      func(r *stagedUpdateRecord) { r.RequiredRestart = !r.RequiredRestart },
		"behavior":     func(r *stagedUpdateRecord) { r.ApplyBehavior = "other" },
		"signed-url":   func(r *stagedUpdateRecord) { r.Manifest.Artifacts[0].DownloadURL += ".other" },
	}
	for name, mutate := range changes {
		t.Run(name, func(t *testing.T) {
			s := signedBindingService(t)
			if _, err := s.StageUpdate(context.Background(), "1.2.0"); err != nil {
				t.Fatal(err)
			}
			s = legacyTestService(t, s)
			r, err := readTestStaged(t, s.store)
			if err != nil {
				t.Fatal(err)
			}
			mutate(&r)
			if name == "hash" {
				body := []byte(strings.Repeat("x", int(r.Size)))
				sum := sha256.Sum256(body)
				r.SHA256 = hex.EncodeToString(sum[:])
				if err := os.WriteFile(r.ArtifactPath, body, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if name == "name" {
				renamed := filepath.Join(s.store.stagedDir(), r.ArtifactName)
				if err := os.Rename(r.ArtifactPath, renamed); err != nil {
					t.Fatal(err)
				}
				r.ArtifactPath = renamed
			}
			if err := writeJSON(context.Background(), s.store.stagedMetaPath(), r); err != nil {
				t.Fatal(err)
			}
			if _, err := s.BuildApplyPlan(context.Background()); err == nil {
				t.Error("altered staged authority accepted")
			}
			if _, err := s.DescribeStagedUpdate(context.Background()); err == nil {
				t.Error("altered staged record described as ready")
			}
			if _, err := s.GetLifecycleEnvelope(context.Background()); err == nil {
				t.Error("altered staged record exposed as a valid lifecycle")
			}
			if _, err := s.RecordPackageHandoff(context.Background(), PackageHandoffRequest{ExpectedRevision: 1, IdempotencyKey: "tampered-handoff", ConsumerID: "consumer"}); err == nil {
				t.Error("altered staged record handed off")
			}
		})
	}
}

// Cancel after the copy has actually written bytes, without timing sleeps.
type cancelDuringStageCopy struct {
	context.Context
	cancel context.CancelFunc
	dir    string
}

func (c cancelDuringStageCopy) Err() error {
	files, _ := filepath.Glob(filepath.Join(c.dir, "*", ".tmp-*"))
	for _, path := range files {
		if info, err := os.Stat(path); err == nil && info.Size() > 0 {
			c.cancel()
			break
		}
	}
	return c.Context.Err()
}

func TestStageCancellationCleansPartialCopy(t *testing.T) {
	s := signedBindingService(t)
	before := testBlobInventory(t, s.store)
	token := testNativeSnapshot(t, s.store).Token
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, err := s.StageUpdate(cancelDuringStageCopy{ctx, cancel, s.store.blobDir()}, "1.2.0")
	if !errors.Is(err, ErrContextCanceled) {
		t.Fatalf("expected cancellation during copy: %v", err)
	}
	assertNoPendingArtifacts(t, s)
	if _, err := readTestStaged(t, s.store); !os.IsNotExist(err) {
		t.Fatalf("canceled copy committed staged metadata: %v", err)
	}
	if testNativeSnapshot(t, s.store).Token != token || !reflect.DeepEqual(before, testBlobInventory(t, s.store)) {
		t.Fatal("canceled copy changed authority or retained uncommitted blob bytes")
	}
}

func TestLegacyStagedAuthorityRecoveryAndIndependentStagedCache(t *testing.T) {
	s := signedBindingService(t)
	ctx := context.Background()
	if _, err := s.StageUpdate(ctx, "1.2.0"); err != nil {
		t.Fatal(err)
	}
	s = legacyTestService(t, s)
	r, err := readTestStaged(t, s.store)
	if err != nil {
		t.Fatal(err)
	}
	if r.Manifest == nil {
		t.Fatal("staged authority missing")
	}
	legacy := r
	legacy.Manifest = nil
	if err := writeJSON(context.Background(), s.store.stagedMetaPath(), legacy); err != nil {
		t.Fatal(err)
	}
	if _, err := s.BuildApplyPlan(ctx); err != nil {
		t.Fatalf("legacy verified evidence rejected: %v", err)
	}
	if err := os.Remove(s.store.verifiedPath()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.BuildApplyPlan(ctx); !errors.Is(err, ErrVerificationFailed) {
		t.Fatalf("legacy record without authority must require restaging: %v", err)
	}
	if err := writeJSON(context.Background(), s.store.stagedMetaPath(), r); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(s.store.downloadedPath()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.BuildApplyPlan(ctx); err != nil {
		t.Fatalf("new staged record depends on download cache: %v", err)
	}
}

func TestDetachedArtifactCannotBypassSignedManifest(t *testing.T) {
	ctx := context.Background()
	cfg, path, hash := testUpdateFiles(t, "1.2.0")
	key, pub, sign := testManifestSigner(t)
	cfg.Policy.RequireManifestSignature = true
	cfg.Policy.ManifestVerificationKeys = map[string]string{key: pub}
	writeManifest(t, cfg.Source.ManifestPath, sign(testManifest(cfg, "1.2.0", path, hash)))
	svc, err := NewRecordOnlyService(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.DownloadUpdate(ctx, "1.2.0"); err != nil {
		t.Fatal(err)
	}
	svc = legacyTestService(t, svc)
	downloaded, err := readTestDownloaded(t, svc.store)
	if err != nil {
		t.Fatal(err)
	}
	replacement := make([]byte, downloaded.BytesWritten)
	for i := range replacement {
		replacement[i] = 'x'
	}
	sum := sha256.Sum256(replacement)
	downloaded.Artifact.SHA256 = hex.EncodeToString(sum[:])
	if downloaded.Manifest.Artifacts[0].SHA256 == downloaded.Artifact.SHA256 {
		t.Fatal("expected different hashes")
	}
	if err := os.WriteFile(downloaded.ArtifactPath, replacement, 0600); err != nil {
		t.Fatal(err)
	}
	if err := writeJSON(context.Background(), svc.store.downloadedPath(), downloaded); err != nil {
		t.Fatal(err)
	}
	if err := verifyManifestSignature(cfg.Policy, downloaded.Manifest); err != nil {
		t.Fatal(err)
	}
	result, err := svc.VerifyUpdate(ctx, "1.2.0")
	if err == nil && result.OK {
		t.Error("UA-01: detached artifact bypassed signed manifest verification")
	}
	staged, err := svc.StageUpdate(ctx, "1.2.0")
	if err == nil && staged.Staged {
		t.Error("UA-01: detached artifact bypassed signed manifest staging")
	}

}
