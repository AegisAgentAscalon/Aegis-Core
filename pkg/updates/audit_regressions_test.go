//go:build auditregression

package updates

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestAuditIdempotentRestageLeaksFullArtifact(t *testing.T) {
	svc, staged := stageInternalRecordOnlyUpdate(t, "1.2.0")
	for i := 0; i < 3; i++ {
		if _, err := svc.StageUpdate(context.Background(), staged.Version); err != nil {
			t.Fatal(err)
		}
	}
	files, err := filepath.Glob(filepath.Join(svc.store.stagedDir(), ".pending-*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 0 {
		t.Fatalf("UA-02: restaging leaked %d pending artifacts", len(files))
	}
	var bytes int64
	for _, p := range files {
		info, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		bytes += info.Size()
	}
	if bytes != 0 {
		t.Fatal("unexpected pending artifact bytes")
	}
}

func TestAuditDetachedArtifactBypassesSignedManifestBinding(t *testing.T) {
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
	downloaded, err := svc.store.readDownloaded()
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
	if err := svc.store.writeDownloaded(downloaded); err != nil {
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

func TestAuditReplaceMissingSourceDeletesDestination(t *testing.T) {
	dir := t.TempDir()
	dst := filepath.Join(dir, "existing.json")
	if err := os.WriteFile(dst, []byte(`{"valid":true}`), 0600); err != nil {
		t.Fatal(err)
	}
	err := replaceFile(filepath.Join(dir, "missing.tmp"), dst)
	if err == nil {
		t.Fatal("expected missing-source failure")
	}
	data, readErr := os.ReadFile(dst)
	if readErr != nil || string(data) != `{"valid":true}` {
		t.Fatalf("UA-05: failed replacement destroyed destination: %v", readErr)
	}

}
