package updates

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func graphForTest(t *testing.T, st *store) stateRecord {
	t.Helper()
	var r stateRecord
	if err := json.Unmarshal(testNativeSnapshot(t, st).Data, &r); err != nil {
		t.Fatal(err)
	}
	return r
}
func removeLegacyForTest(t *testing.T, st *store, indices ...int) {
	t.Helper()
	for _, i := range indices {
		if err := os.Remove(filepath.Join(st.dir, filepath.FromSlash(legacyMetadata[i]))); err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
	}
}
func assertLegacyForTest(t *testing.T, st *store) {
	t.Helper()
	if _, err := os.Lstat(filepath.Dir(testCurrentPath(st))); !os.IsNotExist(err) {
		t.Fatalf("read/rejection activated native state: %v", err)
	}
}

func TestGenerationLegacyPartialCandidateMatrix(t *testing.T) {
	ctx := context.Background()
	source, _ := stageInternalRecordOnlyUpdate(t, "1.2.0")
	for mask := 0; mask < 8; mask++ {
		t.Run(fmt.Sprintf("S-D-V-%03b", mask), func(t *testing.T) {
			svc := legacyTestService(t, source)
			for i := 0; i < 3; i++ {
				if mask&(1<<i) == 0 {
					removeLegacyForTest(t, svc.store, i)
				}
			}
			removeLegacyForTest(t, svc.store, 4)
			before, err := svc.DescribeStagedUpdate(ctx)
			if err != nil {
				t.Fatal(err)
			}
			assertLegacyForTest(t, svc.store)
			if _, err := svc.GetLifecycleEnvelope(ctx); err != nil {
				t.Fatalf("migration: %v", err)
			}
			r := graphForTest(t, svc.store)
			if (r.Selected != nil) != (mask&1 != 0) || (r.Downloaded != "") != (mask&2 != 0) || (r.Verified != nil) != (mask&4 != 0) {
				t.Fatalf("migration changed observations: %+v", r)
			}
			after, err := svc.DescribeStagedUpdate(ctx)
			if err != nil || !reflect.DeepEqual(before, after) {
				t.Fatalf("staged projection changed: before=%+v after=%+v error=%v", before, after, err)
			}
			if _, err := svc.VerifyUpdate(ctx, "1.2.0"); (err == nil) != (mask&2 != 0) {
				t.Fatalf("standalone D eligibility changed: %v", err)
			}
		})
	}
	// A verified observation does not manufacture standalone download state.
	svc := legacyTestService(t, source)
	removeLegacyForTest(t, svc.store, 0, 1, 3, 4)
	if _, err := svc.VerifyUpdate(ctx, "1.2.0"); !errors.Is(err, ErrVerificationFailed) {
		t.Fatal(err)
	}
	assertLegacyForTest(t, svc.store)
	if _, err := svc.StageUpdate(ctx, "1.2.0"); err != nil {
		t.Fatalf("V-only staging: %v", err)
	}
	if graphForTest(t, svc.store).Downloaded != "" {
		t.Fatal("V-only stage invented D")
	}
}

func TestGenerationCompactGraphAndBlobRetention(t *testing.T) {
	ctx := context.Background()
	svc, staged := stageInternalRecordOnlyUpdate(t, "1.2.0")
	r := graphForTest(t, svc.store)
	if len(r.Manifests) != 1 || len(r.Transfers) != 1 || len(r.Blobs) != 2 || r.Selected == nil || r.Verified == nil || r.Staged == nil {
		t.Fatalf("complete workflow was not deduplicated: %+v", r)
	}
	if r.Selected.Manifest != r.Staged.Manifest || r.Selected.Artifact != r.Staged.Artifact || r.Verified.Transfer != r.Downloaded {
		t.Fatal("authority refs disagree")
	}
	snapshot := testNativeSnapshot(t, svc.store)
	view, err := readTestView(svc.store)
	if err != nil {
		t.Fatal(err)
	}
	legacyBytes := 0
	for _, value := range []any{view.selected.value, view.downloaded.value, view.verified.value, view.staged.value, view.lifecycle.value} {
		raw, err := json.MarshalIndent(value, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		legacyBytes += len(raw)
	}
	if len(snapshot.Data) >= legacyBytes {
		t.Fatalf("compact active payload=%d not below logical legacy records=%d", len(snapshot.Data), legacyBytes)
	}
	t.Logf("active owner metadata %d bytes; logical legacy record projection %d bytes; manifests=1 transfers=1 blobs=2 (excludes envelope, retained generations, backup and retained artifact disk bytes)", len(snapshot.Data), legacyBytes)
	before := testBlobInventory(t, svc.store)
	if _, err := svc.ClearStagedUpdate(ctx); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, testBlobInventory(t, svc.store)) {
		t.Fatal("clear deleted immutable bytes")
	}
	if _, err := os.Stat(staged.ArtifactPath); err != nil {
		t.Fatal("disclosed staged path was removed", err)
	}
	r = graphForTest(t, svc.store)
	if r.Staged != nil || r.Lifecycle != nil || r.Verified != nil || r.Downloaded == "" {
		t.Fatal("clear changed wrong graph references")
	}
}

func TestGenerationLegacyQuarantinePreservesIndependentStageAndBackup(t *testing.T) {
	ctx := context.Background()
	source, _ := stageInternalRecordOnlyUpdate(t, "1.2.0")
	for _, fallback := range []bool{false, true} {
		t.Run(fmt.Sprint("fallback-", fallback), func(t *testing.T) {
			svc := legacyTestService(t, source)
			removeLegacyForTest(t, svc.store, 4)
			if fallback {
				r, err := readTestStaged(t, svc.store)
				if err != nil {
					t.Fatal(err)
				}
				r.Manifest = nil
				if err := writeJSON(ctx, svc.store.stagedMetaPath(), r); err != nil {
					t.Fatal(err)
				}
				d, err := readTestDownloaded(t, svc.store)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.Remove(d.ArtifactPath); err != nil {
					t.Fatal(err)
				}
			} else if err := os.WriteFile(svc.store.selectedPath(), []byte("\n{ invalid candidate }\n"), 0600); err != nil {
				t.Fatal(err)
			}
			before := svc.store.readLegacy(ctx).raw
			if _, err := svc.GetLifecycleEnvelope(ctx); err != nil {
				t.Fatalf("independent stage migration: %v", err)
			}
			r := graphForTest(t, svc.store)
			if r.CandidateFault != candidateInvalid || r.Staged == nil || len(r.Transfers) != 0 {
				t.Fatalf("wrong quarantine: %+v", r)
			}
			for key, raw := range before {
				path := filepath.Join(svc.store.dir, "state-v2", "backup", filepath.FromSlash(key))
				got, err := os.ReadFile(path)
				if raw == nil {
					if !os.IsNotExist(err) {
						t.Fatalf("absent backup %s became present: %v", key, err)
					}
					continue
				}
				if err != nil || !bytes.Equal(raw, got) {
					t.Fatalf("backup changed %s: %v", key, err)
				}
				original, err := os.ReadFile(filepath.Join(svc.store.dir, filepath.FromSlash(key)))
				if err != nil || !bytes.Equal(raw, original) {
					t.Fatalf("legacy input changed: %s: %v", key, err)
				}
			}
			status, err := svc.GetStatus(ctx)
			if err != nil || !status.Verified || status.LastError != "stored update metadata is invalid" {
				t.Fatalf("quarantine status: %+v %v", status, err)
			}
			if _, err := svc.VerifyUpdate(ctx, "1.2.0"); !errors.Is(err, ErrStorageUnavailable) {
				t.Fatal(err)
			}
			if _, err := svc.StageUpdate(ctx, "1.2.0"); !errors.Is(err, ErrStorageUnavailable) {
				t.Fatal(err)
			}
			if _, err := svc.CheckForUpdates(ctx); err != nil {
				t.Fatal(err)
			}
			if graphForTest(t, svc.store).CandidateFault != "" {
				t.Fatal("fresh check did not repair fault")
			}
			if _, err := svc.BuildApplyPlan(ctx); err != nil {
				t.Fatal("repair damaged independent stage", err)
			}
		})
	}
}

func TestGenerationLegacyInvalidStageRequiresExplicitClear(t *testing.T) {
	ctx := context.Background()
	source, _ := stageInternalRecordOnlyUpdate(t, "1.2.0")
	for _, index := range []int{3, 4} {
		t.Run(legacyMetadata[index], func(t *testing.T) {
			svc := legacyTestService(t, source)
			path := filepath.Join(svc.store.dir, filepath.FromSlash(legacyMetadata[index]))
			if err := os.WriteFile(path, []byte("{broken"), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := svc.CheckForUpdates(ctx); !errors.Is(err, ErrStorageUnavailable) {
				t.Fatalf("ordinary migration accepted broken T/L: %v", err)
			}
			assertLegacyForTest(t, svc.store)
			if _, err := svc.ClearStagedUpdate(ctx); err != nil {
				t.Fatal(err)
			}
			r := graphForTest(t, svc.store)
			if r.Staged != nil || r.Lifecycle != nil || r.Verified != nil {
				t.Fatal("explicit clear retained invalid stage state")
			}
		})
	}
	// Oversized legacy input is fatal, not quarantined or removed by Clear.
	svc := legacyTestService(t, source)
	f, err := os.OpenFile(svc.store.selectedPath(), os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(maxMetadataBytes + 1); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ClearStagedUpdate(ctx); !errors.Is(err, ErrStorageUnavailable) {
		t.Fatal(err)
	}
	assertLegacyForTest(t, svc.store)
	info, err := os.Stat(svc.store.selectedPath())
	if err != nil || info.Size() != maxMetadataBytes+1 {
		t.Fatal("oversized legacy record was changed", err)
	}
}

func TestGenerationNativeCorruptionNeverFallsBack(t *testing.T) {
	ctx := context.Background()
	for _, corrupt := range []string{"missing-pointer", "invalid-pointer", "null-table", "dangling-artifact", "unsafe-blob", "unreachable-manifest"} {
		t.Run(corrupt, func(t *testing.T) {
			source, _ := stageInternalRecordOnlyUpdate(t, "1.2.0")
			svc := legacyTestService(t, source)
			removeLegacyForTest(t, svc.store, 4)
			if _, err := svc.GetLifecycleEnvelope(ctx); err != nil {
				t.Fatal(err)
			}
			switch corrupt {
			case "missing-pointer":
				if err := os.Remove(testCurrentPath(svc.store)); err != nil {
					t.Fatal(err)
				}
			case "invalid-pointer":
				if err := os.WriteFile(testCurrentPath(svc.store), []byte("{}"), 0600); err != nil {
					t.Fatal(err)
				}
			default:
				mutateTestGraph(t, svc.store, func(r *stateRecord) {
					switch corrupt {
					case "null-table":
						r.Blobs = nil
					case "dangling-artifact":
						r.Staged.Artifact = 500
					case "unsafe-blob":
						r.Staged.Blob = "../../outside"
					case "unreachable-manifest":
						m := r.Manifests[r.Staged.Manifest]
						m.Version = "9.0.0"
						id, err := recordDigest(m)
						if err != nil {
							t.Fatal(err)
						}
						r.Manifests[id] = m
					}
				})
			}
			if _, err := svc.GetStatus(ctx); !errors.Is(err, ErrStorageUnavailable) {
				t.Fatalf("native corruption accepted: %v", err)
			}
			if _, err := svc.BuildApplyPlan(ctx); !errors.Is(err, ErrStorageUnavailable) {
				t.Fatal(err)
			}
			if _, err := svc.ClearStagedUpdate(ctx); !errors.Is(err, ErrStorageUnavailable) {
				t.Fatal(err)
			}
		})
	}
}

func TestGenerationRetainsLegacyHashSpellingAndIgnoresFrozenFiles(t *testing.T) {
	ctx := context.Background()
	source, _ := stageInternalRecordOnlyUpdate(t, "1.2.0")
	svc := legacyTestService(t, source)
	r, err := readTestStaged(t, svc.store)
	if err != nil {
		t.Fatal(err)
	}
	r.SHA256 = strings.ToUpper(r.SHA256)
	if err := writeJSON(ctx, svc.store.stagedMetaPath(), r); err != nil {
		t.Fatal(err)
	}
	removeLegacyForTest(t, svc.store, 4)
	if _, err := svc.GetLifecycleEnvelope(ctx); err != nil {
		t.Fatal(err)
	}
	native, err := readTestStaged(t, svc.store)
	if err != nil || native.SHA256 != r.SHA256 {
		t.Fatal("public hash spelling changed", err)
	}
	if err := os.WriteFile(svc.store.stagedMetaPath(), []byte("invalid frozen file"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.BuildApplyPlan(ctx); err != nil {
		t.Fatal("consulted frozen metadata", err)
	}
}

func TestGenerationDownloadReplacementInvalidatesVerified(t *testing.T) {
	ctx := context.Background()
	svc := signedBindingService(t)
	if _, err := svc.VerifyUpdate(ctx, "1.2.0"); err != nil {
		t.Fatal(err)
	}
	old, err := readTestVerified(t, svc.store)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.DownloadUpdate(ctx, "1.2.0"); err != nil {
		t.Fatal(err)
	}
	if _, err := readTestVerified(t, svc.store); !os.IsNotExist(err) {
		t.Fatalf("replacement retained V: %v", err)
	}
	if _, err := os.Stat(old.Downloaded.ArtifactPath); err != nil {
		t.Fatal("replacement removed old immutable bytes", err)
	}
	if _, err := svc.StageUpdate(ctx, "1.2.0"); err != nil {
		t.Fatal("replacement fallback verification failed", err)
	}
}

func TestGenerationStorageDigestDoesNotAuthorizeUnsignedReplacement(t *testing.T) {
	ctx := context.Background()
	svc := signedBindingService(t)
	d, err := readTestDownloaded(t, svc.store)
	if err != nil {
		t.Fatal(err)
	}
	body := bytes.Repeat([]byte{'x'}, int(d.BytesWritten))
	if err := os.WriteFile(d.ArtifactPath, body, 0600); err != nil {
		t.Fatal(err)
	}
	mutateTestGraph(t, svc.store, func(r *stateRecord) { b := r.Blobs[d.blobID]; b.SHA256 = stateDigest(body); r.Blobs[d.blobID] = b })
	if err := verifyManifestSignature(svc.cfg.Policy, d.Manifest); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.VerifyUpdate(ctx, "1.2.0"); !errors.Is(err, ErrVerificationFailed) {
		t.Fatal(err)
	}
	if _, err := svc.StageUpdate(ctx, "1.2.0"); !errors.Is(err, ErrVerificationFailed) {
		t.Fatal(err)
	}
}

func TestGenerationLegacyAggregateOverflowPreservesInputs(t *testing.T) {
	ctx := context.Background()
	source, _ := stageInternalRecordOnlyUpdate(t, "1.2.0")
	svc := legacyTestService(t, source)
	removeLegacyForTest(t, svc.store, 4)
	v := svc.store.readLegacy(ctx)
	// Individually valid legacy files can have four distinct, large manifests.
	// The native total must reject them without deleting or truncating originals.
	notes := strings.Repeat("x", 16<<20)
	v.selected.value.Manifest.ReleaseNotesText = notes
	v.downloaded.value.Manifest.ReleaseNotesText = notes
	v.downloaded.value.Manifest.Version = "1.3.0"
	v.verified.value.Downloaded.Manifest.ReleaseNotesText = notes
	v.verified.value.Downloaded.Manifest.Version = "1.4.0"
	v.staged.value.Manifest.ReleaseNotesText = notes
	v.staged.value.Manifest.Version = "1.5.0"
	v.staged.value.Version = "1.5.0"
	values := []any{v.selected.value, v.downloaded.value, v.verified.value, v.staged.value}
	for i, value := range values {
		if err := writeJSON(ctx, filepath.Join(svc.store.dir, filepath.FromSlash(legacyMetadata[i])), value); err != nil {
			t.Fatal(err)
		}
	}
	before := map[string]string{}
	for _, key := range legacyMetadata[:4] {
		raw, err := os.ReadFile(filepath.Join(svc.store.dir, filepath.FromSlash(key)))
		if err != nil {
			t.Fatal(err)
		}
		before[key] = stateDigest(raw)
	}
	if _, err := svc.GetLifecycleEnvelope(ctx); !errors.Is(err, ErrStorageUnavailable) {
		t.Fatalf("aggregate oversized migration: %v", err)
	}
	assertLegacyForTest(t, svc.store)
	for key, digest := range before {
		raw, err := os.ReadFile(filepath.Join(svc.store.dir, filepath.FromSlash(key)))
		if err != nil || stateDigest(raw) != digest {
			t.Fatalf("overflow changed input %s: %v", key, err)
		}
	}
	if len(testBlobInventory(t, svc.store)) != 0 {
		t.Fatal("overflow retained uncommitted blob preparations")
	}
}

func TestGenerationPrivateEncodingDoesNotExpandHTMLOrChangeSignatures(t *testing.T) {
	svc := signedBindingService(t)
	d, err := readTestDownloaded(t, svc.store)
	if err != nil {
		t.Fatal(err)
	}
	manifest := d.Manifest
	manifest.ReleaseNotesText = "<>&"
	raw, err := encodePrivateComponent(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(raw, []byte("<>&")) {
		t.Fatal("private metadata expanded HTML")
	}
	// Re-keying altered signed authority cannot turn it into a valid package.
	mutateTestGraph(t, svc.store, func(r *stateRecord) { replaceTestManifest(t, r, r.Selected.Manifest, manifest) })
	if _, err := svc.VerifyUpdate(context.Background(), "1.2.0"); err == nil {
		t.Fatal("altered signed manifest verified")
	}
	if _, err := svc.StageUpdate(context.Background(), "1.2.0"); err == nil {
		t.Fatal("altered signed manifest staged")
	}
}

func TestGenerationRetainsIndependentObservationsAndDeniedHistory(t *testing.T) {
	ctx := context.Background()
	source, _ := stageInternalRecordOnlyUpdate(t, "1.2.0")
	svc := legacyTestService(t, source)
	removeLegacyForTest(t, svc.store, 4)
	v := svc.store.readLegacy(ctx)
	v.selected.value.Manifest.Version = "1.3.0"
	v.selected.value.Manifest.SchemaVersion = 0
	// A bad historical signature is ineligible under current checks but is not
	// malformed storage. Migration may not erase the observation permanently.
	v.selected.value.Manifest.Signature = &SignatureMetadata{Kind: "ed25519", KeyID: "old", Signature: "bad-signature"}
	v.downloaded.value.Manifest.Version = "1.4.0"
	v.downloaded.value.DownloadedAt = v.verified.value.Downloaded.DownloadedAt.Add(24 * time.Hour)
	v.staged.value.Manifest.Version, v.staged.value.Version = "1.5.0", "1.5.0"
	for i, value := range []any{v.selected.value, v.downloaded.value, v.verified.value, v.staged.value} {
		if err := writeJSON(ctx, filepath.Join(svc.store.dir, filepath.FromSlash(legacyMetadata[i])), value); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := svc.GetLifecycleEnvelope(ctx); err != nil {
		t.Fatal(err)
	}
	r := graphForTest(t, svc.store)
	if r.CandidateFault != "" || len(r.Manifests) != 4 || len(r.Transfers) != 2 || len(r.Blobs) != 3 {
		t.Fatalf("independent observations were lost: %+v", r)
	}
	selected, err := readTestSelected(t, svc.store)
	if err != nil || selected.Manifest.SchemaVersion != 0 || selected.Manifest.Version != "1.3.0" {
		t.Fatal("historical selected fields changed", err)
	}
	downloaded, err := readTestDownloaded(t, svc.store)
	if err != nil || downloaded.Manifest.Version != "1.4.0" || !downloaded.DownloadedAt.Equal(v.downloaded.value.DownloadedAt) {
		t.Fatal("independent download changed", err)
	}
	verified, err := readTestVerified(t, svc.store)
	if err != nil || verified.Downloaded.Manifest.Version != "1.2.0" || !verified.VerifiedAt.Equal(v.verified.value.VerifiedAt) {
		t.Fatal("independent verification changed", err)
	}
	if _, err := svc.BuildApplyPlan(ctx); err != nil {
		t.Fatal("denied candidate made valid stage unusable", err)
	}
}
