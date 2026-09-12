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
)

func nativeObjectForTest(root map[string]any, path []string) map[string]any {
	var current any = root
	for _, key := range path {
		if key == "*" {
			for _, value := range current.(map[string]any) {
				current = value
				break
			}
			continue
		}
		if key == "0" {
			current = current.([]any)[0]
			continue
		}
		current = current.(map[string]any)[key]
	}
	return current.(map[string]any)
}

func TestGenerationNativeRequiresExactPresentFields(t *testing.T) {
	svc, _ := stageInternalRecordOnlyUpdate(t, "1.2.0")
	mutateTestGraph(t, svc.store, func(r *stateRecord) {
		id := r.Selected.Manifest
		m := r.Manifests[id]
		m.SchemaVersion = 0
		m.Metadata = map[string]string{"Case": "one", "case": "two"}
		m.Future = map[string][]string{"Case": nil, "case": {}}
		replaceTestManifest(t, r, id, m)
	})
	base := testNativeSnapshot(t, svc.store).Data
	if _, err := svc.store.decodeState(context.Background(), base); err != nil {
		t.Fatalf("canonical schema-0 native fixture: %v", err)
	}
	fields := []struct {
		name     string
		path     []string
		key      string
		nullable bool
	}{
		{"version", nil, "version", false},
		{"selected-index", []string{"selected"}, "artifact", false},
		{"selected-source", []string{"selected"}, "source_key", false},
		{"transfer-index", []string{"transfers", "*"}, "artifact", false},
		{"staged-index", []string{"staged"}, "artifact", false},
		{"source-authenticated-false", []string{"staged", "source"}, "authenticated", false},
		{"capability-false", []string{"lifecycle", "envelope", "capabilities"}, "can_execute_installer", false},
		{"validation-false", []string{"lifecycle", "envelope", "validation"}, "rehashed_at_handoff", false},
		{"manifest-schema-zero", []string{"manifests", "*"}, "schema_version", false},
		{"artifact-platform", []string{"manifests", "*", "artifacts", "0"}, "platform", false},
		{"idempotency", []string{"lifecycle"}, "idempotency", true},
	}
	for _, field := range fields {
		for _, mode := range []string{"alias", "collision", "missing", "null"} {
			if mode == "null" && field.nullable {
				continue
			}
			t.Run(field.name+"/"+mode, func(t *testing.T) {
				var root map[string]any
				if err := json.Unmarshal(base, &root); err != nil {
					t.Fatal(err)
				}
				object := nativeObjectForTest(root, field.path)
				switch mode {
				case "alias":
					object[strings.ToUpper(field.key)] = object[field.key]
					delete(object, field.key)
				case "collision":
					object[strings.ToUpper(field.key)] = object[field.key]
				case "missing":
					delete(object, field.key)
				case "null":
					object[field.key] = nil
				}
				raw, err := json.Marshal(root)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := svc.store.decodeState(context.Background(), raw); !errors.Is(err, ErrStorageUnavailable) {
					t.Fatalf("ambiguous/missing/null native member accepted: %v", err)
				}
			})
		}
	}
	for _, key := range []string{"selected", "verified", "staged", "lifecycle", "downloaded"} {
		t.Run("null-reference/"+key, func(t *testing.T) {
			var root map[string]any
			if err := json.Unmarshal(base, &root); err != nil {
				t.Fatal(err)
			}
			root[key] = nil
			raw, err := json.Marshal(root)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := svc.store.decodeState(context.Background(), raw); !errors.Is(err, ErrStorageUnavailable) {
				t.Fatalf("null reference accepted: %v", err)
			}
		})
	}
	// Explicit nil slices retain their value; required presence is independent
	// from nullability. Free-form map keys and nil/empty values are untouched.
	var root map[string]any
	if err := json.Unmarshal(base, &root); err != nil {
		t.Fatal(err)
	}
	nativeObjectForTest(root, []string{"lifecycle"})["idempotency"] = nil
	raw, err := json.Marshal(root)
	if err != nil {
		t.Fatal(err)
	}
	v, err := svc.store.decodeState(context.Background(), raw)
	if err != nil {
		t.Fatal("required nullable slice rejected", err)
	}
	manifest := v.selected.value.Manifest
	if v.lifecycle.value.Idempotency != nil || manifest.Metadata["Case"] != "one" || manifest.Metadata["case"] != "two" || manifest.Future["Case"] != nil || manifest.Future["case"] == nil {
		t.Fatal("nil/empty slices or case-sensitive free-form keys changed")
	}
	duplicate := append([]byte(`{"version":1,`), base[1:]...)
	if _, err := svc.store.decodeState(context.Background(), duplicate); !errors.Is(err, ErrStorageUnavailable) {
		t.Fatal("exact duplicate key accepted", err)
	}
	// Exercise public fail-closed reading through a correctly committed envelope.
	root["Version"] = root["version"]
	raw, err = json.Marshal(root)
	if err != nil {
		t.Fatal(err)
	}
	guard, err := svc.store.generations.Lock(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	token, err := guard.Token()
	if err != nil {
		_ = guard.Close()
		t.Fatal(err)
	}
	_, err = guard.Commit(token, raw, nil)
	_ = guard.Close()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.GetStatus(context.Background()); !errors.Is(err, ErrStorageUnavailable) {
		t.Fatal("public read accepted ambiguous native fields", err)
	}
}

type fixedGenerationProvider struct{ manifest Manifest }

func (p fixedGenerationProvider) LoadManifest(context.Context) (Manifest, error) {
	return p.manifest, nil
}

func TestGenerationFailedCheckPreservesInvalidCandidate(t *testing.T) {
	ctx := context.Background()
	source, _ := stageInternalRecordOnlyUpdate(t, "1.2.0")
	base, err := readTestSelected(t, source.store)
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"legacy-invalid", "native-quarantined", "legacy-valid", "native-valid"} {
		for _, failure := range []string{"no-compatible", "prerelease-denied"} {
			t.Run(kind+"/"+failure, func(t *testing.T) {
				svc := legacyTestService(t, source)
				invalid := kind == "legacy-invalid" || kind == "native-quarantined"
				if invalid {
					if err := os.WriteFile(svc.store.selectedPath(), []byte("{bad-candidate"), 0600); err != nil {
						t.Fatal(err)
					}
				}
				if strings.HasPrefix(kind, "native") {
					removeLegacyForTest(t, svc.store, 4)
					if _, err := svc.GetLifecycleEnvelope(ctx); err != nil {
						t.Fatal(err)
					}
				}
				before, err := readTestView(svc.store)
				if err != nil {
					t.Fatal(err)
				}
				var native []byte
				if before.token != "" {
					native = testNativeSnapshot(t, svc.store).Data
				}
				inventory := testBlobInventory(t, svc.store)
				manifest := base.Manifest
				want := ErrNoCompatibleArtifact
				if failure == "no-compatible" {
					manifest.Artifacts = nil
				} else {
					manifest.Version = "1.3.0-beta"
					want = ErrNoUpdateAvailable
				}
				svc.provider = fixedGenerationProvider{manifest}
				if _, err := svc.CheckForUpdates(ctx); !errors.Is(err, want) {
					t.Fatalf("failed check error=%v want=%v", err, want)
				}
				after, err := readTestView(svc.store)
				if err != nil {
					t.Fatal(err)
				}
				if invalid {
					if before.token != after.token || !reflect.DeepEqual(before.raw, after.raw) || before.candidateFault != after.candidateFault || !reflect.DeepEqual(inventory, testBlobInventory(t, svc.store)) {
						t.Fatal("failed check changed invalid candidate authority or blob inventory")
					}
					if before.token == "" {
						assertLegacyForTest(t, svc.store)
					} else if !bytes.Equal(native, testNativeSnapshot(t, svc.store).Data) {
						t.Fatal("failed check changed native T/L or fault state")
					}
				} else {
					// Deliberate W13 compatibility exception: valid cached candidates
					// are cleared on these selection errors, preserving independent T/L.
					if after.token == "" || after.selected.value != nil || after.downloaded.value != nil || after.verified.value != nil || after.staged.value == nil || after.lifecycle.value == nil {
						t.Fatal("valid candidate cleanup behavior changed")
					}
				}
				if _, err := svc.BuildApplyPlan(ctx); err != nil {
					t.Fatal("failed check damaged independent stage", err)
				}
			})
		}
	}
}

func TestGenerationSuccessfulNoUpdateRepairsQuarantine(t *testing.T) {
	ctx := context.Background()
	source, _ := stageInternalRecordOnlyUpdate(t, "1.2.0")
	for _, native := range []bool{false, true} {
		t.Run(fmt.Sprint(native), func(t *testing.T) {
			svc := legacyTestService(t, source)
			if err := os.WriteFile(svc.store.selectedPath(), []byte("{bad-candidate"), 0600); err != nil {
				t.Fatal(err)
			}
			if native {
				removeLegacyForTest(t, svc.store, 4)
				if _, err := svc.GetLifecycleEnvelope(ctx); err != nil {
					t.Fatal(err)
				}
			}
			manifest, err := source.provider.LoadManifest(ctx)
			if err != nil {
				t.Fatal(err)
			}
			manifest.Version = svc.cfg.CurrentVersion
			svc.provider = fixedGenerationProvider{manifest}
			result, err := svc.CheckForUpdates(ctx)
			if err != nil || result.UpdateAvailable {
				t.Fatalf("successful no-update: %+v %v", result, err)
			}
			r := graphForTest(t, svc.store)
			if r.CandidateFault != "" || r.Selected != nil || r.Downloaded != "" || r.Verified != nil || r.Staged == nil || r.Lifecycle == nil {
				t.Fatal("successful no-update did not repair candidate while retaining T/L")
			}
		})
	}
}

func TestGenerationLegacyJSONParsingRemainsCompatible(t *testing.T) {
	source, _ := stageInternalRecordOnlyUpdate(t, "1.2.0")
	svc := legacyTestService(t, source)
	raw, err := os.ReadFile(svc.store.selectedPath())
	if err != nil {
		t.Fatal(err)
	}
	raw = bytes.Replace(raw, []byte(`"schema_version"`), []byte(`"SCHEMA_VERSION"`), 1)
	if err := os.WriteFile(filepath.Join(svc.store.dir, "selected_update.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	selected, err := readTestSelected(t, svc.store)
	if err != nil || selected.SchemaVersion != schemaVersion {
		t.Fatalf("legacy parser changed: %+v %v", selected, err)
	}
}

func TestGenerationCanceledCheckRetainsFault(t *testing.T) {
	source, _ := stageInternalRecordOnlyUpdate(t, "1.2.0")
	for _, native := range []bool{false, true} {
		t.Run(fmt.Sprint(native), func(t *testing.T) {
			svc := legacyTestService(t, source)
			if err := os.WriteFile(svc.store.selectedPath(), []byte("{bad-candidate"), 0600); err != nil {
				t.Fatal(err)
			}
			if native {
				removeLegacyForTest(t, svc.store, 4)
				if _, err := svc.GetLifecycleEnvelope(context.Background()); err != nil {
					t.Fatal(err)
				}
			}
			before, err := readTestView(svc.store)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			svc.provider = cancelAfterManifest{Provider: svc.provider, cancel: cancel}
			if _, err := svc.CheckForUpdates(ctx); !errors.Is(err, ErrContextCanceled) {
				t.Fatal(err)
			}
			after, err := readTestView(svc.store)
			if err != nil {
				t.Fatal(err)
			}
			if before.token != after.token || before.candidateFault != after.candidateFault || !reflect.DeepEqual(before.raw, after.raw) {
				t.Fatal("canceled check repaired invalid candidate state")
			}
			if before.token == "" {
				assertLegacyForTest(t, svc.store)
			}
		})
	}
}

func TestGenerationReplacementHashAndFailurePreserveAuthority(t *testing.T) {
	ctx := context.Background()
	for _, failure := range []bool{false, true} {
		t.Run(fmt.Sprint("download-failure-", failure), func(t *testing.T) {
			svc := signedBindingService(t)
			if _, err := svc.VerifyUpdate(ctx, "1.2.0"); err != nil {
				t.Fatal(err)
			}
			verified, err := readTestVerified(t, svc.store)
			if err != nil {
				t.Fatal(err)
			}
			token := testNativeSnapshot(t, svc.store).Token
			inventory := testBlobInventory(t, svc.store)
			if failure {
				if err := os.Remove(verified.Downloaded.Artifact.DownloadURL); err != nil {
					t.Fatal(err)
				}
				if _, err := svc.DownloadUpdate(ctx, "1.2.0"); !errors.Is(err, ErrDownloadFailed) {
					t.Fatal(err)
				}
				after, err := readTestVerified(t, svc.store)
				if err != nil || !reflect.DeepEqual(verified, after) || token != testNativeSnapshot(t, svc.store).Token || !reflect.DeepEqual(inventory, testBlobInventory(t, svc.store)) {
					t.Fatal("failed download changed verified authority or retained partial bytes", err)
				}
			} else {
				if err := os.WriteFile(verified.Downloaded.Artifact.DownloadURL, bytes.Repeat([]byte{'x'}, int(verified.Downloaded.BytesWritten)), 0600); err != nil {
					t.Fatal(err)
				}
				if _, err := svc.DownloadUpdate(ctx, "1.2.0"); err != nil {
					t.Fatal(err)
				}
				if _, err := readTestVerified(t, svc.store); !os.IsNotExist(err) {
					t.Fatal("replacement retained old V", err)
				}
				if _, err := svc.StageUpdate(ctx, "1.2.0"); !errors.Is(err, ErrVerificationFailed) {
					t.Fatal("wrong-hash replacement staged through old V", err)
				}
			}
			oldHash, err := fileSHA256(verified.Downloaded.ArtifactPath)
			if err != nil || !strings.EqualFold(oldHash, verified.Downloaded.Artifact.SHA256) {
				t.Fatal("immutable old blob changed", err)
			}
		})
	}
}

// Retain the independent reviewer's execution-gate regressions in the suite.
func TestGenerationApplyGateCleanup(t *testing.T) {
	for _, mode := range []string{"panic", "error", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			first, _ := stageInternalUpdate(t, "1.2.0", nil)
			second, err := NewService(first.cfg, nil)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			first.apply = generationApplyFunc(func(context.Context, StagedUpdate) (ApplyResult, error) {
				if mode == "panic" {
					panic("test callback panic")
				}
				if mode == "cancel" {
					cancel()
					return ApplyResult{}, context.Canceled
				}
				return ApplyResult{}, errors.New("test callback error")
			})
			panicked := false
			func() {
				defer func() {
					if r := recover(); r != nil {
						if mode != "panic" {
							panic(r)
						}
						panicked = true
					}
				}()
				_, err = first.ApplyUpdate(ctx)
			}()
			if mode == "panic" && !panicked {
				t.Fatal("callback panic was swallowed")
			}
			if mode == "error" && !errors.Is(err, ErrApplyFailed) {
				t.Fatal(err)
			}
			if mode == "cancel" && !errors.Is(err, ErrContextCanceled) {
				t.Fatal(err)
			}
			if first.applyInProgress {
				t.Fatal("local apply flag remained set")
			}
			if _, err := second.ClearStagedUpdate(context.Background()); err != nil {
				t.Fatalf("execution gate remained held: %v", err)
			}
		})
	}
}

func TestGenerationPendingCheckFinalApplyProbe(t *testing.T) {
	ctx := context.Background()
	first, _ := stageInternalUpdate(t, "1.2.0", nil)
	second, err := NewService(first.cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	selected, err := readTestSelected(t, first.store)
	if err != nil {
		t.Fatal(err)
	}
	started, release := make(chan struct{}), make(chan struct{})
	first.provider = pendingGenerationProvider{selected.Manifest, started, release}
	checkDone := make(chan error, 1)
	go func() { _, err := first.CheckForUpdates(ctx); checkDone <- err }()
	<-started
	applyStarted, applyRelease := make(chan struct{}), make(chan struct{})
	second.apply = generationApplyFunc(func(context.Context, StagedUpdate) (ApplyResult, error) {
		close(applyStarted)
		<-applyRelease
		return ApplyResult{OK: true}, nil
	})
	applyDone := make(chan error, 1)
	go func() { _, err := second.ApplyUpdate(ctx); applyDone <- err }()
	<-applyStarted
	before := testNativeSnapshot(t, first.store).Token
	close(release)
	err = <-checkDone
	close(applyRelease)
	if !errors.Is(err, ErrApplyInProgress) {
		t.Fatalf("pending check committed through active Apply: %v", err)
	}
	if err := <-applyDone; err != nil {
		t.Fatal(err)
	}
	if testNativeSnapshot(t, first.store).Token != before {
		t.Fatal("blocked Check changed authority")
	}
}
