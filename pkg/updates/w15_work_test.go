package updates

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Cancel after admission but during repeated read/parse work, without timing a
// goroutine against disk or depending on the host's throughput.
type cancelAfterChecks struct {
	context.Context
	cancel context.CancelFunc
	left   int
}

func (c *cancelAfterChecks) Err() error {
	c.left--
	if c.left <= 0 {
		c.cancel()
	}
	return c.Context.Err()
}

func workCancelContext(t *testing.T) context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	return &cancelAfterChecks{Context: ctx, cancel: cancel, left: 12}
}

func TestW15LongReadsObserveCancellation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "large.bin")
	if err := os.WriteFile(path, bytes.Repeat([]byte("x"), 2<<20), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := hashFile(workCancelContext(t), path); !errors.Is(err, ErrContextCanceled) {
		t.Fatalf("hash cancellation = %v", err)
	}
	svc, _ := stageInternalRecordOnlyUpdate(t, "1.2.0")
	raw := testNativeSnapshot(t, svc.store).Data
	if _, err := svc.store.decodeState(workCancelContext(t), raw); !errors.Is(err, ErrContextCanceled) {
		t.Fatalf("native parse cancellation = %v", err)
	}
}

func TestW15StoreConstructionDoesNotWaitForExecutionOrCommit(t *testing.T) {
	cfg := testConfig(t)
	st, err := newStore(cfg)
	if err != nil {
		t.Fatal(err)
	}
	guard, err := st.generations.Lock(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer guard.Close()
	gate, err := st.tryApply(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer gate.Close()
	done := make(chan error, 1)
	go func() { _, err := newStore(cfg); done <- err }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("constructor waited on a held operation lock")
	}
}

func TestW15HandoffSameSizeTamperAndErrorPrecedence(t *testing.T) {
	for _, mode := range []string{"initial", "duplicate", "stale-revision"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			svc, staged := stageInternalRecordOnlyUpdate(t, "1.2.0")
			envelope, err := svc.GetLifecycleEnvelope(ctx)
			if err != nil {
				t.Fatal(err)
			}
			request := PackageHandoffRequest{ExpectedRevision: envelope.Revision, IdempotencyKey: "handoff-check", ConsumerID: "consumer"}
			if mode == "duplicate" {
				if _, err := svc.RecordPackageHandoff(ctx, request); err != nil {
					t.Fatal(err)
				}
			} else if mode == "stale-revision" {
				request.ExpectedRevision++
			}
			before := testNativeSnapshot(t, svc.store).Token
			info, err := os.Stat(staged.ArtifactPath)
			if err != nil {
				t.Fatal(err)
			}
			body, err := os.ReadFile(staged.ArtifactPath)
			if err != nil || len(body) == 0 {
				t.Fatal("empty artifact", err)
			}
			body[0] ^= 1
			if err := os.WriteFile(staged.ArtifactPath, body, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chtimes(staged.ArtifactPath, info.ModTime(), info.ModTime()); err != nil {
				t.Fatal(err)
			}
			result, err := svc.RecordPackageHandoff(ctx, request)
			if !errors.Is(err, ErrVerificationFailed) || result.ArtifactPath != "" {
				t.Fatalf("tampered handoff = %+v, %v", result, err)
			}
			if after := testNativeSnapshot(t, svc.store).Token; after != before {
				t.Fatal("rejected handoff advanced authority")
			}
		})
	}
}

func TestW15CanonicalTransferReachability(t *testing.T) {
	svc, _ := stageInternalRecordOnlyUpdate(t, "1.2.0")
	r := graphForTest(t, svc.store)
	m := r.Manifests[r.Selected.Manifest]
	m.Artifacts = append(m.Artifacts, m.Artifacts[0])
	manifestID, err := recordDigest(m)
	if err != nil {
		t.Fatal(err)
	}
	r.Manifests = map[string]Manifest{manifestID: m}
	r.Selected.Manifest, r.Staged.Manifest = manifestID, manifestID
	first := r.Transfers[r.Downloaded]
	first.Manifest, first.Artifact = manifestID, 0
	second := first
	second.Artifact = 1
	firstID, err := recordDigest(first)
	if err != nil {
		t.Fatal(err)
	}
	secondID, err := recordDigest(second)
	if err != nil {
		t.Fatal(err)
	}
	for _, duplicate := range []bool{false, true} {
		r.Transfers = map[string]transferRef{secondID: second}
		r.Downloaded, r.Verified.Transfer = secondID, secondID
		if duplicate {
			r.Transfers[firstID], r.Downloaded = first, firstID
		}
		raw, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		_, err = svc.store.decodeState(context.Background(), raw)
		if duplicate && !errors.Is(err, ErrStorageUnavailable) || !duplicate && err != nil {
			t.Fatalf("canonical duplicate=%v: %v", duplicate, err)
		}
	}
}
