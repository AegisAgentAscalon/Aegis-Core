package updates

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

type pendingGenerationProvider struct {
	manifest Manifest
	started  chan struct{}
	release  chan struct{}
}

func (p pendingGenerationProvider) LoadManifest(ctx context.Context) (Manifest, error) {
	close(p.started)
	select {
	case <-p.release:
		return p.manifest, nil
	case <-ctx.Done():
		return Manifest{}, ctx.Err()
	}
}

func TestGenerationSeparateOwnerRejectsStaleCheck(t *testing.T) {
	ctx := context.Background()
	first := signedBindingService(t)
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
	done := make(chan error, 1)
	go func() { _, err := first.CheckForUpdates(ctx); done <- err }()
	<-started
	if _, err := second.VerifyUpdate(ctx, "1.2.0"); err != nil {
		close(release)
		t.Fatal(err)
	}
	authority := testNativeSnapshot(t, second.store).Token
	close(release)
	if err := <-done; !errors.Is(err, ErrUpdateStateChanged) {
		t.Fatalf("stale check was retried or published: %v", err)
	}
	if testNativeSnapshot(t, second.store).Token != authority {
		t.Fatal("stale check replaced committed authority")
	}
}

func TestGenerationSeparateOwnerRejectsStaleDownload(t *testing.T) {
	ctx := context.Background()
	body := []byte("artifact 1.2.0")
	started, release := make(chan struct{}), make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { close(started); <-release; _, _ = w.Write(body) }))
	defer server.Close()
	cfg, _, _ := testUpdateFiles(t, "1.2.0")
	manifest := testManifest(cfg, "1.2.0", server.URL, stateDigest(body))
	writeManifest(t, cfg.Source.ManifestPath, manifest)
	first := newTestUpdateService(t, cfg)
	second := newTestUpdateService(t, cfg)
	if _, err := first.CheckForUpdates(ctx); err != nil {
		t.Fatal(err)
	}
	before := testBlobInventory(t, first.store)
	done := make(chan error, 1)
	go func() { _, err := first.DownloadUpdate(ctx, "1.2.0"); done <- err }()
	<-started
	if _, err := second.ClearStagedUpdate(ctx); err != nil {
		close(release)
		t.Fatal(err)
	}
	authority := testNativeSnapshot(t, second.store).Token
	close(release)
	if err := <-done; !errors.Is(err, ErrUpdateStateChanged) {
		t.Fatalf("stale download published: %v", err)
	}
	if testNativeSnapshot(t, second.store).Token != authority || !reflect.DeepEqual(before, testBlobInventory(t, first.store)) {
		t.Fatal("stale transfer replaced state or leaked operation-owned bytes")
	}
}

type generationApplyFunc func(context.Context, StagedUpdate) (ApplyResult, error)

func (f generationApplyFunc) Apply(ctx context.Context, staged StagedUpdate) (ApplyResult, error) {
	return f(ctx, staged)
}

func TestGenerationApplyGateAllowsReentryAndBlocksOtherOwners(t *testing.T) {
	ctx := context.Background()
	first, _ := stageInternalUpdate(t, "1.2.0", nil)
	second, err := NewService(first.cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	first.apply = generationApplyFunc(func(ctx context.Context, staged StagedUpdate) (ApplyResult, error) {
		for _, svc := range []*Service{first, second} {
			if _, err := svc.GetStatus(ctx); err != nil {
				return ApplyResult{}, err
			}
			if _, err := svc.BuildApplyPlan(ctx); err != nil {
				return ApplyResult{}, err
			}
			if _, err := svc.GetLifecycleEnvelope(ctx); err != nil {
				return ApplyResult{}, err
			}
			calls := []func() error{
				func() error { _, err := svc.ApplyUpdate(ctx); return err },
				func() error { _, err := svc.CheckForUpdates(ctx); return err },
				func() error { _, err := svc.DownloadUpdate(ctx, staged.Version); return err },
				func() error { _, err := svc.VerifyUpdate(ctx, staged.Version); return err },
				func() error { _, err := svc.StageUpdate(ctx, staged.Version); return err },
				func() error { _, err := svc.ClearStagedUpdate(ctx); return err },
				func() error { _, err := svc.ConfigureLane(ctx, LaneConfig{Channel: ChannelStable}); return err },
			}
			for i, call := range calls {
				if err := call(); !errors.Is(err, ErrApplyInProgress) {
					return ApplyResult{}, fmt.Errorf("gate operation %d: %w", i, err)
				}
			}
		}
		_, err := second.RecordPackageHandoff(ctx, PackageHandoffRequest{ExpectedRevision: 1, IdempotencyKey: "apply-reentry", ConsumerID: "test-consumer"})
		return ApplyResult{OK: true}, err
	})
	done := make(chan error, 1)
	go func() { _, err := first.ApplyUpdate(ctx); done <- err }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("apply callback reentry deadlocked")
	}
	if _, err := second.ClearStagedUpdate(ctx); err != nil {
		t.Fatal("execution gate remained held", err)
	}
}

// The callback's stdin stays open while the parent tests cooperative exclusion.
type processGenerationApply struct{}

func (processGenerationApply) Apply(context.Context, StagedUpdate) (ApplyResult, error) {
	fmt.Println("apply-ready")
	_, err := io.Copy(io.Discard, os.Stdin)
	return ApplyResult{OK: true}, err
}

func TestGenerationApplyGateAcrossProcesses(t *testing.T) {
	const childKey = "AEGIS_UPDATES_APPLY_CHILD"
	if path := os.Getenv(childKey); path != "" {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var cfg AppConfig
		if err := json.Unmarshal(raw, &cfg); err != nil {
			t.Fatal(err)
		}
		svc, err := NewService(cfg, processGenerationApply{})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := svc.ApplyUpdate(context.Background()); err != nil {
			t.Fatal(err)
		}
		return
	}
	svc, _ := stageInternalUpdate(t, "1.2.0", nil)
	raw, err := json.Marshal(svc.cfg)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "child-config.json")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(os.Args[0], "-test.run=^TestGenerationApplyGateAcrossProcesses$", "-test.timeout=30s")
	command.Env = append(os.Environ(), childKey+"="+path)
	input, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	output, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	command.Stderr = &stderr
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	waited := false
	t.Cleanup(func() {
		_ = input.Close()
		if !waited {
			_ = command.Process.Kill()
			_ = command.Wait()
		}
	})
	ready := make(chan bool, 1)
	go func() {
		scanner := bufio.NewScanner(output)
		for scanner.Scan() {
			if scanner.Text() == "apply-ready" {
				ready <- true
				return
			}
		}
		ready <- false
	}()
	select {
	case ok := <-ready:
		if !ok {
			t.Fatal("child did not enter apply")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("child apply admission timed out")
	}
	token := testNativeSnapshot(t, svc.store).Token
	if _, err := svc.ClearStagedUpdate(context.Background()); !errors.Is(err, ErrApplyInProgress) {
		t.Fatalf("cross-process clear: %v", err)
	}
	if _, err := svc.ApplyUpdate(context.Background()); !errors.Is(err, ErrApplyInProgress) {
		t.Fatalf("cross-process apply: %v", err)
	}
	if _, err := svc.GetStatus(context.Background()); err != nil {
		t.Fatal(err)
	}
	if testNativeSnapshot(t, svc.store).Token != token {
		t.Fatal("blocked mutation changed state")
	}
	if err := command.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = command.Wait()
	waited = true
	if _, err := svc.ApplyUpdate(context.Background()); err != nil {
		t.Fatalf("process death did not release execution gate: %v", err)
	}
}

// A context callback is used only as a deterministic fixture scheduling point.
// statusFor is outside all owner/commit locks during ConfigureLane preparation.
type configureConflictContext struct {
	context.Context
	once     sync.Once
	conflict func()
}

func (c *configureConflictContext) Err() error {
	var callers [32]uintptr
	frames := runtime.CallersFrames(callers[:runtime.Callers(1, callers[:])])
	for {
		frame, more := frames.Next()
		if strings.HasSuffix(frame.Function, ".statusFor") {
			c.once.Do(c.conflict)
			break
		}
		if !more {
			break
		}
	}
	return c.Context.Err()
}

func TestGenerationConfigureRetriesConcurrentMetadataCommit(t *testing.T) {
	first, _ := stageInternalUpdate(t, "1.2.0", nil)
	second, err := NewService(first.cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	conflicts := 0
	ctx := &configureConflictContext{Context: context.Background(), conflict: func() {
		conflicts++
		if _, err := second.CheckForUpdates(context.Background()); err != nil {
			t.Fatal(err)
		}
	}}
	if _, err := first.ConfigureLane(ctx, LaneConfig{Channel: ChannelStable}); err != nil {
		t.Fatalf("configuration did not retry current authority: %v", err)
	}
	if conflicts != 1 {
		t.Fatalf("test did not inject exactly one commit: %d", conflicts)
	}
}

func TestGenerationWaitingForCommitHonorsCancellation(t *testing.T) {
	svc := signedBindingService(t)
	guard, err := svc.store.generations.Lock(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer guard.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := svc.GetStatus(ctx); done <- err }()
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, ErrContextCanceled) {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("cancellation waited for commit lock")
	}
}
