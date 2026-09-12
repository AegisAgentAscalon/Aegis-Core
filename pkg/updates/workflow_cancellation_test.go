package updates

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestWorkflowWaitCancellationPreservesAuthorityAndReleasesGate(t *testing.T) {
	ctx := context.Background()
	cfg, path, hash := testUpdateFiles(t, "1.2.0")
	manifest := testManifest(cfg, "1.2.0", path, hash)
	writeManifest(t, cfg.Source.ManifestPath, manifest)
	svc := newTestUpdateService(t, cfg)
	if _, err := svc.CheckForUpdates(ctx); err != nil {
		t.Fatal(err)
	}
	before := testNativeSnapshot(t, svc.store).Token
	provider := svc.provider
	started, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	defer unblock()
	svc.provider = pendingGenerationProvider{manifest, started, release}
	firstDone := make(chan error, 1)
	go func() { _, err := svc.CheckForUpdates(ctx); firstDone <- err }()
	select {
	case <-started:
	case err := <-firstDone:
		t.Fatal("initial workflow did not reach its provider", err)
	case <-time.After(2 * time.Second):
		t.Fatal("initial workflow did not reach its provider")
	}

	// Copied handles must wait on the same workflow gate and honor their own
	// deadline while the first operation's provider is still blocked.
	copied := *svc
	waitCtx, cancel := context.WithTimeout(ctx, 30*time.Millisecond)
	defer cancel()
	waitDone := make(chan error, 1)
	go func() { _, err := copied.ClearStagedUpdate(waitCtx); waitDone <- err }()
	select {
	case err := <-waitDone:
		if !errors.Is(err, ErrContextCanceled) {
			t.Fatalf("workflow wait error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("canceled workflow waited for the unrelated provider")
	}
	if testNativeSnapshot(t, svc.store).Token != before {
		t.Fatal("canceled waiter changed authority")
	}
	unblock()
	select {
	case err := <-firstDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("initial workflow did not finish after provider release")
	}
	svc.provider = provider
	reuseCtx, reuseCancel := context.WithTimeout(ctx, 2*time.Second)
	defer reuseCancel()
	if _, err := copied.ClearStagedUpdate(reuseCtx); err != nil {
		t.Fatal("workflow gate was not reusable after canceled wait", err)
	}
	if _, err := svc.CheckForUpdates(reuseCtx); err != nil {
		t.Fatal("workflow gate was not released after reuse", err)
	}
}
