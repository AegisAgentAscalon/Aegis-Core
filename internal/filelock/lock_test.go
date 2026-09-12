//go:build windows || darwin || dragonfly || freebsd || linux || netbsd || openbsd

package filelock

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestDistinctHandlesExcludeAndPreserveSentinel(t *testing.T) {
	for _, content := range []string{"", "existing bytes remain unchanged"} {
		t.Run(fmt.Sprintf("bytes=%d", len(content)), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), ".state.lock")
			if err := os.WriteFile(path, []byte(content), 0600); err != nil {
				t.Fatal(err)
			}
			before, _ := os.Stat(path)
			lock, err := Acquire(nil, path)
			if err != nil {
				t.Fatal(err)
			}
			defer lock.Close()
			if other, err := TryAcquire(nil, path); other != nil || !errors.Is(err, ErrBusy) {
				t.Fatalf("distinct handle did not contend: %v, %v", other, err)
			}
			var wg sync.WaitGroup
			for i := 0; i < 8; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					if err := lock.Close(); err != nil {
						t.Errorf("idempotent concurrent close: %v", err)
					}
				}()
			}
			wg.Wait()
			other, err := TryAcquire(nil, path)
			if err != nil {
				t.Fatal(err)
			}
			if err := other.Close(); err != nil {
				t.Fatal(err)
			}
			after, err := os.Stat(path)
			raw, readErr := os.ReadFile(path)
			if err != nil || readErr != nil || !os.SameFile(before, after) || string(raw) != content || !before.ModTime().Equal(after.ModTime()) {
				t.Fatalf("lock changed sentinel identity, bytes or mtime: %v, %v", err, readErr)
			}
		})
	}
}

func TestAcquireCancellationAndDeferredPanicRelease(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".state.lock")
	held, err := Acquire(nil, path)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if lock, err := Acquire(ctx, path); lock != nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("contended cancellation: %v, %v", lock, err)
	}
	if lock, err := TryAcquire(ctx, path); lock != nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("canceled try: %v, %v", lock, err)
	}
	if err := held.Close(); err != nil {
		t.Fatal(err)
	}
	func() {
		defer func() {
			if recovered := recover(); recovered != "test panic" {
				t.Errorf("panic did not propagate: %v", recovered)
			}
		}()
		lock, err := Acquire(nil, path)
		if err != nil {
			t.Fatal(err)
		}
		defer lock.Close()
		panic("test panic")
	}()
	lock, err := TryAcquire(nil, path)
	if err != nil {
		t.Fatalf("panic stranded exclusion: %v", err)
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
}

// The probe cancels only after a different OS handle proves acquisition has
// happened. This exercises the post-acquisition cancellation check exactly.
type cancelWhenLocked struct {
	context.Context
	cancel   context.CancelFunc
	path     string
	observed bool
	probeErr error
}

func (ctx *cancelWhenLocked) Err() error {
	if err := ctx.Context.Err(); err != nil {
		return err
	}
	file, err := os.OpenFile(ctx.path, os.O_RDWR, 0600)
	if err == nil {
		err = tryLockFile(file)
		if errors.Is(err, ErrBusy) {
			ctx.observed = true
			ctx.cancel()
			err = nil
		} else if err == nil {
			err = unlockFile(file)
		}
		err = errors.Join(err, file.Close())
	}
	if err != nil {
		ctx.probeErr = err
		ctx.cancel()
	}
	return ctx.Context.Err()
}

func TestCancellationAfterAcquisitionReleasesHandle(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".state.lock")
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	base, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx := &cancelWhenLocked{Context: base, cancel: cancel, path: path}
	if lock, err := Acquire(ctx, path); lock != nil || !errors.Is(err, context.Canceled) || !ctx.observed || ctx.probeErr != nil {
		t.Fatalf("post-acquire cancellation: %v, %v; observed=%t probe=%v", lock, err, ctx.observed, ctx.probeErr)
	}
	lock, err := TryAcquire(nil, path)
	if err != nil {
		t.Fatalf("cancellation leaked an OS lock: %v", err)
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestAcquisitionsSerializeDistinctGoroutineHandles(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".state.lock")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var active atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 8; j++ {
				lock, err := Acquire(ctx, path)
				if err != nil {
					t.Error(err)
					return
				}
				if active.Add(1) != 1 {
					t.Error("multiple handles entered the critical section")
				}
				runtime.Gosched()
				active.Add(-1)
				if err := lock.Close(); err != nil {
					t.Error(err)
				}
			}
		}()
	}
	wg.Wait()
}

func lockChild(t *testing.T, path, mode string) *exec.Cmd {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	cmd := exec.CommandContext(ctx, executable, "-test.run=^TestFileLockProcessHelper$")
	cmd.Env = append(os.Environ(), "AEGIS_FILELOCK_CHILD="+mode, "AEGIS_FILELOCK_PATH="+path)
	return cmd
}

func TestChildProcessContentionAndExitRelease(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".state.lock")
	held, err := Acquire(nil, path)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	if output, err := lockChild(t, path, "try").CombinedOutput(); err != nil || !strings.Contains(string(output), "busy\n") {
		t.Fatalf("child bypassed parent lock: %s, %v", output, err)
	}
	if err := held.Close(); err != nil {
		t.Fatal(err)
	}
	// os.Exit deliberately skips Close and defers in the child.
	if output, err := lockChild(t, path, "exit").CombinedOutput(); err != nil || !strings.Contains(string(output), "acquired\n") {
		t.Fatalf("child acquisition/exit: %s, %v", output, err)
	}
	lock, err := TryAcquire(nil, path)
	if err != nil {
		t.Fatalf("child exit stranded the lock: %v", err)
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestKilledChildReleasesStableEmptySentinel(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".state.lock")
	cmd := lockChild(t, path, "hold")
	output, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	input, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	if line, err := bufio.NewReader(output).ReadString('\n'); err != nil || line != "acquired\n" {
		t.Fatalf("child did not acquire: %q, %v", line, err)
	}
	before, err := os.Stat(path)
	if err != nil || before.Size() != 0 {
		t.Fatalf("sentinel was initialized: %v, %v", before, err)
	}
	if lock, err := TryAcquire(nil, path); lock != nil || !errors.Is(err, ErrBusy) {
		t.Fatalf("parent bypassed child lock: %v, %v", lock, err)
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err == nil {
		t.Fatal("killed child unexpectedly exited successfully")
	}
	lock, err := TryAcquire(nil, path)
	if err != nil {
		t.Fatalf("killed child stranded exclusion: %v", err)
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(path)
	if err != nil || !os.SameFile(before, after) || after.Size() != 0 {
		t.Fatalf("process death replaced/initialized sentinel: %v, %v", after, err)
	}
}

func TestFileLockProcessHelper(t *testing.T) {
	mode := os.Getenv("AEGIS_FILELOCK_CHILD")
	if mode == "" {
		return
	}
	lock, err := TryAcquire(context.Background(), os.Getenv("AEGIS_FILELOCK_PATH"))
	if mode == "try" && errors.Is(err, ErrBusy) {
		fmt.Println("busy")
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	fmt.Println("acquired")
	if mode == "exit" {
		os.Exit(0)
	}
	if mode == "hold" {
		var signal [1]byte
		_, _ = os.Stdin.Read(signal[:])
	}
}
