package filepersist

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
)

var injected = errors.New("injected failure")

type faultyFile struct {
	tempFile
	phase  string
	cancel context.CancelFunc
}

func (f faultyFile) Chmod(m os.FileMode) error {
	if f.phase == "chmod" {
		return injected
	}
	return f.tempFile.Chmod(m)
}
func (f faultyFile) Write(p []byte) (int, error) {
	if f.phase == "write" {
		_, _ = f.tempFile.Write(p[:1])
		return 1, injected
	}
	if f.phase == "short" {
		return 0, nil
	}
	return f.tempFile.Write(p)
}
func (f faultyFile) Sync() error {
	if f.phase == "sync" {
		return injected
	}
	return f.tempFile.Sync()
}
func (f faultyFile) Close() error {
	err := f.tempFile.Close()
	if f.phase == "close" {
		return errors.Join(err, injected)
	}
	if f.phase == "cancel-close" {
		f.cancel()
	}
	return err
}

func writeText(ctx context.Context, path, value string) error {
	return Write(ctx, path, 0600, -1, func(w io.Writer) error { _, err := io.WriteString(w, value); return err })
}

func TestWriteFailuresPreserveDestinationAndCleanTemp(t *testing.T) {
	for _, phase := range []string{"create", "chmod", "write", "short", "sync", "close", "replace", "cancel-close", "encode", "oversized", "cleanup"} {
		t.Run(phase, func(t *testing.T) {
			dir := t.TempDir()
			dst := filepath.Join(dir, "state.json")
			old := `{"value":"old"}`
			if err := os.WriteFile(dst, []byte(old), 0600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			ops := diskOperations()
			create := ops.create
			ops.create = func(dir string) (tempFile, error) {
				if phase == "create" {
					return nil, injected
				}
				f, err := create(dir)
				if err != nil {
					return nil, err
				}
				return faultyFile{f, phase, cancel}, nil
			}
			if phase == "replace" {
				ops.replace = func(context.Context, string, string) error { return injected }
			}
			if phase == "cleanup" {
				ops.remove = func(path string) error { _ = os.Remove(path); return injected }
			}
			limit := int64(-1)
			if phase == "oversized" {
				limit = 1
			}
			err := write(ctx, dst, 0600, limit, func(w io.Writer) error {
				if phase == "encode" || phase == "cleanup" {
					return injected
				}
				_, err := io.WriteString(w, `{"value":"new"}`)
				return err
			}, ops)
			if err == nil {
				t.Fatal("expected failure")
			}
			raw, readErr := os.ReadFile(dst)
			if readErr != nil || string(raw) != old {
				t.Fatalf("old destination lost: %q %v", raw, readErr)
			}
			entries, _ := os.ReadDir(dir)
			if len(entries) != 1 {
				t.Fatalf("temp leaked: %v", entries)
			}
			if phase == "cancel-close" && !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
		})
	}
}

func TestJSONBoundsAndPaths(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	dst := filepath.Join(dir, "value.json")
	for _, tc := range []struct {
		raw   string
		limit int64
		want  error
	}{{`{"ok":true}`, 11, nil}, {`{"ok":true}`, 10, ErrTooLarge}, {`{`, 11, ErrInvalidJSON}, {`{} {}`, 20, ErrInvalidJSON}, {``, 20, ErrInvalidJSON}} {
		if err := os.WriteFile(dst, []byte(tc.raw), 0600); err != nil {
			t.Fatal(err)
		}
		var out map[string]any
		if err := ReadJSON(ctx, dst, tc.limit, &out); !errors.Is(err, tc.want) {
			t.Fatalf("%q: %v, want %v", tc.raw, err, tc.want)
		}
	}
	for _, path := range []string{dir, filepath.Join(dst, "child"), dir + string(os.PathSeparator) + ".." + string(os.PathSeparator) + "escape"} {
		if err := writeText(ctx, path, "bad"); err == nil {
			t.Fatalf("unsafe path accepted: %s", path)
		}
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if err := writeText(canceled, filepath.Join(dir, "new", "state"), "bad"); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "new")); !os.IsNotExist(err) {
		t.Fatal("canceled operation created directories")
	}
	var out any
	if err := ReadJSON(canceled, dst, 100, &out); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestReplaceMissingSourceAndDifferentDirectoryPreservesOld(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	dst := filepath.Join(dir, "state")
	src := filepath.Join(t.TempDir(), "source")
	if err := writeText(ctx, dst, "old"); err != nil {
		t.Fatal(err)
	}
	for _, missing := range []bool{true, false} {
		if !missing {
			if err := os.WriteFile(src, []byte("new"), 0600); err != nil {
				t.Fatal(err)
			}
		}
		if err := Replace(ctx, src, dst); err == nil {
			t.Fatal("expected rejection")
		}
		raw, _ := os.ReadFile(dst)
		if string(raw) != "old" {
			t.Fatal("destination changed")
		}
	}
}

func TestSymlinkAndParentRejection(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	real := filepath.Join(dir, "real")
	link := filepath.Join(dir, "link")
	if err := writeText(ctx, real, `{}`); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, link); err != nil {
		if runtime.GOOS == "windows" {
			t.Skip("symlink privilege unavailable")
		}
		t.Fatal(err)
	}
	var out any
	if err := ReadJSON(ctx, link, 100, &out); !errors.Is(err, ErrUnsafePath) {
		t.Fatal(err)
	}
	if err := writeText(ctx, link, "bad"); !errors.Is(err, ErrUnsafePath) {
		t.Fatal(err)
	}
	parentLink := filepath.Join(dir, "parent-link")
	target := t.TempDir()
	if err := os.Symlink(target, parentLink); err != nil {
		t.Fatal(err)
	}
	if err := writeText(ctx, filepath.Join(parentLink, "nested", "state"), "bad"); !errors.Is(err, ErrUnsafePath) {
		t.Fatal(err)
	}
	if entries, _ := os.ReadDir(target); len(entries) != 0 {
		t.Fatal("created data through symlink")
	}
}

func TestConcurrentReadersSeeCompleteReplacements(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "state")
	a, b := strings.Repeat("a", 8192), strings.Repeat("b", 8192)
	if err := writeText(ctx, path, a); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-done:
				return
			default:
			}
			raw, err := os.ReadFile(path)
			if err != nil {
				if runtime.GOOS == "windows" && (os.IsPermission(err) || errors.Is(err, syscall.Errno(32))) {
					continue
				}
				t.Errorf("reader error: %v", err)
				return
			}
			if string(raw) != a && string(raw) != b {
				t.Errorf("partial/missing value: %d", len(raw))
				return
			}
		}
	}()
	success := 0
	for i := 0; i < 30; i++ {
		value := a
		if i%2 == 0 {
			value = b
		}
		err := writeText(ctx, path, value)
		if err == nil {
			success++
		} else if runtime.GOOS != "windows" || !(os.IsPermission(err) || errors.Is(err, syscall.Errno(32))) {
			t.Error(err)
		}
	}
	close(done)
	wg.Wait()
	if success == 0 {
		t.Fatal("no successful overwrite")
	}
	if runtime.GOOS != "windows" {
		info, _ := os.Stat(path)
		if info.Mode().Perm() != 0600 {
			t.Fatalf("permissions: %v", info.Mode())
		}
	}
}
