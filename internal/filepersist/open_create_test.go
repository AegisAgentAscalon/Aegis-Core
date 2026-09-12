package filepersist

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestOpenOrCreateRegularPreservesExistingIdentityAndBytes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sentinel")
	first, err := OpenOrCreateRegular(nil, path)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	before, err := first.Stat()
	if err != nil || before.Size() != 0 || !before.Mode().IsRegular() {
		t.Fatalf("new sentinel: %v, %v", before, err)
	}
	if runtime.GOOS != "windows" && before.Mode().Perm() != 0600 {
		t.Fatalf("creation permissions: %v", before.Mode())
	}
	const content = "existing sentinel bytes"
	if _, err := first.WriteString(content); err != nil {
		t.Fatal(err)
	}
	second, err := OpenOrCreateRegular(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	after, err := second.Stat()
	if err != nil || !os.SameFile(before, after) || after.Size() != int64(len(content)) || first.Fd() == second.Fd() {
		t.Fatalf("reopen changed identity, size or handle: %v, %v", after, err)
	}
	raw, err := os.ReadFile(path)
	if err != nil || string(raw) != content {
		t.Fatalf("reopen changed bytes: %q, %v", raw, err)
	}
}

func TestOpenOrCreateRegularRejectsCanceledAndUnsafePaths(t *testing.T) {
	dir := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	path := filepath.Join(dir, "canceled")
	if f, err := OpenOrCreateRegular(ctx, path); f != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled open: %v, %v", f, err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("canceled operation created sentinel: %v", err)
	}
	for _, path := range []string{"", dir, dir + string(filepath.Separator) + ".." + string(filepath.Separator) + "escape"} {
		if f, err := OpenOrCreateRegular(nil, path); f != nil || !errors.Is(err, ErrUnsafePath) {
			t.Fatalf("accepted unsafe path %q: %v, %v", path, f, err)
		}
	}
	if f, err := OpenOrCreateRegular(nil, filepath.Join(dir, "missing", "sentinel")); f != nil || !os.IsNotExist(err) {
		t.Fatalf("created an unrequested parent: %v, %v", f, err)
	}
}

func TestOpenOrCreateRegularRejectsSymlinkIdentity(t *testing.T) {
	dir := t.TempDir()
	for _, directory := range []bool{false, true} {
		name := "file"
		if directory {
			name = "directory"
		}
		t.Run(name, func(t *testing.T) {
			target, link := filepath.Join(dir, name), filepath.Join(dir, name+"-link")
			if directory {
				if err := os.Mkdir(target, 0700); err != nil {
					t.Fatal(err)
				}
			} else if err := os.WriteFile(target, []byte("untouched"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, link); err != nil {
				t.Skipf("symlink creation unavailable: %v", err)
			}
			if directory {
				link = filepath.Join(link, "sentinel")
			}
			if f, err := OpenOrCreateRegular(nil, link); f != nil || !errors.Is(err, ErrUnsafePath) {
				t.Fatalf("accepted symlink path: %v, %v", f, err)
			}
		})
	}
}
