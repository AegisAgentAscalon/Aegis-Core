//go:build windows

package filepersist

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestWindowsSharingFailurePreservesDestination(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	dst := filepath.Join(dir, "state")
	if err := writeText(ctx, dst, "old"); err != nil {
		t.Fatal(err)
	}
	name, err := syscall.UTF16PtrFromString(dst)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := syscall.CreateFile(name, syscall.GENERIC_READ, syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE, nil, syscall.OPEN_EXISTING, syscall.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		t.Fatal(err)
	}
	err = writeText(ctx, dst, "new")
	closeErr := syscall.CloseHandle(handle)
	if err == nil || closeErr != nil {
		t.Fatalf("expected sharing failure: %v, close: %v", err, closeErr)
	}
	raw, readErr := os.ReadFile(dst)
	if readErr != nil || string(raw) != "old" {
		t.Fatalf("old bytes lost: %q %v", raw, readErr)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Fatal("temporary file leaked")
	}
	if err := writeText(ctx, dst, "new"); err != nil {
		t.Fatal(err)
	}
}

func TestWindowsReservedAndADSPathsRejected(t *testing.T) {
	for _, name := range []string{"NUL", "con.json", "state:stream", "state.", "state "} {
		if err := writeText(context.Background(), filepath.Join(t.TempDir(), name), "bad"); err == nil {
			t.Fatalf("accepted %q", name)
		}
	}
}
