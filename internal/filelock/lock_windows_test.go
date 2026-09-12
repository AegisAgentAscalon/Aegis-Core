package filelock

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestWindowsSharingFailureDoesNotReplaceSentinel(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".state.lock")
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	before, _ := os.Stat(path)
	name, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := syscall.CreateFile(name, syscall.GENERIC_READ, syscall.FILE_SHARE_READ, nil, syscall.OPEN_EXISTING, syscall.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		t.Fatal(err)
	}
	lock, lockErr := TryAcquire(nil, path)
	closeErr := syscall.CloseHandle(handle)
	if lock != nil || !errors.Is(lockErr, syscall.Errno(32)) || closeErr != nil {
		t.Fatalf("sharing violation: %v, %v; close=%v", lock, lockErr, closeErr)
	}
	lock, err = Acquire(nil, path)
	if err != nil {
		t.Fatal(err)
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(path)
	if err != nil || !os.SameFile(before, after) || after.Size() != 0 {
		t.Fatalf("sharing recovery changed sentinel: %v, %v", after, err)
	}
}
