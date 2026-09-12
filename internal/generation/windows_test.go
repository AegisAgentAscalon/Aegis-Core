//go:build windows

package generation

import (
	"path/filepath"
	"syscall"
	"testing"
)

func TestWindowsPointerSharingFailurePreservesAuthority(t *testing.T) {
	s, token := prepareBoundaryCase(t, true)
	path, err := syscall.UTF16PtrFromString(filepath.Join(s.livePath(), "current.json"))
	if err != nil {
		t.Fatal(err)
	}
	h, err := syscall.CreateFile(path, syscall.GENERIC_READ, syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE, nil, syscall.OPEN_EXISTING, syscall.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		t.Fatal(err)
	}
	g := testGuard(t, s)
	_, commitErr := g.Commit(token, []byte(`{"value":"new"}`), nil)
	g.Close()
	if err := syscall.CloseHandle(h); err != nil {
		t.Fatal(err)
	}
	if commitErr == nil {
		t.Fatal("pointer replacement ignored sharing violation")
	}
	assertBoundaryAuthority(t, s, token, false)
}
