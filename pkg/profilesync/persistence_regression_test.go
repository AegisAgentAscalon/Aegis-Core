package profilesync

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPersistenceBytesAndFailedOverwrite(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	original := map[string]string{"value": "original"}
	if err := writeJSONAtomic(ctx, path, original); err != nil {
		t.Fatal(err)
	}
	want, _ := json.MarshalIndent(original, "", "  ")
	want = append(want, '\n')
	raw, _ := os.ReadFile(path)
	if !bytes.Equal(raw, want) {
		t.Fatal("Profile Sync encoding changed")
	}
	for _, bad := range []any{make(chan int), map[string]string{"value": strings.Repeat("x", maxLocalJSONFileBytes)}} {
		if err := writeJSONAtomic(ctx, path, bad); !errors.Is(err, ErrStoreUnavailable) {
			t.Fatal(err)
		}
		raw, _ = os.ReadFile(path)
		if !bytes.Equal(raw, want) {
			t.Fatal("failed write changed old bytes")
		}
		if entries, _ := os.ReadDir(dir); len(entries) != 1 {
			t.Fatal("temporary file leaked")
		}
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if err := writeJSONAtomic(canceled, path, map[string]string{}); !errors.Is(err, ErrStoreUnavailable) {
		t.Fatal(err)
	}
	var loaded map[string]string
	if err := readJSONFile(ctx, path, &loaded); err != nil || loaded["value"] != "original" {
		t.Fatalf("reopen: %v %v", loaded, err)
	}
}

func TestLocalStoreRejectsSymlinkedRoot(t *testing.T) {
	target := t.TempDir()
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(target, link); err != nil {
		t.Skip("symlink creation unavailable")
	}
	if _, err := NewLocalMetadataStore(LocalMetadataStoreConfig{RootDir: link, ProfileNamespace: "profile"}); !errors.Is(err, ErrStoreUnavailable) {
		t.Fatal(err)
	}
	if entries, _ := os.ReadDir(target); len(entries) != 0 {
		t.Fatal("unsafe parent modified")
	}
}
