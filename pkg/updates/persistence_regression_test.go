package updates

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

type failedReader struct{}

func (failedReader) Read([]byte) (int, error) { return 0, errors.New("source failed") }

func TestPersistenceEncodingReopenAndCancellation(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "state.json")
	original := selectedUpdate{SchemaVersion: schemaVersion, SourceKey: "source", PolicyKey: "policy"}
	if err := writeJSON(ctx, path, original); err != nil {
		t.Fatal(err)
	}
	expected, _ := json.MarshalIndent(original, "", "  ")
	raw, _ := os.ReadFile(path)
	if !bytes.Equal(raw, expected) {
		t.Fatal("persisted JSON encoding changed")
	}
	var reopened selectedUpdate
	if err := readJSON(ctx, path, &reopened); err != nil || reopened.SourceKey != "source" {
		t.Fatalf("reopen: %+v %v", reopened, err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if err := writeJSON(canceled, path, selectedUpdate{}); !errors.Is(err, ErrContextCanceled) {
		t.Fatal(err)
	}
	if err := readJSON(canceled, path, &reopened); !errors.Is(err, ErrContextCanceled) {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(after, raw) {
		t.Fatal("canceled write changed bytes")
	}
}

func TestArtifactStreamFailuresKeepDestination(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	path := filepath.Join(dir, "artifact")
	if err := os.WriteFile(path, []byte("old"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		reader io.Reader
		limit  int64
	}{{failedReader{}, 0}, {bytes.NewBufferString("oversized"), 1}} {
		if _, err := writeStreamToFile(ctx, tc.reader, path, tc.limit); !errors.Is(err, ErrDownloadFailed) {
			t.Fatal(err)
		}
		raw, _ := os.ReadFile(path)
		if string(raw) != "old" {
			t.Fatal("failed stream changed destination")
		}
		if entries, _ := os.ReadDir(dir); len(entries) != 1 {
			t.Fatal("stream temp leaked")
		}
	}
}

func TestMetadataReadBoundAndUnsafeDestination(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "state")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.Truncate(maxMetadataBytes + 1); err != nil {
		t.Fatal(err)
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
	var out any
	if err := readJSON(ctx, path, &out); !errors.Is(err, ErrStorageUnavailable) {
		t.Fatal(err)
	}
	if err := writeJSON(ctx, filepath.Dir(path), map[string]int{"v": 1}); !errors.Is(err, ErrStorageUnavailable) {
		t.Fatal(err)
	}
}
