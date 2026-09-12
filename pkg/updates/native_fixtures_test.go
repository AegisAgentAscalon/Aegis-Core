package updates

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/AegisAgentAscalon/aegis-core/internal/filepersist"
	"github.com/AegisAgentAscalon/aegis-core/internal/generation"
)

// W13 encoding/IO adapters are fixture-only after the production migration.
func readJSON(ctx context.Context, path string, out any) error {
	err := filepersist.ReadJSON(ctx, path, maxMetadataBytes, out)
	if errors.Is(err, os.ErrNotExist) {
		return err
	}
	return persistenceError(err)
}
func writeJSON(ctx context.Context, path string, value any) error {
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return ErrStorageUnavailable
	}
	return persistenceError(filepersist.Write(ctx, path, 0600, maxMetadataBytes, func(w io.Writer) error { _, err := w.Write(raw); return err }))
}
func secureMkdirAll(dir string) error {
	return persistenceError(filepersist.EnsureDir(context.Background(), dir))
}
func replaceFile(ctx context.Context, src, dst string) error {
	return persistenceError(filepersist.Replace(ctx, src, dst))
}

func readTestView(st *store) (*stateView, error) {
	guard, err := st.generations.Lock(context.Background())
	if err != nil {
		return nil, err
	}
	defer guard.Close()
	return st.load(context.Background(), guard)
}
func readTestSelected(t *testing.T, st *store) (selectedUpdate, error) {
	t.Helper()
	view, err := readTestView(st)
	if err != nil {
		return selectedUpdate{}, err
	}
	return view.selected.read()
}
func readTestDownloaded(t *testing.T, st *store) (downloadedUpdate, error) {
	t.Helper()
	view, err := readTestView(st)
	if err != nil {
		return downloadedUpdate{}, err
	}
	return view.downloaded.read()
}
func readTestVerified(t *testing.T, st *store) (verifiedUpdate, error) {
	t.Helper()
	view, err := readTestView(st)
	if err != nil {
		return verifiedUpdate{}, err
	}
	return view.verified.read()
}
func readTestStaged(t *testing.T, st *store) (stagedUpdateRecord, error) {
	t.Helper()
	view, err := readTestView(st)
	if err != nil {
		return stagedUpdateRecord{}, err
	}
	return view.staged.read()
}

func testCurrentPath(st *store) string { return filepath.Join(st.dir, "state-v2", "current.json") }
func testNativeSnapshot(t *testing.T, st *store) generation.Snapshot {
	t.Helper()
	guard, err := st.generations.Lock(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer guard.Close()
	snapshot, err := guard.Read()
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Token == "" {
		t.Fatal("native fixture has no committed authority")
	}
	return snapshot
}

// These fixtures intentionally bypass the Updates codec while retaining valid
// shared envelopes. Tests can distinguish graph/signature checks from file hashes.
func mutateTestGraph(t *testing.T, st *store, mutate func(*stateRecord)) {
	t.Helper()
	guard, err := st.generations.Lock(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer guard.Close()
	snapshot, err := guard.Read()
	if err != nil {
		t.Fatal(err)
	}
	var record stateRecord
	if err := json.Unmarshal(snapshot.Data, &record); err != nil {
		t.Fatal(err)
	}
	mutate(&record)
	data, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := guard.Commit(snapshot.Token, data, nil); err != nil {
		t.Fatal(err)
	}
}

func rekeyTestTransfers(t *testing.T, r *stateRecord) {
	t.Helper()
	next := make(map[string]transferRef)
	for id, item := range r.Transfers {
		key, err := recordDigest(item)
		if err != nil {
			t.Fatal(err)
		}
		next[key] = item
		if r.Downloaded == id {
			r.Downloaded = key
		}
		if r.Verified != nil && r.Verified.Transfer == id {
			r.Verified.Transfer = key
		}
	}
	r.Transfers = next
}

func replaceTestManifest(t *testing.T, r *stateRecord, old string, manifest Manifest) {
	t.Helper()
	id, err := recordDigest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	delete(r.Manifests, old)
	r.Manifests[id] = manifest
	if r.Selected != nil && r.Selected.Manifest == old {
		r.Selected.Manifest = id
	}
	if r.Staged != nil && r.Staged.Manifest == old {
		r.Staged.Manifest = id
	}
	for key, item := range r.Transfers {
		if item.Manifest == old {
			item.Manifest = id
			r.Transfers[key] = item
		}
	}
	rekeyTestTransfers(t, r)
}

func testComponentBytes(t *testing.T, st *store, key string) []byte {
	t.Helper()
	snapshot := testNativeSnapshot(t, st)
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(snapshot.Data, &fields); err != nil {
		t.Fatal(err)
	}
	return fields[key]
}

// Seed a separate genuinely legacy root; never turn a migrated root back into
// legacy or teach production code to consult old paths after activation.
func legacyTestService(t *testing.T, source *Service) *Service {
	t.Helper()
	view, err := readTestView(source.store)
	if err != nil {
		t.Fatal(err)
	}
	cfg := cloneConfig(source.cfg)
	cfg.StagingDir = t.TempDir()
	svc, err := NewService(cfg, source.apply)
	if err != nil {
		t.Fatal(err)
	}
	if err := secureMkdirAll(svc.store.downloadsDir()); err != nil {
		t.Fatal(err)
	}
	if err := secureMkdirAll(svc.store.stagedDir()); err != nil {
		t.Fatal(err)
	}
	copyDownload := func(d downloadedUpdate) downloadedUpdate {
		dst := filepath.Join(svc.store.downloadsDir(), d.Artifact.Filename)
		if err := copyFileAtomic(context.Background(), d.ArtifactPath, dst); err != nil {
			t.Fatal(err)
		}
		d.blobID, d.ArtifactPath = "", dst
		return d
	}
	write := func(path string, value any) {
		if err := writeJSON(context.Background(), path, value); err != nil {
			t.Fatal(err)
		}
	}
	if view.selected.value != nil {
		write(svc.store.selectedPath(), *view.selected.value)
	}
	if view.downloaded.value != nil {
		write(svc.store.downloadedPath(), copyDownload(*view.downloaded.value))
	}
	if view.verified.value != nil {
		item := *view.verified.value
		item.Downloaded = copyDownload(item.Downloaded)
		write(svc.store.verifiedPath(), item)
	}
	if view.staged.value != nil {
		item := *view.staged.value
		dst := filepath.Join(svc.store.stagedDir(), item.ArtifactName)
		if err := copyFileAtomic(context.Background(), item.ArtifactPath, dst); err != nil {
			t.Fatal(err)
		}
		item.blobID, item.ArtifactPath = "", dst
		write(svc.store.stagedMetaPath(), item)
	}
	if view.lifecycle.value != nil {
		write(svc.store.lifecyclePath(), *view.lifecycle.value)
	}
	return svc
}

func testBlobInventory(t *testing.T, st *store) map[string]int64 {
	t.Helper()
	out := map[string]int64{}
	err := filepath.WalkDir(st.blobDir(), func(path string, entry os.DirEntry, err error) error {
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return err
		}
		if !entry.IsDir() {
			info, err := entry.Info()
			if err != nil {
				return err
			}
			out[path] = info.Size()
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}
