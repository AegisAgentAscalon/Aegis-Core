package profilesync

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCloudStorageIdentitiesRemainIndependent(t *testing.T) {
	root := t.TempDir()
	ctx := context.Background()
	for _, namespace := range []string{"Profile", "profile"} {
		p, err := NewFileObjectProvider(FileObjectProviderConfig{RootDir: root, ProfileNamespace: namespace})
		if err != nil {
			t.Fatal(err)
		}
		var refs []CloudObjectRef
		paths := map[string]bool{}
		for _, id := range []string{"a:b", "a_b", "Case", "case"} {
			ref, err := p.PutObject(ctx, CloudSyncObject{ProfileNamespace: namespace, ObjectID: id, Kind: CloudObjectSnapshotMetadata, Body: []byte("same bytes"), CreatedAt: time.Now().UTC()})
			if err != nil {
				t.Fatal(err)
			}
			path, _ := p.objectPath(ref)
			folded := strings.ToLower(path)
			if paths[folded] {
				t.Fatal("case-insensitive storage collision")
			}
			paths[folded] = true
			refs = append(refs, ref)
		}
		for _, ref := range refs {
			body, err := p.GetObject(ctx, ref)
			if err != nil || string(body) != "same bytes" {
				t.Fatalf("identity %s: %q %v", ref.ObjectID, body, err)
			}
		}
		manifest := CloudProfileManifest{SchemaVersion: 1, ProfileNamespace: namespace, ManifestID: "manifest", Generation: 1, CreatedAt: time.Now().UTC(), LatestSnapshotRef: &refs[0]}
		if err := p.PutManifest(ctx, manifest); err != nil {
			t.Fatal(err)
		}
	}
	for _, namespace := range []string{"Profile", "profile"} {
		p, err := NewFileObjectProvider(FileObjectProviderConfig{RootDir: root, ProfileNamespace: namespace})
		if err != nil {
			t.Fatal(err)
		}
		refs, err := p.ListObjects(ctx, CloudObjectQuery{ProfileNamespace: namespace})
		if err != nil || len(refs) != 4 {
			t.Fatalf("SD-01: namespace %s: %d refs, %v", namespace, len(refs), err)
		}
		manifest, err := p.GetManifest(ctx, namespace)
		if err != nil || manifest.ProfileNamespace != namespace {
			t.Fatalf("namespace manifest: %+v %v", manifest, err)
		}
	}
}

func TestCloudLegacyReadThroughPreservesOriginals(t *testing.T) {
	ctx := context.Background()
	p, err := NewFileObjectProvider(FileObjectProviderConfig{RootDir: t.TempDir(), ProfileNamespace: "profile"})
	if err != nil {
		t.Fatal(err)
	}
	object := CloudSyncObject{ProfileNamespace: "profile", ObjectID: "a:b", Kind: CloudObjectSnapshotMetadata, Body: []byte("legacy"), CreatedAt: time.Now().UTC()}
	ref, err := ValidateCloudObject(object, 0)
	if err != nil {
		t.Fatal(err)
	}
	legacyPath := p.legacyObjectPath(ref)
	if err := os.MkdirAll(filepath.Dir(legacyPath), 0700); err != nil {
		t.Fatal(err)
	}
	original, _ := json.Marshal(objectFile{Ref: ref, Body: object.Body})
	if err := os.WriteFile(legacyPath, original, 0600); err != nil {
		t.Fatal(err)
	}
	manifest, err := NormalizeCloudManifest(CloudProfileManifest{SchemaVersion: 1, ProfileNamespace: "profile", ManifestID: "legacy", CreatedAt: object.CreatedAt, LatestSnapshotRef: &ref})
	if err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(p.legacyRoot(), "manifest.json")
	manifestBytes, _ := json.Marshal(manifestFile{Manifest: manifest})
	if err := os.WriteFile(manifestPath, manifestBytes, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := p.GetObject(ctx, ref); err != nil {
		t.Fatal(err)
	}
	if _, err := p.GetManifest(ctx, "profile"); err != nil {
		t.Fatal(err)
	}
	if got, err := p.PutObject(ctx, object); err != nil || !sameCloudObjectRef(got, ref) {
		t.Fatalf("legacy retry: %+v %v", got, err)
	}
	object.ObjectID = "a_b"
	if _, err := p.PutObject(ctx, object); err != nil {
		t.Fatal(err)
	}
	object.ObjectID = "A:B"
	if _, err := p.PutObject(ctx, object); err != nil {
		t.Fatal(err)
	}
	refs, err := p.ListObjects(ctx, CloudObjectQuery{ProfileNamespace: "profile"})
	if err != nil || len(refs) != 3 {
		t.Fatalf("mixed list: %+v %v", refs, err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := p.PutObject(canceled, object); err == nil {
		t.Fatal("canceled write succeeded")
	}
	if err := p.PutManifest(canceled, manifest); err == nil {
		t.Fatal("canceled manifest succeeded")
	}
	// An interrupted publication cannot destroy the original legacy manifest.
	blocked := filepath.Join(p.namespaceRoot(), "manifest.json")
	if err := os.Mkdir(blocked, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(blocked, "keep"), []byte("blocked"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := p.PutManifest(ctx, manifest); err == nil {
		t.Fatal("blocked publication succeeded")
	}
	if err := os.Remove(filepath.Join(blocked, "keep")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(blocked); err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string][]byte{legacyPath: original, manifestPath: manifestBytes} {
		got, err := os.ReadFile(path)
		if err != nil || string(got) != string(want) {
			t.Fatalf("legacy bytes changed: %s %v", path, err)
		}
	}
	if _, err := p.GetObject(ctx, ref); err != nil {
		t.Fatal(err)
	}
	if _, err := p.GetManifest(ctx, "profile"); err != nil {
		t.Fatal(err)
	}
}

func TestCloudLegacyCollisionDoesNotInventLostObject(t *testing.T) {
	ctx := context.Background()
	p, err := NewFileObjectProvider(FileObjectProviderConfig{RootDir: t.TempDir(), ProfileNamespace: "profile"})
	if err != nil {
		t.Fatal(err)
	}
	obj := CloudSyncObject{ProfileNamespace: "profile", ObjectID: "a:b", Kind: CloudObjectSnapshotMetadata, Body: []byte("same"), CreatedAt: time.Now().UTC()}
	lost, _ := ValidateCloudObject(obj, 0)
	obj.ObjectID = "a_b"
	survivor, _ := ValidateCloudObject(obj, 0)
	path := p.legacyObjectPath(survivor)
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(objectFile{Ref: survivor, Body: obj.Body})
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := p.GetObject(ctx, lost); !errors.Is(err, ErrCloudHashMismatch) {
		t.Fatalf("lost identity must fail: %v", err)
	}
	if _, err := p.GetObject(ctx, survivor); err != nil {
		t.Fatal(err)
	}
	refs, err := p.ListObjects(ctx, CloudObjectQuery{ProfileNamespace: "profile"})
	if err != nil || len(refs) != 1 || refs[0].ObjectID != "a_b" {
		t.Fatalf("invented legacy record: %+v %v", refs, err)
	}
}

func TestCloudComparisonRejectsDifferentNamespaces(t *testing.T) {
	now := time.Now().UTC()
	local := CloudProfileManifest{SchemaVersion: 1, ProfileNamespace: "Profile", ManifestID: "local", Generation: 1, CreatedAt: now}
	for _, generation := range []int64{0, 1, 2} {
		remote := CloudProfileManifest{SchemaVersion: 1, ProfileNamespace: "profile", ManifestID: "remote", Generation: generation, CreatedAt: now}
		got := CompareCloudManifests(&local, remote, now)
		if got.Relation != CloudManifestInvalid || !got.ReviewRequired {
			t.Fatalf("SD-07: cross-namespace comparison: %+v", got)
		}
	}
}

func TestCloudLegacyNamespaceOwnershipAndDuplicateConflict(t *testing.T) {
	ctx := context.Background()
	p, err := NewFileObjectProvider(FileObjectProviderConfig{RootDir: t.TempDir(), ProfileNamespace: "profile"})
	if err != nil {
		t.Fatal(err)
	}
	obj := CloudSyncObject{ProfileNamespace: "Profile", ObjectID: "old", Kind: CloudObjectSnapshotMetadata, Body: []byte("old"), CreatedAt: time.Now().UTC()}
	foreign, _ := ValidateCloudObject(obj, 0)
	// Simulate the shared legacy namespace directory on a case-insensitive filesystem.
	oldPath := p.legacyObjectPath(foreign)
	if err := os.MkdirAll(filepath.Dir(oldPath), 0700); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(objectFile{Ref: foreign, Body: obj.Body})
	if err := os.WriteFile(oldPath, raw, 0600); err != nil {
		t.Fatal(err)
	}
	manifest, _ := NormalizeCloudManifest(CloudProfileManifest{SchemaVersion: 1, ProfileNamespace: "Profile", ManifestID: "old", CreatedAt: obj.CreatedAt})
	if err := writeJSONAtomic(context.Background(), filepath.Join(p.legacyRoot(), "manifest.json"), manifestFile{Manifest: manifest}); err != nil {
		t.Fatal(err)
	}
	if _, err := p.GetManifest(ctx, "profile"); !errors.Is(err, ErrCloudStoreCorrupt) {
		t.Fatalf("foreign manifest accepted: %v", err)
	}
	refs, err := p.ListObjects(ctx, CloudObjectQuery{ProfileNamespace: "profile"})
	if err != nil || len(refs) != 0 {
		t.Fatalf("foreign objects exposed: %+v %v", refs, err)
	}
	obj.ProfileNamespace = "profile"
	current, err := p.PutObject(ctx, obj)
	if err != nil {
		t.Fatal(err)
	}
	// Simulate a surviving conflicting legacy record: never pick a winner silently.
	obj.Body = []byte("different")
	conflict, _ := ValidateCloudObject(obj, 0)
	raw, _ = json.Marshal(objectFile{Ref: conflict, Body: obj.Body})
	if err := os.WriteFile(p.legacyObjectPath(conflict), raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := p.ListObjects(ctx, CloudObjectQuery{ProfileNamespace: "profile"}); !errors.Is(err, ErrCloudObjectConflict) {
		t.Fatalf("conflict hidden: %v", err)
	}
	if _, err := p.PutObject(ctx, obj); !errors.Is(err, ErrCloudObjectConflict) {
		t.Fatalf("conflict overwritten: %v", err)
	}
	if _, err := p.GetObject(ctx, current); err != nil {
		t.Fatal(err)
	}
}
