package profilesync

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestCloudScanFindFinishesIntegrityAndConflictChecks(t *testing.T) {
	for _, scenario := range []string{"exact-duplicate", "different-time", "foreign-malformed", "foreign-bad-body", "corruption-first", "conflict-first"} {
		t.Run(scenario, func(t *testing.T) {
			p, object, _ := cloudScanFixture(t, 1, 256, false)
			ctx := context.Background()
			ref, _ := ValidateCloudObject(object, 0)
			legacy := filepath.Join(p.legacyRoot(), "objects")
			if err := os.MkdirAll(legacy, 0700); err != nil {
				t.Fatal(err)
			}
			write := func(name string, raw []byte) {
				t.Helper()
				if err := os.WriteFile(filepath.Join(legacy, name), raw, 0600); err != nil {
					t.Fatal(err)
				}
			}
			foreign := ref
			foreign.ProfileNamespace = "Profile"
			badBody, _ := json.Marshal(objectFile{Ref: foreign, Body: []byte("invalid body")})
			changed := ref
			changed.CreatedAt = changed.CreatedAt.Add(time.Second)
			conflict, _ := json.Marshal(objectFile{Ref: changed, Body: object.Body})
			var want error
			switch scenario {
			case "exact-duplicate":
				raw, _ := json.Marshal(objectFile{Ref: ref, Body: object.Body})
				write("duplicate.json", raw)
			case "different-time":
				write("conflict.json", conflict)
				want = ErrCloudObjectConflict
			case "foreign-malformed":
				write("foreign.json", []byte(`{"ref":{"profile_namespace":"Profile"},"body":`))
				want = ErrCloudStoreCorrupt
			case "foreign-bad-body":
				write("foreign.json", badBody)
				want = ErrCloudStoreCorrupt
			case "corruption-first":
				write("000-bad.json", badBody)
				write("999-conflict.json", conflict)
				want = ErrCloudStoreCorrupt
			case "conflict-first":
				write("000-conflict.json", conflict)
				write("999-bad.json", badBody)
				want = ErrCloudObjectConflict
			}
			got, err := p.PutObject(ctx, object)
			if !errors.Is(err, want) || want == nil && !sameCloudObjectRef(got, ref) {
				t.Fatal("lookup hid a later record or changed error order", got, err)
			}
			refs, err := p.ListObjects(ctx, CloudObjectQuery{ProfileNamespace: p.namespace})
			if !errors.Is(err, want) || want == nil && len(refs) != 1 {
				t.Fatal("list scan differs", refs, err)
			}
			status := p.GetStatus(ctx)
			if status.Available != (want == nil) || want == nil && status.ObjectCount != 1 || want != nil && status.ObjectCount != 0 {
				t.Fatal("status scan differs", status)
			}
		})
	}
}

func TestCloudScanObservesExternalChangesAndSameSizeTampering(t *testing.T) {
	p, object, _ := cloudScanFixture(t, 4, 256, true)
	ctx := context.Background()
	other, err := NewFileObjectProvider(FileObjectProviderConfig{RootDir: p.root, ProfileNamespace: p.namespace})
	if err != nil {
		t.Fatal(err)
	}
	added := object
	added.ObjectID = "another:object"
	if _, err := other.PutObject(ctx, added); err != nil {
		t.Fatal(err)
	}
	all, err := p.ListObjects(ctx, CloudObjectQuery{ProfileNamespace: p.namespace})
	if err != nil || len(all) != 5 || p.GetStatus(ctx).ObjectCount != 5 {
		t.Fatal("provider retained an old inventory", all, err)
	}
	var want []CloudObjectRef
	for _, ref := range all {
		if ref.Kind == CloudObjectProposalMetadata {
			want = append(want, ref)
		}
	}
	filtered, err := p.ListObjects(ctx, CloudObjectQuery{ProfileNamespace: p.namespace, Kind: CloudObjectProposalMetadata})
	if err != nil || !reflect.DeepEqual(filtered, want) {
		t.Fatal("filtered list changed order or values", filtered, want, err)
	}
	ref, _ := ValidateCloudObject(object, 0)
	path, _ := p.objectPath(ref)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(path)
	var stored objectFile
	if err := json.Unmarshal(raw, &stored); err != nil {
		t.Fatal(err)
	}
	stored.Body[0] ^= 1
	tampered, _ := json.Marshal(stored)
	if len(tampered) != len(raw) {
		t.Fatal("fixture changed length")
	}
	if err := os.WriteFile(path, tampered, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, info.ModTime(), info.ModTime()); err != nil {
		t.Fatal(err)
	}
	if _, err := p.PutObject(ctx, added); !errors.Is(err, ErrCloudStoreCorrupt) {
		t.Fatal("unrelated tampering hidden by lookup", err)
	}
	if p.GetStatus(ctx).Available {
		t.Fatal("status trusted same-size/mtime bytes")
	}
}

type cloudScanCancelContext struct {
	context.Context
	checks int
	cancel context.CancelFunc
}

func (ctx *cloudScanCancelContext) Err() error {
	ctx.checks++
	if ctx.checks > 8 {
		ctx.cancel()
	}
	return ctx.Context.Err()
}

func TestCloudScanCancellationIncludesIgnoredEntries(t *testing.T) {
	p, _, _ := cloudScanFixture(t, 0, 256, false)
	for i := 0; i < 32; i++ {
		if err := os.WriteFile(filepath.Join(p.objectsDir(), fmt.Sprintf("ignored-%02d.txt", i)), nil, 0600); err != nil {
			t.Fatal(err)
		}
	}
	base, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx := &cloudScanCancelContext{Context: base, cancel: cancel}
	p.mu.Lock()
	err := p.scanObjectsLocked(ctx, func(CloudObjectRef) { t.Fatal("unexpected object") })
	p.mu.Unlock()
	if !errors.Is(err, ErrTransportUnavailable) || ctx.checks >= 32 {
		t.Fatal("ignored-entry loop did not observe cancellation", err, ctx.checks)
	}
}
