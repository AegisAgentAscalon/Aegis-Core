package profilesync

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The same fixture/benchmark file is overlaid onto the immutable baseline.
// Fixture writes are outside timing and avoid quadratic setup through PutObject.
func cloudScanFixture(tb testing.TB, count, size int, mixed bool) (*FileObjectProvider, CloudSyncObject, int) {
	tb.Helper()
	p, err := NewFileObjectProvider(FileObjectProviderConfig{RootDir: tb.TempDir(), ProfileNamespace: "profile"})
	if err != nil {
		tb.Fatal(err)
	}
	object := CloudSyncObject{ProfileNamespace: p.namespace, ObjectID: "Object:000000", Kind: CloudObjectSnapshotMetadata,
		Body: bytes.Repeat([]byte("x"), size), CreatedAt: time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)}
	files := 0
	write := func(value CloudSyncObject, legacy bool) {
		tb.Helper()
		ref, err := ValidateCloudObject(value, 0)
		if err != nil {
			tb.Fatal(err)
		}
		path, _ := p.objectPath(ref)
		if legacy {
			path = p.legacyObjectPath(ref)
		}
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			tb.Fatal(err)
		}
		raw, err := json.Marshal(objectFile{Ref: ref, Body: value.Body})
		if err != nil {
			tb.Fatal(err)
		}
		if err := os.WriteFile(path, raw, 0600); err != nil {
			tb.Fatal(err)
		}
		files++
	}
	for i := 0; i < count; i++ {
		value := object
		value.ObjectID = fmt.Sprintf("Object:%06d", i)
		if i%2 != 0 {
			value.Kind = CloudObjectProposalMetadata
		}
		write(value, mixed && i%2 != 0)
		if mixed && i%10 == 0 {
			write(value, true) // Exact current/legacy duplicate, counted only once.
		}
	}
	if mixed && count > 0 {
		foreign := object
		foreign.ProfileNamespace = "Profile"
		foreign.ObjectID = "foreign"
		write(foreign, true) // Validated body, excluded only after namespace check.
	}
	return p, object, files
}

// Only benchmark overlays route scanner reads/key calls through these counters.
// Production source retains ordinary readJSONFile/cloudStorageKey calls.
var cloudBenchReads, cloudBenchBodyBytes, cloudBenchStorageKeys int64

func cloudBenchReadJSON(ctx context.Context, path string, out *objectFile) error {
	cloudBenchReads++
	err := readJSONFile(ctx, path, out)
	cloudBenchBodyBytes += int64(len(out.Body))
	return err
}

func BenchmarkCloudFileObjectScan(b *testing.B) {
	for _, count := range []int{1, 100, 1000} {
		for _, size := range []int{256, 16 << 10} {
			for _, operation := range []string{"status", "list", "idempotent", "insert", "conflict"} {
				b.Run(fmt.Sprintf("mixed/n=%d/bytes=%d/%s", count, size, operation), func(b *testing.B) {
					p, object, files := cloudScanFixture(b, count, size, true)
					ctx := context.Background()
					if operation == "insert" {
						object.ObjectID = "new:object"
					} else if operation == "conflict" {
						object.Body = bytes.Repeat([]byte("y"), size)
					}
					ref, _ := ValidateCloudObject(object, 0)
					inserted, _ := p.objectPath(ref)
					cloudBenchReads, cloudBenchBodyBytes, cloudBenchStorageKeys = 0, 0, 0
					b.ReportAllocs()
					b.ResetTimer()
					for i := 0; i < b.N; i++ {
						switch operation {
						case "status":
							status := p.GetStatus(ctx)
							if !status.Available || status.ObjectCount != count {
								b.Fatal(status)
							}
						case "list":
							refs, err := p.ListObjects(ctx, CloudObjectQuery{ProfileNamespace: p.namespace})
							if err != nil || len(refs) != count {
								b.Fatal(len(refs), err)
							}
						default:
							_, err := p.PutObject(ctx, object)
							if operation == "conflict" && !errors.Is(err, ErrCloudObjectConflict) || operation != "conflict" && err != nil {
								b.Fatal(err)
							}
						}
						if operation == "insert" {
							b.StopTimer()
							if err := os.Remove(inserted); err != nil {
								b.Fatal(err)
							}
							b.StartTimer()
						}
					}
					b.StopTimer()
					if cloudBenchReads > 0 {
						if cloudBenchReads != int64(files*b.N) {
							b.Fatal("body scan count changed", cloudBenchReads, files*b.N)
						}
						b.ReportMetric(float64(cloudBenchReads)/float64(b.N), "body_reads/op")
						b.ReportMetric(float64(cloudBenchBodyBytes)/float64(b.N), "body_bytes/op")
						b.ReportMetric(float64(cloudBenchStorageKeys)/float64(b.N), "storage_keys/op")
					}
				})
			}
		}
	}
}
