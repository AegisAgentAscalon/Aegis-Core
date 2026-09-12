package updates

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Counters are populated only by measurement overlays, never production code.
var updatesBenchInstrumented bool
var updatesBenchHashes, updatesBenchHashedBytes, updatesBenchCopiedBytes, updatesBenchDigests, updatesBenchLoads int64

func updateBenchmarkFixture(tb testing.TB, artifactBytes, noteBytes int, staged bool) *Service {
	tb.Helper()
	dir := tb.TempDir()
	artifactPath := filepath.Join(dir, "package.zip")
	body := bytes.Repeat([]byte("a"), artifactBytes)
	sum := sha256.Sum256(body)
	if err := os.WriteFile(artifactPath, body, 0600); err != nil {
		tb.Fatal(err)
	}
	cfg := AppConfig{AppID: "bench", CurrentVersion: "1.0.0", Channel: ChannelStable, Platform: "windows", Architecture: "amd64", Namespace: "default", StagingDir: filepath.Join(dir, "staging"), Source: SourceConfig{Provider: ProviderFileManifest, ManifestPath: filepath.Join(dir, "manifest.json")}, Policy: Policy{RequireSHA256: true, MaximumArtifactSize: int64(artifactBytes)}}
	cfg.DisplayName = "Benchmark"
	manifest := testManifest(cfg, "1.2.0", artifactPath, hex.EncodeToString(sum[:]))
	manifest.Artifacts[0].Size = int64(artifactBytes)
	manifest.ReleaseNotesText = strings.Repeat("n", noteBytes)
	raw, err := json.Marshal(manifest)
	if err != nil {
		tb.Fatal(err)
	}
	if err := os.WriteFile(cfg.Source.ManifestPath, raw, 0600); err != nil {
		tb.Fatal(err)
	}
	svc, err := NewRecordOnlyService(cfg)
	if err != nil {
		tb.Fatal(err)
	}
	ctx := context.Background()
	if _, err = svc.CheckForUpdates(ctx); err != nil {
		tb.Fatal(err)
	}
	if _, err = svc.DownloadUpdate(ctx, "1.2.0"); err != nil {
		tb.Fatal(err)
	}
	if _, err = svc.VerifyUpdate(ctx, "1.2.0"); err != nil {
		tb.Fatal(err)
	}
	if staged {
		if _, err = svc.StageUpdate(ctx, "1.2.0"); err != nil {
			tb.Fatal(err)
		}
	}
	return svc
}

func resetUpdateBenchCounters() {
	updatesBenchHashes, updatesBenchHashedBytes, updatesBenchCopiedBytes, updatesBenchDigests, updatesBenchLoads = 0, 0, 0, 0, 0
}

func reportUpdateBenchCounters(b *testing.B, totals [5]int64) {
	if !updatesBenchInstrumented {
		return
	}
	for i, name := range []string{"hashes/op", "hashed_bytes/op", "copied_bytes/op", "private_digests/op", "owner_loads/op"} {
		b.ReportMetric(float64(totals[i])/float64(b.N), name)
	}
}

func BenchmarkUpdatesArtifactWork(b *testing.B) {
	for _, size := range []int{4 << 10, 1 << 20, 16 << 20, 128 << 20} {
		for _, operation := range []string{"stage", "restage", "status", "handoff", "duplicate-handoff"} {
			b.Run(fmt.Sprintf("bytes=%d/%s", size, operation), func(b *testing.B) {
				var totals [5]int64
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					b.StopTimer()
					svc := updateBenchmarkFixture(b, size, 0, operation != "stage")
					ctx := context.Background()
					request := PackageHandoffRequest{IdempotencyKey: "bench-handoff", ConsumerID: "consumer"}
					if operation == "handoff" || operation == "duplicate-handoff" {
						envelope, err := svc.GetLifecycleEnvelope(ctx)
						if err != nil {
							b.Fatal(err)
						}
						request.ExpectedRevision = envelope.Revision
						if operation == "duplicate-handoff" {
							if _, err := svc.RecordPackageHandoff(ctx, request); err != nil {
								b.Fatal(err)
							}
						}
					}
					resetUpdateBenchCounters()
					b.StartTimer()
					var err error
					switch operation {
					case "stage", "restage":
						_, err = svc.StageUpdate(ctx, "1.2.0")
					case "status":
						_, err = svc.GetStatus(ctx)
					default:
						_, err = svc.RecordPackageHandoff(ctx, request)
					}
					b.StopTimer()
					if err != nil {
						b.Fatal(err)
					}
					for j, n := range [5]int64{updatesBenchHashes, updatesBenchHashedBytes, updatesBenchCopiedBytes, updatesBenchDigests, updatesBenchLoads} {
						totals[j] += n
					}
					b.StartTimer()
				}
				b.StopTimer()
				reportUpdateBenchCounters(b, totals)
			})
		}
	}
}

func BenchmarkUpdatesMetadataWork(b *testing.B) {
	for _, size := range []int{4 << 10, 256 << 10, (4 << 20) - 4096} {
		for _, operation := range []string{"encode", "decode"} {
			b.Run(fmt.Sprintf("notes=%d/%s", size, operation), func(b *testing.B) {
				svc := updateBenchmarkFixture(b, 4096, size, true)
				view, err := readTestView(svc.store)
				if err != nil {
					b.Fatal(err)
				}
				ctx := context.Background()
				raw, err := benchmarkEncode(ctx, svc.store, view)
				if err != nil {
					b.Fatal(err)
				}
				resetUpdateBenchCounters()
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					if operation == "encode" {
						_, err = benchmarkEncode(ctx, svc.store, view)
					} else {
						_, err = benchmarkDecode(ctx, svc.store, raw)
					}
					if err != nil {
						b.Fatal(err)
					}
				}
				b.StopTimer()
				b.ReportMetric(float64(len(raw)), "encoded_state_bytes")
				reportUpdateBenchCounters(b, [5]int64{updatesBenchHashes, updatesBenchHashedBytes, updatesBenchCopiedBytes, updatesBenchDigests, updatesBenchLoads})
			})
		}
	}
}

// Baseline overlays adapt only these private signatures; the harness is shared.
func benchmarkEncode(ctx context.Context, st *store, v *stateView) ([]byte, error) {
	return st.encodeState(ctx, v)
}

func benchmarkDecode(ctx context.Context, st *store, raw []byte) (*stateView, error) {
	return st.decodeState(ctx, raw)
}
