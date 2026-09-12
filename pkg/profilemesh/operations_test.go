package profilemesh

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type meshClockFunc func() time.Time

func (f meshClockFunc) Now() time.Time { return f() }

type meshWaitContext struct {
	context.Context
	waiting chan struct{}
	once    sync.Once
}

func (ctx *meshWaitContext) Done() <-chan struct{} {
	ctx.once.Do(func() { close(ctx.waiting) })
	return ctx.Context.Done()
}

func TestW14ClockMayReenterUntimedReads(t *testing.T) {
	cfg := testConfig(t, "clock-reentry")
	var svc *Service
	clock := meshClockFunc(func() time.Time {
		if _, err := svc.GetProfile(context.Background()); err != nil && !errors.Is(err, ErrProfileNotFound) {
			t.Error(err)
		}
		if _, err := svc.ListProfileDevices(context.Background()); err != nil {
			t.Error(err)
		}
		return time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)
	})
	var err error
	svc, err = NewService(cfg, WithClock(clock))
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := svc.BootstrapProfile(context.Background(), BootstrapProfileRequest{ProfileID: "profile"})
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("clock reentry deadlocked")
	}
}

func TestW14PanicReleasesMeshGuard(t *testing.T) {
	s, _ := w08Service(t)
	before := w08Bytes(t, s)
	func() {
		defer func() {
			if recover() != "domain panic" {
				t.Error("domain panic did not propagate")
			}
		}()
		_, _ = runMesh(s, context.Background(), untimed, true, false, func(view *Service) (struct{}, error) {
			view.store.state.Profile.DisplayName = "must not persist"
			view.store.dirty = true
			panic("domain panic")
		})
	}()
	guard, err := s.store.generations.TryLock(context.Background())
	if err != nil {
		t.Fatal("panic retained storage lock", err)
	}
	if err = guard.Close(); err != nil {
		t.Fatal(err)
	}
	w08Unchanged(t, s, before)
}

func TestW14StaleImportRejectsButIncrementalIntentRebases(t *testing.T) {
	for _, full := range []bool{true, false} {
		t.Run(fmt.Sprint("full=", full), func(t *testing.T) {
			original, snapshot := w08Service(t)
			now := original.clock.Now()
			entered, release := make(chan struct{}), make(chan struct{})
			var once sync.Once
			clock := meshClockFunc(func() time.Time { once.Do(func() { close(entered); <-release }); return now })
			first, err := NewService(original.cfg, WithClock(clock))
			if err != nil {
				t.Fatal(err)
			}
			second, err := NewService(original.cfg, WithClock(sampledClock{now}))
			if err != nil {
				t.Fatal(err)
			}
			snapshot.Profile.DisplayName = "import replacement"
			snapshot.SnapshotFingerprint = snapshotFingerprint(snapshot)
			done := make(chan error, 1)
			go func() {
				if full {
					done <- first.ImportProfileMeshSnapshot(context.Background(), snapshot)
				} else {
					_, err := first.RegisterProfileDevice(context.Background(), RegisterProfileDeviceRequest{DeviceID: "first", PublicKeyFingerprint: "fp-first"})
					done <- err
				}
			}()
			select {
			case <-entered:
			case <-time.After(3 * time.Second):
				t.Fatal("clock not entered")
			}
			_, err = second.RegisterProfileDevice(context.Background(), RegisterProfileDeviceRequest{DeviceID: "second", PublicKeyFingerprint: "fp-second"})
			if err != nil {
				t.Fatal(err)
			}
			close(release)
			select {
			case err = <-done:
			case <-time.After(3 * time.Second):
				t.Fatal("operation did not resume")
			}
			if full && !errors.Is(err, ErrStorageUnavailable) || !full && err != nil {
				t.Fatal("wrong stale-writer result", err)
			}
			devices, err := second.ListProfileDevices(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			want := 3
			if !full {
				want = 4
			}
			if len(devices) != want {
				t.Fatal("concurrent registration lost", devices)
			}
			profile, err := second.GetProfile(context.Background())
			if err != nil || profile.DisplayName == "import replacement" {
				t.Fatal("stale import replaced profile", profile, err)
			}
		})
	}
}

func TestW14LockContentionDiscardsOldClockSample(t *testing.T) {
	original, _ := w08Service(t)
	now := original.clock.Now()
	entered, release := make(chan struct{}), make(chan struct{})
	releaseClock := sync.OnceFunc(func() { close(release) })
	defer releaseClock()
	base, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx := &meshWaitContext{Context: base, waiting: make(chan struct{})}
	var calls atomic.Int32
	clock := meshClockFunc(func() time.Time {
		if calls.Add(1) == 1 {
			close(entered)
			<-release
			return now
		}
		return now.Add(time.Hour)
	})
	svc, err := NewService(original.cfg, WithClock(clock))
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := svc.SetProfileHostingMode(ctx, SetProfileHostingModeRequest{PrimaryProfileDeviceID: "device-a"})
		done <- err
	}()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("clock not entered")
	}
	guard, err := original.store.generations.Lock(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer guard.Close()
	releaseClock()
	// Acquire evaluates Done only in its retry select after ErrBusy. Observe
	// that wait before releasing the guard so scheduling cannot skip contention.
	select {
	case <-ctx.waiting:
	case err := <-done:
		t.Fatal("operation finished before encountering contention", err)
	case <-time.After(3 * time.Second):
		t.Fatal("operation did not enter the lock wait")
	}
	if err = guard.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err = <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("contended operation did not finish")
	}
	if !errors.Is(err, ErrDeviceStale) || calls.Load() < 2 {
		t.Fatal("old time sample authorized an expired host", err, calls.Load())
	}
}

func TestW14CanceledLockWaitDoesNotPublish(t *testing.T) {
	s, _ := w08Service(t)
	before := w08Bytes(t, s)
	guard, err := s.store.generations.Lock(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := s.RegisterProfileDevice(ctx, RegisterProfileDeviceRequest{DeviceID: "canceled", PublicKeyFingerprint: "fp-canceled"})
		done <- err
	}()
	cancel()
	select {
	case err = <-done:
		if !errors.Is(err, ErrContextCanceled) {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("lock cancellation blocked")
	}
	if err = guard.Close(); err != nil {
		t.Fatal(err)
	}
	w08Unchanged(t, s, before)
}

func TestW14AggregateImportReadersNeverMixRecords(t *testing.T) {
	s, snapshot := w14HintSnapshot(t)
	now := s.clock.Now()
	snapshot.Resources = []ProfileResourceRecord{{ResourceID: "marker", ResourceType: ResourceTool, ProfileOwnerID: snapshot.Profile.ProfileID, CurrentHostDeviceID: "device-a", Availability: ResourceAvailable, HostingMode: ResourceHostingSingleHost, CreatedAt: now, UpdatedAt: now, Metadata: map[string]string{"marker": "old"}}}
	snapshot.Profile.DisplayName = "old"
	snapshot.EndpointHints[0].Metadata = map[string]string{"marker": "old"}
	snapshot.SnapshotFingerprint = snapshotFingerprint(snapshot)
	if err := s.ImportProfileMeshSnapshot(context.Background(), snapshot); err != nil {
		t.Fatal(err)
	}
	reader, err := NewService(s.cfg, WithClock(s.clock))
	if err != nil {
		t.Fatal(err)
	}
	stop, done := make(chan struct{}), make(chan struct{})
	var reads atomic.Int32
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
			}
			value, err := reader.ExportProfileMeshSnapshot(context.Background())
			if err != nil {
				t.Error(err)
				return
			}
			if len(value.Resources) != 1 || len(value.EndpointHints) != 1 || value.Profile.DisplayName != value.Resources[0].Metadata["marker"] || value.Profile.DisplayName != value.EndpointHints[0].Metadata["marker"] {
				t.Error("reader observed mixed import", value)
				return
			}
			reads.Add(1)
		}
	}()
	for i := 0; i < 6; i++ {
		marker := fmt.Sprint(i)
		snapshot.Profile.DisplayName = marker
		snapshot.Resources[0].Metadata["marker"] = marker
		snapshot.EndpointHints[0].Metadata["marker"] = marker
		snapshot.SnapshotFingerprint = snapshotFingerprint(snapshot)
		if err := s.ImportProfileMeshSnapshot(context.Background(), snapshot); err != nil {
			t.Fatal(err)
		}
	}
	close(stop)
	<-done
	if reads.Load() == 0 {
		t.Fatal("no reader observations")
	}
}

func TestW14MeshProcessWriter(t *testing.T) {
	raw := os.Getenv("AEGIS_W14_MESH_CONFIG")
	if raw == "" {
		return
	}
	var cfg AppConfig
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		t.Fatal(err)
	}
	svc, err := NewService(cfg)
	if err != nil {
		t.Fatal(err)
	}
	prefix := os.Getenv("AEGIS_W14_MESH_WRITER")
	for i := 0; i < 4; i++ {
		id := fmt.Sprintf("%s-%d", prefix, i)
		if _, err = svc.RegisterProfileDevice(context.Background(), RegisterProfileDeviceRequest{DeviceID: id, PublicKeyFingerprint: "fp-" + id}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestW14SeparateProcessesPreserveRegistrations(t *testing.T) {
	svc := newTestService(t, "processes")
	if _, err := svc.BootstrapProfile(context.Background(), BootstrapProfileRequest{ProfileID: "profile"}); err != nil {
		t.Fatal(err)
	}
	config, err := json.Marshal(svc.cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	results := make(chan error, 2)
	for _, prefix := range []string{"first", "second"} {
		go func(prefix string) {
			command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestW14MeshProcessWriter$", "-test.count=1")
			command.Env = append(os.Environ(), "AEGIS_W14_MESH_CONFIG="+string(config), "AEGIS_W14_MESH_WRITER="+prefix)
			output, err := command.CombinedOutput()
			if err != nil {
				err = fmt.Errorf("child: %w: %s", err, output)
			}
			results <- err
		}(prefix)
	}
	for i := 0; i < 2; i++ {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	devices, err := svc.ListProfileDevices(context.Background())
	if err != nil || len(devices) != 8 {
		t.Fatal("process registration lost", len(devices), err)
	}
}
