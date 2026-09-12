package profilemesh

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

// Explicit native corruption fixture. Tests may seed a structurally invalid
// payload to prove the reader rejects it; production writers cannot bypass validation.
func w14SeedState(t *testing.T, s *Service, edit func(*meshState)) {
	t.Helper()
	guard, err := s.store.generations.Lock(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer guard.Close()
	state, token, backup, err := s.store.loadGuard(context.Background(), guard)
	if err != nil {
		t.Fatal(err)
	}
	edit(state)
	raw, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = guard.Commit(token, raw, backup); err != nil {
		t.Fatal(err)
	}
}

func w14WriteLegacy(t *testing.T, s *Service, state *meshState) {
	t.Helper()
	for _, entry := range []struct {
		path    string
		value   any
		present bool
	}{
		{s.store.profilePath(), state.Profile, state.Profile != nil}, {s.store.hostingPath(), state.Hosting, state.Hosting != nil},
		{s.store.devicesPath(), state.Devices, len(state.Devices.Devices) > 0}, {s.store.resourcesPath(), state.Resources, len(state.Resources.Resources) > 0},
	} {
		if !entry.present {
			continue
		}
		raw, err := json.Marshal(entry.value)
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(entry.path, raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := os.Stat(filepath.Join(s.store.dir, "state-v2")); !os.IsNotExist(err) {
		t.Fatal("legacy fixture already activated", err)
	}
}

func w14LegacyState(now time.Time) *meshState {
	state := emptyMesh()
	state.Profile = &ProfileIdentity{ProfileID: "profile", AppID: "sample-app", Namespace: "legacy", DisplayName: "Legacy", CreatedAt: now, UpdatedAt: now, SchemaVersion: 1, MetadataVersion: 1}
	hosting := defaultHostingConfig(now)
	hosting.PrimaryProfileDeviceID = "device-a"
	state.Hosting = &hosting
	state.Devices = deviceRegistryFile{SchemaVersion: 1, UpdatedAt: now, Devices: []ProfileDeviceRecord{{DeviceID: "device-a", DisplayName: "A", PublicKeyFingerprint: "fp-device-a", TrustStatus: DeviceTrustTrusted, Status: DeviceStatusActive, RegisteredAt: now, UpdatedAt: now, LastSeen: now, ProfileMetadataVersion: 1}}}
	state.Resources = resourceRegistryFile{SchemaVersion: 1, UpdatedAt: now, Resources: []ProfileResourceRecord{{ResourceID: "tool", ResourceType: ResourceTool, ProfileOwnerID: "profile", CurrentHostDeviceID: "device-a", AllowedHostDeviceIDs: []string{"device-a"}, Availability: ResourceAvailable, HostingMode: ResourceHostingSingleHost, CreatedAt: now, UpdatedAt: now}}}
	return state
}

func TestW14LegacyAcceptedStateMigration(t *testing.T) {
	now := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)
	for _, scenario := range []struct {
		name string
		edit func(*meshState)
	}{
		{"ordinary", func(*meshState) {}},
		{"missing-hosting", func(s *meshState) { s.Hosting = nil }},
		{"schema-zero", func(s *meshState) { s.Devices.SchemaVersion = 0; s.Resources.SchemaVersion = 0 }},
		{"zero-clock", func(s *meshState) {
			s.Profile.CreatedAt = time.Time{}
			s.Profile.UpdatedAt = time.Time{}
			s.Hosting.UpdatedAt = time.Time{}
			d := &s.Devices.Devices[0]
			d.RegisteredAt = time.Time{}
			d.UpdatedAt = time.Time{}
			d.LastSeen = time.Time{}
			s.Resources.Resources[0].CreatedAt = time.Time{}
		}},
		{"backward-clock", func(s *meshState) {
			s.Devices.Devices[0].UpdatedAt = now.Add(-time.Hour)
			s.Resources.Resources[0].UpdatedAt = now.Add(-time.Hour)
		}},
		{"stale-host", func(s *meshState) { s.Devices.Devices[0].LastSeen = now.Add(-time.Hour) }},
		{"removed-host", func(s *meshState) {
			d := &s.Devices.Devices[0]
			d.Status = DeviceStatusRemoved
			d.TrustStatus = DeviceTrustRevoked
			removed := now.Add(-time.Hour)
			d.RemovedAt = &removed
			d.UpdatedAt = removed
		}},
		{"non-strict-pair", func(s *meshState) { s.Devices.Devices[0].TrustStatus = DeviceTrustUnknown }},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			clock := &testClock{now: now}
			s := newTestService(t, "legacy", WithClock(clock))
			state := w14LegacyState(now)
			scenario.edit(state)
			w14WriteLegacy(t, s, state)
			before, err := s.ExportProfileMeshSnapshot(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(filepath.Join(s.store.dir, "state-v2")); !os.IsNotExist(err) {
				t.Fatal("read activated legacy state", err)
			}
			rawBefore := w08Bytes(t, s)
			if _, err = s.RegisterProfileDevice(context.Background(), RegisterProfileDeviceRequest{DeviceID: "device-b", PublicKeyFingerprint: "fp-device-b"}); err != nil {
				t.Fatal(err)
			}
			for path, raw := range rawBefore {
				after, err := os.ReadFile(path)
				if err != nil || !bytes.Equal(raw, after) {
					t.Fatalf("migration rewrote legacy %s: %v", filepath.Base(path), err)
				}
				if filepath.Base(path) != ".state.lock" {
					backup, err := os.ReadFile(filepath.Join(s.store.dir, "state-v2", "backup", filepath.Base(path)))
					if err != nil || !bytes.Equal(raw, backup) {
						t.Fatalf("backup mismatch %s: %v", filepath.Base(path), err)
					}
				}
			}
			reopened, err := NewService(s.cfg, WithClock(clock))
			if err != nil {
				t.Fatal(err)
			}
			after, err := reopened.ExportProfileMeshSnapshot(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(after.Profile, before.Profile) || !reflect.DeepEqual(after.HostingConfig, before.HostingConfig) || !reflect.DeepEqual(after.Resources, before.Resources) || len(after.Devices) != 2 || !reflect.DeepEqual(after.Devices[0], before.Devices[0]) {
				t.Fatal("migration changed accepted legacy metadata")
			}
			if scenario.name == "stale-host" || scenario.name == "removed-host" || scenario.name == "non-strict-pair" {
				host, err := reopened.GetResourceHost(context.Background(), "tool")
				if err != nil || host.HostAvailable {
					t.Fatal("migration revived historical host", host, err)
				}
			}
		})
	}
}

func TestW14RejectedLegacyMutationDoesNotActivate(t *testing.T) {
	now := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)
	for _, scenario := range []string{"invalid-request", "corrupt", "unknown-schema", "wrong-owner", "null-profile", "null-hosting"} {
		t.Run(scenario, func(t *testing.T) {
			s := newTestService(t, "legacy", WithClock(sampledClock{now}))
			state := w14LegacyState(now)
			if scenario == "unknown-schema" {
				state.Devices.SchemaVersion = 88
			}
			if scenario == "wrong-owner" {
				state.Profile.AppID = "other"
			}
			w14WriteLegacy(t, s, state)
			if scenario == "corrupt" {
				if err := os.WriteFile(s.store.resourcesPath(), []byte("broken"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if scenario == "null-profile" || scenario == "null-hosting" {
				path := s.store.profilePath()
				if scenario == "null-hosting" {
					path = s.store.hostingPath()
				}
				if err := os.WriteFile(path, []byte("null"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			before := w08Bytes(t, s)
			_, err := s.SetResourceHost(context.Background(), SetResourceHostRequest{ResourceID: "tool", DeviceID: "missing"})
			if err == nil {
				t.Fatal("invalid first mutation succeeded")
			}
			w08Unchanged(t, s, before)
			if _, err := os.Stat(filepath.Join(s.store.dir, "state-v2")); !os.IsNotExist(err) {
				t.Fatal("invalid mutation activated native state", err)
			}
		})
	}
}

func TestW14OversizedLegacyPreservesBytes(t *testing.T) {
	s := newTestService(t, "oversize")
	f, err := os.Create(s.store.profilePath())
	if err != nil {
		t.Fatal(err)
	}
	if err = f.Truncate((64 << 20) + 1); err != nil {
		t.Fatal(err)
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
	digest := func() []byte {
		t.Helper()
		f, err := os.Open(s.store.profilePath())
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		h := sha256.New()
		if _, err = io.Copy(h, f); err != nil {
			t.Fatal(err)
		}
		return h.Sum(nil)
	}
	before := digest()
	if _, err = s.BootstrapProfile(context.Background(), BootstrapProfileRequest{ProfileID: "profile"}); !errors.Is(err, ErrStorageUnavailable) {
		t.Fatal("oversized legacy accepted", err)
	}
	if !bytes.Equal(before, digest()) {
		t.Fatal("oversized legacy bytes changed")
	}
	if _, err = os.Stat(filepath.Join(s.store.dir, "state-v2")); !os.IsNotExist(err) {
		t.Fatal("oversized legacy activated", err)
	}
}

func TestW14NativeAuthorityNeverFallsBackToLegacy(t *testing.T) {
	s := newTestService(t, "legacy")
	w14WriteLegacy(t, s, w14LegacyState(time.Now().UTC()))
	if _, err := s.RegisterProfileDevice(context.Background(), RegisterProfileDeviceRequest{DeviceID: "device-b", PublicKeyFingerprint: "fp-device-b"}); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(s.store.dir, "state-v2", "current.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetProfile(context.Background()); !errors.Is(err, ErrStorageUnavailable) {
		t.Fatal("missing native authority fell back to legacy", err)
	}
}

func TestW14NativePayloadRequiresKnownVersion(t *testing.T) {
	for _, version := range []int{0, 88} {
		s, _ := w08Service(t)
		w14SeedState(t, s, func(state *meshState) { state.Version = version })
		before := w08Bytes(t, s)
		if _, err := s.GetProfile(context.Background()); !errors.Is(err, ErrStorageUnavailable) {
			t.Fatal("native payload version was defaulted or ignored", version, err)
		}
		w08Unchanged(t, s, before)
	}
}

func TestW14PublicZeroAndBackwardClockStateReopens(t *testing.T) {
	for _, initial := range []time.Time{{}, time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)} {
		t.Run(initial.String(), func(t *testing.T) {
			clock := &testClock{now: initial}
			s := newTestService(t, "clock-state", WithClock(clock))
			ctx := context.Background()
			profile, err := s.BootstrapProfile(ctx, BootstrapProfileRequest{ProfileID: "profile"})
			if err != nil {
				t.Fatal(err)
			}
			registerDevice(t, s, "device-a")
			if _, err = s.SetProfileHostingMode(ctx, SetProfileHostingModeRequest{PrimaryProfileDeviceID: "device-a"}); err != nil {
				t.Fatal(err)
			}
			if _, err = s.RegisterProfileResource(ctx, RegisterProfileResourceRequest{ResourceID: "tool", ResourceType: ResourceTool, CurrentHostDeviceID: "device-a"}); err != nil {
				t.Fatal(err)
			}
			clock.Add(-time.Hour)
			if err = s.RemoveProfileDevice(ctx, "device-a"); err != nil {
				t.Fatal(err)
			}
			reopened, err := NewService(s.cfg, WithClock(clock))
			if err != nil {
				t.Fatal(err)
			}
			value, err := reopened.ExportProfileMeshSnapshot(ctx)
			if err != nil || value.Profile != profile || len(value.Devices) != 1 || value.Devices[0].RemovedAt == nil || !value.Devices[0].RemovedAt.Equal(initial.Add(-time.Hour)) || !value.Devices[0].RegisteredAt.Equal(initial) || len(value.Resources) != 1 || !value.Resources[0].CreatedAt.Equal(initial) {
				t.Fatal("public clock state failed to reopen unchanged", value, err)
			}
			host, err := reopened.GetResourceHost(ctx, "tool")
			if err != nil || host.HostAvailable {
				t.Fatal("removed retained host became available", host, err)
			}
			if err = reopened.ImportProfileMeshSnapshot(ctx, value); !errors.Is(err, ErrInvalidProfileSnapshot) {
				t.Fatal("stored-state rules weakened strict import time admission", err)
			}
		})
	}
}
