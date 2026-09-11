package profilemesh

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"
)

func TestW08AllowlistPolicySurvivesNormalization(t *testing.T) {
	for _, writer := range []string{"register", "import-v1", "import-v2"} {
		for _, mixed := range []bool{false, true} {
			name := writer + "/sole"
			if mixed {
				name = writer + "/mixed"
			}
			t.Run(name, func(t *testing.T) {
				s, _ := w08Service(t)
				ctx := context.Background()
				if _, err := s.RegisterProfileDeviceStrict(ctx, RegisterProfileDeviceRequest{DeviceID: "device-secret", PublicKeyFingerprint: "fp-safe-device-key", TrustStatus: DeviceTrustTrusted, Status: DeviceStatusActive}); err != nil {
					t.Fatal(err)
				}
				allowed := []string{"device-secret", "device-secret"}
				want := []string{"device-secret"}
				if mixed {
					allowed = append(allowed, "device-b")
					want = []string{"device-b", "device-secret"}
				}
				if writer == "register" {
					_, err := s.RegisterProfileResource(ctx, RegisterProfileResourceRequest{ResourceID: "restricted", ResourceType: ResourceTool, CurrentHostDeviceID: "device-secret", AllowedHostDeviceIDs: allowed})
					if err != nil {
						t.Fatal(err)
					}
				} else {
					snapshot, err := s.ExportProfileMeshSnapshot(ctx)
					if err != nil {
						t.Fatal(err)
					}
					snapshot.Resources = []ProfileResourceRecord{{ResourceID: "restricted", ResourceType: ResourceTool, ProfileOwnerID: snapshot.Profile.ProfileID, CurrentHostDeviceID: "device-secret", AllowedHostDeviceIDs: allowed, Availability: ResourceAvailable, HostingMode: ResourceHostingSingleHost, CreatedAt: s.clock.Now(), UpdatedAt: s.clock.Now()}}
					snapshot.SnapshotFingerprint = snapshotFingerprint(normalizeProfileMeshSnapshot(snapshot))
					if writer == "import-v1" {
						snapshot.SchemaVersion = 1
						snapshot.SnapshotFingerprint = ""
					}
					if err := s.ImportProfileMeshSnapshot(ctx, snapshot); err != nil {
						t.Fatal(err)
					}
				}
				reopened, err := NewService(s.cfg, WithClock(s.clock))
				if err != nil {
					t.Fatal(err)
				}
				snapshot, err := reopened.ExportProfileMeshSnapshot(ctx)
				if err != nil {
					t.Fatal(err)
				}
				if len(snapshot.Resources) != 1 || !reflect.DeepEqual(snapshot.Resources[0].AllowedHostDeviceIDs, want) {
					t.Fatalf("allowlist changed: %+v", snapshot.Resources)
				}
				if err := reopened.ImportProfileMeshSnapshot(ctx, snapshot); err != nil {
					t.Fatal("own export rejected", err)
				}
				again, err := reopened.ExportProfileMeshSnapshot(ctx)
				if err != nil || again.SnapshotFingerprint != snapshot.SnapshotFingerprint {
					t.Fatal("round trip changed policy", err)
				}
				if _, err := reopened.SetResourceHost(ctx, SetResourceHostRequest{ResourceID: "restricted", DeviceID: "device-a"}); !errors.Is(err, ErrDeviceNotAllowed) {
					t.Fatalf("non-allowlisted host accepted: %v", err)
				}
				if mixed {
					if _, err := reopened.SetResourceHost(ctx, SetResourceHostRequest{ResourceID: "restricted", DeviceID: "device-b"}); err != nil {
						t.Fatal("allowed host rejected", err)
					}
				}
			})
		}
	}
}

func TestW08FailoverPreservesAllowlistAndRejectsUnavailableTarget(t *testing.T) {
	for _, state := range []string{"removed", "revoked", "stale"} {
		t.Run(state, func(t *testing.T) {
			s, _ := w08Service(t)
			ctx := context.Background()
			allowed := []string{"device-a", "device-b"}
			if _, err := s.RegisterProfileResource(ctx, RegisterProfileResourceRequest{ResourceID: "resource", ResourceType: ResourceTool, CurrentHostDeviceID: "device-a", AllowedHostDeviceIDs: allowed}); err != nil {
				t.Fatal(err)
			}
			switch state {
			case "removed":
				if err := s.RemoveProfileDevice(ctx, "device-a"); err != nil {
					t.Fatal(err)
				}
			case "revoked":
				device, err := s.requireDeviceLocked("device-a")
				if err != nil {
					t.Fatal(err)
				}
				if _, err := s.RegisterProfileDeviceStrict(ctx, RegisterProfileDeviceRequest{DeviceID: device.DeviceID, PublicKeyFingerprint: device.PublicKeyFingerprint, TrustStatus: DeviceTrustRevoked, Status: DeviceStatusRevoked}); err != nil {
					t.Fatal(err)
				}
			case "stale":
				s.clock.(*testClock).Add(time.Hour)
				registerDevice(t, s, "device-b")
			}
			if host, err := s.GetResourceHost(ctx, "resource"); err != nil || host.HostAvailable {
				t.Fatal("old host should be unavailable", host, err)
			}
			moved, err := s.SetResourceHost(ctx, SetResourceHostRequest{ResourceID: "resource", DeviceID: "device-b"})
			if err != nil || moved.CurrentHostDeviceID != "device-b" || !reflect.DeepEqual(moved.AllowedHostDeviceIDs, allowed) {
				t.Fatal("safe failover blocked or policy changed", moved, err)
			}
			if _, err := s.SetResourceHost(ctx, SetResourceHostRequest{ResourceID: "resource", DeviceID: "device-a"}); err == nil {
				t.Fatal("unavailable target accepted")
			}
			snapshot, err := s.ExportProfileMeshSnapshot(ctx)
			if err != nil {
				t.Fatal(err)
			}
			reopened, err := NewService(s.cfg, WithClock(s.clock))
			if err != nil {
				t.Fatal(err)
			}
			if err := reopened.ImportProfileMeshSnapshot(ctx, snapshot); err != nil {
				t.Fatal("valid failover state cannot round trip", err)
			}
			if host, err := reopened.GetResourceHost(ctx, "resource"); err != nil || !host.HostAvailable || host.HostDeviceID != "device-b" {
				t.Fatal("failover lost after reopen/import", host, err)
			}
		})
	}
}
