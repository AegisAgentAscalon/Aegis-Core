package profilemesh

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func w08Service(t *testing.T) (*Service, ProfileMeshSnapshot) {
	t.Helper()
	s := newTestService(t, "w08", WithClock(&testClock{now: time.Now().UTC()}))
	if _, err := s.BootstrapProfile(context.Background(), BootstrapProfileRequest{ProfileID: "profile"}); err != nil {
		t.Fatal(err)
	}
	registerDevice(t, s, "device-a")
	registerDevice(t, s, "device-b")
	snapshot, err := s.ExportProfileMeshSnapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return s, snapshot
}

func w08Bytes(t *testing.T, s *Service) map[string][]byte {
	t.Helper()
	out := map[string][]byte{}
	for _, path := range []string{s.store.profilePath(), s.store.hostingPath(), s.store.devicesPath(), s.store.resourcesPath()} {
		raw, err := os.ReadFile(path)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
		out[path] = raw
	}
	return out
}

func w08Unchanged(t *testing.T, s *Service, before map[string][]byte) {
	t.Helper()
	for path, raw := range w08Bytes(t, s) {
		if !bytes.Equal(before[path], raw) {
			t.Errorf("rejected operation changed %s", filepath.Base(path))
		}
	}
}

func TestW08ResourceValidationAcrossWriters(t *testing.T) {
	cases := []struct {
		name           string
		mutate         func(*ProfileResourceRecord, []ProfileDeviceRecord)
		valid, setHost bool
	}{
		{"valid", func(*ProfileResourceRecord, []ProfileDeviceRecord) {}, true, true},
		{"blank allowed host", func(r *ProfileResourceRecord, _ []ProfileDeviceRecord) { r.AllowedHostDeviceIDs = []string{""} }, false, true},
		{"disallowed host", func(r *ProfileResourceRecord, _ []ProfileDeviceRecord) { r.AllowedHostDeviceIDs = []string{"device-b"} }, false, true},
		{"missing allowed host", func(r *ProfileResourceRecord, _ []ProfileDeviceRecord) {
			r.AllowedHostDeviceIDs = []string{"device-a", "missing"}
		}, false, true},
		{"unsupported mode", func(r *ProfileResourceRecord, _ []ProfileDeviceRecord) {
			r.HostingMode = ResourceHostingMultiHostPlanned
		}, false, true},
		{"invalid availability", func(r *ProfileResourceRecord, _ []ProfileDeviceRecord) { r.Availability = "invalid" }, false, false},
		{"revoked host", func(_ *ProfileResourceRecord, d []ProfileDeviceRecord) {
			d[0].Status = DeviceStatusRevoked
			d[0].TrustStatus = DeviceTrustRevoked
		}, false, true},
		{"stale allowed host", func(_ *ProfileResourceRecord, d []ProfileDeviceRecord) {
			d[1].Status = DeviceStatusStale
			d[1].TrustStatus = DeviceTrustStale
		}, false, true},
		{"expired presence", func(_ *ProfileResourceRecord, d []ProfileDeviceRecord) {
			d[0].RegisteredAt = d[0].RegisteredAt.Add(-time.Hour)
			d[0].LastSeen = d[0].LastSeen.Add(-time.Hour)
		}, false, true},
		{"untrusted host", func(_ *ProfileResourceRecord, d []ProfileDeviceRecord) { d[0].TrustStatus = DeviceTrustUnknown }, false, true},
	}
	for _, tc := range cases {
		for _, writer := range []string{"register", "set", "import-v1", "import-v2"} {
			if writer == "set" && !tc.setHost {
				continue
			} // Setter explicitly sets availability to available.
			t.Run(tc.name+"/"+writer, func(t *testing.T) {
				s, snapshot := w08Service(t)
				r := ProfileResourceRecord{ResourceID: "resource", ResourceType: ResourceTool, ProfileOwnerID: snapshot.Profile.ProfileID, CurrentHostDeviceID: "device-a", AllowedHostDeviceIDs: []string{"device-a", "device-b"}, HostingMode: ResourceHostingSingleHost, Availability: ResourceAvailable, CreatedAt: s.clock.Now(), UpdatedAt: s.clock.Now()}
				tc.mutate(&r, snapshot.Devices)
				if err := s.store.writeDevices(deviceRegistryFile{SchemaVersion: schemaVersion, Devices: snapshot.Devices, UpdatedAt: s.clock.Now()}); err != nil {
					t.Fatal(err)
				}
				if writer == "set" {
					if err := s.store.writeResources(resourceRegistryFile{SchemaVersion: schemaVersion, Resources: []ProfileResourceRecord{r}, UpdatedAt: s.clock.Now()}); err != nil {
						t.Fatal(err)
					}
				}
				before := w08Bytes(t, s)
				var err error
				switch writer {
				case "register":
					_, err = s.RegisterProfileResource(context.Background(), RegisterProfileResourceRequest{ResourceID: r.ResourceID, ResourceType: r.ResourceType, CurrentHostDeviceID: r.CurrentHostDeviceID, AllowedHostDeviceIDs: r.AllowedHostDeviceIDs, HostingMode: r.HostingMode, Availability: r.Availability})
				case "set":
					_, err = s.SetResourceHost(context.Background(), SetResourceHostRequest{ResourceID: r.ResourceID, DeviceID: r.CurrentHostDeviceID})
				default:
					snapshot.Resources = []ProfileResourceRecord{r}
					snapshot.SnapshotFingerprint = snapshotFingerprint(normalizeProfileMeshSnapshot(snapshot))
					if writer == "import-v1" {
						snapshot.SchemaVersion = 1
						snapshot.SnapshotFingerprint = ""
					}
					err = s.ImportProfileMeshSnapshot(context.Background(), snapshot)
				}
				if (err == nil) != tc.valid {
					t.Fatalf("valid=%v, error=%v", tc.valid, err)
				}
				if !tc.valid {
					w08Unchanged(t, s, before)
				}
			})
		}
	}
}

func TestW08DefaultHostRespectsAllowlist(t *testing.T) {
	s, _ := w08Service(t)
	ctx := context.Background()
	if _, err := s.SetProfileHostingMode(ctx, SetProfileHostingModeRequest{HostingMode: HostingSingleProfileDevice, ProfileDataHostDeviceID: "device-a"}); err != nil {
		t.Fatal(err)
	}
	before := w08Bytes(t, s)
	if _, err := s.RegisterProfileResource(ctx, RegisterProfileResourceRequest{ResourceID: "data", ResourceType: ResourceProfileData, AllowedHostDeviceIDs: []string{"device-b"}}); !errors.Is(err, ErrDeviceNotAllowed) {
		t.Fatalf("default host bypassed allowlist: %v", err)
	}
	w08Unchanged(t, s, before)
}

func TestW08HintImportRejectedBeforeWrites(t *testing.T) {
	for _, version := range []int{1, ProfileMeshSnapshotSchemaVersion} {
		for _, relayHint := range []bool{false, true} {
			s, snapshot := w08Service(t)
			before := w08Bytes(t, s)
			snapshot.Profile.DisplayName = "must not persist"
			if relayHint {
				snapshot.RelayHints = []ProfileRelayHint{{ProfileID: "profile", DeviceID: "device-a", RelayProviderID: "relay"}}
			} else {
				snapshot.EndpointHints = []ProfileEndpointHint{{ProfileID: "profile", DeviceID: "device-a", Address: "127.0.0.1"}}
			}
			snapshot.SchemaVersion = version
			snapshot.SnapshotFingerprint = ""
			if version == ProfileMeshSnapshotSchemaVersion {
				snapshot.SnapshotFingerprint = snapshotFingerprint(normalizeProfileMeshSnapshot(snapshot))
			}
			if err := s.ImportProfileMeshSnapshot(context.Background(), snapshot); !errors.Is(err, ErrInvalidProfileSnapshot) {
				t.Fatalf("unsupported hints accepted: %v", err)
			}
			w08Unchanged(t, s, before)
		}
	}
}

func TestW08ImportWriteFailureReportsFailure(t *testing.T) {
	s, snapshot := w08Service(t)
	if err := os.Mkdir(s.store.resourcesPath(), 0700); err != nil {
		t.Fatal(err)
	}
	snapshot.Profile.DisplayName = "partially imported"
	snapshot.SnapshotFingerprint = snapshotFingerprint(normalizeProfileMeshSnapshot(snapshot))
	if err := s.ImportProfileMeshSnapshot(context.Background(), snapshot); !errors.Is(err, ErrStorageUnavailable) {
		t.Fatalf("partial import reported success: %v", err)
	}
}

func TestW08LegacyImportDoesNotRefreshPresence(t *testing.T) {
	s, _ := w08Service(t)
	ctx := context.Background()
	if _, err := s.RegisterProfileResource(ctx, RegisterProfileResourceRequest{ResourceID: "data", ResourceType: ResourceProfileData, CurrentHostDeviceID: "device-a"}); err != nil {
		t.Fatal(err)
	}
	snapshot, err := s.ExportProfileMeshSnapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	s.clock.(*testClock).Add(time.Hour)
	if err := s.ImportProfileMeshSnapshot(ctx, snapshot); !errors.Is(err, ErrDeviceStale) {
		t.Fatalf("schema 2 stale presence accepted: %v", err)
	}
	snapshot.SchemaVersion = 1
	snapshot.SnapshotFingerprint = ""
	if err := s.ImportProfileMeshSnapshot(ctx, snapshot); err != nil {
		t.Fatal(err)
	}
	host, err := s.GetResourceHost(ctx, "data")
	if err != nil || host.HostAvailable {
		t.Fatal("historical import renewed presence", host, err)
	}
}

func TestW08CorruptDefaultHostingCannotBeIgnored(t *testing.T) {
	s, _ := w08Service(t)
	if err := os.WriteFile(s.store.hostingPath(), []byte("broken"), 0600); err != nil {
		t.Fatal(err)
	}
	before := w08Bytes(t, s)
	if _, err := s.RegisterProfileResource(context.Background(), RegisterProfileResourceRequest{ResourceID: "data", ResourceType: ResourceProfileData}); !errors.Is(err, ErrStorageUnavailable) {
		t.Fatalf("corrupt default host ignored: %v", err)
	}
	w08Unchanged(t, s, before)
}
