package profilemesh

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *testClock) Add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func testConfig(t *testing.T, namespace string) AppConfig {
	t.Helper()
	return AppConfig{AppID: "sample-app", DisplayName: "Sample App", DataDir: t.TempDir(), Namespace: namespace}
}

func newTestService(t *testing.T, namespace string, opts ...Option) *Service {
	t.Helper()
	svc, err := NewService(testConfig(t, namespace), opts...)
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

func TestValidateConfigRejectsUnsafeNames(t *testing.T) {
	cases := []AppConfig{
		{AppID: "", DisplayName: "App", DataDir: t.TempDir(), Namespace: "safe"},
		{AppID: "../bad", DisplayName: "App", DataDir: t.TempDir(), Namespace: "safe"},
		{AppID: "bad/app", DisplayName: "App", DataDir: t.TempDir(), Namespace: "safe"},
		{AppID: "safe", DisplayName: "", DataDir: t.TempDir(), Namespace: "safe"},
		{AppID: "safe", DisplayName: "App", DataDir: "", Namespace: "safe"},
		{AppID: "safe", DisplayName: "App", DataDir: t.TempDir(), Namespace: ""},
		{AppID: "safe", DisplayName: "App", DataDir: t.TempDir(), Namespace: "..\\bad"},
		{AppID: "safe", DisplayName: "App", DataDir: t.TempDir(), Namespace: "bad/ns"},
	}
	for _, cfg := range cases {
		if err := ValidateConfig(cfg); err == nil {
			t.Fatalf("expected config error for %+v", cfg)
		}
	}
	if err := ValidateConfig(AppConfig{AppID: "Aegis.Sample_01", DisplayName: "App", DataDir: t.TempDir(), Namespace: "profile-01"}); err != nil {
		t.Fatalf("expected valid config, got %v", err)
	}
}

func TestBootstrapProfileIdempotentAndCorruptStorage(t *testing.T) {
	svc := newTestService(t, "profile")
	if _, err := svc.GetProfile(context.Background()); !errors.Is(err, ErrProfileNotFound) {
		t.Fatalf("expected missing profile, got %v", err)
	}
	first, err := svc.BootstrapProfile(context.Background(), BootstrapProfileRequest{DisplayName: "Profile"})
	if err != nil {
		t.Fatal(err)
	}
	second, err := svc.BootstrapProfile(context.Background(), BootstrapProfileRequest{DisplayName: "Other"})
	if err != nil {
		t.Fatal(err)
	}
	if first.ProfileID != second.ProfileID || second.DisplayName != "Profile" {
		t.Fatalf("bootstrap should be idempotent, got %+v %+v", first, second)
	}
	hosting, err := svc.GetProfileHostingConfig(context.Background())
	if err != nil || hosting.HostingMode != HostingSingleProfileDevice {
		t.Fatalf("expected default single hosted mode, got %+v %v", hosting, err)
	}
	if err := os.WriteFile(svc.store.profilePath(), []byte(`{bad-json`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.GetProfile(context.Background()); !errors.Is(err, ErrStorageUnavailable) {
		t.Fatalf("expected safe corrupt profile error, got %v", err)
	} else if strings.Contains(err.Error(), svc.store.dir) {
		t.Fatalf("profile error leaked path")
	}
}

func TestHostingConfigRequiresRegisteredActiveDevice(t *testing.T) {
	svc := newTestService(t, "profile")
	if _, err := svc.BootstrapProfile(context.Background(), BootstrapProfileRequest{}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.SetProfileHostingMode(context.Background(), SetProfileHostingModeRequest{HostingMode: HostingSingleProfileDevice, ProfileDataHostDeviceID: "missing"}); !errors.Is(err, ErrDeviceNotRegistered) {
		t.Fatalf("expected missing host rejection, got %v", err)
	}
	device := registerDevice(t, svc, "device-1")
	hosting, err := svc.SetProfileHostingMode(context.Background(), SetProfileHostingModeRequest{HostingMode: HostingSingleProfileDevice, PrimaryProfileDeviceID: device.DeviceID, ProfileDataHostDeviceID: device.DeviceID, LocalCacheEnabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if hosting.ProfileDataHostDeviceID != device.DeviceID {
		t.Fatalf("expected profile kb host, got %+v", hosting)
	}
	if _, err := svc.SetProfileHostingMode(context.Background(), SetProfileHostingModeRequest{HostingMode: HostingMultiProfileDevices}); !errors.Is(err, ErrUnsupportedHostingMode) {
		t.Fatalf("expected multi-host unsupported, got %v", err)
	}
	if err := svc.RemoveProfileDevice(context.Background(), device.DeviceID); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.SetProfileHostingMode(context.Background(), SetProfileHostingModeRequest{HostingMode: HostingSingleProfileDevice, ProfileDataHostDeviceID: device.DeviceID}); !errors.Is(err, ErrDeviceRevoked) {
		t.Fatalf("expected removed host rejection, got %v", err)
	}
}

func TestDeviceRegistryLifecycle(t *testing.T) {
	svc := newTestService(t, "profile")
	if _, err := svc.BootstrapProfile(context.Background(), BootstrapProfileRequest{}); err != nil {
		t.Fatal(err)
	}
	device := registerDevice(t, svc, "device-1")
	again, err := svc.RegisterProfileDevice(context.Background(), RegisterProfileDeviceRequest{DeviceID: device.DeviceID, DisplayName: "Updated", PublicKeyFingerprint: device.PublicKeyFingerprint})
	if err != nil || again.DisplayName != "Updated" {
		t.Fatalf("expected duplicate update, got %+v %v", again, err)
	}
	if _, err := svc.RegisterProfileDevice(context.Background(), RegisterProfileDeviceRequest{DeviceID: device.DeviceID, PublicKeyFingerprint: "different"}); !errors.Is(err, ErrDeviceNotAllowed) {
		t.Fatalf("expected conflicting fingerprint rejection, got %v", err)
	}
	list, err := svc.ListProfileDevices(context.Background())
	if err != nil || len(list) != 1 {
		t.Fatalf("expected one device, got %+v %v", list, err)
	}
	if err := os.WriteFile(svc.store.devicesPath(), []byte(`{bad-json`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ListProfileDevices(context.Background()); !errors.Is(err, ErrStorageUnavailable) {
		t.Fatalf("expected corrupt registry error, got %v", err)
	}
}

func TestStrictDeviceRegistrationRequiresExplicitTrustState(t *testing.T) {
	svc := newTestService(t, "strict-profile")
	if _, err := svc.BootstrapProfile(context.Background(), BootstrapProfileRequest{}); err != nil {
		t.Fatal(err)
	}
	legacy, err := svc.RegisterProfileDevice(context.Background(), RegisterProfileDeviceRequest{DeviceID: "legacy-device", PublicKeyFingerprint: "fp-legacy-device"})
	if err != nil || legacy.TrustStatus != DeviceTrustTrusted || legacy.Status != DeviceStatusActive {
		t.Fatalf("legacy registration compatibility changed: %+v %v", legacy, err)
	}
	if _, err := svc.RegisterProfileDeviceStrict(context.Background(), RegisterProfileDeviceRequest{DeviceID: "strict-missing", PublicKeyFingerprint: "fp-strict-missing"}); !errors.Is(err, ErrDeviceNotAllowed) {
		t.Fatalf("strict registration without trust state error = %v, want ErrDeviceNotAllowed", err)
	}
	strict, err := svc.RegisterProfileDeviceStrict(context.Background(), RegisterProfileDeviceRequest{DeviceID: "strict-device", PublicKeyFingerprint: "fp-strict-device", TrustStatus: DeviceTrustTrusted, Status: DeviceStatusActive})
	if err != nil || strict.TrustStatus != DeviceTrustTrusted || strict.Status != DeviceStatusActive {
		t.Fatalf("explicit strict registration failed: %+v %v", strict, err)
	}
	if _, err := svc.RegisterProfileDeviceStrict(context.Background(), RegisterProfileDeviceRequest{DeviceID: "strict-invalid", PublicKeyFingerprint: "fp-strict-invalid", TrustStatus: "accepted", Status: DeviceStatusActive}); !errors.Is(err, ErrDeviceNotAllowed) {
		t.Fatalf("invalid explicit trust state error = %v, want ErrDeviceNotAllowed", err)
	}
}

func TestResourceRegistryProfileOwnedDeviceHosted(t *testing.T) {
	svc := newTestService(t, "profile")
	profile, _ := svc.BootstrapProfile(context.Background(), BootstrapProfileRequest{})
	device := registerDevice(t, svc, "device-1")
	if _, err := svc.SetProfileHostingMode(context.Background(), SetProfileHostingModeRequest{HostingMode: HostingSingleProfileDevice, ProfileDataHostDeviceID: device.DeviceID, LocalCacheEnabled: true}); err != nil {
		t.Fatal(err)
	}
	kb, err := svc.RegisterProfileResource(context.Background(), RegisterProfileResourceRequest{ResourceID: "profile-kb", ResourceType: ResourceProfileData, DisplayName: "Profile data"})
	if err != nil {
		t.Fatal(err)
	}
	if kb.ProfileOwnerID != profile.ProfileID || kb.CurrentHostDeviceID != device.DeviceID {
		t.Fatalf("resource should be profile-owned/device-hosted, got %+v", kb)
	}
	if _, err := svc.RegisterProfileResource(context.Background(), RegisterProfileResourceRequest{ResourceID: "profile-kb", ResourceType: ResourceProfileData}); !errors.Is(err, ErrInvalidResource) {
		t.Fatalf("expected duplicate resource rejection, got %v", err)
	}
	if _, err := svc.RegisterProfileResource(context.Background(), RegisterProfileResourceRequest{ResourceID: "bad", ResourceType: "unsupported"}); !errors.Is(err, ErrInvalidResource) {
		t.Fatalf("expected unsupported resource type, got %v", err)
	}
	if _, err := svc.SetResourceHost(context.Background(), SetResourceHostRequest{ResourceID: kb.ResourceID, DeviceID: "missing"}); !errors.Is(err, ErrDeviceNotRegistered) {
		t.Fatalf("expected missing host rejection, got %v", err)
	}
	status, err := svc.GetResourceHost(context.Background(), kb.ResourceID)
	if err != nil || !status.HostAvailable {
		t.Fatalf("expected available host, got %+v %v", status, err)
	}
	if _, err := svc.GetResourceHost(context.Background(), "missing"); !errors.Is(err, ErrResourceNotFound) {
		t.Fatalf("expected missing resource, got %v", err)
	}
}

func TestResourceHostRejectsStaleDevice(t *testing.T) {
	clock := &testClock{now: time.Now().UTC()}
	svc := newTestService(t, "profile", WithClock(clock))
	if _, err := svc.BootstrapProfile(context.Background(), BootstrapProfileRequest{}); err != nil {
		t.Fatal(err)
	}
	device := registerDevice(t, svc, "device-1")
	if _, err := svc.RegisterProfileResource(context.Background(), RegisterProfileResourceRequest{ResourceID: "service-1", ResourceType: ResourceService}); err != nil {
		t.Fatal(err)
	}
	clock.Add(defaultStaleAge + time.Second)
	if _, err := svc.SetResourceHost(context.Background(), SetResourceHostRequest{ResourceID: "service-1", DeviceID: device.DeviceID}); !errors.Is(err, ErrDeviceStale) {
		t.Fatalf("expected stale host rejection, got %v", err)
	}
}

func TestSnapshotExportImportValidation(t *testing.T) {
	svc := newTestService(t, "profile")
	profile, _ := svc.BootstrapProfile(context.Background(), BootstrapProfileRequest{})
	device := registerDevice(t, svc, "device-1")
	if _, err := svc.RegisterProfileResource(context.Background(), RegisterProfileResourceRequest{ResourceID: "tool-1", ResourceType: ResourceTool, CurrentHostDeviceID: device.DeviceID}); err != nil {
		t.Fatal(err)
	}
	snap, err := svc.ExportProfileMeshSnapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	other := newTestService(t, "profile")
	if err := other.ImportProfileMeshSnapshot(context.Background(), snap); err != nil {
		t.Fatal(err)
	}
	tampered := snap
	tampered.Resources[0].CurrentHostDeviceID = "missing"
	if err := other.ImportProfileMeshSnapshot(context.Background(), tampered); !errors.Is(err, ErrInvalidProfileSnapshot) {
		t.Fatalf("expected fingerprint tamper rejection, got %v", err)
	}
	wrong := snap
	wrong.Namespace = "wrong"
	if err := other.ImportProfileMeshSnapshot(context.Background(), wrong); !errors.Is(err, ErrInvalidProfileSnapshot) {
		t.Fatalf("expected wrong namespace rejection, got %v", err)
	}
	unsafe := snap
	unsafe.SnapshotFingerprint = ""
	unsafe.Resources[0].CurrentHostDeviceID = "missing"
	if err := other.ImportProfileMeshSnapshot(context.Background(), unsafe); !errors.Is(err, ErrDeviceNotAllowed) {
		t.Fatalf("expected unsafe host rejection, got %v", err)
	}
	duplicate := snap
	duplicate.SnapshotFingerprint = ""
	duplicate.Devices = append(duplicate.Devices, ProfileDeviceRecord{DeviceID: device.DeviceID, PublicKeyFingerprint: "different", Status: DeviceStatusActive, TrustStatus: DeviceTrustTrusted})
	if err := other.ImportProfileMeshSnapshot(context.Background(), duplicate); !errors.Is(err, ErrInvalidProfileSnapshot) {
		t.Fatalf("expected duplicate conflict rejection, got %v", err)
	}
	if profile.ProfileID == "" {
		t.Fatalf("expected profile id")
	}
}

func TestProfileMeshFingerprintCoversTrustCapabilityAndTimestampFields(t *testing.T) {
	svc := newTestService(t, "fingerprint-profile")
	profile, err := svc.BootstrapProfile(context.Background(), BootstrapProfileRequest{})
	if err != nil {
		t.Fatal(err)
	}
	device := registerDevice(t, svc, "device-1")
	if _, err := svc.RegisterProfileResource(context.Background(), RegisterProfileResourceRequest{ResourceID: "tool-1", ResourceType: ResourceTool, CurrentHostDeviceID: device.DeviceID, AllowedHostDeviceIDs: []string{device.DeviceID}}); err != nil {
		t.Fatal(err)
	}
	snapshot, err := svc.ExportProfileMeshSnapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	now := snapshot.UpdatedAt
	snapshot.RelayHints = []ProfileRelayHint{{ProfileID: profile.ProfileID, DeviceID: device.DeviceID, RelayProviderID: "relay-1", EndpointType: EndpointRelay, ExpiresAt: now.Add(time.Hour), LastSeen: now, Capabilities: []string{"rendezvous"}}}
	snapshot.EndpointHints = []ProfileEndpointHint{{ProfileID: profile.ProfileID, DeviceID: device.DeviceID, EndpointType: EndpointLocal, Address: "127.0.0.1", ExpiresAt: now.Add(time.Hour), LastSeen: now, Capabilities: []string{"lan"}}}
	baseFingerprint := snapshotFingerprint(snapshot)
	tests := map[string]func(*ProfileMeshSnapshot){
		"snapshot created at":     func(s *ProfileMeshSnapshot) { s.CreatedAt = s.CreatedAt.Add(time.Second) },
		"snapshot updated at":     func(s *ProfileMeshSnapshot) { s.UpdatedAt = s.UpdatedAt.Add(time.Second) },
		"profile created at":      func(s *ProfileMeshSnapshot) { s.Profile.CreatedAt = s.Profile.CreatedAt.Add(time.Second) },
		"profile updated at":      func(s *ProfileMeshSnapshot) { s.Profile.UpdatedAt = s.Profile.UpdatedAt.Add(time.Second) },
		"hosting updated at":      func(s *ProfileMeshSnapshot) { s.HostingConfig.UpdatedAt = s.HostingConfig.UpdatedAt.Add(time.Second) },
		"device trust":            func(s *ProfileMeshSnapshot) { s.Devices[0].TrustStatus = DeviceTrustRevoked },
		"device status":           func(s *ProfileMeshSnapshot) { s.Devices[0].Status = DeviceStatusStale },
		"device capabilities":     func(s *ProfileMeshSnapshot) { s.Devices[0].Capabilities = append(s.Devices[0].Capabilities, "runtime") },
		"device last seen":        func(s *ProfileMeshSnapshot) { s.Devices[0].LastSeen = s.Devices[0].LastSeen.Add(time.Second) },
		"device registered at":    func(s *ProfileMeshSnapshot) { s.Devices[0].RegisteredAt = s.Devices[0].RegisteredAt.Add(time.Second) },
		"device updated at":       func(s *ProfileMeshSnapshot) { s.Devices[0].UpdatedAt = s.Devices[0].UpdatedAt.Add(time.Second) },
		"device removed at":       func(s *ProfileMeshSnapshot) { value := now.Add(time.Second); s.Devices[0].RemovedAt = &value },
		"device metadata version": func(s *ProfileMeshSnapshot) { s.Devices[0].ProfileMetadataVersion++ },
		"resource host policy": func(s *ProfileMeshSnapshot) {
			s.Resources[0].AllowedHostDeviceIDs = append(s.Resources[0].AllowedHostDeviceIDs, "device-2")
		},
		"resource updated at": func(s *ProfileMeshSnapshot) { s.Resources[0].UpdatedAt = s.Resources[0].UpdatedAt.Add(time.Second) },
		"relay capabilities": func(s *ProfileMeshSnapshot) {
			s.RelayHints[0].Capabilities = append(s.RelayHints[0].Capabilities, "proof")
		},
		"relay last seen":  func(s *ProfileMeshSnapshot) { s.RelayHints[0].LastSeen = s.RelayHints[0].LastSeen.Add(time.Second) },
		"relay expiration": func(s *ProfileMeshSnapshot) { s.RelayHints[0].ExpiresAt = s.RelayHints[0].ExpiresAt.Add(time.Second) },
		"endpoint capabilities": func(s *ProfileMeshSnapshot) {
			s.EndpointHints[0].Capabilities = append(s.EndpointHints[0].Capabilities, "proof")
		},
		"endpoint last seen": func(s *ProfileMeshSnapshot) {
			s.EndpointHints[0].LastSeen = s.EndpointHints[0].LastSeen.Add(time.Second)
		},
		"endpoint expiration": func(s *ProfileMeshSnapshot) {
			s.EndpointHints[0].ExpiresAt = s.EndpointHints[0].ExpiresAt.Add(time.Second)
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			copy := cloneProfileMeshSnapshot(t, snapshot)
			mutate(&copy)
			if got := snapshotFingerprint(copy); got == baseFingerprint {
				t.Fatalf("fingerprint did not cover %s", name)
			}
		})
	}
}

func TestOverviewStates(t *testing.T) {
	svc := newTestService(t, "profile")
	overview, err := svc.BuildProfileMeshOverview(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if overview.Ready || len(overview.Issues) == 0 || !strings.Contains(overview.Message, "profile") {
		t.Fatalf("expected not bootstrapped profile overview, got %+v", overview)
	}
	if _, err := svc.BootstrapProfile(context.Background(), BootstrapProfileRequest{}); err != nil {
		t.Fatal(err)
	}
	overview, err = svc.BuildProfileMeshOverview(context.Background())
	if err != nil || !overview.Ready || len(overview.Warnings) == 0 {
		t.Fatalf("expected bootstrapped profile warning, got %+v %v", overview, err)
	}
	device := registerDevice(t, svc, "device-1")
	if _, err := svc.SetProfileHostingMode(context.Background(), SetProfileHostingModeRequest{HostingMode: HostingSingleProfileDevice, ProfileDataHostDeviceID: device.DeviceID, LocalCacheEnabled: true}); err != nil {
		t.Fatal(err)
	}
	overview, err = svc.BuildProfileMeshOverview(context.Background())
	if err != nil || !overview.Ready || overview.ProfileDataHostDeviceID != device.DeviceID {
		t.Fatalf("expected ready overview, got %+v %v", overview, err)
	}
}

func TestConcurrentProfileOperations(t *testing.T) {
	svc := newTestService(t, "profile")
	var wg sync.WaitGroup
	errs := make(chan error, 16)
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := svc.BootstrapProfile(context.Background(), BootstrapProfileRequest{})
			errs <- err
		}()
	}
	wg.Wait()
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := svc.RegisterProfileDevice(context.Background(), RegisterProfileDeviceRequest{DeviceID: "device-" + string(rune('a'+i)), PublicKeyFingerprint: "fp-" + string(rune('a'+i)) + "123"})
			errs <- err
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("unexpected concurrent error: %v", err)
		}
	}
	devices, err := svc.ListProfileDevices(context.Background())
	if err != nil || len(devices) != 6 {
		t.Fatalf("expected six devices, got %+v %v", devices, err)
	}
}

func TestProfileMeshTreatsFutureDatedPresenceAsStale(t *testing.T) {
	now := time.Now().UTC()
	if !isStale(now, now.Add(defaultFutureSkew+time.Second)) {
		t.Fatal("future-dated profile device presence was treated as fresh")
	}
	if isStale(now, now.Add(defaultFutureSkew-time.Second)) {
		t.Fatal("presence within permitted clock skew was treated as stale")
	}
}

func TestProfileMeshRejectsWindowsReservedNamespaceWithExtension(t *testing.T) {
	if _, err := NewService(testConfig(t, "LPT1.profile")); !errors.Is(err, ErrInvalidNamespace) {
		t.Fatalf("reserved namespace error = %v", err)
	}
}

func registerDevice(t *testing.T, svc *Service, deviceID string) ProfileDeviceRecord {
	t.Helper()
	device, err := svc.RegisterProfileDevice(context.Background(), RegisterProfileDeviceRequest{
		DeviceID:             deviceID,
		DisplayName:          deviceID,
		PublicKeyFingerprint: "fp-" + deviceID + "-12345",
		Capabilities:         []string{"service", "tool", "service"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return device
}

func cloneProfileMeshSnapshot(t *testing.T, snapshot ProfileMeshSnapshot) ProfileMeshSnapshot {
	t.Helper()
	raw, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	var cloned ProfileMeshSnapshot
	if err := json.Unmarshal(raw, &cloned); err != nil {
		t.Fatal(err)
	}
	return cloned
}
