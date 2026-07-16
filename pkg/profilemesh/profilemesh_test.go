package profilemesh

import (
	"context"
	"reflect"
	"testing"

	internal "github.com/AegisAgentAscalon/aegis-core/internal/profilemesh"
)

func TestProfileMeshPublicDTOConversionsPreserveSnapshotHints(t *testing.T) {
	internalSnapshot := internal.ProfileMeshSnapshot{
		SchemaVersion: 1,
		AppID:         "aegis-test",
		Namespace:     "profilemesh-test",
		Profile:       internal.ProfileIdentity{ProfileID: "prof_test", AppID: "aegis-test", Namespace: "profilemesh-test"},
		RelayHints: []internal.ProfileRelayHint{{
			ProfileID:       "prof_test",
			DeviceID:        "device-1",
			RelayProviderID: "relay-test",
			EndpointType:    internal.EndpointRelay,
			Capabilities:    []string{"rendezvous"},
			Metadata:        map[string]string{"safe": "value"},
		}},
		EndpointHints: []internal.ProfileEndpointHint{{
			ProfileID:    "prof_test",
			DeviceID:     "device-1",
			EndpointType: internal.EndpointLocal,
			Address:      "127.0.0.1",
			Capabilities: []string{"lan"},
		}},
	}
	publicSnapshot := fromInternalSnapshot(internalSnapshot)
	roundTrip := toInternalSnapshot(publicSnapshot)
	if !reflect.DeepEqual(roundTrip.RelayHints, internalSnapshot.RelayHints) {
		t.Fatalf("relay hints were not preserved: got %+v want %+v", roundTrip.RelayHints, internalSnapshot.RelayHints)
	}
	if !reflect.DeepEqual(roundTrip.EndpointHints, internalSnapshot.EndpointHints) {
		t.Fatalf("endpoint hints were not preserved: got %+v want %+v", roundTrip.EndpointHints, internalSnapshot.EndpointHints)
	}
}

func TestProfileMeshPublicSnapshotFingerprintIsStable(t *testing.T) {
	ctx := context.Background()
	svc, err := NewService(AppConfig{AppID: "aegis-test", DisplayName: "Aegis Test", DataDir: t.TempDir(), Namespace: "profilemesh-test"})
	if err != nil {
		t.Fatalf("NewService returned error: %v", err)
	}
	if _, err := svc.BootstrapProfile(ctx, BootstrapProfileRequest{ProfileID: "prof_test"}); err != nil {
		t.Fatalf("BootstrapProfile returned error: %v", err)
	}
	if _, err := svc.RegisterProfileDevice(ctx, RegisterProfileDeviceRequest{
		DeviceID:             "device-1",
		DisplayName:          "Device 1",
		PublicKeyFingerprint: "fp_test_device_1",
		TrustStatus:          DeviceTrustTrusted,
		Status:               DeviceStatusActive,
	}); err != nil {
		t.Fatalf("RegisterProfileDevice returned error: %v", err)
	}
	snapshot, err := svc.ExportProfileMeshSnapshot(ctx)
	if err != nil {
		t.Fatalf("ExportProfileMeshSnapshot returned error: %v", err)
	}
	importSvc, err := NewService(AppConfig{AppID: "aegis-test", DisplayName: "Aegis Test", DataDir: t.TempDir(), Namespace: "profilemesh-test"})
	if err != nil {
		t.Fatalf("NewService import returned error: %v", err)
	}
	if err := importSvc.ImportProfileMeshSnapshot(ctx, snapshot); err != nil {
		t.Fatalf("ImportProfileMeshSnapshot returned error: %v", err)
	}
	exported, err := importSvc.ExportProfileMeshSnapshot(ctx)
	if err != nil {
		t.Fatalf("ExportProfileMeshSnapshot after import returned error: %v", err)
	}
	if exported.SnapshotFingerprint != snapshot.SnapshotFingerprint {
		t.Fatalf("snapshot fingerprint changed after import/export: got %q want %q", exported.SnapshotFingerprint, snapshot.SnapshotFingerprint)
	}
}

func TestProfileMeshRejectsInvalidPublicEnums(t *testing.T) {
	ctx := context.Background()
	svc, err := NewService(AppConfig{AppID: "aegis-test", DisplayName: "Aegis Test", DataDir: t.TempDir(), Namespace: "profilemesh-test"})
	if err != nil {
		t.Fatalf("NewService returned error: %v", err)
	}
	if _, err := svc.BootstrapProfile(ctx, BootstrapProfileRequest{ProfileID: "prof_test"}); err != nil {
		t.Fatalf("BootstrapProfile returned error: %v", err)
	}
	if _, err := svc.RegisterProfileResource(ctx, RegisterProfileResourceRequest{ResourceID: "resource-1", ResourceType: ProfileResourceType("not-real")}); err == nil {
		t.Fatal("expected invalid resource type to be rejected")
	}
	if _, err := svc.SetProfileHostingMode(ctx, SetProfileHostingModeRequest{HostingMode: HostingMultiProfileDevices}); err == nil {
		t.Fatal("expected deferred multi-host mode to be rejected")
	}
	if _, err := svc.RegisterProfileDeviceStrict(ctx, RegisterProfileDeviceRequest{DeviceID: "device-strict", PublicKeyFingerprint: "fp-device-strict"}); err == nil {
		t.Fatal("expected strict registration to reject implicit trust defaults")
	}
	if _, err := svc.RegisterProfileDeviceStrict(ctx, RegisterProfileDeviceRequest{DeviceID: "device-strict", PublicKeyFingerprint: "fp-device-strict", TrustStatus: DeviceTrustTrusted, Status: DeviceStatusActive}); err != nil {
		t.Fatalf("expected explicit strict registration to succeed: %v", err)
	}
}
