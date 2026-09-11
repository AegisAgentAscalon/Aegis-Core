package profilemesh_test

import (
	"context"
	"testing"

	"github.com/AegisAgentAscalon/aegis-core/pkg/profilemesh"
)

func TestServiceResultsPreserveEmptyPublicCollections(t *testing.T) {
	ctx := context.Background()
	svc, err := profilemesh.NewService(profilemesh.AppConfig{
		AppID: "compatibility", DisplayName: "Compatibility", Namespace: "profile",
		DataDir: t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = svc.BootstrapProfile(ctx, profilemesh.BootstrapProfileRequest{ProfileID: "profile-1"}); err != nil {
		t.Fatal(err)
	}
	device, err := svc.RegisterProfileDevice(ctx, profilemesh.RegisterProfileDeviceRequest{
		DeviceID: "device-1", PublicKeyFingerprint: "fp-device-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if device.Capabilities == nil {
		t.Fatal("device capabilities must encode as []")
	}
	resource, err := svc.RegisterProfileResource(ctx, profilemesh.RegisterProfileResourceRequest{
		ResourceID: "resource-1", ResourceType: profilemesh.ResourceService,
		CurrentHostDeviceID: "device-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	checkResource := func(resource profilemesh.ProfileResourceRecord) {
		t.Helper()
		if resource.AllowedHostDeviceIDs == nil || resource.Tags == nil {
			t.Fatal("empty public resource collections must encode as []")
		}
	}
	checkResource(resource)
	devices, err := svc.ListProfileDevices(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(devices) != 1 || devices[0].Capabilities == nil {
		t.Fatal("stored device changed public collection shape")
	}
	resources, err := svc.ListProfileResources(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(resources) != 1 {
		t.Fatal("missing stored resource")
	}
	checkResource(resources[0])
	snapshot, err := svc.ExportProfileMeshSnapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Resources) != 1 || snapshot.RelayHints == nil || snapshot.EndpointHints == nil {
		t.Fatal("export changed public collection shape")
	}
	checkResource(snapshot.Resources[0])
}
