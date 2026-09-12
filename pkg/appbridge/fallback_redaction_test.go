package appbridge

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/AegisAgentAscalon/aegis-core/pkg/auth"
	"github.com/AegisAgentAscalon/aegis-core/pkg/devicelink"
	"github.com/AegisAgentAscalon/aegis-core/pkg/profilemesh"
)

type fallbackProvider struct {
	AuthService
	id, name string
}

func (p fallbackProvider) Status(context.Context) (auth.AuthStatus, error) {
	return auth.AuthStatus{AppID: p.id, DisplayName: p.name}, nil
}
func (p fallbackProvider) GetCurrentDevice(context.Context) (devicelink.DeviceIdentity, error) {
	return devicelink.DeviceIdentity{DeviceID: "local"}, nil
}
func (p fallbackProvider) ListTrustedDevices(context.Context) ([]devicelink.TrustedDevice, error) {
	return []devicelink.TrustedDevice{{DeviceID: p.id, DisplayName: p.name}}, nil
}
func (p fallbackProvider) BuildProfileMeshOverview(context.Context) (profilemesh.ProfileMeshOverview, error) {
	return profilemesh.ProfileMeshOverview{}, nil
}
func (p fallbackProvider) ListProfileResources(context.Context) ([]profilemesh.ProfileResourceRecord, error) {
	return []profilemesh.ProfileResourceRecord{{ResourceID: p.id, DisplayName: p.name}}, nil
}

func TestStatusDisplayFallbacksAreRedacted(t *testing.T) {
	for _, id := range []string{"access_token=private", `C:\Users\private\credentials`, "safe-id"} {
		for _, name := range []string{"", "secret=private", "Safe display"} {
			t.Run(id+"/"+name, func(t *testing.T) {
				p := fallbackProvider{id: id, name: name}
				enabled := CapabilityConfig{Enabled: true}
				b, err := NewSetupBridge(AppBridgeConfig{
					Identity:    AppIdentity{AppID: "test-app", DisplayName: "Test app"},
					Auth:        AuthBridgeConfig{CapabilityConfig: enabled, Service: p},
					DeviceLink:  DeviceLinkBridgeConfig{CapabilityConfig: enabled, Service: p},
					ProfileMesh: ProfileMeshBridgeConfig{CapabilityConfig: enabled, Service: p},
				})
				if err != nil {
					t.Fatal(err)
				}
				a, err := b.AuthStatus(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				d, err := b.DeviceLinkStatus(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				m, err := b.ProfileMeshStatus(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				want := ""
				if name == "Safe display" {
					want = name
				} else if id == "safe-id" {
					want = id
				}
				for _, display := range []string{a.Status.DisplayName, d.TrustedDevices[0].DisplayName, m.HostedResources[0].DisplayName} {
					if display != want {
						t.Errorf("display = %q, want %q", display, want)
					}
				}
				raw, err := json.Marshal([]any{a, d, m})
				if err != nil {
					t.Fatal(err)
				}
				if strings.Contains(string(raw), "private") {
					t.Fatalf("unsafe provider detail reached JSON: %s", raw)
				}
			})
		}
	}
}
