package profilemesh

import "slices"

// Stored validity is independent of wall-clock availability and preserves the
// zero/backward times and non-strict lifecycle combinations existing APIs write.
func validateStoredMesh(cfg AppConfig, state *meshState) error {
	if state.Version != 1 || state.Devices.SchemaVersion != 1 || state.Resources.SchemaVersion != 1 {
		return ErrStorageUnavailable
	}
	if state.Profile == nil {
		if state.Hosting != nil || len(state.Devices.Devices) > 0 || len(state.Resources.Resources) > 0 || len(state.RelayHints) > 0 || len(state.EndpointHints) > 0 {
			return ErrStorageUnavailable
		}
		return nil
	}
	profile := state.Profile
	if profile.ProfileID == "" || profile.AppID != cfg.AppID || profile.Namespace != cfg.Namespace {
		return ErrStorageUnavailable
	}
	devices := make(map[string]ProfileDeviceRecord, len(state.Devices.Devices))
	for _, device := range state.Devices.Devices {
		if !validID(device.DeviceID) || !validFingerprint(device.PublicKeyFingerprint) || !validDeviceTrustStatus(device.TrustStatus) || !validDeviceStatus(device.Status) || device.ProfileMetadataVersion != 1 {
			return ErrStorageUnavailable
		}
		if device.Status == DeviceStatusRemoved {
			if device.TrustStatus != DeviceTrustRevoked || device.RemovedAt == nil {
				return ErrStorageUnavailable
			}
		} else if device.RemovedAt != nil {
			return ErrStorageUnavailable
		}
		if _, ok := devices[device.DeviceID]; ok {
			return ErrStorageUnavailable
		}
		devices[device.DeviceID] = device
	}
	if state.Hosting != nil {
		if state.Hosting.HostingMode != HostingSingleProfileDevice {
			return ErrStorageUnavailable
		}
		for _, id := range []string{state.Hosting.PrimaryProfileDeviceID, state.Hosting.ProfileDataHostDeviceID} {
			if id != "" {
				if _, ok := devices[id]; !ok {
					return ErrStorageUnavailable
				}
			}
		}
	}
	resources := make(map[string]bool, len(state.Resources.Resources))
	for _, resource := range state.Resources.Resources {
		if !validID(resource.ResourceID) || !validResourceType(resource.ResourceType) || !validAvailability(resource.Availability) || resource.HostingMode != ResourceHostingSingleHost || resource.ProfileOwnerID != profile.ProfileID || resources[resource.ResourceID] {
			return ErrStorageUnavailable
		}
		resources[resource.ResourceID] = true
		for _, id := range resource.AllowedHostDeviceIDs {
			if !validID(id) {
				return ErrStorageUnavailable
			}
			if _, ok := devices[id]; !ok {
				return ErrStorageUnavailable
			}
		}
		if id := resource.CurrentHostDeviceID; id != "" {
			if _, ok := devices[id]; !ok {
				return ErrStorageUnavailable
			}
			if len(resource.AllowedHostDeviceIDs) > 0 && !slices.Contains(resource.AllowedHostDeviceIDs, id) {
				return ErrStorageUnavailable
			}
		}
	}
	snapshot := ProfileMeshSnapshot{SchemaVersion: 2, Profile: *profile, Devices: state.Devices.Devices, RelayHints: state.RelayHints, EndpointHints: state.EndpointHints}
	if err := validateHintFields(snapshot, zeroHintTime, false); err != nil {
		return ErrStorageUnavailable
	}
	return nil
}
