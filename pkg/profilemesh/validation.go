package profilemesh

import (
	"strings"
	"time"
)

func validateSnapshot(snapshot ProfileMeshSnapshot, now time.Time) error {
	devices := map[string]ProfileDeviceRecord{}
	for _, device := range snapshot.Devices {
		if device.DeviceID == "" || !validID(device.DeviceID) || !validFingerprint(device.PublicKeyFingerprint) {
			return ErrInvalidProfileSnapshot
		}
		if !validDeviceTrustStatus(device.TrustStatus) || !validDeviceStatus(device.Status) || device.RegisteredAt.IsZero() || device.UpdatedAt.IsZero() || device.UpdatedAt.Before(device.RegisteredAt) || device.ProfileMetadataVersion != metadataVersion {
			return ErrInvalidProfileSnapshot
		}
		if !device.LastSeen.IsZero() && (device.LastSeen.Before(device.RegisteredAt) || device.LastSeen.After(device.UpdatedAt)) {
			return ErrInvalidProfileSnapshot
		}
		if device.Status == DeviceStatusRemoved {
			if device.TrustStatus != DeviceTrustRevoked || device.RemovedAt == nil || device.RemovedAt.Before(device.RegisteredAt) || device.RemovedAt.After(device.UpdatedAt) {
				return ErrInvalidProfileSnapshot
			}
		} else if device.RemovedAt != nil {
			return ErrInvalidProfileSnapshot
		}
		if _, ok := devices[device.DeviceID]; ok {
			return ErrInvalidProfileSnapshot
		}
		devices[device.DeviceID] = device
	}
	resources := map[string]bool{}
	for _, resource := range snapshot.Resources {
		if err := validateResource(resource, snapshot.Profile.ProfileID, devices, now); err != nil {
			if err == ErrInvalidResource {
				return ErrInvalidProfileSnapshot
			}
			return err
		}
		if resources[resource.ResourceID] {
			return ErrInvalidProfileSnapshot
		}
		resources[resource.ResourceID] = true
	}
	if snapshot.HostingConfig.HostingMode == HostingMultiProfileDevices {
		return ErrUnsupportedHostingMode
	}
	if snapshot.HostingConfig.HostingMode != HostingSingleProfileDevice {
		return ErrInvalidProfileSnapshot
	}
	for _, id := range []string{snapshot.HostingConfig.PrimaryProfileDeviceID, snapshot.HostingConfig.ProfileDataHostDeviceID} {
		if id != "" {
			if err := validateHost(id, devices, now); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateResource(resource ProfileResourceRecord, profileID string, devices map[string]ProfileDeviceRecord, now time.Time) error {
	if !validID(resource.ResourceID) || !validResourceType(resource.ResourceType) || resource.ProfileOwnerID != profileID || !validAvailability(resource.Availability) {
		return ErrInvalidResource
	}
	if resource.HostingMode != ResourceHostingSingleHost {
		return ErrUnsupportedHostingMode
	}
	for _, id := range resource.AllowedHostDeviceIDs {
		if err := validateHost(id, devices, now); err != nil {
			return err
		}
	}
	if host := resource.CurrentHostDeviceID; host != "" {
		if err := validateHost(host, devices, now); err != nil {
			return err
		}
		if len(resource.AllowedHostDeviceIDs) > 0 && !contains(resource.AllowedHostDeviceIDs, host) {
			return ErrDeviceNotAllowed
		}
	}
	return nil
}

func validateHost(id string, devices map[string]ProfileDeviceRecord, now time.Time) error {
	device, ok := devices[id]
	if !ok {
		return ErrDeviceNotAllowed
	}
	return validateActiveDevice(device, now)
}

func validateActiveDevice(device ProfileDeviceRecord, now time.Time) error {
	if device.Status == DeviceStatusRemoved || device.Status == DeviceStatusRevoked || device.TrustStatus == DeviceTrustRevoked {
		return ErrDeviceRevoked
	}
	if device.Status == DeviceStatusStale || device.TrustStatus == DeviceTrustStale || isStale(now, device.LastSeen) {
		return ErrDeviceStale
	}
	if !isDeviceUsable(device) {
		return ErrDeviceNotAllowed
	}
	return nil
}

func validResourceType(rt ProfileResourceType) bool {
	switch rt {
	case ResourceProfileData, ResourceService, ResourceConnector, ResourceRuntime, ResourceTool, ResourceOther:
		return true
	default:
		return false
	}
}

func validAvailability(a ProfileResourceAvailability) bool {
	switch a {
	case ResourceAvailable, ResourceUnavailable, ResourceStale, ResourceMigrating, ResourceUnknown:
		return true
	default:
		return false
	}
}

func validDeviceTrustStatus(status ProfileDeviceTrustStatus) bool {
	switch status {
	case DeviceTrustUnknown, DeviceTrustTrusted, DeviceTrustRevoked, DeviceTrustStale:
		return true
	default:
		return false
	}
}

func validDeviceStatus(status ProfileDeviceStatus) bool {
	switch status {
	case DeviceStatusActive, DeviceStatusStale, DeviceStatusRevoked, DeviceStatusRemoved:
		return true
	default:
		return false
	}
}

func validStrictDeviceLifecycle(trust ProfileDeviceTrustStatus, status ProfileDeviceStatus) bool {
	switch status {
	case DeviceStatusActive:
		return trust == DeviceTrustTrusted
	case DeviceStatusStale:
		return trust == DeviceTrustStale
	case DeviceStatusRevoked, DeviceStatusRemoved:
		return trust == DeviceTrustRevoked
	default:
		return false
	}
}

func latestTime(values ...time.Time) time.Time {
	var latest time.Time
	for _, value := range values {
		if value.After(latest) {
			latest = value
		}
	}
	return latest.UTC()
}

func displayOrID(displayName, id string) string {
	if displayName != "" {
		return displayName
	}
	return id
}

func stringsTrim(s string) string {
	return strings.TrimSpace(s)
}

func contains(items []string, item string) bool {
	for _, value := range items {
		if value == item {
			return true
		}
	}
	return false
}

func isDeviceUsable(device ProfileDeviceRecord) bool {
	return device.TrustStatus == DeviceTrustTrusted && device.Status == DeviceStatusActive
}

func isStale(now, lastSeen time.Time) bool {
	return !lastSeen.IsZero() && (lastSeen.After(now.Add(defaultFutureSkew)) || now.Sub(lastSeen) > defaultStaleAge)
}
