package profilemesh

import (
	"strings"
	"time"
)

func validateSnapshot(snapshot ProfileMeshSnapshot) error {
	devices := map[string]string{}
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
		if old, ok := devices[device.DeviceID]; ok {
			if old != device.PublicKeyFingerprint {
				return ErrInvalidProfileSnapshot
			}
			return ErrInvalidProfileSnapshot
		}
		devices[device.DeviceID] = device.PublicKeyFingerprint
	}
	resources := map[string]bool{}
	for _, resource := range snapshot.Resources {
		if resource.ResourceID == "" || !validID(resource.ResourceID) || !validResourceType(resource.ResourceType) || resource.ProfileOwnerID != snapshot.Profile.ProfileID {
			return ErrInvalidProfileSnapshot
		}
		if resources[resource.ResourceID] {
			return ErrInvalidProfileSnapshot
		}
		resources[resource.ResourceID] = true
		if resource.CurrentHostDeviceID != "" {
			if _, ok := devices[resource.CurrentHostDeviceID]; !ok {
				return ErrDeviceNotAllowed
			}
		}
	}
	if snapshot.HostingConfig.HostingMode == HostingMultiProfileDevices {
		return ErrUnsupportedHostingMode
	}
	if snapshot.HostingConfig.HostingMode != HostingSingleProfileDevice {
		return ErrInvalidProfileSnapshot
	}
	if snapshot.HostingConfig.PrimaryProfileDeviceID != "" {
		if _, ok := devices[snapshot.HostingConfig.PrimaryProfileDeviceID]; !ok {
			return ErrDeviceNotAllowed
		}
	}
	if snapshot.HostingConfig.ProfileDataHostDeviceID != "" {
		if _, ok := devices[snapshot.HostingConfig.ProfileDataHostDeviceID]; !ok {
			return ErrDeviceNotAllowed
		}
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
