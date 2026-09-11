package profilemesh

import (
	"context"
	"errors"
	"os"
)

func (s *Service) BuildProfileMeshOverview(ctx context.Context) (ProfileMeshOverview, error) {
	if err := contextError(ctx); err != nil {
		return ProfileMeshOverview{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	overview := ProfileMeshOverview{AppID: s.cfg.AppID, Namespace: s.cfg.Namespace, DisplayName: s.cfg.DisplayName, Ready: true, HostingMode: HostingSingleProfileDevice}
	profile, err := s.store.readProfile()
	if err != nil {
		if errors.Is(err, ErrProfileNotFound) {
			overview.Ready = false
			overview.Message = "profile mesh is not bootstrapped"
			overview.Issues = append(overview.Issues, ProfileMeshIssue{Code: "profile_not_bootstrapped", Message: "profile mesh is not bootstrapped", Blocking: true})
			return overview, nil
		}
		return ProfileMeshOverview{}, err
	}
	overview.ProfileID = profile.ProfileID
	overview.Bootstrapped = true
	hosting, err := s.store.readHosting()
	if errors.Is(err, os.ErrNotExist) {
		hosting = defaultHostingConfig(s.clock.Now())
	} else if err != nil {
		return ProfileMeshOverview{}, err
	}
	overview.HostingMode = hosting.HostingMode
	overview.PrimaryProfileDeviceID = hosting.PrimaryProfileDeviceID
	overview.ProfileDataHostDeviceID = hosting.ProfileDataHostDeviceID
	devices, err := s.store.readDevices()
	if err != nil {
		return ProfileMeshOverview{}, err
	}
	resources, err := s.store.readResources()
	if err != nil {
		return ProfileMeshOverview{}, err
	}
	overview.DeviceCount = len(devices.Devices)
	overview.ResourceCount = len(resources.Resources)
	if hosting.ProfileDataHostDeviceID == "" {
		overview.Warnings = append(overview.Warnings, ProfileMeshIssue{Code: "profile_data_host_unset", Message: "Profile data host is not selected", Blocking: false})
	} else if device, err := s.requireDeviceLocked(hosting.ProfileDataHostDeviceID); err != nil || !isDeviceUsable(device) || isStale(s.clock.Now().UTC(), device.LastSeen) {
		overview.Ready = false
		overview.Issues = append(overview.Issues, ProfileMeshIssue{Code: "profile_data_host_unavailable", Message: "Profile data host device is not available", Blocking: true})
	}
	overview.Message = "profile owns identity, device trust, and resource metadata"
	return overview, nil
}

func (s *Service) requireActiveDeviceLocked(deviceID string) (ProfileDeviceRecord, error) {
	device, err := s.requireDeviceLocked(deviceID)
	if err != nil {
		return ProfileDeviceRecord{}, err
	}
	if device.Status == DeviceStatusRemoved || device.Status == DeviceStatusRevoked || device.TrustStatus == DeviceTrustRevoked {
		return ProfileDeviceRecord{}, ErrDeviceRevoked
	}
	if device.Status == DeviceStatusStale || device.TrustStatus == DeviceTrustStale || isStale(s.clock.Now().UTC(), device.LastSeen) {
		return ProfileDeviceRecord{}, ErrDeviceStale
	}
	if device.TrustStatus != DeviceTrustTrusted || device.Status != DeviceStatusActive {
		return ProfileDeviceRecord{}, ErrDeviceNotAllowed
	}
	return device, nil
}

func (s *Service) requireDeviceLocked(deviceID string) (ProfileDeviceRecord, error) {
	reg, err := s.store.readDevices()
	if err != nil {
		return ProfileDeviceRecord{}, err
	}
	for _, device := range reg.Devices {
		if device.DeviceID == deviceID {
			return device, nil
		}
	}
	return ProfileDeviceRecord{}, ErrDeviceNotRegistered
}

func (s *Service) findResourceLocked(resourceID string) (ProfileResourceRecord, error) {
	reg, err := s.store.readResources()
	if err != nil {
		return ProfileResourceRecord{}, err
	}
	for _, resource := range reg.Resources {
		if resource.ResourceID == resourceID {
			return resource, nil
		}
	}
	return ProfileResourceRecord{}, ErrResourceNotFound
}
