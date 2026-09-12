package profilemesh

import (
	"context"
	"errors"
	"os"
	"sort"
	"strings"
)

func (s *Service) registerProfileResource(ctx context.Context, req RegisterProfileResourceRequest) (ProfileResourceRecord, error) {
	if err := contextError(ctx); err != nil {
		return ProfileResourceRecord{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	profile, err := s.store.readProfile()
	if err != nil {
		return ProfileResourceRecord{}, err
	}
	req.ResourceID = strings.TrimSpace(req.ResourceID)
	if req.HostingMode == "" {
		req.HostingMode = ResourceHostingSingleHost
	}
	if req.Availability == "" {
		req.Availability = ResourceUnknown
	}
	host := req.CurrentHostDeviceID
	if host == "" && req.ResourceType == ResourceProfileData {
		if config, err := s.store.readHosting(); err == nil {
			if config.ProfileDataHostDeviceID != "" {
				host = config.ProfileDataHostDeviceID
			} else {
				host = config.PrimaryProfileDeviceID
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return ProfileResourceRecord{}, err
		}
	}
	reg, err := s.store.readResources()
	if err != nil {
		return ProfileResourceRecord{}, err
	}
	for _, existing := range reg.Resources {
		if existing.ResourceID == req.ResourceID {
			return ProfileResourceRecord{}, ErrInvalidResource
		}
	}
	now := s.clock.Now().UTC()
	resource := ProfileResourceRecord{
		ResourceID:           req.ResourceID,
		ResourceType:         req.ResourceType,
		DisplayName:          displayOrID(req.DisplayName, req.ResourceID),
		ProfileOwnerID:       profile.ProfileID,
		CurrentHostDeviceID:  host,
		AllowedHostDeviceIDs: uniqueHostIDs(req.AllowedHostDeviceIDs),
		Availability:         req.Availability,
		HostingMode:          req.HostingMode,
		Tags:                 compactStrings(req.Tags),
		Metadata:             cloneMetadata(req.Metadata),
		CreatedAt:            now,
		UpdatedAt:            now,
	}
	if resource.CurrentHostDeviceID != "" && resource.Availability == ResourceUnknown {
		resource.Availability = ResourceAvailable
	}
	if err := s.validateResourceLocked(resource, profile.ProfileID); err != nil {
		return ProfileResourceRecord{}, err
	}
	reg.Resources = append(reg.Resources, resource)
	reg.UpdatedAt = now
	if err := s.store.writeResources(reg); err != nil {
		return ProfileResourceRecord{}, err
	}
	return cloneProfileResource(resource), nil
}

func (s *Service) listProfileResources(ctx context.Context) ([]ProfileResourceRecord, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	reg, err := s.store.readResources()
	if err != nil {
		return nil, err
	}
	out := cloneProfileResources(reg.Resources)
	sort.Slice(out, func(i, j int) bool { return out[i].ResourceID < out[j].ResourceID })
	return out, nil
}

func (s *Service) setResourceHost(ctx context.Context, req SetResourceHostRequest) (ProfileResourceRecord, error) {
	if err := contextError(ctx); err != nil {
		return ProfileResourceRecord{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.requireActiveDeviceLocked(req.DeviceID); err != nil {
		return ProfileResourceRecord{}, err
	}
	reg, err := s.store.readResources()
	if err != nil {
		return ProfileResourceRecord{}, err
	}
	now := s.clock.Now().UTC()
	for i, resource := range reg.Resources {
		if resource.ResourceID != req.ResourceID {
			continue
		}
		resource.CurrentHostDeviceID = req.DeviceID
		resource.Availability = ResourceAvailable
		resource.UpdatedAt = now
		profile, err := s.store.readProfile()
		if err != nil {
			return ProfileResourceRecord{}, err
		}
		if err := s.validateResourceLocked(resource, profile.ProfileID); err != nil {
			return ProfileResourceRecord{}, err
		}
		reg.Resources[i] = resource
		reg.UpdatedAt = now
		if err := s.store.writeResources(reg); err != nil {
			return ProfileResourceRecord{}, err
		}
		return cloneProfileResource(resource), nil
	}
	return ProfileResourceRecord{}, ErrResourceNotFound
}

func (s *Service) getResourceHost(ctx context.Context, resourceID string) (ProfileResourceHostStatus, error) {
	if err := contextError(ctx); err != nil {
		return ProfileResourceHostStatus{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	resource, err := s.findResourceLocked(resourceID)
	if err != nil {
		return ProfileResourceHostStatus{}, err
	}
	if resource.CurrentHostDeviceID == "" {
		return ProfileResourceHostStatus{}, ErrHostUnavailable
	}
	device, err := s.requireDeviceLocked(resource.CurrentHostDeviceID)
	if err != nil {
		return ProfileResourceHostStatus{}, err
	}
	status := ProfileResourceHostStatus{ResourceID: resource.ResourceID, ProfileOwnerID: resource.ProfileOwnerID, HostDeviceID: device.DeviceID, HostStatus: device.Status, Availability: resource.Availability}
	if isDeviceUsable(device) && !isStale(s.clock.Now().UTC(), device.LastSeen) {
		status.HostAvailable = true
		status.Message = "profile-owned resource has an active trusted host"
		return status, nil
	}
	status.HostAvailable = false
	status.Availability = ResourceUnavailable
	status.Message = "profile-owned resource host is not currently available"
	return status, nil
}

// Read the device registry once for all references in a proposed resource.
func (s *Service) validateResourceLocked(resource ProfileResourceRecord, profileID string) error {
	reg, err := s.store.readDevices()
	if err != nil {
		return err
	}
	devices := make(map[string]ProfileDeviceRecord, len(reg.Devices))
	for _, device := range reg.Devices {
		devices[device.DeviceID] = device
	}
	// Preserve the live API's missing-device sentinel.
	for _, id := range append([]string{resource.CurrentHostDeviceID}, resource.AllowedHostDeviceIDs...) {
		if id != "" {
			if _, ok := devices[id]; !ok {
				return ErrDeviceNotRegistered
			}
		}
	}
	return validateResource(resource, profileID, devices, s.clock.Now().UTC())
}
