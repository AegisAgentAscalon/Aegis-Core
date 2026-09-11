package profilemesh

import (
	"context"
	"sort"
)

func (s *Service) RegisterProfileResource(ctx context.Context, req RegisterProfileResourceRequest) (ProfileResourceRecord, error) {
	if err := contextError(ctx); err != nil {
		return ProfileResourceRecord{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	profile, err := s.store.readProfile()
	if err != nil {
		return ProfileResourceRecord{}, err
	}
	req.ResourceID = stringsTrim(req.ResourceID)
	if req.ResourceID == "" || !validID(req.ResourceID) || !validResourceType(req.ResourceType) {
		return ProfileResourceRecord{}, ErrInvalidResource
	}
	if req.HostingMode == "" {
		req.HostingMode = ResourceHostingSingleHost
	}
	if req.HostingMode == ResourceHostingMultiHostPlanned {
		return ProfileResourceRecord{}, ErrUnsupportedHostingMode
	}
	if req.HostingMode != ResourceHostingSingleHost {
		return ProfileResourceRecord{}, ErrUnsupportedHostingMode
	}
	if req.Availability == "" {
		req.Availability = ResourceUnknown
	}
	if !validAvailability(req.Availability) {
		return ProfileResourceRecord{}, ErrInvalidResource
	}
	host := req.CurrentHostDeviceID
	if host == "" && req.ResourceType == ResourceProfileData {
		if config, err := s.store.readHosting(); err == nil {
			if config.ProfileDataHostDeviceID != "" {
				host = config.ProfileDataHostDeviceID
			} else {
				host = config.PrimaryProfileDeviceID
			}
		}
	}
	if host != "" {
		if _, err := s.requireActiveDeviceLocked(host); err != nil {
			return ProfileResourceRecord{}, err
		}
	}
	for _, allowed := range req.AllowedHostDeviceIDs {
		if _, err := s.requireActiveDeviceLocked(allowed); err != nil {
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
		AllowedHostDeviceIDs: compactStrings(req.AllowedHostDeviceIDs),
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
	reg.Resources = append(reg.Resources, resource)
	reg.UpdatedAt = now
	if err := s.store.writeResources(reg); err != nil {
		return ProfileResourceRecord{}, err
	}
	return resource, nil
}

func (s *Service) ListProfileResources(ctx context.Context) ([]ProfileResourceRecord, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	reg, err := s.store.readResources()
	if err != nil {
		return nil, err
	}
	out := append([]ProfileResourceRecord{}, reg.Resources...)
	sort.Slice(out, func(i, j int) bool { return out[i].ResourceID < out[j].ResourceID })
	return out, nil
}

func (s *Service) SetResourceHost(ctx context.Context, req SetResourceHostRequest) (ProfileResourceRecord, error) {
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
		if len(resource.AllowedHostDeviceIDs) > 0 && !contains(resource.AllowedHostDeviceIDs, req.DeviceID) {
			return ProfileResourceRecord{}, ErrDeviceNotAllowed
		}
		resource.CurrentHostDeviceID = req.DeviceID
		resource.Availability = ResourceAvailable
		resource.UpdatedAt = now
		reg.Resources[i] = resource
		reg.UpdatedAt = now
		if err := s.store.writeResources(reg); err != nil {
			return ProfileResourceRecord{}, err
		}
		return resource, nil
	}
	return ProfileResourceRecord{}, ErrResourceNotFound
}

func (s *Service) GetResourceHost(ctx context.Context, resourceID string) (ProfileResourceHostStatus, error) {
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
