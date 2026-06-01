package profilemesh

import (
	"context"
	"errors"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

type Service struct {
	cfg   AppConfig
	store *store
	clock Clock
	mu    sync.Mutex
}

func WithClock(clock Clock) Option {
	return func(o *options) { o.clock = clock }
}

func NewService(config AppConfig, opts ...Option) (*Service, error) {
	cfg := NormalizeConfig(config)
	if err := ValidateConfig(cfg); err != nil {
		return nil, err
	}
	st, err := newStore(cfg)
	if err != nil {
		return nil, err
	}
	options := options{clock: realClock{}}
	for _, opt := range opts {
		if opt != nil {
			opt(&options)
		}
	}
	if options.clock == nil {
		options.clock = realClock{}
	}
	return &Service{cfg: cfg, store: st, clock: options.clock}, nil
}

func (s *Service) ValidateConfig() error {
	return ValidateConfig(s.cfg)
}

func (s *Service) BootstrapProfile(ctx context.Context, req BootstrapProfileRequest) (ProfileIdentity, error) {
	if err := contextError(ctx); err != nil {
		return ProfileIdentity{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, err := s.store.readProfile(); err == nil {
		return existing, nil
	} else if !errors.Is(err, ErrProfileNotFound) {
		return ProfileIdentity{}, err
	}
	profileID := req.ProfileID
	if profileID == "" {
		id, err := randomID("prof_", 16)
		if err != nil {
			return ProfileIdentity{}, ErrStorageUnavailable
		}
		profileID = id
	}
	if !validID(profileID) {
		return ProfileIdentity{}, ErrInvalidNamespace
	}
	now := s.clock.Now().UTC()
	displayName := req.DisplayName
	if displayName == "" {
		displayName = s.cfg.DisplayName
	}
	profile := ProfileIdentity{
		ProfileID:       profileID,
		AppID:           s.cfg.AppID,
		Namespace:       s.cfg.Namespace,
		DisplayName:     displayName,
		CreatedAt:       now,
		UpdatedAt:       now,
		SchemaVersion:   SchemaVersion,
		MetadataVersion: MetadataVersion,
	}
	if err := s.store.writeProfile(profile); err != nil {
		return ProfileIdentity{}, err
	}
	if err := s.store.writeHosting(defaultHostingConfig(now)); err != nil {
		return ProfileIdentity{}, err
	}
	return profile, nil
}

func (s *Service) GetProfile(ctx context.Context) (ProfileIdentity, error) {
	if err := contextError(ctx); err != nil {
		return ProfileIdentity{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.store.readProfile()
}

func (s *Service) SetProfileHostingMode(ctx context.Context, req SetProfileHostingModeRequest) (ProfileHostingConfig, error) {
	if err := contextError(ctx); err != nil {
		return ProfileHostingConfig{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.store.readProfile(); err != nil {
		return ProfileHostingConfig{}, err
	}
	if req.HostingMode == "" {
		req.HostingMode = HostingSingleProfileDevice
	}
	if req.HostingMode == HostingMultiProfileDevices {
		return ProfileHostingConfig{}, ErrUnsupportedHostingMode
	}
	if req.HostingMode != HostingSingleProfileDevice {
		return ProfileHostingConfig{}, ErrUnsupportedHostingMode
	}
	if req.PrimaryProfileDeviceID != "" {
		if _, err := s.requireActiveDeviceLocked(req.PrimaryProfileDeviceID); err != nil {
			return ProfileHostingConfig{}, err
		}
	}
	if req.ProfileDataHostDeviceID != "" {
		if _, err := s.requireActiveDeviceLocked(req.ProfileDataHostDeviceID); err != nil {
			return ProfileHostingConfig{}, err
		}
	}
	config := ProfileHostingConfig{
		HostingMode:              req.HostingMode,
		PrimaryProfileDeviceID:   req.PrimaryProfileDeviceID,
		ProfileDataHostDeviceID:  req.ProfileDataHostDeviceID,
		LocalCacheEnabled:        req.LocalCacheEnabled,
		OfflineBranchModePlanned: true,
		UpdatedAt:                s.clock.Now().UTC(),
	}
	if err := s.store.writeHosting(config); err != nil {
		return ProfileHostingConfig{}, err
	}
	return config, nil
}

func (s *Service) GetProfileHostingConfig(ctx context.Context) (ProfileHostingConfig, error) {
	if err := contextError(ctx); err != nil {
		return ProfileHostingConfig{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.store.readProfile(); err != nil {
		return ProfileHostingConfig{}, err
	}
	config, err := s.store.readHosting()
	if errors.Is(err, os.ErrNotExist) {
		return defaultHostingConfig(s.clock.Now()), nil
	}
	return config, err
}

func (s *Service) RegisterProfileDevice(ctx context.Context, req RegisterProfileDeviceRequest) (ProfileDeviceRecord, error) {
	if err := contextError(ctx); err != nil {
		return ProfileDeviceRecord{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.store.readProfile(); err != nil {
		return ProfileDeviceRecord{}, err
	}
	req.DeviceID = stringsTrim(req.DeviceID)
	if req.DeviceID == "" || !validID(req.DeviceID) || !validFingerprint(req.PublicKeyFingerprint) {
		return ProfileDeviceRecord{}, ErrDeviceNotAllowed
	}
	if req.TrustStatus == "" {
		req.TrustStatus = DeviceTrustTrusted
	}
	if req.Status == "" {
		req.Status = DeviceStatusActive
	}
	now := s.clock.Now().UTC()
	reg, err := s.store.readDevices()
	if err != nil {
		return ProfileDeviceRecord{}, err
	}
	for i, device := range reg.Devices {
		if device.DeviceID != req.DeviceID {
			continue
		}
		if device.PublicKeyFingerprint != req.PublicKeyFingerprint {
			return ProfileDeviceRecord{}, ErrDeviceNotAllowed
		}
		device.DisplayName = displayOrID(req.DisplayName, req.DeviceID)
		device.TrustStatus = req.TrustStatus
		device.Status = req.Status
		device.Capabilities = compactStrings(req.Capabilities)
		device.MetadataSource = req.MetadataSource
		device.UpdatedAt = now
		device.LastSeen = now
		device.ProfileMetadataVersion = MetadataVersion
		reg.Devices[i] = device
		reg.UpdatedAt = now
		if err := s.store.writeDevices(reg); err != nil {
			return ProfileDeviceRecord{}, err
		}
		return device, nil
	}
	device := ProfileDeviceRecord{
		DeviceID:               req.DeviceID,
		DisplayName:            displayOrID(req.DisplayName, req.DeviceID),
		PublicKeyFingerprint:   req.PublicKeyFingerprint,
		TrustStatus:            req.TrustStatus,
		Status:                 req.Status,
		Capabilities:           compactStrings(req.Capabilities),
		LastSeen:               now,
		RegisteredAt:           now,
		UpdatedAt:              now,
		MetadataSource:         req.MetadataSource,
		ProfileMetadataVersion: MetadataVersion,
	}
	reg.Devices = append(reg.Devices, device)
	reg.UpdatedAt = now
	if err := s.store.writeDevices(reg); err != nil {
		return ProfileDeviceRecord{}, err
	}
	return device, nil
}

func (s *Service) ListProfileDevices(ctx context.Context) ([]ProfileDeviceRecord, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	reg, err := s.store.readDevices()
	if err != nil {
		return nil, err
	}
	out := append([]ProfileDeviceRecord{}, reg.Devices...)
	sort.Slice(out, func(i, j int) bool { return out[i].DeviceID < out[j].DeviceID })
	return out, nil
}

func (s *Service) RemoveProfileDevice(ctx context.Context, deviceID string) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	reg, err := s.store.readDevices()
	if err != nil {
		return err
	}
	now := s.clock.Now().UTC()
	for i, device := range reg.Devices {
		if device.DeviceID == deviceID {
			device.Status = DeviceStatusRemoved
			device.TrustStatus = DeviceTrustRevoked
			device.RemovedAt = &now
			device.UpdatedAt = now
			reg.Devices[i] = device
			reg.UpdatedAt = now
			return s.store.writeDevices(reg)
		}
	}
	return ErrDeviceNotRegistered
}

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

func (s *Service) ExportProfileMeshSnapshot(ctx context.Context) (ProfileMeshSnapshot, error) {
	if err := contextError(ctx); err != nil {
		return ProfileMeshSnapshot{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	profile, err := s.store.readProfile()
	if err != nil {
		return ProfileMeshSnapshot{}, err
	}
	hosting, err := s.store.readHosting()
	if errors.Is(err, os.ErrNotExist) {
		hosting = defaultHostingConfig(s.clock.Now())
	} else if err != nil {
		return ProfileMeshSnapshot{}, err
	}
	devices, err := s.store.readDevices()
	if err != nil {
		return ProfileMeshSnapshot{}, err
	}
	resources, err := s.store.readResources()
	if err != nil {
		return ProfileMeshSnapshot{}, err
	}
	now := s.clock.Now().UTC()
	snapshot := ProfileMeshSnapshot{
		SchemaVersion:   SchemaVersion,
		AppID:           s.cfg.AppID,
		Namespace:       s.cfg.Namespace,
		Profile:         profile,
		HostingConfig:   hosting,
		Devices:         append([]ProfileDeviceRecord{}, devices.Devices...),
		Resources:       append([]ProfileResourceRecord{}, resources.Resources...),
		CreatedAt:       now,
		UpdatedAt:       now,
		MetadataVersion: MetadataVersion,
	}
	snapshot.SnapshotFingerprint = snapshotFingerprint(snapshot)
	return snapshot, nil
}

func (s *Service) ImportProfileMeshSnapshot(ctx context.Context, snapshot ProfileMeshSnapshot) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if snapshot.SchemaVersion != SchemaVersion || snapshot.AppID != s.cfg.AppID || snapshot.Namespace != s.cfg.Namespace || snapshot.Profile.ProfileID == "" || snapshot.Profile.AppID != s.cfg.AppID || snapshot.Profile.Namespace != s.cfg.Namespace {
		return ErrInvalidProfileSnapshot
	}
	if snapshot.SnapshotFingerprint != "" && snapshot.SnapshotFingerprint != snapshotFingerprint(snapshot) {
		return ErrInvalidProfileSnapshot
	}
	if err := validateSnapshot(snapshot); err != nil {
		return err
	}
	if err := s.store.writeProfile(snapshot.Profile); err != nil {
		return err
	}
	if err := s.store.writeHosting(snapshot.HostingConfig); err != nil {
		return err
	}
	if err := s.store.writeDevices(deviceRegistryFile{SchemaVersion: SchemaVersion, Devices: append([]ProfileDeviceRecord{}, snapshot.Devices...), UpdatedAt: s.clock.Now().UTC()}); err != nil {
		return err
	}
	return s.store.writeResources(resourceRegistryFile{SchemaVersion: SchemaVersion, Resources: append([]ProfileResourceRecord{}, snapshot.Resources...), UpdatedAt: s.clock.Now().UTC()})
}

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

func validateSnapshot(snapshot ProfileMeshSnapshot) error {
	devices := map[string]string{}
	for _, device := range snapshot.Devices {
		if device.DeviceID == "" || !validID(device.DeviceID) || !validFingerprint(device.PublicKeyFingerprint) {
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
	return !lastSeen.IsZero() && now.Sub(lastSeen) > defaultStaleAge
}
