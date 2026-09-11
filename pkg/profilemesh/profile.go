package profilemesh

import (
	"context"
	"errors"
	"os"
)

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
		SchemaVersion:   schemaVersion,
		MetadataVersion: metadataVersion,
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
