package profilemesh

import (
	"context"
	"errors"
	"os"
)

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
	createdAt := profile.CreatedAt.UTC()
	updatedAt := latestTime(profile.UpdatedAt, hosting.UpdatedAt, devices.UpdatedAt, resources.UpdatedAt)
	snapshot := ProfileMeshSnapshot{
		SchemaVersion:   ProfileMeshSnapshotSchemaVersion,
		AppID:           s.cfg.AppID,
		Namespace:       s.cfg.Namespace,
		Profile:         profile,
		HostingConfig:   hosting,
		Devices:         append([]ProfileDeviceRecord{}, devices.Devices...),
		Resources:       append([]ProfileResourceRecord{}, resources.Resources...),
		CreatedAt:       createdAt,
		UpdatedAt:       updatedAt,
		MetadataVersion: metadataVersion,
	}
	snapshot = normalizeProfileMeshSnapshot(snapshot)
	snapshot.SnapshotFingerprint = snapshotFingerprint(snapshot)
	return publicProfileMeshSnapshot(snapshot), nil
}

func (s *Service) ImportProfileMeshSnapshot(ctx context.Context, snapshot ProfileMeshSnapshot) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	// The legacy multi-file store has no durable home for these fields yet.
	// Reject before writing anything rather than accepting and discarding them.
	if len(snapshot.RelayHints) > 0 || len(snapshot.EndpointHints) > 0 {
		return ErrInvalidProfileSnapshot
	}
	if snapshot.AppID != s.cfg.AppID || snapshot.Namespace != s.cfg.Namespace || snapshot.Profile.ProfileID == "" || snapshot.Profile.AppID != s.cfg.AppID || snapshot.Profile.Namespace != s.cfg.Namespace {
		return ErrInvalidProfileSnapshot
	}
	switch snapshot.SchemaVersion {
	case legacyProfileMeshSnapshotSchemaVersion:
		if snapshot.SnapshotFingerprint != "" && snapshot.SnapshotFingerprint != legacyProfileMeshSnapshotFingerprint(snapshot) {
			return ErrInvalidProfileSnapshot
		}
	case ProfileMeshSnapshotSchemaVersion:
		if snapshot.SnapshotFingerprint == "" {
			return ErrInvalidProfileSnapshot
		}
	default:
		return ErrInvalidProfileSnapshot
	}
	normalized := normalizeProfileMeshSnapshot(snapshot)
	if snapshot.SchemaVersion == ProfileMeshSnapshotSchemaVersion && snapshot.SnapshotFingerprint != snapshotFingerprint(normalized) {
		return ErrInvalidProfileSnapshot
	}
	normalized.SchemaVersion = ProfileMeshSnapshotSchemaVersion
	normalized.SnapshotFingerprint = snapshotFingerprint(normalized)
	validationTime := s.clock.Now().UTC()
	// Schema 1 is a historical-state import, not a fresh presence assertion.
	// Keep its recorded time; live host queries still use the service clock.
	if snapshot.SchemaVersion == legacyProfileMeshSnapshotSchemaVersion && !normalized.UpdatedAt.IsZero() {
		validationTime = normalized.UpdatedAt
	}
	if err := validateSnapshot(normalized, validationTime); err != nil {
		return err
	}
	if err := s.store.writeProfile(normalized.Profile); err != nil {
		return err
	}
	if err := s.store.writeHosting(normalized.HostingConfig); err != nil {
		return err
	}
	if err := s.store.writeDevices(deviceRegistryFile{SchemaVersion: schemaVersion, Devices: append([]ProfileDeviceRecord{}, normalized.Devices...), UpdatedAt: normalized.UpdatedAt}); err != nil {
		return err
	}
	return s.store.writeResources(resourceRegistryFile{SchemaVersion: schemaVersion, Resources: append([]ProfileResourceRecord{}, normalized.Resources...), UpdatedAt: normalized.UpdatedAt})
}
