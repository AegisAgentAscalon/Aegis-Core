package devicelink

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"os"
	"slices"
	"strings"
)

func InspectBootstrap(config AppConfig) (BootstrapStatus, error) {
	cfg := normalizeConfig(config)
	if err := validateConfig(cfg); err != nil {
		return BootstrapStatus{}, err
	}
	st := storeForConfig(cfg)
	identityPresent, err := regularFileExists(st.identityPath())
	if err != nil {
		return BootstrapStatus{}, err
	}
	privateKeyPresent, err := regularFileExists(st.privateKeyPath())
	if err != nil {
		return BootstrapStatus{}, err
	}
	status := BootstrapStatus{
		State:             BootstrapAbsent,
		IdentityPresent:   identityPresent,
		PrivateKeyPresent: privateKeyPresent,
		Message:           "device link is not bootstrapped",
	}
	if !identityPresent && !privateKeyPresent {
		return status, nil
	}
	if !identityPresent || !privateKeyPresent {
		status.State = BootstrapPartial
		status.Message = "device link bootstrap is incomplete"
		return status, nil
	}
	identity, identityErr := st.readIdentity()
	encodedPrivateKey, privateKeyErr := st.readPrivateKey()
	if identityErr != nil || privateKeyErr != nil {
		status.State = BootstrapInvalid
		status.Message = "device link bootstrap storage is invalid"
		return status, nil
	}
	privateKey, err := decodePrivateKey(encodedPrivateKey)
	bundle := publicIdentityBundleFromIdentity(identity)
	if err != nil || identity.AppID != cfg.AppID || identity.Namespace != cfg.Namespace || validateIdentityKeyPair(identity, privateKey) != nil || ValidatePublicIdentityBundle(bundle) != nil {
		status.State = BootstrapInvalid
		status.Message = "device link bootstrap identity is invalid"
		return status, nil
	}
	status.State = BootstrapReady
	status.Bootstrapped = true
	status.Ready = true
	status.DeviceID = identity.DeviceID
	status.Message = "device link bootstrap is ready"
	return status, nil
}

func regularFileExists(path string) (bool, error) {
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, ErrStorageUnavailable
	}
	if !info.Mode().IsRegular() {
		return true, nil
	}
	return true, nil
}

func (s *Service) BootstrapCurrentDevice(ctx context.Context, req BootstrapDeviceRequest) (DeviceIdentity, error) {
	if err := contextError(ctx); err != nil {
		return DeviceIdentity{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, err := s.store.readIdentity(); err == nil {
		privateKey, keyErr := s.privateKey()
		if keyErr != nil {
			return DeviceIdentity{}, keyErr
		}
		bundle := publicIdentityBundleFromIdentity(existing)
		if existing.AppID != s.cfg.AppID || existing.Namespace != s.cfg.Namespace || validateIdentityKeyPair(existing, privateKey) != nil || ValidatePublicIdentityBundle(bundle) != nil {
			return DeviceIdentity{}, ErrStorageUnavailable
		}
		return cloneDeviceIdentity(existing), nil
	} else if !errors.Is(err, ErrCurrentDeviceNotFound) {
		return DeviceIdentity{}, err
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return DeviceIdentity{}, ErrStorageUnavailable
	}
	deviceID, err := randomID("dev_", 16)
	if err != nil {
		return DeviceIdentity{}, ErrStorageUnavailable
	}
	now := s.clock.Now().UTC()
	displayName := strings.TrimSpace(req.DisplayName)
	if displayName == "" {
		displayName = s.cfg.DisplayName
	}
	id := DeviceIdentity{
		DeviceID:             deviceID,
		DisplayName:          displayName,
		AppID:                s.cfg.AppID,
		Namespace:            s.cfg.Namespace,
		PublicKey:            encodePublicKey(publicKey),
		PublicKeyFingerprint: fingerprintPublicKey(publicKey),
		CreatedAt:            now,
		UpdatedAt:            now,
		Capabilities:         compactStrings(req.Capabilities),
		MetadataVersion:      metadataVersion,
	}
	if err := s.store.writePrivateKey(base64.RawStdEncoding.EncodeToString(privateKey)); err != nil {
		return DeviceIdentity{}, err
	}
	if err := s.store.writeIdentity(id); err != nil {
		return DeviceIdentity{}, err
	}
	return cloneDeviceIdentity(id), nil
}

func (s *Service) GetCurrentDevice(ctx context.Context) (DeviceIdentity, error) {
	if err := contextError(ctx); err != nil {
		return DeviceIdentity{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	id, err := s.store.readIdentity()
	if err != nil {
		return DeviceIdentity{}, err
	}
	return cloneDeviceIdentity(id), nil
}

// ExportPublicIdentityBundle returns public key and identity metadata intended
// for explicit identity exchange. The bundle does not grant membership,
// establish trust, prove possession, or authorize payloads.
func (s *Service) ExportPublicIdentityBundle(ctx context.Context) (PublicIdentityBundle, error) {
	if err := contextError(ctx); err != nil {
		return PublicIdentityBundle{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	identity, err := s.store.readIdentity()
	if err != nil {
		return PublicIdentityBundle{}, err
	}
	privateKey, err := s.privateKey()
	if err != nil {
		return PublicIdentityBundle{}, err
	}
	if err := validateIdentityKeyPair(identity, privateKey); err != nil {
		return PublicIdentityBundle{}, err
	}
	bundle := publicIdentityBundleFromIdentity(identity)
	if err := ValidatePublicIdentityBundle(bundle); err != nil {
		return PublicIdentityBundle{}, ErrStorageUnavailable
	}
	return bundle, nil
}

// ValidatePublicIdentityBundle validates public identity consistency only. A
// valid bundle is not network authorization or proof of key possession.
func ValidatePublicIdentityBundle(bundle PublicIdentityBundle) error {
	if bundle.SchemaVersion != schemaVersion || bundle.BundleVersion != identityBundleVersion || bundle.MetadataVersion != metadataVersion {
		return ErrInvalidIdentityBundle
	}
	if !validSafeName(bundle.DeviceID) || !validSafeName(bundle.AppID) || !validSafeName(bundle.Namespace) {
		return ErrInvalidIdentityBundle
	}
	if strings.TrimSpace(bundle.DisplayName) == "" || bundle.DisplayName != strings.TrimSpace(bundle.DisplayName) {
		return ErrInvalidIdentityBundle
	}
	if bundle.CreatedAt.IsZero() || bundle.UpdatedAt.IsZero() || bundle.UpdatedAt.Before(bundle.CreatedAt) {
		return ErrInvalidIdentityBundle
	}
	publicKey, err := decodePublicKey(bundle.PublicKey)
	if err != nil || fingerprintPublicKey(publicKey) != bundle.PublicKeyFingerprint {
		return ErrInvalidIdentityBundle
	}
	if !slices.Equal(bundle.Capabilities, compactStrings(bundle.Capabilities)) {
		return ErrInvalidIdentityBundle
	}
	if bundle.BundleFingerprint == "" || bundle.BundleFingerprint != publicIdentityBundleFingerprint(bundle) {
		return ErrInvalidIdentityBundle
	}
	return nil
}
