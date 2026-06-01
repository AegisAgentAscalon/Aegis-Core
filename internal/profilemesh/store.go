package profilemesh

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

type store struct {
	dir string
}

func newStore(cfg AppConfig) (*store, error) {
	dir := filepath.Join(cfg.DataDir, cfg.AppID, cfg.Namespace, "profilemesh")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, ErrStorageUnavailable
	}
	return &store{dir: dir}, nil
}

func (s *store) profilePath() string   { return filepath.Join(s.dir, "profile_identity.json") }
func (s *store) hostingPath() string   { return filepath.Join(s.dir, "hosting_config.json") }
func (s *store) devicesPath() string   { return filepath.Join(s.dir, "profile_devices.json") }
func (s *store) resourcesPath() string { return filepath.Join(s.dir, "profile_resources.json") }

func (s *store) readProfile() (ProfileIdentity, error) {
	var out ProfileIdentity
	if err := readJSON(s.profilePath(), &out); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return ProfileIdentity{}, ErrProfileNotFound
		}
		return ProfileIdentity{}, ErrStorageUnavailable
	}
	if out.ProfileID == "" || out.AppID == "" || out.Namespace == "" {
		return ProfileIdentity{}, ErrStorageUnavailable
	}
	return out, nil
}

func (s *store) writeProfile(profile ProfileIdentity) error {
	return writeJSON(s.profilePath(), profile)
}

func (s *store) readHosting() (ProfileHostingConfig, error) {
	var out ProfileHostingConfig
	if err := readJSON(s.hostingPath(), &out); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return ProfileHostingConfig{}, os.ErrNotExist
		}
		return ProfileHostingConfig{}, ErrStorageUnavailable
	}
	if out.HostingMode == "" {
		return ProfileHostingConfig{}, ErrStorageUnavailable
	}
	return out, nil
}

func (s *store) writeHosting(config ProfileHostingConfig) error {
	return writeJSON(s.hostingPath(), config)
}

func (s *store) readDevices() (deviceRegistryFile, error) {
	out := deviceRegistryFile{SchemaVersion: SchemaVersion, Devices: []ProfileDeviceRecord{}}
	if err := readJSON(s.devicesPath(), &out); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return out, nil
		}
		return deviceRegistryFile{}, ErrStorageUnavailable
	}
	if out.SchemaVersion == 0 {
		out.SchemaVersion = SchemaVersion
	}
	return out, nil
}

func (s *store) writeDevices(reg deviceRegistryFile) error {
	reg.SchemaVersion = SchemaVersion
	return writeJSON(s.devicesPath(), reg)
}

func (s *store) readResources() (resourceRegistryFile, error) {
	out := resourceRegistryFile{SchemaVersion: SchemaVersion, Resources: []ProfileResourceRecord{}}
	if err := readJSON(s.resourcesPath(), &out); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return out, nil
		}
		return resourceRegistryFile{}, ErrStorageUnavailable
	}
	if out.SchemaVersion == 0 {
		out.SchemaVersion = SchemaVersion
	}
	return out, nil
}

func (s *store) writeResources(reg resourceRegistryFile) error {
	reg.SchemaVersion = SchemaVersion
	return writeJSON(s.resourcesPath(), reg)
}

func readJSON(path string, out any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return err
		}
		return ErrStorageUnavailable
	}
	if err := json.Unmarshal(b, out); err != nil {
		return ErrStorageUnavailable
	}
	return nil
}

func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return ErrStorageUnavailable
	}
	return writeFileAtomic(path, b, 0o600)
}

func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return ErrStorageUnavailable
	}
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return ErrStorageUnavailable
	}
	name := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(name)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return ErrStorageUnavailable
	}
	if err := tmp.Close(); err != nil {
		return ErrStorageUnavailable
	}
	if err := os.Chmod(name, perm); err != nil {
		return ErrStorageUnavailable
	}
	if err := os.Rename(name, path); err != nil {
		return ErrStorageUnavailable
	}
	cleanup = false
	return nil
}

func safeErrorString(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	if strings.Contains(msg, `:\`) || strings.Contains(msg, "/") {
		return "profile mesh data is unavailable"
	}
	return msg
}
