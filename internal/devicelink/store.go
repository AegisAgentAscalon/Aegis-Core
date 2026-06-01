package devicelink

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
	dir := filepath.Join(cfg.DataDir, cfg.AppID, cfg.Namespace, "devicelink")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, ErrStorageUnavailable
	}
	return &store{dir: dir}, nil
}

func (s *store) identityPath() string           { return filepath.Join(s.dir, "device_identity.json") }
func (s *store) privateKeyPath() string         { return filepath.Join(s.dir, "device_private_key.json") }
func (s *store) registryPath() string           { return filepath.Join(s.dir, "trusted_registry.json") }
func (s *store) resourcesPath() string          { return filepath.Join(s.dir, "resources.json") }
func (s *store) peersPath() string              { return filepath.Join(s.dir, "peers.json") }
func (s *store) linkStatusPath() string         { return filepath.Join(s.dir, "link_status.json") }
func (s *store) handshakesDir() string          { return filepath.Join(s.dir, "handshakes") }
func (s *store) handshakePath(id string) string { return filepath.Join(s.handshakesDir(), id+".json") }

func (s *store) writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return ErrStorageUnavailable
	}
	return writeFileAtomic(path, b, 0o600)
}

func (s *store) readJSON(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return err
		}
		return ErrStorageUnavailable
	}
	if err := json.Unmarshal(b, v); err != nil {
		return ErrStorageUnavailable
	}
	return nil
}

func (s *store) writeIdentity(id DeviceIdentity) error { return s.writeJSON(s.identityPath(), id) }

func (s *store) readIdentity() (DeviceIdentity, error) {
	var id DeviceIdentity
	if err := s.readJSON(s.identityPath(), &id); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return DeviceIdentity{}, ErrCurrentDeviceNotFound
		}
		return DeviceIdentity{}, ErrStorageUnavailable
	}
	if id.DeviceID == "" || id.PublicKey == "" || id.PublicKeyFingerprint == "" {
		return DeviceIdentity{}, ErrStorageUnavailable
	}
	return id, nil
}

func (s *store) writePrivateKey(encoded string) error {
	return s.writeJSON(s.privateKeyPath(), privateKeyFile{PrivateKey: encoded})
}

func (s *store) readPrivateKey() (string, error) {
	var pk privateKeyFile
	if err := s.readJSON(s.privateKeyPath(), &pk); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", ErrCurrentDeviceNotFound
		}
		return "", ErrStorageUnavailable
	}
	if strings.TrimSpace(pk.PrivateKey) == "" {
		return "", ErrStorageUnavailable
	}
	return pk.PrivateKey, nil
}

func (s *store) readRegistry() (registryFile, error) {
	out := registryFile{SchemaVersion: SchemaVersion, Devices: []TrustedDevice{}}
	if err := s.readJSON(s.registryPath(), &out); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return out, nil
		}
		return registryFile{}, ErrInvalidRegistrySnapshot
	}
	if out.SchemaVersion == 0 {
		out.SchemaVersion = SchemaVersion
	}
	return out, nil
}

func (s *store) writeRegistry(reg registryFile) error {
	reg.SchemaVersion = SchemaVersion
	return s.writeJSON(s.registryPath(), reg)
}

func (s *store) readResources() (resourceFile, error) {
	out := resourceFile{SchemaVersion: SchemaVersion, Resources: []ResourceDescriptor{}}
	if err := s.readJSON(s.resourcesPath(), &out); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return out, nil
		}
		return resourceFile{}, ErrStorageUnavailable
	}
	return out, nil
}

func (s *store) writeResources(resources resourceFile) error {
	resources.SchemaVersion = SchemaVersion
	return s.writeJSON(s.resourcesPath(), resources)
}

func (s *store) readPeers() (peerFile, error) {
	out := peerFile{SchemaVersion: SchemaVersion, Peers: []PresenceRecord{}}
	if err := s.readJSON(s.peersPath(), &out); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return out, nil
		}
		return peerFile{}, ErrStorageUnavailable
	}
	return out, nil
}

func (s *store) writePeers(peers peerFile) error {
	peers.SchemaVersion = SchemaVersion
	return s.writeJSON(s.peersPath(), peers)
}

func (s *store) writeHandshake(h handshakeSession) error {
	if !validSessionID(h.SessionID) {
		return ErrInvalidSessionID
	}
	if err := os.MkdirAll(s.handshakesDir(), 0o700); err != nil {
		return ErrStorageUnavailable
	}
	return s.writeJSON(s.handshakePath(h.SessionID), h)
}

func (s *store) readHandshake(id string) (handshakeSession, error) {
	if !validSessionID(id) {
		return handshakeSession{}, ErrInvalidSessionID
	}
	var h handshakeSession
	if err := s.readJSON(s.handshakePath(id), &h); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return handshakeSession{}, ErrHandshakeFailed
		}
		return handshakeSession{}, ErrHandshakeFailed
	}
	return h, nil
}

func (s *store) writeLinks(status linkStatusFile) error {
	status.SchemaVersion = SchemaVersion
	return s.writeJSON(s.linkStatusPath(), status)
}

func (s *store) readLinks() (linkStatusFile, error) {
	out := linkStatusFile{SchemaVersion: SchemaVersion, Links: []ConnectionStatus{}}
	if err := s.readJSON(s.linkStatusPath(), &out); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return out, nil
		}
		return linkStatusFile{}, ErrStorageUnavailable
	}
	return out, nil
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
