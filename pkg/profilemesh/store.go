package profilemesh

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/AegisAgentAscalon/aegis-core/internal/filepersist"
	"github.com/AegisAgentAscalon/aegis-core/internal/generation"
)

type deviceRegistryFile struct {
	SchemaVersion int                   `json:"schema_version"`
	Devices       []ProfileDeviceRecord `json:"devices"`
	UpdatedAt     time.Time             `json:"updated_at"`
}
type resourceRegistryFile struct {
	SchemaVersion int                     `json:"schema_version"`
	Resources     []ProfileResourceRecord `json:"resources"`
	UpdatedAt     time.Time               `json:"updated_at"`
}
type meshState struct {
	Version       int                   `json:"version"`
	Profile       *ProfileIdentity      `json:"profile"`
	Hosting       *ProfileHostingConfig `json:"hosting"`
	Devices       deviceRegistryFile    `json:"devices"`
	Resources     resourceRegistryFile  `json:"resources"`
	RelayHints    []ProfileRelayHint    `json:"relay_hints"`
	EndpointHints []ProfileEndpointHint `json:"endpoint_hints"`
}
type store struct {
	dir         string
	cfg         AppConfig
	generations *generation.Store
	state       *meshState // non-nil only for a single operation-owned aggregate
	dirty       bool
}

func newStore(cfg AppConfig) (*store, error) {
	dir := filepath.Join(cfg.DataDir, cfg.AppID, cfg.Namespace, "profilemesh")
	owner, _ := json.Marshal([]string{"profilemesh", cfg.AppID, cfg.Namespace})
	generations, err := generation.New(dir, string(owner))
	if err != nil {
		return nil, meshStorageError(err)
	}
	return &store{dir: dir, cfg: cfg, generations: generations}, nil
}
func (s *store) profilePath() string   { return filepath.Join(s.dir, "profile_identity.json") }
func (s *store) hostingPath() string   { return filepath.Join(s.dir, "hosting_config.json") }
func (s *store) devicesPath() string   { return filepath.Join(s.dir, "profile_devices.json") }
func (s *store) resourcesPath() string { return filepath.Join(s.dir, "profile_resources.json") }

func emptyMesh() *meshState {
	return &meshState{Version: 1, Devices: deviceRegistryFile{SchemaVersion: 1, Devices: []ProfileDeviceRecord{}}, Resources: resourceRegistryFile{SchemaVersion: 1, Resources: []ProfileResourceRecord{}}, RelayHints: []ProfileRelayHint{}, EndpointHints: []ProfileEndpointHint{}}
}
func encodeMesh(state *meshState) ([]byte, error) { return json.Marshal(state) }
func (s *store) loadGuard(ctx context.Context, guard *generation.Guard) (*meshState, string, map[string][]byte, error) {
	current, err := guard.Read()
	if err != nil {
		return nil, "", nil, err
	}
	state := emptyMesh()
	var backup map[string][]byte
	if current.Token != "" {
		state, err = decodeMesh(current.Data)
		if err != nil {
			return nil, "", nil, err
		}
	} else {
		backup = make(map[string][]byte, 4)
		for _, entry := range []struct {
			path string
			out  any
		}{
			{s.profilePath(), &state.Profile}, {s.hostingPath(), &state.Hosting}, {s.devicesPath(), &state.Devices}, {s.resourcesPath(), &state.Resources},
		} {
			raw, readErr := readLegacyMesh(ctx, entry.path)
			if readErr != nil {
				return nil, "", nil, readErr
			}
			backup[filepath.Base(entry.path)] = raw
			if raw == nil {
				continue
			}
			if err = json.Unmarshal(raw, entry.out); err != nil {
				return nil, "", nil, err
			}
			if entry.path == s.profilePath() && state.Profile == nil || entry.path == s.hostingPath() && state.Hosting == nil {
				return nil, "", nil, ErrStorageUnavailable
			}
		}
		if state.Devices.SchemaVersion == 0 {
			state.Devices.SchemaVersion = 1
		}
		if state.Resources.SchemaVersion == 0 {
			state.Resources.SchemaVersion = 1
		}
	}
	if err = validateStoredMesh(s.cfg, state); err != nil {
		return nil, "", nil, err
	}
	return state, current.Token, backup, nil
}

type meshContextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r meshContextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(p)
}
func readLegacyMesh(ctx context.Context, path string) ([]byte, error) {
	f, err := filepersist.OpenRegular(ctx, path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	raw, err := io.ReadAll(io.LimitReader(meshContextReader{ctx, f}, (64<<20)+1))
	err = errors.Join(err, f.Close(), ctx.Err())
	if err != nil {
		return nil, err
	}
	if len(raw) > 64<<20 {
		return nil, generation.ErrTooLarge
	}
	if len(raw) == 0 {
		raw = []byte{}
	}
	return raw, nil
}

// Root reads exist for private diagnostic helpers; operation views never reread disk.
func (s *store) readState() (*meshState, error) {
	if s.state != nil {
		return s.state, nil
	}
	guard, err := s.generations.Lock(context.Background())
	if err != nil {
		return nil, meshStorageError(err)
	}
	defer guard.Close()
	state, _, _, err := s.loadGuard(context.Background(), guard)
	return state, meshStorageError(err)
}
func (s *store) readProfile() (ProfileIdentity, error) {
	state, err := s.readState()
	if err != nil {
		return ProfileIdentity{}, err
	}
	if state.Profile == nil {
		return ProfileIdentity{}, ErrProfileNotFound
	}
	return *state.Profile, nil
}
func (s *store) readHosting() (ProfileHostingConfig, error) {
	state, err := s.readState()
	if err != nil {
		return ProfileHostingConfig{}, err
	}
	if state.Hosting == nil {
		return ProfileHostingConfig{}, os.ErrNotExist
	}
	return *state.Hosting, nil
}
func (s *store) readDevices() (deviceRegistryFile, error) {
	state, err := s.readState()
	if err != nil {
		return deviceRegistryFile{}, err
	}
	return state.Devices, nil
}
func (s *store) readResources() (resourceRegistryFile, error) {
	state, err := s.readState()
	if err != nil {
		return resourceRegistryFile{}, err
	}
	return state.Resources, nil
}
func (s *store) writeProfile(value ProfileIdentity) error {
	if s.state == nil {
		return ErrStorageUnavailable
	}
	s.state.Profile = &value
	s.dirty = true
	return nil
}
func (s *store) writeHosting(value ProfileHostingConfig) error {
	if s.state == nil {
		return ErrStorageUnavailable
	}
	s.state.Hosting = &value
	s.dirty = true
	return nil
}
func (s *store) writeDevices(value deviceRegistryFile) error {
	if s.state == nil {
		return ErrStorageUnavailable
	}
	value.SchemaVersion = 1
	s.state.Devices = value
	s.dirty = true
	return nil
}
func (s *store) writeResources(value resourceRegistryFile) error {
	if s.state == nil {
		return ErrStorageUnavailable
	}
	value.SchemaVersion = 1
	s.state.Resources = value
	s.dirty = true
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
