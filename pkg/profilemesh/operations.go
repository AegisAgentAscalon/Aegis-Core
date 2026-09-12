package profilemesh

import (
	"context"
	"errors"
	"maps"
	"slices"
	"time"

	"github.com/AegisAgentAscalon/aegis-core/internal/filelock"
	"github.com/AegisAgentAscalon/aegis-core/internal/generation"
)

type operationTime int

const (
	untimed operationTime = iota
	timed
	bootstrapTime
	hostingTime
	overviewTime
)

type sampledClock struct{ now time.Time }

func (c sampledClock) Now() time.Time { return c.now }

func needsClock(kind operationTime, state *meshState) bool {
	switch kind {
	case timed:
		return true
	case bootstrapTime:
		return state.Profile == nil
	case hostingTime:
		return state.Profile != nil && state.Hosting == nil
	case overviewTime:
		return state.Profile != nil && (state.Hosting == nil || state.Hosting.ProfileDataHostDeviceID != "")
	default:
		return false
	}
}

// runMesh keeps each operation on one owned aggregate. External clocks are
// sampled only after releasing the storage guard; their reentry may use reads.
func runMesh[T any](s *Service, ctx context.Context, kind operationTime, write, fullImport bool, operation func(*Service) (T, error)) (result T, err error) {
	if ctx == nil {
		ctx = context.Background()
	}
	var originalToken string
	var guard *generation.Guard
	defer func() {
		if guard != nil {
			_ = guard.Close()
		}
	}()
	captured := false
	for {
		guard, err = s.store.generations.Lock(ctx)
		if err != nil {
			return result, meshStorageError(err)
		}
		state, token, backup, err := s.store.loadGuard(ctx, guard)
		if err != nil {
			_ = guard.Close()
			return result, meshStorageError(err)
		}
		if fullImport {
			if !captured {
				originalToken, captured = token, true
			}
			if token != originalToken {
				_ = guard.Close()
				return result, ErrStorageUnavailable
			}
		}
		now := time.Time{}
		if needsClock(kind, state) {
			_ = guard.Close()
			// No owner or storage mutex is held while invoking caller code.
			now = s.clock.Now().UTC()
			guard, err = s.store.generations.TryLock(ctx)
			if errors.Is(err, filelock.ErrBusy) {
				// Wait without preserving the time sample. An import still retains its
				// original token so contention never turns it into a newer replacement.
				waiting, waitErr := s.store.generations.Lock(ctx)
				if waitErr != nil {
					return result, meshStorageError(waitErr)
				}
				_ = waiting.Close()
				continue
			}
			if err != nil {
				return result, meshStorageError(err)
			}
			current, tokenErr := guard.Token()
			if tokenErr != nil {
				_ = guard.Close()
				return result, meshStorageError(tokenErr)
			}
			if current != token {
				_ = guard.Close()
				if fullImport {
					return result, ErrStorageUnavailable
				}
				continue
			}
		}
		return finishMesh(s, ctx, guard, state, token, backup, now, write, operation)
	}
}

func finishMesh[T any](s *Service, ctx context.Context, guard *generation.Guard, state *meshState, token string, backup map[string][]byte, now time.Time, write bool, operation func(*Service) (T, error)) (result T, err error) {
	if err = contextError(ctx); err != nil {
		return result, err
	}
	viewStore := &store{dir: s.store.dir, cfg: s.cfg, state: state}
	view := &Service{serviceState: &serviceState{cfg: s.cfg, store: viewStore, clock: sampledClock{now}}}
	result, err = operation(view)
	if err == nil && write && viewStore.dirty {
		err = validateStoredMesh(s.cfg, state)
		if err == nil {
			var data []byte
			data, err = encodeMesh(state)
			if err == nil {
				_, err = guard.Commit(token, data, backup)
			}
		}
		if err != nil {
			var zero T
			return zero, meshStorageError(err)
		}
	}
	return result, err
}

func meshStorageError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, ErrContextCanceled) {
		return ErrContextCanceled
	}
	return ErrStorageUnavailable
}

func (s *Service) BootstrapProfile(ctx context.Context, req BootstrapProfileRequest) (ProfileIdentity, error) {
	return runMesh(s, ctx, bootstrapTime, true, false, func(view *Service) (ProfileIdentity, error) { return view.bootstrapProfile(ctx, req) })
}

func (s *Service) GetProfile(ctx context.Context) (ProfileIdentity, error) {
	return runMesh(s, ctx, untimed, false, false, func(view *Service) (ProfileIdentity, error) { return view.getProfile(ctx) })
}

func (s *Service) SetProfileHostingMode(ctx context.Context, req SetProfileHostingModeRequest) (ProfileHostingConfig, error) {
	return runMesh(s, ctx, timed, true, false, func(view *Service) (ProfileHostingConfig, error) { return view.setProfileHostingMode(ctx, req) })
}

func (s *Service) GetProfileHostingConfig(ctx context.Context) (ProfileHostingConfig, error) {
	return runMesh(s, ctx, hostingTime, false, false, func(view *Service) (ProfileHostingConfig, error) { return view.getProfileHostingConfig(ctx) })
}

func (s *Service) RegisterProfileDevice(ctx context.Context, req RegisterProfileDeviceRequest) (ProfileDeviceRecord, error) {
	req.Capabilities = slices.Clone(req.Capabilities)
	return runMesh(s, ctx, timed, true, false, func(view *Service) (ProfileDeviceRecord, error) { return view.registerProfileDeviceDefault(ctx, req) })
}

func (s *Service) RegisterProfileDeviceStrict(ctx context.Context, req RegisterProfileDeviceRequest) (ProfileDeviceRecord, error) {
	req.Capabilities = slices.Clone(req.Capabilities)
	return runMesh(s, ctx, timed, true, false, func(view *Service) (ProfileDeviceRecord, error) { return view.registerProfileDeviceStrict(ctx, req) })
}

func (s *Service) ListProfileDevices(ctx context.Context) ([]ProfileDeviceRecord, error) {
	return runMesh(s, ctx, untimed, false, false, func(view *Service) ([]ProfileDeviceRecord, error) { return view.listProfileDevices(ctx) })
}

func (s *Service) RegisterProfileResource(ctx context.Context, req RegisterProfileResourceRequest) (ProfileResourceRecord, error) {
	req.AllowedHostDeviceIDs = slices.Clone(req.AllowedHostDeviceIDs)
	req.Tags = slices.Clone(req.Tags)
	req.Metadata = maps.Clone(req.Metadata)
	return runMesh(s, ctx, timed, true, false, func(view *Service) (ProfileResourceRecord, error) { return view.registerProfileResource(ctx, req) })
}

func (s *Service) ListProfileResources(ctx context.Context) ([]ProfileResourceRecord, error) {
	return runMesh(s, ctx, untimed, false, false, func(view *Service) ([]ProfileResourceRecord, error) { return view.listProfileResources(ctx) })
}

func (s *Service) SetResourceHost(ctx context.Context, req SetResourceHostRequest) (ProfileResourceRecord, error) {
	return runMesh(s, ctx, timed, true, false, func(view *Service) (ProfileResourceRecord, error) { return view.setResourceHost(ctx, req) })
}

func (s *Service) GetResourceHost(ctx context.Context, resourceID string) (ProfileResourceHostStatus, error) {
	return runMesh(s, ctx, timed, false, false, func(view *Service) (ProfileResourceHostStatus, error) { return view.getResourceHost(ctx, resourceID) })
}

func (s *Service) BuildProfileMeshOverview(ctx context.Context) (ProfileMeshOverview, error) {
	return runMesh(s, ctx, overviewTime, false, false, func(view *Service) (ProfileMeshOverview, error) { return view.buildProfileMeshOverview(ctx) })
}

func (s *Service) ExportProfileMeshSnapshot(ctx context.Context) (ProfileMeshSnapshot, error) {
	return runMesh(s, ctx, hostingTime, false, false, func(view *Service) (ProfileMeshSnapshot, error) { return view.exportProfileMeshSnapshot(ctx) })
}

func (s *Service) RemoveProfileDevice(ctx context.Context, deviceID string) error {
	_, err := runMesh(s, ctx, timed, true, false, func(view *Service) (struct{}, error) { return struct{}{}, view.removeProfileDevice(ctx, deviceID) })
	return err
}

func (s *Service) ImportProfileMeshSnapshot(ctx context.Context, snapshot ProfileMeshSnapshot) error {
	snapshot = publicProfileMeshSnapshot(snapshot)
	_, err := runMesh(s, ctx, timed, true, true, func(view *Service) (struct{}, error) {
		return struct{}{}, view.importProfileMeshSnapshot(ctx, snapshot)
	})
	return err
}
