// Service construction and state/configuration ownership for the public Updates package.
package updates

import (
	"context"
	"errors"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// Service is the public update service handle. Its private state is shared when
// a Service value is copied, matching the historical facade's pointer-owner
// semantics while keeping implementation details out of the public contract.
type Service struct {
	*serviceState
}

type serviceState struct {
	cfg                AppConfig
	store              *store
	provider           Provider
	apply              ApplyStrategy
	client             *http.Client
	options            ServiceOptions
	revision           uint64
	legacyApplyEnabled bool

	mu              sync.Mutex
	workflowMu      sync.Mutex
	applyInProgress bool
}

func NewRecordOnlyService(cfg AppConfig) (*Service, error) {
	return NewRecordOnlyServiceWithOptions(cfg, ServiceOptions{})
}

func NewRecordOnlyServiceWithOptions(cfg AppConfig, options ServiceOptions) (*Service, error) {
	return newServiceWithOptions(cfg, ManualApplyStrategy{}, options, false)
}

func newServiceWithOptions(cfg AppConfig, apply ApplyStrategy, options ServiceOptions, legacyApplyEnabled bool) (*Service, error) {
	cfg = normalizeConfig(cfg)
	if err := validateConfigWithOptions(cfg, options); err != nil {
		return nil, err
	}
	st, err := newStore(cfg)
	if err != nil {
		return nil, err
	}
	client, err := clientForSource(cfg, options)
	if err != nil {
		return nil, err
	}
	provider, err := newProvider(cfg, client)
	if err != nil {
		return nil, err
	}
	if apply == nil {
		apply = ManualApplyStrategy{}
	}
	return &Service{serviceState: &serviceState{
		cfg: cfg, store: st, provider: provider, apply: apply,
		client: client, options: options, revision: 1, legacyApplyEnabled: legacyApplyEnabled,
	}}, nil
}

type serviceSnapshot struct {
	cfg      AppConfig
	store    *store
	provider Provider
	client   *http.Client
	revision uint64
}

func (s *Service) snapshotLocked() serviceSnapshot {
	return serviceSnapshot{
		cfg: cloneConfig(s.cfg), store: s.store, provider: s.provider,
		client: s.client, revision: s.revision,
	}
}

func (s *Service) operationSnapshot() (serviceSnapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.applyInProgress {
		return serviceSnapshot{}, ErrApplyInProgress
	}
	return s.snapshotLocked(), nil
}

func (s *Service) currentLocked(snapshot serviceSnapshot) bool {
	return s.revision == snapshot.revision && s.store == snapshot.store && sourceAndPolicyMatch(s.cfg, sourceKey(snapshot.cfg.Source), policyKey(snapshot.cfg.Policy)) && s.cfg.Channel == snapshot.cfg.Channel
}

func (s *Service) ValidateConfig() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return validateConfigWithOptions(s.cfg, s.options)
}

func (s *Service) GetStatus(ctx context.Context) (CurrentState, error) {
	ctx = normalizeContext(ctx)
	if err := contextError(ctx); err != nil {
		return CurrentState{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.getStatusLocked()
}

func (s *Service) getStatusLocked() (CurrentState, error) {
	state := CurrentState{
		Source:         sourceSummary(s.cfg.Source),
		AppID:          s.cfg.AppID,
		DisplayName:    s.cfg.DisplayName,
		CurrentVersion: s.cfg.CurrentVersion,
		Channel:        s.cfg.Channel,
		Platform:       s.cfg.Platform,
		Architecture:   s.cfg.Architecture,
		Provider:       s.cfg.Source.Provider,
		Configured:     true,
		Message:        "updates configured",
	}
	if cached, err := s.store.readSelected(context.Background()); err == nil {
		if sourceAndPolicyMatch(s.cfg, cached.SourceKey, cached.PolicyKey) && cached.Manifest.Channel == s.cfg.Channel {
			if err := validateSelectedUpdate(s.cfg, cached); err == nil {
				release := releaseFromSelection(cached.Manifest, cached.Artifact, time.Time{}, sourceSummary(s.cfg.Source))
				state.LatestRelease = &release
				state.UpdateAvailable = compareVersions(cached.Manifest.Version, s.cfg.CurrentVersion) > 0
			} else {
				state.LastError = safeStatusMessage(err)
			}
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		state.LastError = "stored update metadata is invalid"
	}
	if stagedRecord, err := s.store.readStaged(context.Background()); err == nil {
		if err := validateStagedUpdateReadyFor(context.Background(), s.cfg, s.store, stagedRecord, time.Now().UTC()); err == nil {
			state.StagedVersion = stagedRecord.Version
			state.Verified = true
		} else {
			state.LastError = safeStatusMessage(err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		state.LastError = "staged update metadata is invalid"
	}
	return state, nil
}

func (s *Service) ConfigureSource(ctx context.Context, source SourceConfig) (CurrentState, error) {
	if source.Provider == "" {
		return CurrentState{}, ErrInvalidProvider
	}
	return s.ConfigureLane(ctx, LaneConfig{Source: source})
}

func (s *Service) SetChannel(ctx context.Context, channel Channel) (CurrentState, error) {
	channel = Channel(strings.TrimSpace(string(channel)))
	if channel == "" || !validSafeName(string(channel)) {
		return CurrentState{}, ErrInvalidConfig
	}
	return s.ConfigureLane(ctx, LaneConfig{Channel: channel, Source: SourceConfig{}})
}

func (s *Service) ConfigureLane(ctx context.Context, lane LaneConfig) (CurrentState, error) {
	ctx = normalizeContext(ctx)
	if err := contextError(ctx); err != nil {
		return CurrentState{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.applyInProgress {
		return CurrentState{}, ErrApplyInProgress
	}
	next := cloneConfig(s.cfg)
	if lane.Channel != "" {
		next.Channel = Channel(strings.TrimSpace(string(lane.Channel)))
	}
	if lane.Source.Provider != "" {
		next.Source = lane.Source
	}
	if lane.Policy != nil {
		next.Policy = *lane.Policy
	}
	next = normalizeConfig(next)
	if err := validateConfigWithOptions(next, s.options); err != nil {
		return CurrentState{}, err
	}
	st, err := newStore(next)
	if err != nil {
		return CurrentState{}, err
	}
	client, err := clientForSource(next, s.options)
	if err != nil {
		return CurrentState{}, err
	}
	provider, err := newProvider(next, client)
	if err != nil {
		return CurrentState{}, err
	}
	s.cfg, s.store, s.client, s.provider = next, st, client, provider
	s.revision++
	return s.getStatusLocked()
}
