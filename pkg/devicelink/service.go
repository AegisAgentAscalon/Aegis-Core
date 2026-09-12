package devicelink

import (
	"context"
	"sync"
	"time"
)

type Service struct {
	*serviceState
}

type serviceState struct {
	cfg       AppConfig
	store     *store
	discovery DiscoveryProvider
	transport Transport
	clock     Clock
	mu        sync.Mutex
}

func WithDiscoveryProvider(provider DiscoveryProvider) Option {
	return func(o *options) { o.discovery = provider }
}

func WithTransport(transport Transport) Option {
	return func(o *options) { o.transport = transport }
}

func WithClock(clock Clock) Option {
	return func(o *options) { o.clock = clock }
}

func NewService(config AppConfig, opts ...Option) (*Service, error) {
	cfg := normalizeConfig(config)
	if err := validateConfig(cfg); err != nil {
		return nil, err
	}
	st, err := newStore(cfg)
	if err != nil {
		return nil, err
	}
	options := options{discovery: noopDiscoveryProvider{}, clock: realClock{}}
	for _, opt := range opts {
		if opt != nil {
			opt(&options)
		}
	}
	if options.discovery == nil {
		options.discovery = noopDiscoveryProvider{}
	}
	options.discovery = ownedDiscoveryProvider{provider: options.discovery}
	if options.transport != nil {
		options.transport = ownedTransport{transport: options.transport}
	}
	if options.clock == nil {
		options.clock = realClock{}
	}
	return &Service{serviceState: &serviceState{cfg: cfg, store: st, discovery: options.discovery, transport: options.transport, clock: options.clock}}, nil
}

func (s *Service) ValidateConfig() error {
	return validateConfig(s.cfg)
}

// Clock implementations are host callbacks. Observe time before taking the
// owner mutex, then recheck cancellation before reading or changing state.
func (s *Service) operationTime(ctx context.Context) (time.Time, error) {
	if err := contextError(ctx); err != nil {
		return time.Time{}, err
	}
	now := s.clock.Now().UTC()
	return now, contextError(ctx)
}

// lockAtTime returns with the owner mutex held and a fresh time observation.
// If another operation owns the mutex, discard the sample before waiting and
// resample afterward. Clock callbacks never run while this mutex is held.
func (s *Service) lockAtTime(ctx context.Context) (time.Time, error) {
	for {
		now, err := s.operationTime(ctx)
		if err != nil {
			return time.Time{}, err
		}
		if s.mu.TryLock() {
			if err := contextError(ctx); err != nil {
				s.mu.Unlock()
				return time.Time{}, err
			}
			return now, nil
		}
		s.mu.Lock()
		s.mu.Unlock()
	}
}
