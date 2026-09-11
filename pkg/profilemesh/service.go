package profilemesh

import "sync"

type Service struct {
	*serviceState
}

type serviceState struct {
	cfg   AppConfig
	store *store
	clock Clock
	mu    sync.Mutex
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
	options := options{clock: realClock{}}
	for _, opt := range opts {
		if opt != nil {
			opt(&options)
		}
	}
	if options.clock == nil {
		options.clock = realClock{}
	}
	return &Service{serviceState: &serviceState{cfg: cfg, store: st, clock: options.clock}}, nil
}

func (s *Service) ValidateConfig() error {
	return validateConfig(s.cfg)
}
