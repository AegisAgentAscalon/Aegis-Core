package auth

import (
	"reflect"
	"sync"

	"github.com/AegisAgentAscalon/aegis-core/pkg/secretstore"
)

// Service owns app-scoped OAuth setup operations.
type Service struct {
	*serviceState
}

// serviceState keeps copied Service values attached to the same owner and lock.
type serviceState struct {
	cfg   AppConfig
	store *store
	mu    sync.Mutex
}

// Option configures an auth service without expanding the legacy constructor.
type Option func(*serviceOptions) error

type serviceOptions struct {
	protectedStore secretstore.Store
}

// WithStrictProtectedStorage requires OAuth tokens and pending PKCE sessions
// to use the supplied host-owned protected store without plaintext fallback.
func WithStrictProtectedStorage(store secretstore.Store) Option {
	return func(options *serviceOptions) error {
		if isNilSecretStore(store) {
			return ErrStorageUnavailable
		}
		options.protectedStore = store
		return nil
	}
}

func isNilSecretStore(store secretstore.Store) bool {
	if store == nil {
		return true
	}
	value := reflect.ValueOf(store)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

// NewService creates a service with the legacy app-scoped file store.
func NewService(cfg AppConfig) (*Service, error) {
	return newService(cfg, serviceOptions{})
}

// NewServiceWithOptions creates a service with explicit storage options.
func NewServiceWithOptions(cfg AppConfig, options ...Option) (*Service, error) {
	resolved := serviceOptions{}
	for _, option := range options {
		if option == nil {
			return nil, ErrStorageUnavailable
		}
		if err := option(&resolved); err != nil {
			return nil, err
		}
	}
	return newService(cfg, resolved)
}

// NewStrictService creates a service that requires host-owned protected
// storage for OAuth tokens and pending PKCE sessions.
func NewStrictService(cfg AppConfig, store secretstore.Store) (*Service, error) {
	return NewServiceWithOptions(cfg, WithStrictProtectedStorage(store))
}

func newService(cfg AppConfig, options serviceOptions) (*Service, error) {
	cfg = normalizeConfig(cfg)
	if err := validateConfig(cfg); err != nil {
		return nil, err
	}
	st, err := newStore(cfg, options.protectedStore)
	if err != nil {
		return nil, err
	}
	return &Service{serviceState: &serviceState{cfg: cfg, store: st}}, nil
}

// ValidateConfig validates the service configuration.
func (s *Service) ValidateConfig() error {
	return validateConfig(s.cfg)
}
