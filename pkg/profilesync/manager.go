package profilesync

import (
	"sync"
	"time"
)

type Option func(*options)

type options struct {
	snapshots SnapshotStore
	proposals ProposalStore
	transport SyncTransport
	trust     TrustVerifier
	clock     Clock
}

type SyncManager struct {
	cfg       SyncConfig
	snapshots SnapshotStore
	proposals ProposalStore
	transport SyncTransport
	trust     TrustVerifier
	clock     Clock
	lastMu    sync.Mutex
	last      time.Time
}

func WithSnapshotStore(store SnapshotStore) Option {
	return func(opts *options) {
		opts.snapshots = store
	}
}

func WithProposalStore(store ProposalStore) Option {
	return func(opts *options) {
		opts.proposals = store
	}
}

func WithTransport(transport SyncTransport) Option {
	return func(opts *options) {
		opts.transport = transport
	}
}

func WithTrustVerifier(verifier TrustVerifier) Option {
	return func(opts *options) {
		opts.trust = verifier
	}
}

func WithClock(clock Clock) Option {
	return func(opts *options) {
		opts.clock = clock
	}
}

func NewSyncManager(config SyncConfig, opts ...Option) (*SyncManager, error) {
	parsed := options{}
	for _, opt := range opts {
		if opt != nil {
			opt(&parsed)
		}
	}
	if config.Enabled && !validSyncName(config.ProfileNamespace) {
		return nil, ErrInvalidConfig
	}
	if config.Enabled && !validSyncID(config.LocalDeviceID) {
		return nil, ErrInvalidConfig
	}
	return &SyncManager{cfg: config, snapshots: parsed.snapshots, proposals: parsed.proposals, transport: parsed.transport, trust: parsed.trust, clock: parsed.clock}, nil
}

func (m *SyncManager) now() time.Time {
	if m != nil && m.clock != nil {
		return m.clock.Now().UTC()
	}
	return time.Now().UTC()
}

func (m *SyncManager) recordExchange() {
	m.lastMu.Lock()
	defer m.lastMu.Unlock()
	m.last = m.now()
}

func (m *SyncManager) lastExchangeAt() time.Time {
	m.lastMu.Lock()
	defer m.lastMu.Unlock()
	return m.last
}
