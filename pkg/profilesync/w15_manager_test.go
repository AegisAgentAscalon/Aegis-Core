package profilesync

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/AegisAgentAscalon/aegis-core/pkg/profilemesh"
	"github.com/AegisAgentAscalon/aegis-core/pkg/relay"
)

type w15Trust func(context.Context, string, string) TrustDecision

func (f w15Trust) VerifySigner(ctx context.Context, id, key string) TrustDecision {
	return f(ctx, id, key)
}

type w15Clock func() time.Time

func (f w15Clock) Now() time.Time { return f() }

type w15Transport struct {
	status                     SyncTransportStatus
	queue                      []SyncEnvelope
	statusCalls, pushes, pulls int
	onPush                     func()
}

func (t *w15Transport) GetStatus(context.Context) SyncTransportStatus {
	t.statusCalls++
	return t.status
}
func (t *w15Transport) PushEnvelope(context.Context, SyncEnvelope) (relay.DeliveryReceipt, error) {
	t.pushes++
	if t.onPush != nil {
		t.onPush()
	}
	return relay.DeliveryReceipt{Accepted: true}, nil
}
func (t *w15Transport) PullEnvelopes(context.Context) ([]SyncEnvelope, error) {
	t.pulls++
	out := t.queue
	t.queue = nil
	return out, nil
}

type w15Store struct {
	*MemoryMetadataStore
	localLoads, snapshotLists, proposalLists int
	onSnapshot                               func(context.Context, RemoteSnapshotRecord) error
	onProposal                               func(context.Context, RemoteProposalRecord) error
}

func (s *w15Store) LoadLocalSnapshot(ctx context.Context) (profilemesh.SignedProfileSnapshot, error) {
	s.localLoads++
	return s.MemoryMetadataStore.LoadLocalSnapshot(ctx)
}
func (s *w15Store) ListRemoteSnapshots(ctx context.Context) ([]RemoteSnapshotRecord, error) {
	s.snapshotLists++
	return s.MemoryMetadataStore.ListRemoteSnapshots(ctx)
}
func (s *w15Store) ListRemoteProposals(ctx context.Context) ([]RemoteProposalRecord, error) {
	s.proposalLists++
	return s.MemoryMetadataStore.ListRemoteProposals(ctx)
}
func (s *w15Store) SaveRemoteSnapshot(ctx context.Context, record RemoteSnapshotRecord) error {
	if s.onSnapshot != nil {
		return s.onSnapshot(ctx, record)
	}
	return s.MemoryMetadataStore.SaveRemoteSnapshot(ctx, record)
}
func (s *w15Store) SaveRemoteProposal(ctx context.Context, record RemoteProposalRecord) error {
	if s.onProposal != nil {
		return s.onProposal(ctx, record)
	}
	return s.MemoryMetadataStore.SaveRemoteProposal(ctx, record)
}
func w15Manager(t *testing.T) (*SyncManager, *w15Store, *w15Transport, time.Time) {
	t.Helper()
	now := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)
	store := &w15Store{MemoryMetadataStore: NewMemoryMetadataStore()}
	store.SetLocalSnapshot(validSyncSnapshot("local", "", now))
	transport := &w15Transport{status: SyncTransportStatus{Available: true}}
	manager, err := NewSyncManager(SyncConfig{Enabled: true, ProfileNamespace: "profile-a", LocalDeviceID: "device-local"}, WithSnapshotStore(store), WithProposalStore(store), WithTransport(transport), WithClock(inboxClock{at: now}), WithTrustVerifier(staticTrust{trusted: true}))
	if err != nil {
		t.Fatal(err)
	}
	return manager, store, transport, now
}

func TestW15CallbackInsertedMetadataIsObserved(t *testing.T) {
	for _, trigger := range []string{"trust", "save"} {
		for _, kind := range []string{"snapshot", "proposal"} {
			t.Run(trigger+"/"+kind, func(t *testing.T) {
				m, store, transport, now := w15Manager(t)
				ctx := context.Background()
				first := validSyncProposal("first", "other-base", now)
				future := validSyncProposal("future", "local", now)
				if kind == "snapshot" {
					transport.queue = []SyncEnvelope{snapshotEnvelope("profile-a", "device-remote", validSyncSnapshot("first", "local", now), now), snapshotEnvelope("profile-a", "device-remote", validSyncSnapshot("future", "local", now), now)}
				} else {
					transport.queue = []SyncEnvelope{proposalEnvelope("profile-a", "device-remote", first, now), proposalEnvelope("profile-a", "device-remote", future, now)}
				}
				var once sync.Once
				insert := func() {
					once.Do(func() {
						var err error
						if kind == "snapshot" {
							err = store.MemoryMetadataStore.SaveRemoteSnapshot(ctx, RemoteSnapshotRecord{Snapshot: validSyncSnapshot("future", "local", now), ReceivedAt: now, TrustState: TrustTrusted})
						} else {
							competitor := validSyncProposal("competitor", "local", now)
							err = store.MemoryMetadataStore.SaveRemoteProposal(ctx, RemoteProposalRecord{Proposal: competitor, ReceivedAt: now, TrustState: TrustTrusted})
						}
						if err != nil {
							t.Error(err)
						}
					})
				}
				if trigger == "trust" {
					m.trust = w15Trust(func(context.Context, string, string) TrustDecision {
						insert()
						_ = m.BuildStatus(ctx)
						return TrustDecision{Trusted: true}
					})
				} else {
					store.onSnapshot = func(ctx context.Context, r RemoteSnapshotRecord) error {
						insert()
						return store.MemoryMetadataStore.SaveRemoteSnapshot(ctx, r)
					}
					store.onProposal = func(ctx context.Context, r RemoteProposalRecord) error {
						insert()
						return store.MemoryMetadataStore.SaveRemoteProposal(ctx, r)
					}
				}
				result, err := m.PullRemote(ctx)
				if err != nil {
					t.Fatal(err)
				}
				if kind == "snapshot" && (result.ReceivedSnapshots != 1 || result.Rejected != 1 || !hasSyncIssue(result.Issues, "duplicate_snapshot_id")) {
					t.Fatal("future duplicate missed", result)
				}
				if kind == "proposal" && (result.ReceivedProposals != 2 || !hasSyncIssue(result.Issues, "competing_proposal_review_required")) {
					t.Fatal("future competitor missed", result)
				}
			})
		}
	}
}

func TestW15ExchangeReloadsLocalBeforeConsumingQueue(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "changed", true: "failed"}[fail], func(t *testing.T) {
			m, store, transport, now := w15Manager(t)
			m.proposals = nil
			transport.queue = []SyncEnvelope{snapshotEnvelope("profile-a", "device-remote", validSyncSnapshot("remote", "new-local", now), now)}
			transport.onPush = func() {
				if fail {
					store.SetError(errors.New("read failed"))
				} else {
					store.SetLocalSnapshot(validSyncSnapshot("new-local", "", now))
				}
			}
			result, err := m.Exchange(context.Background())
			if fail {
				if !errors.Is(err, ErrStoreUnavailable) || transport.pulls != 0 || len(transport.queue) != 1 {
					t.Fatal("failed re-admission consumed queue", result, err)
				}
			} else if err != nil || result.Pull.ReceivedSnapshots != 1 || result.Pull.ReviewRequired || result.Status.LocalSnapshotID != "new-local" {
				t.Fatal("stale local snapshot reused", result, err)
			}
		})
	}
}

func TestW15ExchangeRechecksDirectionalReadiness(t *testing.T) {
	for _, phase := range []string{"proposal-push", "pull"} {
		t.Run(phase, func(t *testing.T) {
			m, store, transport, now := w15Manager(t)
			store.AddLocalProposal(validSyncProposal("local-proposal", "local", now))
			transport.queue = []SyncEnvelope{snapshotEnvelope("profile-a", "device-remote", validSyncSnapshot("remote", "local", now), now)}
			transport.onPush = func() {
				if phase == "proposal-push" {
					transport.status = SyncTransportStatus{Available: true, PullAvailable: true}
				} else if transport.pushes == 2 {
					transport.status = SyncTransportStatus{Available: true, PushAvailable: true}
				}
			}
			_, err := m.Exchange(context.Background())
			want := ErrTransportUnavailable
			if phase == "proposal-push" {
				want = ErrReceiveOnlyTransport
			}
			if !errors.Is(err, want) || transport.pulls != 0 || len(transport.queue) != 1 {
				t.Fatal("direction change bypassed", err, transport)
			}
		})
	}
}

func TestW15ExchangeFinalStatusObservesProviderWrites(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "normalized", true: "saved-then-failed"}[fail], func(t *testing.T) {
			m, store, transport, now := w15Manager(t)
			transport.queue = []SyncEnvelope{snapshotEnvelope("profile-a", "device-remote", validSyncSnapshot("remote", "local", now), now)}
			store.onSnapshot = func(ctx context.Context, r RemoteSnapshotRecord) error {
				r.RequiresReview = true
				if err := store.MemoryMetadataStore.SaveRemoteSnapshot(ctx, r); err != nil {
					return err
				}
				if fail {
					return errors.New("saved then failed")
				}
				return nil
			}
			result, err := m.Exchange(context.Background())
			if fail && !errors.Is(err, ErrStoreUnavailable) || !fail && err != nil || result.Status.RemoteSnapshotCount != 1 || !result.Status.ReviewRequired {
				t.Fatal("final status used submitted bookkeeping", result, err)
			}
		})
	}
}

func TestW15GenericExchangeRetainsObservationCounts(t *testing.T) {
	m, store, transport, now := w15Manager(t)
	transport.queue = []SyncEnvelope{snapshotEnvelope("profile-a", "device-remote", validSyncSnapshot("first", "local", now), now), snapshotEnvelope("profile-a", "device-remote", validSyncSnapshot("second", "local", now), now)}
	if _, err := m.Exchange(context.Background()); err != nil {
		t.Fatal(err)
	}
	if transport.statusCalls != 5 || store.localLoads != 3 || store.snapshotLists != 3 || store.proposalLists != 1 {
		t.Fatal("generic observations were cached", transport.statusCalls, store.localLoads, store.snapshotLists, store.proposalLists)
	}
}

func TestW15RecordExchangeClockReentry(t *testing.T) {
	m := &SyncManager{cfg: SyncConfig{Enabled: true, ProfileNamespace: "profile-a", LocalDeviceID: "device-local"}}
	now := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)
	m.clock = w15Clock(func() time.Time { _ = m.BuildStatus(context.Background()); return now })
	done := make(chan struct{})
	go func() { m.recordExchange(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("clock reentry held lastMu")
	}
	if !m.lastExchangeAt().Equal(now) {
		t.Fatal("exchange time lost")
	}
}
