package profilesync

import (
	"context"
	"sync"

	"github.com/AegisAgentAscalon/aegis-core/pkg/profilemesh"
)

type MemoryMetadataStore struct {
	mu              sync.Mutex
	err             error
	localSnapshot   profilemesh.SignedProfileSnapshot
	localProposals  []profilemesh.ProfileChangeProposal
	remoteSnapshots map[string]RemoteSnapshotRecord
	remoteProposals map[string]RemoteProposalRecord
}

func NewMemoryMetadataStore() *MemoryMetadataStore {
	return &MemoryMetadataStore{remoteSnapshots: map[string]RemoteSnapshotRecord{}, remoteProposals: map[string]RemoteProposalRecord{}}
}

func (s *MemoryMetadataStore) SetError(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.err = err
}

func (s *MemoryMetadataStore) SetLocalSnapshot(snapshot profilemesh.SignedProfileSnapshot) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.localSnapshot = snapshot
}

func (s *MemoryMetadataStore) AddLocalProposal(proposal profilemesh.ProfileChangeProposal) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.localProposals = append(s.localProposals, proposal)
}

func (s *MemoryMetadataStore) LoadLocalSnapshot(ctx context.Context) (profilemesh.SignedProfileSnapshot, error) {
	if err := storeContextError(ctx); err != nil {
		return profilemesh.SignedProfileSnapshot{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return profilemesh.SignedProfileSnapshot{}, s.err
	}
	return s.localSnapshot, nil
}

func (s *MemoryMetadataStore) SaveRemoteSnapshot(ctx context.Context, record RemoteSnapshotRecord) error {
	if err := storeContextError(ctx); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return s.err
	}
	if s.remoteSnapshots == nil {
		s.remoteSnapshots = map[string]RemoteSnapshotRecord{}
	}
	s.remoteSnapshots[record.Snapshot.Metadata.SnapshotID] = record
	return nil
}

func (s *MemoryMetadataStore) ListRemoteSnapshots(ctx context.Context) ([]RemoteSnapshotRecord, error) {
	if err := storeContextError(ctx); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return nil, s.err
	}
	out := make([]RemoteSnapshotRecord, 0, len(s.remoteSnapshots))
	for _, record := range s.remoteSnapshots {
		out = append(out, record)
	}
	return out, nil
}

func (s *MemoryMetadataStore) LoadLocalProposals(ctx context.Context) ([]profilemesh.ProfileChangeProposal, error) {
	if err := storeContextError(ctx); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return nil, s.err
	}
	return append([]profilemesh.ProfileChangeProposal{}, s.localProposals...), nil
}

func (s *MemoryMetadataStore) SaveRemoteProposal(ctx context.Context, record RemoteProposalRecord) error {
	if err := storeContextError(ctx); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return s.err
	}
	if s.remoteProposals == nil {
		s.remoteProposals = map[string]RemoteProposalRecord{}
	}
	s.remoteProposals[record.Proposal.ProposalID] = record
	return nil
}

func (s *MemoryMetadataStore) ListRemoteProposals(ctx context.Context) ([]RemoteProposalRecord, error) {
	if err := storeContextError(ctx); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return nil, s.err
	}
	out := make([]RemoteProposalRecord, 0, len(s.remoteProposals))
	for _, record := range s.remoteProposals {
		out = append(out, record)
	}
	return out, nil
}

func storeContextError(ctx context.Context) error {
	if ctx == nil {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return ErrStoreUnavailable
	}
	return nil
}
