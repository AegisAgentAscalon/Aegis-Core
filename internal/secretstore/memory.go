// Package secretstore provides development and test support for the public
// protected secret-store contract. It does not provide production protection.
package secretstore

import (
	"context"
	"sync"

	public "github.com/AegisAgentAscalon/aegis-core/pkg/secretstore"
)

// MemoryStore is an in-memory conformance implementation for development and
// tests only. It does not encrypt or otherwise protect values from the host.
type MemoryStore struct {
	mu        sync.RWMutex
	records   map[public.Key][]byte
	revisions map[public.Key]public.Revision
}

var _ public.Store = (*MemoryStore)(nil)
var _ public.VersionedStore = (*MemoryStore)(nil)

// NewMemoryStore creates an empty development/test-only store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		records:   make(map[public.Key][]byte),
		revisions: make(map[public.Key]public.Revision),
	}
}

// Get returns a defensive copy of the value stored for key.
func (s *MemoryStore) Get(ctx context.Context, key public.Key) ([]byte, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	value, ok := s.records[key]
	if !ok {
		return nil, public.ErrNotFound
	}
	return append([]byte(nil), value...), nil
}

// Put stores a defensive copy of value for key.
func (s *MemoryStore) Put(ctx context.Context, key public.Key, value []byte) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records[key] = append([]byte(nil), value...)
	s.revisions[key]++
	return nil
}

// Delete removes key or returns secretstore.ErrNotFound when it is absent.
func (s *MemoryStore) Delete(ctx context.Context, key public.Key) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.records[key]; !ok {
		return public.ErrNotFound
	}
	delete(s.records, key)
	s.revisions[key]++
	return nil
}

// GetWithRevision returns a defensive value copy and the current per-key
// revision. An absent key still returns its current revision with ErrNotFound.
func (s *MemoryStore) GetWithRevision(ctx context.Context, key public.Key) ([]byte, public.Revision, error) {
	if err := contextError(ctx); err != nil {
		return nil, 0, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	revision := s.revisions[key]
	value, ok := s.records[key]
	if !ok {
		return nil, revision, public.ErrNotFound
	}
	return append([]byte(nil), value...), revision, nil
}

// CompareAndSwap stores value only when expected is the current key revision.
func (s *MemoryStore) CompareAndSwap(ctx context.Context, key public.Key, expected public.Revision, value []byte) (public.Revision, error) {
	if err := contextError(ctx); err != nil {
		return 0, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.revisions[key] != expected {
		return s.revisions[key], public.ErrConflict
	}
	s.records[key] = append([]byte(nil), value...)
	s.revisions[key]++
	return s.revisions[key], nil
}

// CompareAndDelete removes key only when expected is its current revision.
func (s *MemoryStore) CompareAndDelete(ctx context.Context, key public.Key, expected public.Revision) (public.Revision, error) {
	if err := contextError(ctx); err != nil {
		return 0, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.revisions[key] != expected {
		return s.revisions[key], public.ErrConflict
	}
	if _, ok := s.records[key]; !ok {
		return s.revisions[key], public.ErrNotFound
	}
	delete(s.records, key)
	s.revisions[key]++
	return s.revisions[key], nil
}

func contextError(ctx context.Context) error {
	if ctx == nil {
		return nil
	}
	return ctx.Err()
}
