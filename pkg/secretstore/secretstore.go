// Package secretstore defines the host-owned protected storage contract used by
// Aegis Core packages. Hosts choose and configure the platform protection
// mechanism; Aegis Core supplies only opaque logical keys and record bytes.
// Separately owned packages can adopt this contract without importing Auth
// internals or sharing Auth record formats.
package secretstore

import (
	"context"
	"errors"
)

var (
	// ErrNotFound reports that a logical key has no protected record.
	ErrNotFound = errors.New("protected secret not found")
	// ErrConflict reports that a versioned mutation used a stale revision.
	ErrConflict = errors.New("protected secret revision conflict")
)

// Key is an opaque logical record identifier. Store implementations must not
// derive security policy from its current string format.
type Key string

// Store persists opaque records using protection owned by the host process.
// Implementations must copy values they retain and values they return. Get and
// Delete must return ErrNotFound when key does not exist.
type Store interface {
	Get(ctx context.Context, key Key) ([]byte, error)
	Put(ctx context.Context, key Key, value []byte) error
	Delete(ctx context.Context, key Key) error
}

// Revision is an opaque, per-key mutation version. The zero revision is valid
// for a key that has never been mutated.
type Revision uint64

// VersionedStore optionally extends Store with atomic compare-and-swap
// mutations. Revisions must increase after every successful mutation and must
// not reset when a key is deleted. GetWithRevision returns the current revision
// together with ErrNotFound for an absent key, so callers can atomically create
// it. Stale comparisons return ErrConflict without changing the record.
type VersionedStore interface {
	Store
	GetWithRevision(ctx context.Context, key Key) ([]byte, Revision, error)
	CompareAndSwap(ctx context.Context, key Key, expected Revision, value []byte) (Revision, error)
	CompareAndDelete(ctx context.Context, key Key, expected Revision) (Revision, error)
}
