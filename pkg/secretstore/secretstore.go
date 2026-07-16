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

// ErrNotFound reports that a logical key has no protected record.
var ErrNotFound = errors.New("protected secret not found")

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
