// Package devicelink owns device identity, trust, signed proof and presence.
package devicelink

import (
	"errors"
	"time"
)

const (
	schemaVersion                       = 1
	RegistrySnapshotSchemaVersion       = 2
	legacyRegistrySnapshotSchemaVersion = 1
	metadataVersion                     = 1
	identityBundleVersion               = 1
	defaultLinkTTL                      = 15 * time.Minute
	defaultStaleAfter                   = 5 * time.Minute
	defaultFutureSkew                   = 2 * time.Minute
	defaultTransportTimeout             = 5 * time.Second
)

var (
	ErrNotConfigured           = errors.New("device link is not configured")
	ErrInvalidNamespace        = errors.New("invalid app id or namespace")
	ErrCurrentDeviceNotFound   = errors.New("current device is not bootstrapped")
	ErrDeviceAlreadyExists     = errors.New("device already exists with different trust data")
	ErrDeviceNotFound          = errors.New("device not found")
	ErrDeviceNotTrusted        = errors.New("device is not trusted")
	ErrDeviceRevoked           = errors.New("device is revoked")
	ErrDeviceStale             = errors.New("device is stale")
	ErrInvalidRegistrySnapshot = errors.New("invalid registry snapshot")
	ErrFingerprintMismatch     = errors.New("device fingerprint mismatch")
	ErrInvalidPublicKey        = errors.New("invalid device public key")
	ErrInvalidIdentityBundle   = errors.New("invalid public identity bundle")
	ErrHandshakeFailed         = errors.New("handshake failed")
	ErrInvalidSessionID        = errors.New("invalid handshake session id")
	ErrChallengeExpired        = errors.New("handshake challenge expired")
	ErrChallengeReplay         = errors.New("handshake challenge already used")
	ErrTransportUnavailable    = errors.New("transport unavailable")
	ErrDiscoveryUnavailable    = errors.New("discovery unavailable")
	ErrStorageUnavailable      = errors.New("device link storage unavailable")
	ErrInvalidResource         = errors.New("invalid resource advertisement")
	ErrContextCanceled         = errors.New("device link operation canceled")
)
