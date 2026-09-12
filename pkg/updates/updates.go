// Package updates exposes the public, app-agnostic Aegis Update Framework.
package updates

import (
	"errors"
	"time"
)

const (
	schemaVersion      = 1
	defaultHTTPTimeout = 15 * time.Second
	maxManifestBytes   = 4 * 1024 * 1024

	manifestSignatureKindEd25519 = "ed25519"
)

var (
	ErrNotConfigured        = errors.New("updates are not configured")
	ErrInvalidConfig        = errors.New("invalid update configuration")
	ErrInvalidProvider      = errors.New("invalid update provider")
	ErrProviderUnavailable  = errors.New("update provider unavailable")
	ErrInvalidManifest      = errors.New("invalid update manifest")
	ErrNoUpdateAvailable    = errors.New("no update available")
	ErrNoCompatibleArtifact = errors.New("no compatible update artifact")
	ErrDownloadFailed       = errors.New("update download failed")
	ErrVerificationFailed   = errors.New("update verification failed")
	ErrUpdateBlocked        = errors.New("update blocked by policy")
	ErrManifestStale        = errors.New("update manifest stale")
	ErrManifestFutureDated  = errors.New("update manifest future dated")
	ErrRollbackRisk         = errors.New("update rollback risk")
	ErrStagedUpdateStale    = errors.New("staged update stale")
	ErrStagedUpdateNotFound = errors.New("staged update is not available")
	ErrApplyFailed          = errors.New("update apply failed")
	ErrStorageUnavailable   = errors.New("update storage unavailable")
	ErrContextCanceled      = errors.New("update operation canceled")
	ErrUpdateStateChanged   = errors.New("update source or policy changed during operation")
	ErrApplyInProgress      = errors.New("update apply is already in progress")
)
