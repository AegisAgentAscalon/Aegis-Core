package updates

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/AegisAgentAscalon/aegis-core/internal/filepersist"
	"github.com/AegisAgentAscalon/aegis-core/internal/generation"
)

type recordSlot[T any] struct {
	value *T
	err   error
}

func stored[T any](value T) recordSlot[T] { return recordSlot[T]{value: &value} }
func (r recordSlot[T]) read() (out T, err error) {
	if r.err != nil {
		return out, r.err
	}
	if r.value == nil {
		return out, os.ErrNotExist
	}
	return *r.value, nil
}

// stateView belongs to one operation. Only stateRecord is persisted natively.
type stateView struct {
	token          string
	raw            map[string][]byte
	fatal          error
	candidateFault bool
	selected       recordSlot[selectedUpdate]
	downloaded     recordSlot[downloadedUpdate]
	verified       recordSlot[verifiedUpdate]
	staged         recordSlot[stagedUpdateRecord]
	lifecycle      recordSlot[lifecycleRecord]
	blobs          map[string]blobRecord
}

func (v *stateView) clearCandidate() {
	v.selected = recordSlot[selectedUpdate]{}
	v.clearTransfers()
	v.candidateFault = false
}
func (v *stateView) clearTransfers() {
	v.downloaded = recordSlot[downloadedUpdate]{}
	v.verified = recordSlot[verifiedUpdate]{}
}
func (v *stateView) clearStaged() {
	v.staged = recordSlot[stagedUpdateRecord]{}
	v.lifecycle = recordSlot[lifecycleRecord]{}
	v.verified = recordSlot[verifiedUpdate]{}
}
func (v *stateView) quarantineCandidate() {
	v.clearCandidate()
	v.candidateFault = true
	v.selected.err, v.downloaded.err, v.verified.err = ErrStorageUnavailable, ErrStorageUnavailable, ErrStorageUnavailable
}

func (v *stateView) stagedFor(cfg AppConfig) (stagedUpdateRecord, error) {
	r, err := v.staged.read()
	if err != nil || r.Manifest != nil {
		return r, err
	}
	verified, err := v.verified.read()
	if err != nil || verified.SchemaVersion != schemaVersion || verified.VerifiedAt.IsZero() ||
		!sourceAndPolicyMatch(cfg, verified.Downloaded.SourceKey, verified.Downloaded.PolicyKey) {
		return r, ErrVerificationFailed
	}
	r.Manifest = &verified.Downloaded.Manifest
	return r, nil
}

func (s *store) load(ctx context.Context, guard *generation.Guard) (*stateView, error) {
	snapshot, err := guard.Read()
	if err != nil {
		return nil, persistenceError(err)
	}
	if snapshot.Token == "" {
		return s.readLegacy(ctx), nil
	}
	v, err := s.decodeState(ctx, snapshot.Data)
	if err != nil {
		if canceled := contextError(ctx); canceled != nil {
			return nil, canceled
		}
		return nil, ErrStorageUnavailable
	}
	v.token = snapshot.Token
	return v, nil
}

var legacyMetadata = []string{
	"selected_update.json", "downloaded_update.json", "verified_update.json",
	"staged/staged_update.json", "staged/lifecycle_envelope.json",
}

func (s *store) readLegacy(ctx context.Context) *stateView {
	v := &stateView{raw: make(map[string][]byte), blobs: make(map[string]blobRecord)}
	v.selected = readLegacySlot[selectedUpdate](ctx, s, legacyMetadata[0], v)
	v.downloaded = readLegacySlot[downloadedUpdate](ctx, s, legacyMetadata[1], v)
	v.verified = readLegacySlot[verifiedUpdate](ctx, s, legacyMetadata[2], v)
	v.staged = readLegacySlot[stagedUpdateRecord](ctx, s, legacyMetadata[3], v)
	v.lifecycle = readLegacySlot[lifecycleRecord](ctx, s, legacyMetadata[4], v)
	if v.staged.value != nil && v.staged.value.ArtifactPath == "" && v.staged.value.ArtifactName != "" {
		v.staged.value.ArtifactPath = filepath.Join(s.stagedDir(), v.staged.value.ArtifactName)
	}
	return v
}

func readLegacySlot[T any](ctx context.Context, s *store, key string, view *stateView) recordSlot[T] {
	raw, err := readLegacyBytes(ctx, filepath.Join(s.dir, filepath.FromSlash(key)))
	view.raw[key] = raw
	if errors.Is(err, os.ErrNotExist) {
		return recordSlot[T]{}
	}
	if err != nil {
		view.fatal = persistenceError(err)
		return recordSlot[T]{err: persistenceError(err)}
	}
	var value T
	if err := json.Unmarshal(raw, &value); err != nil {
		return recordSlot[T]{err: ErrStorageUnavailable}
	}
	return stored(value)
}

func readLegacyBytes(ctx context.Context, path string) ([]byte, error) {
	f, err := filepersist.OpenRegular(ctx, path)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err == nil && info.Size() > maxMetadataBytes {
		err = filepersist.ErrTooLarge
	}
	var raw []byte
	if err == nil {
		raw, err = io.ReadAll(io.LimitReader(contextReader{ctx, f}, maxMetadataBytes+1))
	}
	err = errors.Join(err, f.Close())
	if int64(len(raw)) > maxMetadataBytes {
		return nil, filepersist.ErrTooLarge
	}
	if err != nil {
		return nil, err
	}
	if raw == nil {
		raw = []byte{}
	}
	return raw, ctx.Err()
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(p)
}

func (s *store) checkExpected(ctx context.Context, guard *generation.Guard, v *stateView) error {
	token, err := guard.Token()
	if err != nil {
		return persistenceError(err)
	}
	if token != v.token {
		return ErrUpdateStateChanged
	}
	if token == "" {
		for _, key := range legacyMetadata {
			raw, err := readLegacyBytes(ctx, filepath.Join(s.dir, filepath.FromSlash(key)))
			if err != nil && !errors.Is(err, os.ErrNotExist) {
				return persistenceError(err)
			}
			if (raw == nil) != (v.raw[key] == nil) || !bytes.Equal(raw, v.raw[key]) {
				return ErrUpdateStateChanged
			}
		}
	}
	return nil
}

// publish is called under the commit guard after public-operation admission.
// No legacy writer or cleanup path remains after native activation.
func (s *store) publish(ctx context.Context, guard *generation.Guard, cfg AppConfig, view *stateView, reveal bool) error {
	if err := s.checkExpected(ctx, guard, view); err != nil {
		return err
	}
	if view.fatal != nil {
		return view.fatal
	}
	prepared := []string{}
	committed := false
	defer func() {
		if !committed {
			s.discardPrepared(prepared)
		}
	}()
	if view.token == "" {
		if err := s.prepareLegacy(ctx, cfg, view, &prepared); err != nil {
			return err
		}
	}
	data, err := s.encodeState(ctx, view)
	if err != nil {
		return persistenceError(err)
	}
	// Validate the exact bounded representation that will become authoritative.
	if _, err := s.decodeState(ctx, data); err != nil {
		if canceled := contextError(ctx); canceled != nil {
			return canceled
		}
		return ErrStorageUnavailable
	}
	if reveal {
		r, err := view.stagedFor(cfg)
		if err != nil {
			return err
		}
		if err := validateStagedUpdateReadyFor(ctx, cfg, s, r, time.Now().UTC()); err != nil {
			return err
		}
	}
	snapshot, err := guard.Commit(view.token, data, view.raw)
	if errors.Is(err, generation.ErrConflict) {
		return ErrUpdateStateChanged
	}
	if err != nil {
		return persistenceError(err)
	}
	committed = true
	view.token, view.raw = snapshot.Token, nil
	return nil
}
