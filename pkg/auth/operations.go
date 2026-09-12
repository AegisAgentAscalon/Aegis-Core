package auth

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/AegisAgentAscalon/aegis-core/pkg/secretstore"
)

type authOperation struct {
	owner         *Service
	ctx           context.Context
	cancel        context.CancelFunc
	epoch         uint64
	tokenRevision secretstore.Revision
}

func (s *Service) beginOperation(ctx context.Context) *authOperation {
	ctx, cancel := context.WithCancel(normalizeContext(ctx))
	s.mu.Lock()
	defer s.mu.Unlock()
	op := &authOperation{owner: s, ctx: ctx, cancel: cancel, epoch: s.epoch}
	if s.operations == nil {
		s.operations = make(map[*authOperation]struct{})
	}
	s.operations[op] = struct{}{}
	return op
}

func (op *authOperation) finish() {
	op.owner.mu.Lock()
	delete(op.owner.operations, op)
	op.owner.mu.Unlock()
	op.cancel()
}

func (op *authOperation) check() error {
	op.owner.mu.Lock()
	defer op.owner.mu.Unlock()
	if op.epoch != op.owner.epoch {
		return ErrAuthCanceled
	}
	return checkContext(op.ctx)
}

// No owner mutex is held across host callbacks. Strict concurrent/reentrant
// storage operations fail safely; legacy local I/O remains serialized.
// HTTP work never holds this reservation.
func (s *Service) reserveStore(ctx context.Context) error {
	for {
		if err := checkContext(ctx); err != nil {
			return err
		}
		s.mu.Lock()
		if !s.ioBusy {
			s.ioBusy = true
			s.ioDone = make(chan struct{})
			s.mu.Unlock()
			return nil
		}
		done := s.ioDone
		strict := s.store.isStrict()
		s.mu.Unlock()
		if strict {
			return ErrStorageUnavailable
		}
		select {
		case <-ctx.Done():
			return ErrAuthCanceled
		case <-done:
		}
	}
}

func (s *Service) releaseStore() {
	s.mu.Lock()
	s.ioBusy = false
	close(s.ioDone)
	s.mu.Unlock()
}

func (op *authOperation) reserveStore() error {
	if err := op.check(); err != nil {
		return err
	}
	if err := op.owner.reserveStore(op.ctx); err != nil {
		return err
	}
	if err := op.check(); err != nil {
		op.owner.releaseStore()
		return err
	}
	return nil
}

func (op *authOperation) recordError(err error) {
	op.owner.mu.Lock()
	defer op.owner.mu.Unlock()
	if op.epoch == op.owner.epoch {
		op.owner.store.writeLastError(err)
	}
}

// A committed login supersedes older HTTP work, including its failure cleanup.
// SignOut also advances the epoch, even when its cleanup cannot complete.
func (s *Service) invalidateLocked(keep *authOperation) {
	s.epoch++
	for op := range s.operations {
		if op == keep {
			op.epoch = s.epoch
		} else {
			op.cancel()
		}
	}
}

func (op *authOperation) publishProfile(profile ProfileSummary) error {
	s := op.owner
	s.mu.Lock()
	defer s.mu.Unlock()
	if op.epoch != s.epoch || checkContext(op.ctx) != nil {
		return ErrAuthCanceled
	}
	// These are local file operations, with no host callbacks under the mutex.
	if err := s.store.writeProfile(op.ctx, profileFile{Email: profile.Email, DisplayName: profile.DisplayName, Subject: profile.Subject, PictureURL: profile.PictureURL}); err != nil {
		return err
	}
	s.invalidateLocked(op)
	s.store.writeLastError(nil)
	return nil
}

// Strict token writes have an owned revision so obsolete cleanup cannot delete
// a credential committed by another service sharing the protected store.
func (op *authOperation) commitToken(tok token) (func() error, error) {
	s := op.owner.store
	if !s.isStrict() {
		if err := s.writeToken(op.ctx, tok); err != nil {
			return nil, err
		}
		return func() error { return s.deleteToken(context.Background()) }, nil
	}
	if err := op.check(); err != nil {
		return nil, err
	}
	value, err := encodeToken(tok)
	if err != nil {
		return nil, err
	}
	revision, err := s.versioned.CompareAndSwap(op.ctx, s.tokenKey, op.tokenRevision, value)
	if err != nil {
		return nil, protectedCallError(op.ctx, err)
	}
	return func() error {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(op.ctx), 3*time.Second)
		defer cancel()
		_, err := s.versioned.CompareAndDelete(ctx, s.tokenKey, revision)
		if err == nil || errors.Is(err, secretstore.ErrNotFound) || errors.Is(err, secretstore.ErrConflict) {
			return nil
		}
		return ErrSignOutIncomplete
	}, nil
}

// Capture before HTTP so another owner's newer credential cannot be replaced
// or removed by this operation's completion. Same-owner sign-out additionally
// uses the epoch, because deleting an absent key need not advance its revision.
func (op *authOperation) captureTokenRevision() error {
	s := op.owner.store
	if !s.isStrict() {
		return nil
	}
	_, revision, err := s.versioned.GetWithRevision(op.ctx, s.tokenKey)
	if err != nil && !errors.Is(err, secretstore.ErrNotFound) {
		return protectedCallError(op.ctx, err)
	}
	op.tokenRevision = revision
	return op.check()
}

func (op *authOperation) deletePreviousToken() error {
	s := op.owner.store
	if !s.isStrict() {
		return s.deleteToken(op.ctx)
	}
	_, err := s.versioned.CompareAndDelete(op.ctx, s.tokenKey, op.tokenRevision)
	if errors.Is(err, secretstore.ErrNotFound) || errors.Is(err, secretstore.ErrConflict) {
		err = nil
	}
	return protectedCallError(op.ctx, err)
}

// Preserve HTTP timeout classification; only a superseding owner generation
// replaces an already classified provider failure with cancellation.
func (op *authOperation) resultError(err error) error {
	op.owner.mu.Lock()
	defer op.owner.mu.Unlock()
	if op.epoch != op.owner.epoch {
		return ErrAuthCanceled
	}
	if err != nil {
		return err
	}
	return checkContext(op.ctx)
}

func encodeToken(tok token) ([]byte, error) {
	raw, err := json.MarshalIndent(tok, "", "  ")
	if err != nil {
		return nil, ErrStorageUnavailable
	}
	if _, err := decodeProtectedToken(raw); err != nil {
		return nil, ErrStorageUnavailable
	}
	return raw, nil
}
