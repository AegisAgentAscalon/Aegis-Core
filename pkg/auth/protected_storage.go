package auth

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/AegisAgentAscalon/aegis-core/pkg/secretstore"
)

func (s *store) getProtected(ctx context.Context, key secretstore.Key) ([]byte, error) {
	ctx = normalizeContext(ctx)
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	b, err := s.protected.Get(ctx, key)
	if canceled := protectedCallError(ctx, err); errors.Is(canceled, ErrAuthCanceled) {
		return nil, canceled
	}
	if err == nil {
		return b, nil
	}
	if errors.Is(err, secretstore.ErrNotFound) {
		return nil, secretstore.ErrNotFound
	}
	return nil, ErrStorageUnavailable
}

func (s *store) putProtected(ctx context.Context, key secretstore.Key, value []byte) error {
	ctx = normalizeContext(ctx)
	if err := checkContext(ctx); err != nil {
		return err
	}
	return protectedCallError(ctx, s.protected.Put(ctx, key, value))
}

func (s *store) deleteProtected(ctx context.Context, key secretstore.Key) error {
	ctx = normalizeContext(ctx)
	if err := checkContext(ctx); err != nil {
		return err
	}
	err := s.protected.Delete(ctx, key)
	if canceled := protectedCallError(ctx, err); errors.Is(canceled, ErrAuthCanceled) {
		return canceled
	}
	if err == nil || errors.Is(err, secretstore.ErrNotFound) {
		return nil
	}
	return ErrStorageUnavailable
}

// Protected stores are host callbacks. Preserve cancellation while keeping
// backend diagnostics out of the app-facing error surface.
func protectedCallError(ctx context.Context, err error) error {
	if checkContext(ctx) != nil || errors.Is(err, context.Canceled) ||
		errors.Is(err, context.DeadlineExceeded) || errors.Is(err, ErrAuthCanceled) {
		return ErrAuthCanceled
	}
	if err != nil {
		return ErrStorageUnavailable
	}
	return nil
}

func decodeProtectedToken(b []byte) (token, error) {
	var t token
	if err := json.Unmarshal(b, &t); err != nil || strings.TrimSpace(t.AccessToken) == "" || t.Expiry.IsZero() {
		return token{}, ErrProtectedStorageCorrupt
	}
	return t, nil
}
