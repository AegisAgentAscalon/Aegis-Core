package relay

import (
	"context"
	"errors"
)

func SanitizeProviderError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) {
		return ErrContextCanceled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return ErrProviderTimeout
	}
	return ErrProviderUnavailable
}
