package auth

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
)

func checkContext(ctx context.Context) error {
	if ctx == nil {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return ErrAuthCanceled
	}
	return nil
}

func normalizeContext(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}

func classifyProviderError(ctx context.Context, err error, op string) error {
	if ctx != nil && ctx.Err() != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			if op == "profile fetch" {
				return fmt.Errorf("profile fetch timed out")
			}
			return fmt.Errorf("token exchange timed out")
		}
		return ErrAuthCanceled
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		if op == "profile fetch" {
			return fmt.Errorf("profile fetch timed out")
		}
		return fmt.Errorf("token exchange timed out")
	}
	return ErrProviderUnavailable
}

func safeStorageError(err error) error {
	switch {
	case errors.Is(err, ErrSessionNotFound),
		errors.Is(err, ErrSessionExpired),
		errors.Is(err, ErrSessionConsumed),
		errors.Is(err, ErrInvalidProviderResponse),
		errors.Is(err, ErrStorageUnavailable),
		errors.Is(err, ErrProtectedStorageCorrupt):
		return err
	default:
		var pathErr *os.PathError
		if errors.As(err, &pathErr) {
			return ErrStorageUnavailable
		}
		return err
	}
}

func safeAuthError(err error) string {
	if err == nil {
		return ""
	}
	var pathErr *os.PathError
	switch {
	case errors.As(err, &pathErr):
		return "auth storage operation failed"
	case errors.Is(err, ErrNotConfigured),
		errors.Is(err, ErrNotSignedIn),
		errors.Is(err, ErrProfileNotFound),
		errors.Is(err, ErrSessionNotFound),
		errors.Is(err, ErrSessionExpired),
		errors.Is(err, ErrSessionConsumed),
		errors.Is(err, ErrStateMismatch),
		errors.Is(err, ErrTokenExchangeFailed),
		errors.Is(err, ErrProviderUnavailable),
		errors.Is(err, ErrInvalidProviderResponse),
		errors.Is(err, ErrStorageUnavailable),
		errors.Is(err, ErrProtectedStorageCorrupt),
		errors.Is(err, ErrAuthCanceled),
		errors.Is(err, ErrSignOutIncomplete),
		errors.Is(err, errProfileFetchFailed):
		return unwrapAuthSentinel(err).Error()
	}
	lower := strings.ToLower(err.Error())
	switch {
	case strings.Contains(lower, "token exchange timed out"):
		return "token exchange timed out"
	case strings.Contains(lower, "profile fetch timed out"):
		return "profile fetch timed out"
	case strings.Contains(lower, "state is required"):
		return "state is required"
	case strings.Contains(lower, "authorization code is required"):
		return "authorization code is required"
	default:
		return "auth operation failed"
	}
}

func unwrapAuthSentinel(err error) error {
	for _, sentinel := range []error{
		ErrNotConfigured,
		ErrNotSignedIn,
		ErrProfileNotFound,
		ErrSessionNotFound,
		ErrSessionExpired,
		ErrSessionConsumed,
		ErrStateMismatch,
		ErrTokenExchangeFailed,
		ErrProviderUnavailable,
		ErrInvalidProviderResponse,
		ErrStorageUnavailable,
		ErrProtectedStorageCorrupt,
		ErrAuthCanceled,
		ErrSignOutIncomplete,
		errProfileFetchFailed,
	} {
		if errors.Is(err, sentinel) {
			return sentinel
		}
	}
	return errors.New("auth operation failed")
}
