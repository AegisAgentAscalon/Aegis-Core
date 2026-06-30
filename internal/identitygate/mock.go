package identitygate

import (
	"context"
	"time"
)

type MockVerificationProvider struct {
	Allow bool
	Clock Clock
}

func (m MockVerificationProvider) ProviderName() string { return "mock-verification-provider" }

func (m MockVerificationProvider) CanVerify(ctx context.Context, userID string) bool {
	return ctx.Err() == nil && m.Allow && userID != ""
}

func (m MockVerificationProvider) RequestVerification(ctx context.Context, userID, reason string) (VerificationResult, error) {
	if !m.CanVerify(ctx, userID) {
		return VerificationResult{}, ErrReauthRequired
	}
	clock := m.Clock
	if clock == nil {
		clock = realClock{}
	}
	now := clock.Now().UTC()
	return VerificationResult{UserID: userID, Verified: true, VerifiedAt: now, ExpiresAt: now.Add(30 * time.Minute), Provider: m.ProviderName()}, nil
}

func (m MockVerificationProvider) RequestFreshVerification(ctx context.Context, userID, reason string) (VerificationResult, error) {
	result, err := m.RequestVerification(ctx, userID, reason)
	result.Fresh = true
	return result, err
}
