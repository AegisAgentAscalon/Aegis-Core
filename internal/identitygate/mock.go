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

// Verify returns an explicitly injected, receipt-shaped mock result. It never
// captures or transports biometric or credential material.
func (m MockVerificationProvider) Verify(ctx context.Context, request VerificationRequest) (VerificationReceipt, error) {
	if !m.CanVerify(ctx, request.SubjectUserID) || !validOpaqueReference(request.AttemptID) || !validOpaqueReference(request.AssertionID) || !validOpaqueReference(request.SessionID) {
		return VerificationReceipt{}, ErrReauthRequired
	}
	clock := m.Clock
	if clock == nil {
		clock = realClock{}
	}
	now := clock.Now().UTC()
	receiptID, err := newOpaqueID("receipt")
	if err != nil {
		return VerificationReceipt{}, err
	}
	return VerificationReceipt{
		ReceiptID:     receiptID,
		AttemptID:     request.AttemptID,
		AssertionID:   request.AssertionID,
		SessionID:     request.SessionID,
		SubjectUserID: request.SubjectUserID,
		Provider:      m.ProviderName(),
		Verified:      true,
		Fresh:         request.FreshRequired,
		VerifiedAt:    now,
		ExpiresAt:     now.Add(30 * time.Minute),
	}, nil
}

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
