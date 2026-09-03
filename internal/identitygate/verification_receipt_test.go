package identitygate

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

type receiptProviderFunc struct {
	name   string
	verify func(context.Context, VerificationRequest) (VerificationReceipt, error)
}

func (p receiptProviderFunc) ProviderName() string { return p.name }

func (p receiptProviderFunc) Verify(ctx context.Context, request VerificationRequest) (VerificationReceipt, error) {
	return p.verify(ctx, request)
}

func validTestReceipt(request VerificationRequest, now time.Time, receiptID string) VerificationReceipt {
	return VerificationReceipt{
		ReceiptID:     receiptID,
		AttemptID:     request.AttemptID,
		AssertionID:   request.AssertionID,
		SessionID:     request.SessionID,
		SubjectUserID: request.SubjectUserID,
		Provider:      "external-test-provider",
		Verified:      true,
		Fresh:         request.FreshRequired,
		VerifiedAt:    now,
		ExpiresAt:     now.Add(time.Hour),
	}
}

func newReceiptTestService(t *testing.T, clock *fakeClock, verify func(context.Context, VerificationRequest) (VerificationReceipt, error), policy VerificationCadencePolicy) *Service {
	t.Helper()
	svc, err := NewService(Config{
		Clock: clock,
		ReceiptProvider: receiptProviderFunc{
			name:   "external-test-provider",
			verify: verify,
		},
		CadencePolicy: policy,
	})
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

func TestNewServiceFailsClosedWithoutProvider(t *testing.T) {
	if _, err := NewService(Config{}); !errors.Is(err, ErrVerificationProviderRequired) {
		t.Fatalf("expected provider-required error, got %v", err)
	}
	if _, err := NewService(Config{
		ReceiptProvider:      MockVerificationProvider{Allow: true},
		VerificationProvider: MockVerificationProvider{Allow: true},
	}); !errors.Is(err, ErrInvalidVerificationConfig) {
		t.Fatalf("expected ambiguous-provider error, got %v", err)
	}
	var typedNil *nilReceiptProvider
	if _, err := NewService(Config{ReceiptProvider: typedNil}); !errors.Is(err, ErrVerificationProviderRequired) {
		t.Fatalf("expected typed-nil provider to fail closed, got %v", err)
	}
	if _, err := NewService(Config{ReceiptProvider: receiptProviderFunc{name: "", verify: func(context.Context, VerificationRequest) (VerificationReceipt, error) {
		return VerificationReceipt{}, nil
	}}}); !errors.Is(err, ErrInvalidVerificationConfig) {
		t.Fatalf("expected invalid provider name to fail closed, got %v", err)
	}
}

type nilReceiptProvider struct{}

func (*nilReceiptProvider) ProviderName() string { return "must-not-be-called" }

func (*nilReceiptProvider) Verify(context.Context, VerificationRequest) (VerificationReceipt, error) {
	return VerificationReceipt{}, nil
}

func TestReceiptRequestIDsAreRandomUniqueAndSessionBound(t *testing.T) {
	clock := &fakeClock{now: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)}
	var requests []VerificationRequest
	svc := newReceiptTestService(t, clock, func(_ context.Context, request VerificationRequest) (VerificationReceipt, error) {
		requests = append(requests, request)
		return validTestReceipt(request, clock.Now(), fmt.Sprintf("receipt_test_%d", len(requests))), nil
	}, VerificationCadencePolicy{})

	for i := 0; i < 2; i++ {
		receipt, session, err := svc.RequestVerificationReceipt(context.Background(), "user", "test")
		if err != nil {
			t.Fatal(err)
		}
		if receipt.SessionID != session.SessionID || receipt.AttemptID == "" || receipt.AssertionID == "" {
			t.Fatalf("receipt was not bound to the session request: receipt=%+v session=%+v", receipt, session)
		}
	}
	if requests[0].SessionID != requests[1].SessionID {
		t.Fatalf("attempts changed session: %+v", requests)
	}
	if requests[0].AttemptID == requests[1].AttemptID || requests[0].AssertionID == requests[1].AssertionID {
		t.Fatalf("one-use request identifiers repeated: %+v", requests)
	}
	if requests[0].AttemptID == requests[0].AssertionID {
		t.Fatalf("attempt and assertion identifiers must be independent: %+v", requests[0])
	}

	other, err := NewService(Config{ReceiptProvider: MockVerificationProvider{Allow: true}})
	if err != nil {
		t.Fatal(err)
	}
	otherSession, err := other.CurrentSession(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if otherSession.SessionID == requests[0].SessionID {
		t.Fatalf("random session identifier repeated: %q", otherSession.SessionID)
	}
}

func TestFreshAssuranceRequiresProviderProvenFresh(t *testing.T) {
	clock := &fakeClock{now: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)}
	call := 0
	svc := newReceiptTestService(t, clock, func(_ context.Context, request VerificationRequest) (VerificationReceipt, error) {
		call++
		receipt := validTestReceipt(request, clock.Now(), fmt.Sprintf("receipt_fresh_%d", call))
		receipt.Fresh = false
		return receipt, nil
	}, VerificationCadencePolicy{})

	_, session, err := svc.RequestFreshVerificationReceipt(context.Background(), "user", "test")
	if !errors.Is(err, ErrReauthRequired) {
		t.Fatalf("expected fresh denial, got %v", err)
	}
	if session.AssuranceLevel == AssuranceFreshVerified || !session.FreshUntil.IsZero() {
		t.Fatalf("provider-unproven freshness changed session: %+v", session)
	}

	_, session, err = svc.RequestVerificationReceipt(context.Background(), "user", "test")
	if err != nil {
		t.Fatal(err)
	}
	if session.AssuranceLevel != AssuranceVerified {
		t.Fatalf("ordinary verified receipt was not accepted: %+v", session)
	}
}

func TestReceiptValidationRejectsMismatchedAndInvalidFields(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name   string
		mutate func(*VerificationReceipt)
	}{
		{"empty receipt id", func(r *VerificationReceipt) { r.ReceiptID = "" }},
		{"attempt mismatch", func(r *VerificationReceipt) { r.AttemptID = "attempt_wrong" }},
		{"assertion mismatch", func(r *VerificationReceipt) { r.AssertionID = "assertion_wrong" }},
		{"session mismatch", func(r *VerificationReceipt) { r.SessionID = "session_wrong" }},
		{"subject mismatch", func(r *VerificationReceipt) { r.SubjectUserID = "other-user" }},
		{"provider mismatch", func(r *VerificationReceipt) { r.Provider = "other-provider" }},
		{"zero verified time", func(r *VerificationReceipt) { r.VerifiedAt = time.Time{} }},
		{"future verified time", func(r *VerificationReceipt) {
			r.VerifiedAt = now.Add(maxProviderClockSkew + time.Second)
			r.ExpiresAt = r.VerifiedAt.Add(time.Minute)
		}},
		{"verified before attempt", func(r *VerificationReceipt) { r.VerifiedAt = now.Add(-maxProviderClockSkew - time.Second) }},
		{"expiry before verification", func(r *VerificationReceipt) { r.ExpiresAt = r.VerifiedAt.Add(-time.Second) }},
		{"expired", func(r *VerificationReceipt) { r.VerifiedAt = now.Add(-time.Hour); r.ExpiresAt = now.Add(-time.Second) }},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			clock := &fakeClock{now: now}
			svc := newReceiptTestService(t, clock, func(_ context.Context, request VerificationRequest) (VerificationReceipt, error) {
				receipt := validTestReceipt(request, now, "receipt_invalid_test")
				test.mutate(&receipt)
				return receipt, nil
			}, VerificationCadencePolicy{})

			_, session, err := svc.RequestVerificationReceipt(context.Background(), "user", "test")
			if !errors.Is(err, ErrInvalidVerificationReceipt) {
				t.Fatalf("expected invalid-receipt error, got %v", err)
			}
			if session.VerifiedOperatorUserID != "" || session.AssuranceLevel == AssuranceVerified || session.AssuranceLevel == AssuranceFreshVerified {
				t.Fatalf("invalid receipt changed assurance: %+v", session)
			}
		})
	}
}

func TestOrdinaryRequestDoesNotEscalateProviderFreshReceipt(t *testing.T) {
	clock := &fakeClock{now: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)}
	svc := newReceiptTestService(t, clock, func(_ context.Context, request VerificationRequest) (VerificationReceipt, error) {
		receipt := validTestReceipt(request, clock.Now(), "receipt_no_escalation")
		receipt.Fresh = true
		return receipt, nil
	}, VerificationCadencePolicy{})

	_, session, err := svc.RequestVerificationReceipt(context.Background(), "user", "test")
	if err != nil {
		t.Fatal(err)
	}
	if session.AssuranceLevel != AssuranceVerified || !session.FreshUntil.IsZero() {
		t.Fatalf("ordinary request escalated to fresh assurance: %+v", session)
	}
}

func TestReceiptIsOneUseEvenAcrossNewAttempts(t *testing.T) {
	clock := &fakeClock{now: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)}
	svc := newReceiptTestService(t, clock, func(_ context.Context, request VerificationRequest) (VerificationReceipt, error) {
		return validTestReceipt(request, clock.Now(), "receipt_replay_test"), nil
	}, VerificationCadencePolicy{})

	if _, _, err := svc.RequestVerificationReceipt(context.Background(), "user", "first"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := svc.RequestVerificationReceipt(context.Background(), "user", "second"); !errors.Is(err, ErrVerificationReceiptUsed) {
		t.Fatalf("expected one-use receipt rejection, got %v", err)
	}
}

func TestProviderIsNotCalledUnderServiceMutex(t *testing.T) {
	clock := &fakeClock{now: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)}
	var svc *Service
	svc = newReceiptTestService(t, clock, func(ctx context.Context, request VerificationRequest) (VerificationReceipt, error) {
		done := make(chan error, 1)
		go func() {
			_, err := svc.CurrentSession(ctx)
			done <- err
		}()
		select {
		case err := <-done:
			if err != nil {
				return VerificationReceipt{}, err
			}
		case <-time.After(500 * time.Millisecond):
			return VerificationReceipt{}, errors.New("service mutex held during provider call")
		}
		return validTestReceipt(request, clock.Now(), "receipt_reentrant_test"), nil
	}, VerificationCadencePolicy{})

	if _, _, err := svc.RequestVerificationReceipt(context.Background(), "user", "test"); err != nil {
		t.Fatal(err)
	}
}

func TestLocalWindowsAreCappedByHardLimitsAndProviderExpiry(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	t.Run("hard limits", func(t *testing.T) {
		clock := &fakeClock{now: now}
		svc := newReceiptTestService(t, clock, func(_ context.Context, request VerificationRequest) (VerificationReceipt, error) {
			receipt := validTestReceipt(request, now, "receipt_hard_cap")
			receipt.ExpiresAt = now.Add(48 * time.Hour)
			return receipt, nil
		}, VerificationCadencePolicy{
			VerifiedWindow:    24 * time.Hour,
			FreshWindow:       24 * time.Hour,
			MaxVerifiedWindow: 24 * time.Hour,
			MaxFreshWindow:    24 * time.Hour,
		})

		_, session, err := svc.RequestFreshVerificationReceipt(context.Background(), "user", "test")
		if err != nil {
			t.Fatal(err)
		}
		if got := session.VerifiedUntil.Sub(session.VerifiedAt); got != hardMaxVerifiedWindow {
			t.Fatalf("verified window escaped hard cap: %v", got)
		}
		if got := session.FreshUntil.Sub(session.FreshVerifiedAt); got != hardMaxFreshWindow {
			t.Fatalf("fresh window escaped hard cap: %v", got)
		}
	})

	t.Run("provider expiry", func(t *testing.T) {
		clock := &fakeClock{now: now}
		svc := newReceiptTestService(t, clock, func(_ context.Context, request VerificationRequest) (VerificationReceipt, error) {
			receipt := validTestReceipt(request, now, "receipt_provider_cap")
			receipt.ExpiresAt = now.Add(2 * time.Minute)
			return receipt, nil
		}, VerificationCadencePolicy{})

		_, session, err := svc.RequestFreshVerificationReceipt(context.Background(), "user", "test")
		if err != nil {
			t.Fatal(err)
		}
		if got := session.VerifiedUntil.Sub(session.VerifiedAt); got != 2*time.Minute {
			t.Fatalf("verified window exceeded provider expiry: %v", got)
		}
		if got := session.FreshUntil.Sub(session.FreshVerifiedAt); got != 2*time.Minute {
			t.Fatalf("fresh window exceeded provider expiry: %v", got)
		}
	})
}

func TestLegacyProviderAdapterPreservesWrappersAndFreshProof(t *testing.T) {
	clock := &fakeClock{now: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)}
	legacy := legacyProviderWithoutFresh{clock: clock}
	svc, err := NewService(Config{Clock: clock, VerificationProvider: legacy})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.RequestVerification(context.Background(), "user", "legacy"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.RequestFreshVerification(context.Background(), "user", "legacy fresh"); !errors.Is(err, ErrReauthRequired) {
		t.Fatalf("legacy provider granted unproven freshness: %v", err)
	}
}

type legacyProviderWithoutFresh struct{ clock Clock }

func (legacyProviderWithoutFresh) ProviderName() string { return "legacy-test-provider" }

func (legacyProviderWithoutFresh) CanVerify(ctx context.Context, userID string) bool {
	return ctx.Err() == nil && userID != ""
}

func (p legacyProviderWithoutFresh) RequestVerification(_ context.Context, userID, _ string) (VerificationResult, error) {
	now := p.clock.Now().UTC()
	return VerificationResult{UserID: userID, Verified: true, VerifiedAt: now, ExpiresAt: now.Add(time.Minute), Provider: p.ProviderName()}, nil
}

func (p legacyProviderWithoutFresh) RequestFreshVerification(ctx context.Context, userID, reason string) (VerificationResult, error) {
	return p.RequestVerification(ctx, userID, reason)
}
