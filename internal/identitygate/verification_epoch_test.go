package identitygate

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

type verificationOutcome struct {
	receipt VerificationReceipt
	session IdentitySession
	err     error
}

func TestProviderCompletionAfterDowngradeCannotRestoreAssurance(t *testing.T) {
	clock := &fakeClock{now: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)}
	started := make(chan VerificationRequest, 1)
	release := make(chan struct{})
	svc := newReceiptTestService(t, clock, func(_ context.Context, request VerificationRequest) (VerificationReceipt, error) {
		started <- request
		<-release
		return validTestReceipt(request, clock.Now(), "receipt_stale_downgrade"), nil
	}, VerificationCadencePolicy{})

	done := make(chan verificationOutcome, 1)
	go func() {
		receipt, session, err := svc.RequestVerificationReceipt(context.Background(), "user", "test")
		done <- verificationOutcome{receipt: receipt, session: session, err: err}
	}()

	request := <-started
	downgraded, err := svc.DowngradeSession(context.Background(), "security posture changed")
	if err != nil {
		t.Fatal(err)
	}
	if downgraded.VerificationEpoch <= request.VerificationEpoch {
		t.Fatalf("downgrade did not invalidate request epoch: request=%d session=%d", request.VerificationEpoch, downgraded.VerificationEpoch)
	}
	close(release)
	outcome := <-done
	if !errors.Is(outcome.err, ErrReauthRequired) {
		t.Fatalf("stale provider completion was not rejected: %v", outcome.err)
	}
	if outcome.session.VerifiedOperatorUserID != "" || outcome.session.AssuranceLevel == AssuranceVerified || outcome.session.AssuranceLevel == AssuranceFreshVerified {
		t.Fatalf("stale provider completion restored assurance: %+v", outcome.session)
	}
}

func TestCancelledProviderCompletionCannotMutateAssurance(t *testing.T) {
	clock := &fakeClock{now: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)}
	started := make(chan VerificationRequest, 1)
	svc := newReceiptTestService(t, clock, func(ctx context.Context, request VerificationRequest) (VerificationReceipt, error) {
		started <- request
		<-ctx.Done()
		return validTestReceipt(request, clock.Now(), "receipt_cancelled"), nil
	}, VerificationCadencePolicy{})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan verificationOutcome, 1)
	go func() {
		receipt, session, err := svc.RequestVerificationReceipt(ctx, "user", "test")
		done <- verificationOutcome{receipt: receipt, session: session, err: err}
	}()
	<-started
	cancel()
	outcome := <-done
	if !errors.Is(outcome.err, context.Canceled) {
		t.Fatalf("cancelled completion returned %v", outcome.err)
	}
	if outcome.session.VerifiedOperatorUserID != "" || outcome.session.AssuranceLevel == AssuranceVerified || outcome.session.AssuranceLevel == AssuranceFreshVerified {
		t.Fatalf("cancelled provider completion changed assurance: %+v", outcome.session)
	}
}

func TestLockedVerificationDoesNotAllocateRequestIdentifiers(t *testing.T) {
	clock := &fakeClock{now: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)}
	providerCalls := 0
	svc := newReceiptTestService(t, clock, func(_ context.Context, request VerificationRequest) (VerificationReceipt, error) {
		providerCalls++
		return validTestReceipt(request, clock.Now(), "receipt_locked"), nil
	}, VerificationCadencePolicy{})
	if _, err := svc.LockSession(context.Background(), "locked"); err != nil {
		t.Fatal(err)
	}

	if _, _, err := svc.RequestVerificationReceipt(context.Background(), "user", "test"); !errors.Is(err, ErrLocked) {
		t.Fatalf("locked request returned %v", err)
	}
	if providerCalls != 0 {
		t.Fatalf("locked request called provider %d times", providerCalls)
	}
	if len(svc.usedAttemptIDs) != 0 || len(svc.usedAssertionIDs) != 0 || len(svc.usedReceiptIDs) != 0 {
		t.Fatalf("locked request allocated replay identifiers: attempts=%d assertions=%d receipts=%d", len(svc.usedAttemptIDs), len(svc.usedAssertionIDs), len(svc.usedReceiptIDs))
	}
}

func TestReplayTrackingIsCountAndExpiryBounded(t *testing.T) {
	clock := &fakeClock{now: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)}
	providerCalls := 0
	svc := newReceiptTestService(t, clock, func(_ context.Context, request VerificationRequest) (VerificationReceipt, error) {
		providerCalls++
		return validTestReceipt(request, clock.Now(), fmt.Sprintf("receipt_bound_%d", providerCalls)), nil
	}, VerificationCadencePolicy{})

	for i := 0; i < maxReplayCacheEntries; i++ {
		if _, _, err := svc.RequestVerificationReceipt(context.Background(), "user", "test"); err != nil {
			t.Fatalf("request %d failed before capacity: %v", i, err)
		}
	}
	if _, _, err := svc.RequestVerificationReceipt(context.Background(), "user", "test"); !errors.Is(err, ErrVerificationTrackingCapacity) {
		t.Fatalf("capacity did not fail closed: %v", err)
	}
	if len(svc.usedAttemptIDs) > maxReplayCacheEntries || len(svc.usedAssertionIDs) > maxReplayCacheEntries || len(svc.usedReceiptIDs) > maxReplayCacheEntries {
		t.Fatalf("replay cache exceeded count bound: attempts=%d assertions=%d receipts=%d", len(svc.usedAttemptIDs), len(svc.usedAssertionIDs), len(svc.usedReceiptIDs))
	}

	clock.Add(maxReplayTrackingTTL + time.Second)
	if _, _, err := svc.RequestVerificationReceipt(context.Background(), "user", "after expiry"); err != nil {
		t.Fatalf("expired replay records were not pruned: %v", err)
	}
	if len(svc.usedAttemptIDs) != 1 || len(svc.usedAssertionIDs) != 1 || len(svc.usedReceiptIDs) != 1 {
		t.Fatalf("expired replay records remain: attempts=%d assertions=%d receipts=%d", len(svc.usedAttemptIDs), len(svc.usedAssertionIDs), len(svc.usedReceiptIDs))
	}
}
