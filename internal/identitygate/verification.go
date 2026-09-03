package identitygate

import (
	"context"
	"strings"
	"time"
)

const (
	maxProviderClockSkew   = time.Minute
	verificationRequestTTL = 10 * time.Minute
	maxReplayTrackingTTL   = hardMaxVerifiedWindow + maxProviderClockSkew
	maxReplayCacheEntries  = 256
)

// RequestVerification is the source-compatible session-only wrapper.
//
// Deprecated: use RequestVerificationReceipt to retain the safe receipt.
func (s *Service) RequestVerification(ctx context.Context, userID, reason string) (IdentitySession, error) {
	_, session, err := s.RequestVerificationReceipt(ctx, userID, reason)
	return session, err
}

// RequestFreshVerification is the source-compatible session-only wrapper.
//
// Deprecated: use RequestFreshVerificationReceipt to retain the safe receipt.
func (s *Service) RequestFreshVerification(ctx context.Context, userID, reason string) (IdentitySession, error) {
	_, session, err := s.RequestFreshVerificationReceipt(ctx, userID, reason)
	return session, err
}

// RequestVerificationReceipt asks the configured provider for ordinary
// verification and evaluates its opaque receipt against the current session.
func (s *Service) RequestVerificationReceipt(ctx context.Context, userID, reason string) (VerificationReceipt, IdentitySession, error) {
	return s.requestReceipt(ctx, userID, reason, false)
}

// RequestFreshVerificationReceipt asks the configured provider for fresh
// verification. Fresh assurance is granted only when the receipt proves Fresh.
func (s *Service) RequestFreshVerificationReceipt(ctx context.Context, userID, reason string) (VerificationReceipt, IdentitySession, error) {
	return s.requestReceipt(ctx, userID, reason, true)
}

func (s *Service) requestReceipt(ctx context.Context, userID, reason string, fresh bool) (VerificationReceipt, IdentitySession, error) {
	if err := ctx.Err(); err != nil {
		return VerificationReceipt{}, IdentitySession{}, err
	}
	if strings.TrimSpace(userID) == "" {
		return VerificationReceipt{}, s.sessionSnapshot(), ErrReauthRequired
	}

	request, session, err := s.issueVerificationRequest(ctx, userID, reason, fresh)
	if err != nil {
		return VerificationReceipt{}, session, err
	}

	// Provider code is intentionally invoked without the service mutex held.
	receipt, providerErr := s.verifier.Verify(ctx, request)
	if providerErr != nil {
		if err := ctx.Err(); err != nil {
			return receipt, s.failVerification(ctx), err
		}
		return receipt, s.failVerification(ctx), ErrReauthRequired
	}
	return s.evaluateVerificationReceipt(ctx, request, receipt)
}

func (s *Service) issueVerificationRequest(ctx context.Context, userID, reason string, fresh bool) (VerificationRequest, IdentitySession, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refresh()
	if err := ctx.Err(); err != nil {
		return VerificationRequest{}, cloneSession(s.session), err
	}
	if s.session.AssuranceLevel == AssuranceLocked {
		s.record(ctx, EventVerificationFailed, "verification denied because session is locked")
		return VerificationRequest{}, cloneSession(s.session), ErrLocked
	}
	if len(s.usedAttemptIDs) >= maxReplayCacheEntries || len(s.usedAssertionIDs) >= maxReplayCacheEntries || len(s.usedReceiptIDs) >= maxReplayCacheEntries {
		return VerificationRequest{}, cloneSession(s.session), ErrVerificationTrackingCapacity
	}
	now := s.clock.Now().UTC()
	expiresAt := now.Add(verificationRequestTTL)
	attemptID, err := s.reserveRandomIDLocked("attempt", s.usedAttemptIDs, expiresAt, now)
	if err != nil {
		return VerificationRequest{}, cloneSession(s.session), err
	}
	assertionID, err := s.reserveRandomIDLocked("assertion", s.usedAssertionIDs, expiresAt, now)
	if err != nil {
		return VerificationRequest{}, cloneSession(s.session), err
	}
	s.touchActivityLocked(now)
	request := VerificationRequest{
		AttemptID:         attemptID,
		AssertionID:       assertionID,
		SessionID:         s.session.SessionID,
		VerificationEpoch: s.session.VerificationEpoch,
		SubjectUserID:     userID,
		Reason:            safe(reason),
		FreshRequired:     fresh,
		RequestedAt:       now,
		ExpiresAt:         expiresAt,
	}
	s.record(ctx, EventVerificationRequested, "verification requested")
	return request, cloneSession(s.session), nil
}

func (s *Service) reserveRandomIDLocked(prefix string, used map[string]time.Time, expiresAt, now time.Time) (string, error) {
	for i := 0; i < 4; i++ {
		id, err := newOpaqueID(prefix)
		if err != nil {
			return "", err
		}
		tracked, err := s.trackReplayIDLocked(used, id, expiresAt, now)
		if err != nil {
			return "", err
		}
		if tracked {
			return id, nil
		}
	}
	return "", ErrInvalidVerificationConfig
}

func (s *Service) evaluateVerificationReceipt(ctx context.Context, request VerificationRequest, receipt VerificationReceipt) (VerificationReceipt, IdentitySession, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refresh()

	fail := func(err error) (VerificationReceipt, IdentitySession, error) {
		s.record(ctx, EventVerificationFailed, "verification receipt rejected")
		return receipt, cloneSession(s.session), err
	}
	if err := ctx.Err(); err != nil {
		return fail(err)
	}
	if s.session.AssuranceLevel == AssuranceLocked {
		return fail(ErrLocked)
	}
	if request.SessionID != s.session.SessionID || request.VerificationEpoch != s.session.VerificationEpoch {
		return fail(ErrReauthRequired)
	}
	if validOpaqueReference(receipt.ReceiptID) {
		now := s.clock.Now().UTC()
		expiresAt := now.Add(maxReplayTrackingTTL)
		if receipt.ExpiresAt.After(now) && receipt.ExpiresAt.Before(expiresAt) {
			expiresAt = receipt.ExpiresAt.UTC()
		}
		tracked, err := s.trackReplayIDLocked(s.usedReceiptIDs, receipt.ReceiptID, expiresAt, now)
		if err != nil {
			return fail(err)
		}
		if !tracked {
			return fail(ErrVerificationReceiptUsed)
		}
	}
	if err := s.validateReceiptLocked(request, receipt); err != nil {
		return fail(err)
	}
	if !receipt.Verified || (request.FreshRequired && !receipt.Fresh) {
		return fail(ErrReauthRequired)
	}

	now := s.clock.Now().UTC()
	verifiedHardUntil := earliestTime(
		receipt.ExpiresAt.UTC(),
		receipt.VerifiedAt.UTC().Add(s.policy.MaxVerifiedWindow),
		now.Add(s.policy.MaxVerifiedWindow),
	)
	verifiedUntil := earliestTime(
		verifiedHardUntil,
		receipt.VerifiedAt.UTC().Add(s.policy.VerifiedWindow),
		now.Add(s.policy.VerifiedWindow),
	)
	if !verifiedUntil.After(now) {
		return fail(ErrInvalidVerificationReceipt)
	}

	var freshUntil time.Time
	var freshHardUntil time.Time
	if request.FreshRequired {
		freshHardUntil = earliestTime(
			receipt.ExpiresAt.UTC(),
			receipt.VerifiedAt.UTC().Add(s.policy.MaxFreshWindow),
			now.Add(s.policy.MaxFreshWindow),
		)
		freshUntil = earliestTime(
			freshHardUntil,
			receipt.VerifiedAt.UTC().Add(s.policy.FreshWindow),
			now.Add(s.policy.FreshWindow),
		)
		if !freshUntil.After(now) {
			return fail(ErrInvalidVerificationReceipt)
		}
	}
	if err := ctx.Err(); err != nil {
		return fail(err)
	}
	if request.SessionID != s.session.SessionID || request.VerificationEpoch != s.session.VerificationEpoch {
		return fail(ErrReauthRequired)
	}

	s.bumpVerificationEpochLocked()
	s.session.VerifiedUserID = receipt.SubjectUserID
	s.session.VerifiedOperatorUserID = receipt.SubjectUserID
	s.session.VerifiedAt = now
	s.session.VerifiedUntil = verifiedUntil
	s.session.FreshVerifiedAt = time.Time{}
	s.session.FreshUntil = time.Time{}
	s.session.AssuranceLevel = AssuranceVerified
	s.session.OperatorAssurance = OperatorVerified
	s.session.ReauthRequired = false
	s.session.ReauthReason = ""
	s.session.LastActiveAt = now
	s.verifiedHardUntil = verifiedHardUntil
	s.freshHardUntil = time.Time{}
	if request.FreshRequired {
		s.session.FreshVerifiedAt = now
		s.session.FreshUntil = freshUntil
		s.session.AssuranceLevel = AssuranceFreshVerified
		s.session.OperatorAssurance = OperatorFreshVerified
		s.freshHardUntil = freshHardUntil
	}
	s.recompute()
	s.record(ctx, EventVerificationSucceeded, "verification succeeded")
	return receipt, cloneSession(s.session), nil
}

func (s *Service) validateReceiptLocked(request VerificationRequest, receipt VerificationReceipt) error {
	now := s.clock.Now().UTC()
	attemptExpiresAt, attemptTracked := s.usedAttemptIDs[request.AttemptID]
	assertionExpiresAt, assertionTracked := s.usedAssertionIDs[request.AssertionID]
	if !validOpaqueReference(receipt.ReceiptID) ||
		!attemptTracked ||
		!assertionTracked ||
		!now.Before(attemptExpiresAt) ||
		!now.Before(assertionExpiresAt) ||
		receipt.AttemptID != request.AttemptID ||
		receipt.AssertionID != request.AssertionID ||
		receipt.SessionID != request.SessionID ||
		receipt.SessionID != s.session.SessionID ||
		receipt.SubjectUserID != request.SubjectUserID ||
		receipt.Provider != s.providerName ||
		request.VerificationEpoch == 0 ||
		request.RequestedAt.IsZero() ||
		request.ExpiresAt.IsZero() ||
		receipt.VerifiedAt.IsZero() ||
		receipt.ExpiresAt.IsZero() {
		return ErrInvalidVerificationReceipt
	}
	if !request.ExpiresAt.After(request.RequestedAt) ||
		request.ExpiresAt.After(request.RequestedAt.Add(verificationRequestTTL)) ||
		!now.Before(request.ExpiresAt) ||
		receipt.VerifiedAt.After(request.ExpiresAt) ||
		receipt.VerifiedAt.After(now.Add(maxProviderClockSkew)) ||
		receipt.VerifiedAt.Before(request.RequestedAt.Add(-maxProviderClockSkew)) ||
		!receipt.ExpiresAt.After(receipt.VerifiedAt) ||
		!receipt.ExpiresAt.After(now) {
		return ErrInvalidVerificationReceipt
	}
	return nil
}

func (s *Service) trackReplayIDLocked(cache map[string]time.Time, id string, expiresAt, now time.Time) (bool, error) {
	pruneReplayCache(cache, now)
	if _, exists := cache[id]; exists {
		return false, nil
	}
	if len(cache) >= maxReplayCacheEntries {
		return false, ErrVerificationTrackingCapacity
	}
	cache[id] = expiresAt
	return true, nil
}

func (s *Service) pruneReplayCachesLocked(now time.Time) {
	pruneReplayCache(s.usedAttemptIDs, now)
	pruneReplayCache(s.usedAssertionIDs, now)
	pruneReplayCache(s.usedReceiptIDs, now)
}

func pruneReplayCache(cache map[string]time.Time, now time.Time) {
	for id, expiresAt := range cache {
		if !now.Before(expiresAt) {
			delete(cache, id)
		}
	}
}

func (s *Service) failVerification(ctx context.Context) IdentitySession {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refresh()
	s.record(ctx, EventVerificationFailed, "verification failed")
	return cloneSession(s.session)
}

func (s *Service) sessionSnapshot() IdentitySession {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refresh()
	return cloneSession(s.session)
}

func earliestTime(values ...time.Time) time.Time {
	if len(values) == 0 {
		return time.Time{}
	}
	earliest := values[0]
	for _, value := range values[1:] {
		if value.Before(earliest) {
			earliest = value
		}
	}
	return earliest
}
