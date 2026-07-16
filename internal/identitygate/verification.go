package identitygate

import (
	"context"
	"strings"
	"time"
)

const maxProviderClockSkew = time.Minute

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
	attemptID, err := s.reserveRandomID("attempt", s.usedAttemptIDs)
	if err != nil {
		return VerificationRequest{}, s.sessionSnapshot(), err
	}
	assertionID, err := s.reserveRandomID("assertion", s.usedAssertionIDs)
	if err != nil {
		return VerificationRequest{}, s.sessionSnapshot(), err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.refresh()
	if s.session.AssuranceLevel == AssuranceLocked {
		s.record(ctx, EventVerificationFailed, "verification denied because session is locked")
		return VerificationRequest{}, cloneSession(s.session), ErrLocked
	}
	request := VerificationRequest{
		AttemptID:     attemptID,
		AssertionID:   assertionID,
		SessionID:     s.session.SessionID,
		SubjectUserID: userID,
		Reason:        safe(reason),
		FreshRequired: fresh,
		RequestedAt:   s.clock.Now().UTC(),
	}
	s.record(ctx, EventVerificationRequested, "verification requested")
	return request, cloneSession(s.session), nil
}

func (s *Service) reserveRandomID(prefix string, used map[string]struct{}) (string, error) {
	for i := 0; i < 4; i++ {
		id, err := newOpaqueID(prefix)
		if err != nil {
			return "", err
		}
		s.mu.Lock()
		_, exists := used[id]
		if !exists {
			used[id] = struct{}{}
		}
		s.mu.Unlock()
		if !exists {
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
	if s.session.AssuranceLevel == AssuranceLocked {
		return fail(ErrLocked)
	}
	if validOpaqueReference(receipt.ReceiptID) {
		if _, used := s.usedReceiptIDs[receipt.ReceiptID]; used {
			return fail(ErrVerificationReceiptUsed)
		}
		s.usedReceiptIDs[receipt.ReceiptID] = struct{}{}
	}
	if err := s.validateReceiptLocked(request, receipt); err != nil {
		return fail(err)
	}
	if !receipt.Verified || (request.FreshRequired && !receipt.Fresh) {
		return fail(ErrReauthRequired)
	}

	now := s.clock.Now().UTC()
	verifiedUntil := earliestTime(
		receipt.ExpiresAt.UTC(),
		receipt.VerifiedAt.UTC().Add(s.policy.VerifiedWindow),
		now.Add(s.policy.VerifiedWindow),
	)
	if !verifiedUntil.After(now) {
		return fail(ErrInvalidVerificationReceipt)
	}

	var freshUntil time.Time
	if request.FreshRequired {
		freshUntil = earliestTime(
			receipt.ExpiresAt.UTC(),
			receipt.VerifiedAt.UTC().Add(s.policy.FreshWindow),
			now.Add(s.policy.FreshWindow),
		)
		if !freshUntil.After(now) {
			return fail(ErrInvalidVerificationReceipt)
		}
	}

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
	if request.FreshRequired {
		s.session.FreshVerifiedAt = now
		s.session.FreshUntil = freshUntil
		s.session.AssuranceLevel = AssuranceFreshVerified
		s.session.OperatorAssurance = OperatorFreshVerified
	}
	s.recompute()
	s.record(ctx, EventVerificationSucceeded, "verification succeeded")
	return receipt, cloneSession(s.session), nil
}

func (s *Service) validateReceiptLocked(request VerificationRequest, receipt VerificationReceipt) error {
	now := s.clock.Now().UTC()
	if !validOpaqueReference(receipt.ReceiptID) ||
		receipt.AttemptID != request.AttemptID ||
		receipt.AssertionID != request.AssertionID ||
		receipt.SessionID != request.SessionID ||
		receipt.SessionID != s.session.SessionID ||
		receipt.SubjectUserID != request.SubjectUserID ||
		receipt.Provider != s.providerName ||
		receipt.VerifiedAt.IsZero() ||
		receipt.ExpiresAt.IsZero() {
		return ErrInvalidVerificationReceipt
	}
	if receipt.VerifiedAt.After(now.Add(maxProviderClockSkew)) ||
		receipt.VerifiedAt.Before(request.RequestedAt.Add(-maxProviderClockSkew)) ||
		!receipt.ExpiresAt.After(receipt.VerifiedAt) ||
		!receipt.ExpiresAt.After(now) {
		return ErrInvalidVerificationReceipt
	}
	return nil
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
