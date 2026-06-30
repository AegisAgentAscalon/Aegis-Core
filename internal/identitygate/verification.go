package identitygate

import "context"

func (s *Service) RequestVerification(ctx context.Context, userID, reason string) (IdentitySession, error) {
	return s.verify(ctx, userID, false)
}

func (s *Service) RequestFreshVerification(ctx context.Context, userID, reason string) (IdentitySession, error) {
	return s.verify(ctx, userID, true)
}

func (s *Service) verify(ctx context.Context, userID string, fresh bool) (IdentitySession, error) {
	if err := ctx.Err(); err != nil {
		return IdentitySession{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refresh()
	if s.session.AssuranceLevel == AssuranceLocked {
		return cloneSession(s.session), ErrLocked
	}
	var result VerificationResult
	var err error
	if fresh {
		result, err = s.verifier.RequestFreshVerification(ctx, userID, "fresh")
	} else {
		result, err = s.verifier.RequestVerification(ctx, userID, "verify")
	}
	if err != nil || !result.Verified || result.UserID == "" {
		return cloneSession(s.session), ErrReauthRequired
	}
	now := s.clock.Now().UTC()
	s.session.VerifiedUserID = result.UserID
	s.session.VerifiedOperatorUserID = result.UserID
	s.session.VerifiedAt = now
	s.session.VerifiedUntil = now.Add(s.policy.VerifiedWindow)
	s.session.AssuranceLevel = AssuranceVerified
	s.session.OperatorAssurance = OperatorVerified
	if fresh {
		s.session.FreshVerifiedAt = now
		s.session.FreshUntil = now.Add(s.policy.FreshWindow)
		s.session.AssuranceLevel = AssuranceFreshVerified
		s.session.OperatorAssurance = OperatorFreshVerified
	}
	s.recompute()
	return cloneSession(s.session), nil
}
