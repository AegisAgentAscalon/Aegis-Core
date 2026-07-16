package identitygate

import (
	"context"
	"strings"
)

func (s *Service) ClaimIdentity(ctx context.Context, userID string) (IdentitySession, error) {
	if err := ctx.Err(); err != nil {
		return IdentitySession{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.session.AssuranceLevel == AssuranceLocked {
		return cloneSession(s.session), ErrLocked
	}
	s.bumpVerificationEpochLocked()
	s.clearVerificationStateLocked("identity claim changed")
	s.session.ClaimedUserID = userID
	s.session.AssuranceLevel = AssuranceClaimed
	s.session.OperatorAssurance = OperatorClaimed
	s.touchActivityLocked(s.clock.Now().UTC())
	s.recompute()
	s.record(ctx, EventIdentityClaimed, "identity claimed")
	return cloneSession(s.session), nil
}

func (s *Service) RecognizeProfile(ctx context.Context, signals SessionSignals) (RecognitionResult, IdentitySession, error) {
	if err := ctx.Err(); err != nil {
		return RecognitionResult{}, IdentitySession{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.session.AssuranceLevel == AssuranceLocked {
		return RecognitionResult{}, cloneSession(s.session), ErrLocked
	}
	var best RecognitionResult
	for _, profile := range s.profiles {
		score := 0.0
		if signals.ClaimedUserID != "" && signals.ClaimedUserID == profile.UserID {
			score += .7
		}
		for _, alias := range signals.Aliases {
			for _, profileAlias := range profile.RecognitionFeatures.Aliases {
				if strings.EqualFold(alias, profileAlias) {
					score += .2
				}
			}
		}
		if score > best.Confidence {
			best = RecognitionResult{CandidateUserID: profile.UserID, Confidence: score, RequiresVerification: true, Explanation: "safe profile match"}
		}
	}
	verified := s.session.AssuranceLevel == AssuranceVerified || s.session.AssuranceLevel == AssuranceFreshVerified
	recognitionTransition := best.CandidateUserID != "" && (s.session.RecognizedUserID != best.CandidateUserID || !verified && s.session.OperatorAssurance != OperatorRecognized)
	deviceTransition := signals.DeviceKnown && !s.session.TrustedDevice
	accountTransition := signals.AccountUserID != "" && (!s.session.AccountAuthenticated || s.session.AccountUserID != signals.AccountUserID)
	if recognitionTransition || deviceTransition || accountTransition {
		s.bumpVerificationEpochLocked()
		s.clearVerificationStateLocked("identity recognition changed")
		if best.CandidateUserID != "" {
			s.session.RecognizedUserID = best.CandidateUserID
		}
		if signals.DeviceKnown {
			s.session.TrustedDevice = true
		}
		if signals.AccountUserID != "" {
			s.session.AccountUserID = signals.AccountUserID
			s.session.AccountAuthenticated = true
		}
		s.setBaseAssuranceLocked()
	}
	if best.CandidateUserID != "" {
		s.record(ctx, EventProfileRecognized, "profile recognized; verification still required")
	}
	s.touchActivityLocked(s.clock.Now().UTC())
	s.recompute()
	return best, cloneSession(s.session), nil
}
