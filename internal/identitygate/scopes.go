package identitygate

import (
	"context"
	"time"
)

func (s *Service) EvaluateScope(ctx context.Context, scope Scope) (ScopeAccessDecision, error) {
	return s.evaluateScope(ctx, scope, false)
}

func (s *Service) evaluateScope(ctx context.Context, scope Scope, consumeFresh bool) (ScopeAccessDecision, error) {
	if err := ctx.Err(); err != nil {
		return ScopeAccessDecision{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refresh()
	if s.session.AssuranceLevel != AssuranceLocked {
		s.touchActivityLocked(s.clock.Now().UTC())
	}
	decision := s.evaluateScopeLocked(scope)
	if decision.Allowed {
		s.record(ctx, EventScopeAllowed, "scope allowed")
	} else {
		s.record(ctx, EventScopeDenied, decision.Reason)
	}
	if decision.Allowed && consumeFresh && high(scope) && s.policy.BurnFreshAfterSensitiveUse {
		s.burnFreshLocked()
	}
	if !decision.KnownScope {
		return decision, ErrUnknownScope
	}
	return decision, nil
}

func (s *Service) CanAccessScope(ctx context.Context, scope Scope) (bool, error) {
	decision, err := s.EvaluateScope(ctx, scope)
	if err != nil {
		return false, err
	}
	return decision.Allowed, nil
}

func (s *Service) RequireScope(ctx context.Context, scope Scope, reason string) error {
	decision, err := s.evaluateScope(ctx, scope, true)
	if err != nil {
		return err
	}
	if !decision.Allowed {
		return ErrReauthRequired
	}
	return nil
}

func (s *Service) LockSession(ctx context.Context, reason string) (IdentitySession, error) {
	if err := ctx.Err(); err != nil {
		return IdentitySession{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.bumpVerificationEpochLocked()
	s.clearVerificationStateLocked(safe(reason))
	s.session.AssuranceLevel = AssuranceLocked
	s.session.OperatorAssurance = OperatorLocked
	s.session.LockReason = safe(reason)
	s.recompute()
	s.record(ctx, EventSessionLocked, "session locked")
	return cloneSession(s.session), nil
}

func (s *Service) DowngradeSession(ctx context.Context, reason string) (IdentitySession, error) {
	if err := ctx.Err(); err != nil {
		return IdentitySession{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.bumpVerificationEpochLocked()
	s.clearVerificationStateLocked(safe(reason))
	s.recompute()
	s.record(ctx, EventSessionDowngraded, "session downgraded")
	return cloneSession(s.session), nil
}

func (s *Service) refresh() {
	now := s.clock.Now().UTC()
	s.pruneReplayCachesLocked(now)
	if s.session.AssuranceLevel == AssuranceLocked {
		return
	}
	if s.hasVerifiedStateLocked() && s.policy.IdleTimeout > 0 && !s.session.LastActiveAt.IsZero() && !now.Before(s.session.LastActiveAt.Add(s.policy.IdleTimeout)) {
		s.bumpVerificationEpochLocked()
		s.clearVerificationStateLocked("idle timeout")
		s.recompute()
		return
	}
	if !s.session.VerifiedUntil.IsZero() && !now.Before(s.session.VerifiedUntil) {
		s.bumpVerificationEpochLocked()
		s.clearVerificationStateLocked("verification expired")
	} else if !s.session.FreshUntil.IsZero() && !now.Before(s.session.FreshUntil) {
		s.bumpVerificationEpochLocked()
		s.clearFreshStateLocked()
	}
	s.recompute()
}

func (s *Service) recompute() {
	allowed := []Scope{ScopePublic}
	if !s.policy.PublicChatRequiresAuth || s.session.AccountAuthenticated {
		allowed = append(allowed, ScopePublicChat)
	}
	if s.policy.IdleTimeout > 0 && !s.session.LastActiveAt.IsZero() {
		s.session.IdleTimeoutAt = s.session.LastActiveAt.Add(s.policy.IdleTimeout)
	} else {
		s.session.IdleTimeoutAt = time.Time{}
	}
	if s.session.AssuranceLevel == AssuranceLocked {
		s.session.AllowedScopes = allowed
		return
	}
	profileLightContext := s.session.ClaimedUserID != "" || s.session.RecognizedUserID != "" || s.session.TrustedDevice
	if profileLightContext && (!s.policy.ProfileLightRequiresAuth || s.session.AccountAuthenticated) {
		allowed = append(allowed, ScopeProfileLight)
	}
	verified := s.session.VerifiedOperatorUserID != "" && (s.session.AssuranceLevel == AssuranceVerified || s.session.AssuranceLevel == AssuranceFreshVerified)
	fresh := verified && s.session.AssuranceLevel == AssuranceFreshVerified && s.clock.Now().UTC().Before(s.session.FreshUntil)
	if verified {
		allowed = append(allowed, ScopeUserPrivateMemory, ScopePrivateMemoryRead, ScopeProjectPrivate, ScopeRelationshipPrivate, ScopePrivateMemoryWrite)
	}
	if fresh {
		allowed = append(allowed, ScopeAgentIdentityVault, ScopeIdentityContinuityPrivate, ScopeIntimatePrivate, ScopeSecurityAdmin, ScopeModelForge, ScopeTrainingLineage, ScopeVaultExport, ScopePrivateMemoryExport)
	}
	s.session.AllowedScopes = allowed
}

func (s *Service) evaluateScopeLocked(scope Scope) ScopeAccessDecision {
	decision := ScopeAccessDecision{Scope: scope, KnownScope: known(scope), CurrentAssurance: s.session.AssuranceLevel, OperatorAssurance: s.session.OperatorAssurance}
	if !decision.KnownScope {
		decision.Reason = "unknown scope"
		return decision
	}
	if s.session.AssuranceLevel == AssuranceLocked {
		decision.Locked = true
		decision.ReauthRequired = true
		decision.Reason = "session locked"
		return decision
	}
	for _, allowed := range s.session.AllowedScopes {
		if allowed == scope {
			decision.Allowed = true
			decision.Reason = "scope allowed"
			return decision
		}
	}
	if (scope == ScopePublicChat && s.policy.PublicChatRequiresAuth || scope == ScopeProfileLight && s.policy.ProfileLightRequiresAuth) && !s.session.AccountAuthenticated {
		decision.ReauthRequired = true
		decision.Reason = "account authentication required"
		return decision
	}
	decision.ReauthRequired = protected(scope) || high(scope)
	decision.FreshRequired = high(scope)
	if high(scope) {
		decision.Reason = "fresh verification required"
	} else if protected(scope) {
		decision.Reason = "operator verification required"
	} else {
		decision.Reason = "scope denied"
	}
	return decision
}

func (s *Service) bumpVerificationEpochLocked() {
	s.session.VerificationEpoch++
}

func (s *Service) hasVerifiedStateLocked() bool {
	return s.session.VerifiedOperatorUserID != "" ||
		!s.session.VerifiedUntil.IsZero() ||
		!s.session.FreshUntil.IsZero() ||
		s.session.AssuranceLevel == AssuranceVerified ||
		s.session.AssuranceLevel == AssuranceFreshVerified
}

func (s *Service) clearVerificationStateLocked(reason string) {
	s.session.VerifiedUserID = ""
	s.session.VerifiedOperatorUserID = ""
	s.session.VerifiedAt = time.Time{}
	s.session.VerifiedUntil = time.Time{}
	s.session.FreshVerifiedAt = time.Time{}
	s.session.FreshUntil = time.Time{}
	s.verifiedHardUntil = time.Time{}
	s.freshHardUntil = time.Time{}
	s.session.ReauthRequired = true
	s.session.ReauthReason = reason
	s.setBaseAssuranceLocked()
}

func (s *Service) clearFreshStateLocked() {
	s.session.FreshVerifiedAt = time.Time{}
	s.session.FreshUntil = time.Time{}
	s.freshHardUntil = time.Time{}
	if s.session.VerifiedOperatorUserID != "" && s.clock.Now().UTC().Before(s.session.VerifiedUntil) {
		s.session.AssuranceLevel = AssuranceVerified
		s.session.OperatorAssurance = OperatorVerified
		return
	}
	s.setBaseAssuranceLocked()
}

func (s *Service) setBaseAssuranceLocked() {
	switch {
	case s.session.RecognizedUserID != "":
		s.session.AssuranceLevel = AssuranceRecognizedProfile
		s.session.OperatorAssurance = OperatorRecognized
	case s.session.TrustedDevice:
		s.session.AssuranceLevel = AssuranceKnownDevice
		s.session.OperatorAssurance = OperatorKnownDevice
	case s.session.ClaimedUserID != "":
		s.session.AssuranceLevel = AssuranceClaimed
		s.session.OperatorAssurance = OperatorClaimed
	default:
		s.session.AssuranceLevel = AssuranceAnonymous
		s.session.OperatorAssurance = OperatorUnknown
	}
}

func (s *Service) touchActivityLocked(now time.Time) {
	s.session.LastActiveAt = now
	if s.policy.IdleTimeout > 0 {
		s.session.IdleTimeoutAt = now.Add(s.policy.IdleTimeout)
	}
	if s.policy.SlidingVerifiedWindow && s.session.VerifiedOperatorUserID != "" && !s.verifiedHardUntil.IsZero() {
		extended := earliestTime(now.Add(s.policy.VerifiedWindow), s.verifiedHardUntil)
		if extended.After(s.session.VerifiedUntil) {
			s.session.VerifiedUntil = extended
		}
	}
	if s.policy.SlidingFreshWindow && s.session.AssuranceLevel == AssuranceFreshVerified && !s.freshHardUntil.IsZero() {
		extended := earliestTime(now.Add(s.policy.FreshWindow), s.freshHardUntil)
		if extended.After(s.session.FreshUntil) {
			s.session.FreshUntil = extended
		}
	}
}

func (s *Service) burnFreshLocked() {
	if s.session.FreshUntil.IsZero() && s.session.AssuranceLevel != AssuranceFreshVerified {
		return
	}
	s.bumpVerificationEpochLocked()
	s.clearFreshStateLocked()
	s.recompute()
}

func known(scope Scope) bool { return public(scope) || protected(scope) || high(scope) }

func public(scope Scope) bool {
	return scope == ScopePublic || scope == ScopePublicChat || scope == ScopeProfileLight
}

func protected(scope Scope) bool {
	switch scope {
	case ScopeUserPrivateMemory, ScopePrivateMemoryRead, ScopeProjectPrivate, ScopePrivateMemoryWrite, ScopeRelationshipPrivate:
		return true
	}
	return false
}

func high(scope Scope) bool {
	switch scope {
	case ScopeAgentIdentityVault, ScopeIdentityContinuityPrivate, ScopeIntimatePrivate, ScopeSecurityAdmin, ScopeModelForge, ScopeTrainingLineage, ScopeVaultExport, ScopePrivateMemoryExport:
		return true
	}
	return false
}

func cloneSession(session IdentitySession) IdentitySession {
	session.AllowedScopes = append([]Scope(nil), session.AllowedScopes...)
	return session
}
