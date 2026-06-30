package identitygate

import (
	"context"
	"time"
)

func (s *Service) CanAccessScope(ctx context.Context, scope Scope) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refresh()
	if !known(scope) {
		s.record(ctx, EventScopeDenied, "unknown scope denied")
		return false, ErrUnknownScope
	}
	for _, allowed := range s.session.AllowedScopes {
		if allowed == scope {
			s.record(ctx, EventScopeAllowed, "scope allowed")
			return true, nil
		}
	}
	s.record(ctx, EventScopeDenied, "scope denied")
	return false, nil
}

func (s *Service) RequireScope(ctx context.Context, scope Scope, reason string) error {
	ok, err := s.CanAccessScope(ctx, scope)
	if err != nil {
		return err
	}
	if !ok {
		return ErrReauthRequired
	}
	return nil
}

func (s *Service) LockSession(ctx context.Context, reason string) (IdentitySession, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.session.AssuranceLevel = AssuranceLocked
	s.session.OperatorAssurance = OperatorLocked
	s.session.LockReason = safe(reason)
	s.session.AllowedScopes = []Scope{ScopePublic, ScopePublicChat}
	s.record(ctx, EventSessionLocked, "session locked")
	return cloneSession(s.session), nil
}

func (s *Service) DowngradeSession(ctx context.Context, reason string) (IdentitySession, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.session.VerifiedUserID = ""
	s.session.VerifiedOperatorUserID = ""
	s.session.FreshUntil = time.Time{}
	s.session.VerifiedUntil = time.Time{}
	s.session.ReauthRequired = true
	s.session.ReauthReason = safe(reason)
	if s.session.RecognizedUserID != "" {
		s.session.AssuranceLevel = AssuranceRecognizedProfile
		s.session.OperatorAssurance = OperatorRecognized
	} else {
		s.session.AssuranceLevel = AssuranceAnonymous
		s.session.OperatorAssurance = OperatorUnknown
	}
	s.recompute()
	s.record(ctx, EventSessionDowngraded, "session downgraded")
	return cloneSession(s.session), nil
}

func (s *Service) refresh() {
	now := s.clock.Now().UTC()
	if s.session.AssuranceLevel == AssuranceLocked {
		return
	}
	if !s.session.FreshUntil.IsZero() && !now.Before(s.session.FreshUntil) {
		s.session.FreshUntil = time.Time{}
		s.session.FreshVerifiedAt = time.Time{}
		if s.session.VerifiedOperatorUserID != "" && now.Before(s.session.VerifiedUntil) {
			s.session.AssuranceLevel = AssuranceVerified
			s.session.OperatorAssurance = OperatorVerified
		}
	}
	if !s.session.VerifiedUntil.IsZero() && !now.Before(s.session.VerifiedUntil) {
		s.session.VerifiedUserID = ""
		s.session.VerifiedOperatorUserID = ""
		s.session.VerifiedUntil = time.Time{}
		s.session.FreshUntil = time.Time{}
		s.session.AssuranceLevel = AssuranceRecognizedProfile
		s.session.OperatorAssurance = OperatorRecognized
		s.session.ReauthRequired = true
	}
	s.recompute()
}

func (s *Service) recompute() {
	allowed := []Scope{ScopePublic, ScopePublicChat}
	if s.session.AssuranceLevel == AssuranceLocked {
		s.session.AllowedScopes = allowed
		return
	}
	if s.session.ClaimedUserID != "" || s.session.RecognizedUserID != "" || s.session.TrustedDevice {
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
