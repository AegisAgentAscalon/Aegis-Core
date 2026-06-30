package identitygate

import "context"

func (s *Service) ClassifyPromptFragment(ctx context.Context, fragment PromptFragment) (PromptFragment, error) {
	if err := ctx.Err(); err != nil {
		return PromptFragment{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refresh()
	if fragment.SourceClass == "" {
		fragment.SourceClass = SourceUnknown
	}
	fragment.OperatorVerified = s.session.VerifiedOperatorUserID != "" && s.session.AssuranceLevel != AssuranceLocked
	fragment.AllowedAsData = fragment.SourceClass != SourceUnknown
	fragment.SourceTrust = SourceTrustUntrusted
	switch fragment.SourceClass {
	case SourceSystemPolicy, SourceDeveloperPolicy, SourceAegisCorePolicy:
		fragment.SourceTrust = SourceTrustTrusted
		fragment.AllowedAsInstruction = true
		fragment.AllowedAsData = true
	case SourceVerifiedOperator:
		fragment.SourceTrust = SourceTrustTrusted
		fragment.AllowedAsInstruction = fragment.OperatorVerified
		fragment.AllowedAsData = true
	case SourceCurrentUserMessage:
		fragment.SourceTrust = SourceTrustBounded
		fragment.AllowedAsInstruction = true
		fragment.AllowedAsData = true
	case SourceTrustedMemory:
		fragment.SourceTrust = SourceTrustBounded
		fragment.AllowedAsData = true
	}
	return fragment, nil
}

func (s *Service) CheckPromptAuthority(ctx context.Context, fragment PromptFragment, scopes []Scope) error {
	fragment, err := s.ClassifyPromptFragment(ctx, fragment)
	if err != nil {
		return err
	}
	if len(scopes) == 0 {
		return nil
	}
	if !fragment.AllowedAsInstruction {
		return ErrPromptAuthorityDenied
	}
	for _, scope := range scopes {
		if err := s.RequireScope(ctx, scope, "prompt authority"); err != nil {
			return err
		}
	}
	return nil
}
