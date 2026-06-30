package identitygate

import (
	"context"
	"fmt"
	"sync"
)

type Service struct {
	mu       sync.Mutex
	session  IdentitySession
	profiles map[string]UserProfile
	policy   VerificationCadencePolicy
	verifier IdentityVerificationProvider
	clock    Clock
	audit    AuditSink
}

func NewService(cfg Config) (*Service, error) {
	clock := cfg.Clock
	if clock == nil {
		clock = realClock{}
	}
	policy := resolve(cfg.CadencePolicy)
	verifier := cfg.VerificationProvider
	if verifier == nil {
		verifier = MockVerificationProvider{Allow: true, Clock: clock}
	}
	now := clock.Now().UTC()
	sessionID := cfg.SessionID
	if sessionID == "" {
		sessionID = fmt.Sprintf("sess_%d", now.UnixNano())
	}
	return &Service{
		session: IdentitySession{
			SessionID:         sessionID,
			AssuranceLevel:    AssuranceAnonymous,
			OperatorAssurance: OperatorUnknown,
			LastActiveAt:      now,
			AllowedScopes:     []Scope{ScopePublic, ScopePublicChat},
		},
		profiles: map[string]UserProfile{},
		policy:   policy,
		verifier: verifier,
		clock:    clock,
		audit:    cfg.AuditSink,
	}, nil
}

func (s *Service) CurrentSession(ctx context.Context) (IdentitySession, error) {
	if err := ctx.Err(); err != nil {
		return IdentitySession{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refresh()
	return cloneSession(s.session), nil
}
