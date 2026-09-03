package identitygate

import (
	"context"
	"sync"
	"time"
)

type Service struct {
	mu                sync.Mutex
	session           IdentitySession
	profiles          map[string]UserProfile
	policy            VerificationCadencePolicy
	verifier          VerificationReceiptProvider
	providerName      string
	clock             Clock
	audit             AuditSink
	verifiedHardUntil time.Time
	freshHardUntil    time.Time
	usedAttemptIDs    map[string]time.Time
	usedAssertionIDs  map[string]time.Time
	usedReceiptIDs    map[string]time.Time
}

func NewService(cfg Config) (*Service, error) {
	clock := cfg.Clock
	if clock == nil {
		clock = realClock{}
	}
	policy := resolve(cfg.CadencePolicy)
	verifier, providerName, err := configuredReceiptProvider(cfg)
	if err != nil {
		return nil, err
	}
	now := clock.Now().UTC()
	sessionID := cfg.SessionID
	if sessionID == "" {
		sessionID, err = newOpaqueID("session")
		if err != nil {
			return nil, err
		}
	} else if !validOpaqueReference(sessionID) {
		return nil, ErrInvalidVerificationConfig
	}
	svc := &Service{
		session: IdentitySession{
			SessionID:         sessionID,
			AssuranceLevel:    AssuranceAnonymous,
			OperatorAssurance: OperatorUnknown,
			LastActiveAt:      now,
			VerificationEpoch: 1,
		},
		profiles:         map[string]UserProfile{},
		policy:           policy,
		verifier:         verifier,
		providerName:     providerName,
		clock:            clock,
		audit:            cfg.AuditSink,
		usedAttemptIDs:   map[string]time.Time{},
		usedAssertionIDs: map[string]time.Time{},
		usedReceiptIDs:   map[string]time.Time{},
	}
	svc.recompute()
	svc.record(context.Background(), EventSessionCreated, "session created")
	return svc, nil
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
