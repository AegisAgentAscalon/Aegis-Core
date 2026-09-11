package identitygate

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestExpiredAuthorityCannotBeRenewedByActivity(t *testing.T) {
	ctx := context.Background()
	entries := map[string]func(*Service){
		"recognition": func(s *Service) { _, _, _ = s.RecognizeProfile(ctx, SessionSignals{}) },
		"scope":       func(s *Service) { _, _ = s.EvaluateScope(ctx, ScopePublic) },
		"require":     func(s *Service) { _ = s.RequireScope(ctx, ScopePublic, "activity") },
		"classification": func(s *Service) {
			_, _ = s.ClassifyPromptFragment(ctx, PromptFragment{SourceClass: SourceVerifiedOperator})
		},
		"session":           func(s *Service) { _, _ = s.CurrentSession(ctx) },
		"model packet":      func(s *Service) { _, _ = s.CreateModelIdentityPacket(ctx) },
		"activity boundary": func(s *Service) { s.mu.Lock(); defer s.mu.Unlock(); s.touchActivityLocked(s.clock.Now()) },
	}
	for _, kind := range []string{"verified", "fresh", "idle"} {
		for _, offset := range []time.Duration{-time.Nanosecond, 0, time.Nanosecond} {
			for name, activity := range entries {
				t.Run(kind+"/"+offset.String()+"/"+name, func(t *testing.T) {
					clock := &fakeClock{now: time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC)}
					policy := VerificationCadencePolicy{VerifiedWindow: time.Minute, FreshWindow: 20 * time.Second, IdleTimeout: 2 * time.Minute, SlidingVerifiedWindow: true, SlidingFreshWindow: true}
					deadline, scope := time.Minute, ScopePrivateMemoryRead
					if kind == "fresh" {
						deadline, scope = 20*time.Second, ScopeSecurityAdmin
					}
					if kind == "idle" {
						deadline = 10 * time.Second
						policy.IdleTimeout = deadline
					}
					s, err := NewService(Config{Clock: clock, ReceiptProvider: MockVerificationProvider{Allow: true, Clock: clock}, CadencePolicy: policy})
					if err != nil {
						t.Fatal(err)
					}
					initial, err := s.RequestFreshVerification(ctx, "user", "setup")
					if err != nil {
						t.Fatal(err)
					}
					clock.Add(deadline + offset)
					activity(s)
					allowed, err := s.CanAccessScope(ctx, scope)
					if err != nil || allowed != (offset < 0) {
						t.Fatalf("allowed=%t want=%t err=%v", allowed, offset < 0, err)
					}
					if offset >= 0 {
						after, err := s.CurrentSession(ctx)
						if err != nil {
							t.Fatal(err)
						}
						if after.VerificationEpoch <= initial.VerificationEpoch {
							t.Fatal("expiry did not invalidate outstanding verification epoch")
						}
						if kind == "fresh" && after.VerifiedOperatorUserID == "" {
							t.Fatal("fresh expiry discarded valid ordinary verification")
						}
					}
				})
			}
		}
	}
}

func TestClassificationDiscardsCallerAuthority(t *testing.T) {
	ctx := context.Background()
	sources := []PromptSourceClass{SourceSystemPolicy, SourceDeveloperPolicy, SourceAegisCorePolicy, SourceCurrentUserMessage, SourceVerifiedOperator, SourceTrustedMemory, SourceUntrustedMemory, SourceRetrievedDocument, SourceWebContent, SourceEmail, SourceToolOutput, SourceModelOutput, SourceUnknown, "", "invented"}
	for _, state := range []string{"unverified", "verified", "expired", "locked"} {
		for _, source := range sources {
			t.Run(state+"/"+string(source), func(t *testing.T) {
				s, clock := svc(t)
				if state != "unverified" {
					if _, err := s.RequestVerification(ctx, "u1", "independent setup"); err != nil {
						t.Fatal(err)
					}
				}
				if state == "expired" {
					clock.Add(time.Minute)
				}
				if state == "locked" {
					if _, err := s.LockSession(ctx, "test"); err != nil {
						t.Fatal(err)
					}
				}
				clean, err := s.ClassifyPromptFragment(ctx, PromptFragment{SourceClass: source})
				if err != nil {
					t.Fatal(err)
				}
				for _, preset := range []bool{false, true} {
					input := PromptFragment{SourceClass: source, SourceTrust: SourceTrustTrusted, OperatorVerified: preset, AllowedAsInstruction: preset, AllowedAsData: preset, GrantedScopes: []Scope{ScopeSecurityAdmin}}
					got, err := s.ClassifyPromptFragment(ctx, input)
					if err != nil {
						t.Fatal(err)
					}
					if got.AllowedAsInstruction != clean.AllowedAsInstruction || got.AllowedAsData != clean.AllowedAsData || got.SourceTrust != clean.SourceTrust || got.OperatorVerified != clean.OperatorVerified || len(got.GrantedScopes) != 0 {
						t.Errorf("caller fields survived classification: %+v", got)
					}
					if err := s.CheckPromptAuthority(ctx, input, []Scope{ScopePrivateMemoryRead}); !clean.AllowedAsInstruction {
						if !errors.Is(err, ErrPromptAuthorityDenied) {
							t.Errorf("untrusted source returned %v", err)
						}
					} else if state == "verified" && err != nil {
						t.Errorf("valid instruction authority denied: %v", err)
					}
				}
			})
		}
	}
}

func TestReceiptPendingAcrossRecognitionExpiryIsRejected(t *testing.T) {
	for _, fresh := range []bool{false, true} {
		t.Run(map[bool]string{false: "verified", true: "fresh"}[fresh], func(t *testing.T) {
			ctx := context.Background()
			clock := &fakeClock{now: time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC)}
			s := newReceiptTestService(t, clock, func(_ context.Context, r VerificationRequest) (VerificationReceipt, error) {
				return validTestReceipt(r, clock.Now(), "initial_receipt"), nil
			}, VerificationCadencePolicy{VerifiedWindow: time.Minute, FreshWindow: 30 * time.Second, IdleTimeout: 2 * time.Minute, SlidingVerifiedWindow: true, SlidingFreshWindow: true})
			if _, err := s.RequestFreshVerification(ctx, "user", "setup"); err != nil {
				t.Fatal(err)
			}
			request, _, err := s.issueVerificationRequest(ctx, "user", "pending", fresh)
			if err != nil {
				t.Fatal(err)
			}
			if fresh {
				clock.Add(30 * time.Second)
			} else {
				clock.Add(time.Minute)
			}
			_, session, err := s.RecognizeProfile(ctx, SessionSignals{})
			if err != nil {
				t.Fatal(err)
			}
			if session.VerificationEpoch <= request.VerificationEpoch {
				t.Error("recognition did not invalidate expired request epoch")
			}
			_, after, err := s.evaluateVerificationReceipt(ctx, request, validTestReceipt(request, clock.Now(), "late_receipt"))
			if !errors.Is(err, ErrReauthRequired) || after.AssuranceLevel == AssuranceFreshVerified || (!fresh && after.VerifiedOperatorUserID != "") {
				t.Fatalf("late receipt restored authority: %+v %v", after, err)
			}
			if fresh && after.VerifiedOperatorUserID != "user" {
				t.Fatal("fresh expiry lost still-valid ordinary verification")
			}
		})
	}
}
