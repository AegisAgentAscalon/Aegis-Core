//go:build auditregression

// Audit-only public API probes. Does not modify the audited source.
package auditregression

import (
	"context"
	ig "github.com/AegisAgentAscalon/aegis-core/pkg/identitygate"
	"testing"
	"time"
)

type mutableClock struct{ t time.Time }

func (c *mutableClock) Now() time.Time { return c.t }

type reentrantSink struct{ svc *ig.Service }

func (a *reentrantSink) Record(ctx context.Context, _ ig.AuditEvent) error {
	if a.svc != nil {
		_, err := a.svc.CurrentSession(ctx)
		return err
	}
	return nil
}

func TestIdentityGateAudit(t *testing.T) {
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	ctx := context.Background()
	clock := &mutableClock{time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC)}
	cfg := ig.Config{Clock: clock, ReceiptProvider: ig.MockVerificationProvider{Allow: true, Clock: clock}, CadencePolicy: ig.VerificationCadencePolicy{VerifiedWindow: time.Minute, FreshWindow: 30 * time.Second, IdleTimeout: time.Minute, SlidingVerifiedWindow: true, SlidingFreshWindow: true}}
	svc, err := ig.NewService(cfg)
	must(err)
	_, err = svc.RequestFreshVerification(ctx, "user", "audit")
	must(err)
	clock.t = clock.t.Add(2 * time.Minute)
	_, _, err = svc.RecognizeProfile(ctx, ig.SessionSignals{})
	must(err)
	allowed, err := svc.CanAccessScope(ctx, ig.ScopeSecurityAdmin)
	must(err)
	if allowed {
		t.Error("IG-01: expired verification revived by recognition")
	}
	// Isolate the provenance case from the preceding cadence defect.
	svc, err = ig.NewService(cfg)
	must(err)
	_, err = svc.RequestVerification(ctx, "user", "independent provenance audit")
	must(err)
	fragment := ig.PromptFragment{SourceClass: ig.SourceWebContent, AllowedAsInstruction: true}
	classified, err := svc.ClassifyPromptFragment(ctx, fragment)
	must(err)
	err = svc.CheckPromptAuthority(ctx, fragment, []ig.Scope{ig.ScopePrivateMemoryRead})
	if classified.AllowedAsInstruction || err == nil {
		t.Errorf("IG-02: untrusted source retains authority: flag=%t err=%v", classified.AllowedAsInstruction, err)
	}
	profile := ig.UserProfile{UserID: "known", RecognitionFeatures: ig.RecognitionFeatures{Aliases: []string{"original"}}}
	_, err = svc.CreateUserProfile(ctx, profile)
	must(err)
	profile.RecognitionFeatures.Aliases[0] = "mutated"
	recognized, _, err := svc.RecognizeProfile(ctx, ig.SessionSignals{Aliases: []string{"mutated"}})
	must(err)
	if recognized.CandidateUserID == "known" {
		t.Error("IG-04: caller mutation changed stored profile")
	}
	for _, channel := range []ig.DeliveryChannel{ig.DeliveryHold, ig.DeliveryChannel("invalid")} {
		d := ig.EvaluateChannelPolicy(ig.ChannelPolicyRequest{Channel: channel, ProtectedContent: true})
		if d.Allowed {
			t.Errorf("IG-05: protected content allowed on channel %s", channel)
		}
	}
	sink := &reentrantSink{}
	locked, err := ig.NewService(ig.Config{ReceiptProvider: ig.MockVerificationProvider{Allow: true}, AuditSink: sink})
	must(err)
	sink.svc = locked
	done := make(chan struct{})
	go func() { _, _ = locked.ClaimIdentity(ctx, "user"); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Error("IG-03: reentrant audit callback deadlocked")
	}
}
