// Audit-only public API probes. Does not modify the audited source.
package auditregression

import (
	"context"
	ig "github.com/AegisAgentAscalon/aegis-core/pkg/identitygate"
	"testing"
	"time"
)

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
	svc, err := ig.NewService(ig.Config{ReceiptProvider: ig.MockVerificationProvider{Allow: true}})
	must(err)
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
