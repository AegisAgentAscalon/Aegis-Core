package identitygate

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"
)

type callbackSink func(context.Context, AuditEvent) error

func (f callbackSink) Record(ctx context.Context, e AuditEvent) error { return f(ctx, e) }

func TestProfileInputAndOutputOwnership(t *testing.T) {
	s, err := NewService(Config{ReceiptProvider: MockVerificationProvider{Allow: true}})
	if err != nil {
		t.Fatal(err)
	}
	original := UserProfile{UserID: "user", RecognitionFeatures: RecognitionFeatures{Aliases: []string{"alias"}, Topics: []string{"topic"}, SafeMetadata: map[string]string{"key": "value"}}}
	input := cloneProfile(original)
	output, err := s.CreateUserProfile(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []UserProfile{input, output} {
		p.RecognitionFeatures.Aliases[0] = "changed"
		p.RecognitionFeatures.Topics[0] = "changed"
		p.RecognitionFeatures.SafeMetadata["key"] = "changed"
	}
	if !reflect.DeepEqual(s.profiles["user"], original) {
		t.Fatal("stored profile aliases input or output")
	}
}

func TestChannelPolicyDestinationTable(t *testing.T) {
	for _, channel := range []DeliveryChannel{DeliveryVoice, DeliveryDirect, DeliveryScreen, DeliveryHold, "", "future"} {
		for mask := 0; mask < 16; mask++ {
			req := ChannelPolicyRequest{Channel: channel, ProtectedContent: mask&1 != 0, HighRiskContent: mask&2 != 0, SharedSetting: mask&4 != 0, DirectRoutePossible: mask&8 != 0}
			got := EvaluateChannelPolicy(req)
			hold := channel == DeliveryHold || channel == "" || channel == "future"
			direct := false
			if !hold && (req.ProtectedContent || req.HighRiskContent) && channel != DeliveryDirect {
				direct = req.SharedSetting && req.DirectRoutePossible
				hold = !direct && (req.SharedSetting || channel == DeliveryVoice)
			}
			if got.Hold != hold || got.Allowed == hold || got.UseDirect != direct {
				t.Errorf("%+v => %+v", req, got)
			}
		}
	}
}

func TestAuditReentryAndConcurrentFIFO(t *testing.T) {
	ctx := context.Background()
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var s *Service
	var kinds []string
	sink := callbackSink(func(ctx context.Context, e AuditEvent) error {
		kinds = append(kinds, e.Kind)
		if e.Kind == EventIdentityClaimed {
			if _, err := s.CurrentSession(ctx); err != nil {
				return err
			}
			// A nested audited operation must enqueue, return, then be delivered.
			if _, err := s.EvaluateScope(ctx, ScopePublic); err != nil {
				return err
			}
			close(entered)
			<-release
		}
		return errors.New("best effort sink failure")
	})
	var err error
	s, err = NewService(Config{ReceiptProvider: MockVerificationProvider{Allow: true}, AuditSink: sink})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _, _ = s.ClaimIdentity(ctx, "user"); close(done) }()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("reentrant sink deadlocked")
	}
	// These transitions complete while the first callback remains blocked.
	concurrent := make(chan struct{})
	go func() { _, _ = s.LockSession(ctx, "test"); close(concurrent) }()
	select {
	case <-concurrent:
	case <-time.After(3 * time.Second):
		close(release)
		t.Fatal("sink holds state lock")
	}
	close(release)
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("drain deadlocked")
	}
	want := []string{EventSessionCreated, EventIdentityClaimed, EventScopeAllowed, EventSessionLocked}
	if !reflect.DeepEqual(kinds, want) {
		t.Fatalf("event order: %v, want %v", kinds, want)
	}
}

func TestAuditConcurrentEventsAreNotLost(t *testing.T) {
	sink := &MemoryAuditSink{}
	s, err := NewService(Config{ReceiptProvider: MockVerificationProvider{Allow: true}, AuditSink: sink})
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _, _ = s.EvaluateScope(context.Background(), ScopePublic) }()
	}
	wg.Wait()
	events := sink.Snapshot()
	if len(events) != 33 {
		t.Fatalf("got %d events, want 33", len(events))
	}
	for _, e := range events[1:] {
		if e.Kind != EventScopeAllowed {
			t.Fatal(e)
		}
	}
}
