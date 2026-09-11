package auth

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	devsecretstore "github.com/AegisAgentAscalon/aegis-core/internal/secretstore"
)

func TestStrictExpiredSessionsDoNotExhaustSignIn(t *testing.T) {
	svc, err := NewStrictService(testConfig(t), devsecretstore.NewMemoryStore())
	if err != nil {
		t.Fatal(err)
	}
	var oldSessions []pendingSession
	for i := 0; i < 5; i++ {
		old := pendingSession{SessionID: fmt.Sprintf("old-%d", i), State: fmt.Sprintf("state-%d", i), Verifier: "verifier", RedirectURI: "http://127.0.0.1:56789/oauth/callback", CreatedAt: time.Now().Add(-time.Hour), ExpiresAt: time.Now().Add(-30 * time.Minute), Consumed: true}
		oldSessions = append(oldSessions, old)
	}
	raw, err := encodeProtectedSessions(oldSessions)
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.store.putProtected(svc.store.sessionsKey, raw); err != nil {
		t.Fatal(err)
	}
	_, err = svc.StartSignIn(context.Background())
	if err != nil {
		t.Fatalf("UA-03: expired sessions must not exhaust sign-in: %v", err)
	}

}

func TestValidTokenCorruptProfileRequiresReconnect(t *testing.T) {
	for _, strict := range []bool{false, true} {
		t.Run(fmt.Sprintf("strict=%t", strict), func(t *testing.T) {
			var svc *Service
			var err error
			if strict {
				svc, err = NewStrictService(testConfig(t), devsecretstore.NewMemoryStore())
			} else {
				svc, err = NewService(testConfig(t))
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := svc.store.writeToken(token{AccessToken: "test", Expiry: time.Now().Add(time.Hour)}); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(svc.store.profilePath(), []byte(`{bad-json`), 0600); err != nil {
				t.Fatal(err)
			}
			st, err := svc.Status(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if !st.NeedsReconnect {
				t.Fatalf("UA-04: corrupt profile must request reconnect: %+v", st)
			}

		})
	}
}
