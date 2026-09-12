package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	devsecretstore "github.com/AegisAgentAscalon/aegis-core/internal/secretstore"
	"github.com/AegisAgentAscalon/aegis-core/pkg/secretstore"
)

type panickingOperationStore struct {
	secretstore.VersionedStore
	method string
	key    secretstore.Key
}

func (s *panickingOperationStore) maybePanic(method string, key secretstore.Key) {
	if s.method == method && s.key == key {
		panic("host callback panic")
	}
}

func (s *panickingOperationStore) Get(ctx context.Context, key secretstore.Key) ([]byte, error) {
	s.maybePanic("read", key)
	return s.VersionedStore.Get(ctx, key)
}

func (s *panickingOperationStore) GetWithRevision(ctx context.Context, key secretstore.Key) ([]byte, secretstore.Revision, error) {
	s.maybePanic("get", key)
	return s.VersionedStore.GetWithRevision(ctx, key)
}

func (s *panickingOperationStore) CompareAndSwap(ctx context.Context, key secretstore.Key, revision secretstore.Revision, value []byte) (secretstore.Revision, error) {
	s.maybePanic("cas", key)
	return s.VersionedStore.CompareAndSwap(ctx, key, revision, value)
}

func (s *panickingOperationStore) CompareAndDelete(ctx context.Context, key secretstore.Key, revision secretstore.Revision) (secretstore.Revision, error) {
	s.maybePanic("delete", key)
	return s.VersionedStore.CompareAndDelete(ctx, key, revision)
}

func TestCompleteSignInReleasesOwnerAfterRecoveredHostPanic(t *testing.T) {
	for _, tc := range []struct {
		name, method string
		session      bool
		profileFails bool
	}{
		{"session-read", "get", true, false},
		{"session-claim", "cas", true, false},
		{"token-revision", "get", false, false},
		{"failed-profile-cleanup", "delete", false, true},
		{"token-commit", "cas", false, false},
		{"final-status", "read", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			tokens, profiles := successOAuthServers(t)
			defer tokens.Close()
			defer profiles.Close()
			cfg := testConfig(t)
			cfg.OAuth.Endpoints.TokenURL, cfg.OAuth.Endpoints.UserInfoURL = tokens.URL, profiles.URL
			if tc.profileFails {
				failedProfile := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(http.StatusServiceUnavailable)
				}))
				defer failedProfile.Close()
				cfg.OAuth.Endpoints.UserInfoURL = failedProfile.URL
			}
			backend := &panickingOperationStore{VersionedStore: devsecretstore.NewMemoryStore()}
			svc, err := NewStrictService(cfg, backend)
			if err != nil {
				t.Fatal(err)
			}
			start, err := svc.StartSignIn(ctx)
			if err != nil {
				t.Fatal(err)
			}
			backend.method, backend.key = tc.method, svc.store.tokenKey
			if tc.session {
				backend.key = svc.store.sessionsKey
			}
			var recovered any
			func() {
				defer func() { recovered = recover() }()
				_, _ = svc.CompleteSignIn(ctx, CompleteSignInRequest{State: mustState(t, start.AuthorizationURL), Code: "code"})
			}()
			if recovered != "host callback panic" {
				t.Fatalf("callback panic did not propagate: %v", recovered)
			}
			backend.method = ""
			copied := *svc
			if _, err := copied.Status(ctx); err != nil {
				t.Fatalf("recovered panic stranded owner reservation: %v", err)
			}
			if err := copied.SignOut(ctx); err != nil {
				t.Fatalf("recovered panic prevented cleanup: %v", err)
			}
			if _, err := svc.StartSignIn(ctx); err != nil {
				t.Fatalf("recovered owner cannot start another sign-in: %v", err)
			}
		})
	}
}
