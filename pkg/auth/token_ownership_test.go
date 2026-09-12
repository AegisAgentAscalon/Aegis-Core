package auth

import (
	"context"
	"errors"
	"testing"
	"time"

	devsecretstore "github.com/AegisAgentAscalon/aegis-core/internal/secretstore"
	"github.com/AegisAgentAscalon/aegis-core/pkg/secretstore"
)

// A callback can commit just as cancellation arrives. Return the actual owned
// revision even when the caller has already invalidated its operation.
type delayedTokenCommit struct {
	secretstore.VersionedStore
	key     secretstore.Key
	entered chan context.Context
	release chan struct{}
	after   func() error
}

func (s *delayedTokenCommit) CompareAndSwap(ctx context.Context, key secretstore.Key, revision secretstore.Revision, value []byte) (secretstore.Revision, error) {
	if key != s.key {
		return s.VersionedStore.CompareAndSwap(ctx, key, revision, value)
	}
	s.entered <- ctx
	<-s.release
	rev, err := s.VersionedStore.CompareAndSwap(context.WithoutCancel(ctx), key, revision, value)
	if err == nil && s.after != nil {
		err = s.after()
	}
	return rev, err
}

func TestSignOutDuringTokenCommitCleansOnlyOwnedRevision(t *testing.T) {
	for _, newer := range []bool{false, true} {
		t.Run(map[bool]string{false: "own-token", true: "newer-token"}[newer], func(t *testing.T) {
			ctx := context.Background()
			tokens, profiles := successOAuthServers(t)
			defer tokens.Close()
			defer profiles.Close()
			cfg := testConfig(t)
			cfg.OAuth.Endpoints.TokenURL, cfg.OAuth.Endpoints.UserInfoURL = tokens.URL, profiles.URL
			backend := devsecretstore.NewMemoryStore()
			svc, err := NewStrictService(cfg, backend)
			if err != nil {
				t.Fatal(err)
			}
			start, err := svc.StartSignIn(ctx)
			if err != nil {
				t.Fatal(err)
			}
			gate := &delayedTokenCommit{VersionedStore: backend, key: svc.store.tokenKey, entered: make(chan context.Context, 1), release: make(chan struct{})}
			if newer {
				gate.after = func() error {
					raw, err := encodeToken(token{AccessToken: "newer", Expiry: time.Now().Add(time.Hour)})
					if err != nil {
						return err
					}
					return backend.Put(ctx, svc.store.tokenKey, raw)
				}
			}
			svc.store.versioned = gate
			state := mustState(t, start.AuthorizationURL)
			finished := make(chan error, 1)
			go func() {
				_, err := svc.CompleteSignIn(ctx, CompleteSignInRequest{State: state, Code: "code"})
				finished <- err
			}()
			var callbackCtx context.Context
			select {
			case callbackCtx = <-gate.entered:
			case <-time.After(3 * time.Second):
				close(gate.release)
				t.Fatal("token commit did not start")
			}
			// The copy must invalidate the original owner's pending operation.
			copy := *svc
			if err := copy.SignOut(ctx); !errors.Is(err, ErrSignOutIncomplete) {
				close(gate.release)
				t.Fatalf("pending mutation reported complete: %v", err)
			}
			if callbackCtx.Err() == nil {
				close(gate.release)
				t.Fatal("pending callback was not canceled")
			}
			close(gate.release)
			select {
			case err := <-finished:
				if !errors.Is(err, ErrAuthCanceled) {
					t.Fatalf("obsolete completion: %v", err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("obsolete completion did not finish")
			}
			tok, err := svc.store.readToken(ctx)
			if newer {
				if err != nil || tok.AccessToken != "newer" {
					t.Fatalf("newer credential lost: %v", err)
				}
			} else if !errors.Is(err, secretstore.ErrNotFound) {
				t.Fatalf("obsolete credential remains: %v", err)
			}
			if _, err := svc.Profile(ctx); !errors.Is(err, ErrProfileNotFound) {
				t.Fatalf("obsolete profile published: %v", err)
			}
			if svc.store.readLastError() != "" {
				t.Fatal("obsolete error was published")
			}
			if err := svc.SignOut(ctx); err != nil {
				t.Fatalf("retry sign-out: %v", err)
			}
		})
	}
}

func TestOlderTokenRevisionCannotReplaceOrDeleteNewCredential(t *testing.T) {
	ctx := context.Background()
	backend := devsecretstore.NewMemoryStore()
	svc, err := NewStrictService(testConfig(t), backend)
	if err != nil {
		t.Fatal(err)
	}
	op := svc.beginOperation(ctx)
	defer op.finish()
	if err := op.captureTokenRevision(); err != nil {
		t.Fatal(err)
	}
	newer := token{AccessToken: "newer", Expiry: time.Now().Add(time.Hour)}
	if err := svc.store.writeToken(ctx, newer); err != nil {
		t.Fatal(err)
	}
	if _, err := op.commitToken(token{AccessToken: "obsolete", Expiry: newer.Expiry}); !errors.Is(err, ErrStorageUnavailable) {
		t.Fatalf("stale commit accepted: %v", err)
	}
	if err := op.deletePreviousToken(); err != nil {
		t.Fatal(err)
	}
	got, err := svc.store.readToken(ctx)
	if err != nil || got.AccessToken != newer.AccessToken {
		t.Fatalf("newer token lost: %v", err)
	}
}
