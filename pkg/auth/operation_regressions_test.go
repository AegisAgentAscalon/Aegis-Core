package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	devsecretstore "github.com/AegisAgentAscalon/aegis-core/internal/secretstore"
	"github.com/AegisAgentAscalon/aegis-core/pkg/secretstore"
)

func awaitAuthOperation[T any](t *testing.T, result <-chan T) T {
	t.Helper()
	select {
	case value := <-result:
		return value
	case <-time.After(3 * time.Second):
		t.Fatal("auth operation did not finish")
		var zero T
		return zero
	}
}

func runAuthOperation(fn func() error) <-chan error {
	result := make(chan error, 1)
	go func() { result <- fn() }()
	return result
}

func newOperationService(t *testing.T, strict bool, endpoint string) *Service {
	t.Helper()
	cfg := testConfig(t)
	cfg.OAuth.Endpoints.TokenURL = endpoint + "/token"
	cfg.OAuth.Endpoints.UserInfoURL = endpoint + "/profile"
	var svc *Service
	var err error
	if strict {
		svc, err = NewStrictService(cfg, devsecretstore.NewMemoryStore())
	} else {
		svc, err = NewService(cfg)
	}
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

func startOperationSignIn(t *testing.T, svc *Service) string {
	t.Helper()
	var start SignInStartResult
	err := awaitAuthOperation(t, runAuthOperation(func() error {
		var err error
		start, err = svc.StartSignIn(context.Background())
		return err
	}))
	if err != nil {
		t.Fatal(err)
	}
	return mustState(t, start.AuthorizationURL)
}

func TestAuthOperationSignOutDuringHTTP(t *testing.T) {
	for _, strict := range []bool{false, true} {
		for _, phase := range []string{"token", "profile"} {
			t.Run(fmt.Sprintf("strict=%t/%s", strict, phase), func(t *testing.T) {
				arrived, release := make(chan struct{}), make(chan struct{})
				var once sync.Once
				unblock := func() { once.Do(func() { close(release) }) }
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path == "/"+phase {
						close(arrived)
						<-release // The remote handler deliberately ignores cancellation.
					}
					if r.URL.Path == "/token" {
						fmt.Fprint(w, `{"access_token":"old-token","expires_in":3600}`)
					} else {
						fmt.Fprint(w, `{"id":"old-profile"}`)
					}
				}))
				t.Cleanup(server.Close)
				t.Cleanup(unblock)
				svc := newOperationService(t, strict, server.URL)
				state := startOperationSignIn(t, svc)
				completion := runAuthOperation(func() error {
					_, err := svc.CompleteSignIn(context.Background(), CompleteSignInRequest{State: state, Code: "old"})
					return err
				})
				awaitAuthOperation(t, arrived)
				if err := awaitAuthOperation(t, runAuthOperation(func() error { _, err := svc.Status(context.Background()); return err })); err != nil {
					t.Fatalf("status blocked by HTTP: %v", err)
				}
				if err := awaitAuthOperation(t, runAuthOperation(func() error { return svc.SignOut(context.Background()) })); err != nil {
					t.Fatalf("sign-out blocked by HTTP: %v", err)
				}
				unblock()
				if err := awaitAuthOperation(t, completion); !errors.Is(err, ErrAuthCanceled) {
					t.Fatalf("obsolete HTTP completion = %v", err)
				}
				status, err := svc.Status(context.Background())
				if err != nil || status.SignedIn || status.TokenPresent || status.ProfilePresent || status.LastError != "" {
					t.Fatalf("sign-out state restored: %+v, %v", status, err)
				}
				for _, path := range []string{svc.store.profilePath(), svc.store.errorPath()} {
					if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
						t.Fatalf("obsolete completion recreated a local record: %v", err)
					}
				}
			})
		}
	}
}

func TestAuthOperationNewLoginSupersedesFailedHTTP(t *testing.T) {
	for _, strict := range []bool{false, true} {
		t.Run(fmt.Sprintf("strict=%t", strict), func(t *testing.T) {
			arrived, release := make(chan struct{}), make(chan struct{})
			var once sync.Once
			unblock := func() { once.Do(func() { close(release) }) }
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/token" {
					fmt.Fprintf(w, `{"access_token":%q,"expires_in":3600}`, r.FormValue("code"))
				} else if r.Header.Get("Authorization") == "Bearer old" {
					close(arrived)
					<-release
					w.WriteHeader(http.StatusServiceUnavailable)
				} else {
					fmt.Fprint(w, `{"id":"new-profile"}`)
				}
			}))
			t.Cleanup(server.Close)
			t.Cleanup(unblock)
			svc := newOperationService(t, strict, server.URL)
			oldState := startOperationSignIn(t, svc)
			oldCompletion := runAuthOperation(func() error {
				_, err := svc.CompleteSignIn(context.Background(), CompleteSignInRequest{State: oldState, Code: "old"})
				return err
			})
			awaitAuthOperation(t, arrived)
			newState := startOperationSignIn(t, svc)
			if err := awaitAuthOperation(t, runAuthOperation(func() error {
				_, err := svc.CompleteSignIn(context.Background(), CompleteSignInRequest{State: newState, Code: "new"})
				return err
			})); err != nil {
				t.Fatal(err)
			}
			unblock()
			if err := awaitAuthOperation(t, oldCompletion); !errors.Is(err, ErrAuthCanceled) {
				t.Fatalf("superseded completion = %v", err)
			}
			status, err := svc.Status(context.Background())
			if err != nil || !status.SignedIn || status.Profile.Subject != "new-profile" || status.LastError != "" {
				t.Fatalf("old failure altered new login: %+v, %v", status, err)
			}
		})
	}
}

type operationCallbackStore struct {
	secretstore.VersionedStore
	beforeGet func(context.Context) error
	beforeCAS func(context.Context) error
}

func (s *operationCallbackStore) Get(ctx context.Context, key secretstore.Key) ([]byte, error) {
	if s.beforeGet != nil {
		if err := s.beforeGet(ctx); err != nil {
			return nil, err
		}
	}
	return s.VersionedStore.Get(ctx, key)
}

func (s *operationCallbackStore) CompareAndSwap(ctx context.Context, key secretstore.Key, revision secretstore.Revision, value []byte) (secretstore.Revision, error) {
	if s.beforeCAS != nil {
		if err := s.beforeCAS(ctx); err != nil {
			return 0, err
		}
	}
	return s.VersionedStore.CompareAndSwap(ctx, key, revision, value)
}

func TestAuthOperationProtectedCallbackReentry(t *testing.T) {
	backend := &operationCallbackStore{VersionedStore: devsecretstore.NewMemoryStore()}
	svc, err := NewStrictService(testConfig(t), backend)
	if err != nil {
		t.Fatal(err)
	}
	reentered := make(chan [2]error, 1)
	backend.beforeGet = func(ctx context.Context) error {
		_, statusErr := svc.Status(ctx)
		_, profileErr := svc.Profile(ctx)
		reentered <- [2]error{statusErr, profileErr}
		return nil
	}
	if err := awaitAuthOperation(t, runAuthOperation(func() error { _, err := svc.Status(context.Background()); return err })); err != nil {
		t.Fatal(err)
	}
	for _, err := range awaitAuthOperation(t, reentered) {
		if !errors.Is(err, ErrStorageUnavailable) {
			t.Fatalf("reentrant storage operation = %v", err)
		}
	}
}

func TestAuthOperationCancellationReachesProtectedStore(t *testing.T) {
	for _, operation := range []string{"get", "session-cas"} {
		t.Run(operation, func(t *testing.T) {
			backend := &operationCallbackStore{VersionedStore: devsecretstore.NewMemoryStore()}
			svc, err := NewStrictService(testConfig(t), backend)
			if err != nil {
				t.Fatal(err)
			}
			type contextKey struct{}
			ctx, cancel := context.WithCancel(context.WithValue(context.Background(), contextKey{}, "caller"))
			defer cancel()
			arrived := make(chan context.Context, 1)
			hook := func(ctx context.Context) error { arrived <- ctx; <-ctx.Done(); return ctx.Err() }
			var result <-chan error
			if operation == "get" {
				backend.beforeGet = hook
				result = runAuthOperation(func() error { _, err := svc.Status(ctx); return err })
			} else {
				backend.beforeCAS = hook
				result = runAuthOperation(func() error { _, err := svc.StartSignIn(ctx); return err })
			}
			if got := awaitAuthOperation(t, arrived); got.Value(contextKey{}) != "caller" {
				t.Fatal("protected callback lost caller context")
			}
			cancel()
			if err := awaitAuthOperation(t, result); !errors.Is(err, ErrAuthCanceled) {
				t.Fatalf("canceled protected operation = %v", err)
			}
		})
	}
}

func TestAuthOperationCancellationDuringResponseBody(t *testing.T) {
	for _, phase := range []string{"token", "profile"} {
		t.Run(phase, func(t *testing.T) {
			arrived, canceled := make(chan struct{}), make(chan struct{})
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/"+phase {
					fmt.Fprint(w, `{"unfinished":`)
					w.(http.Flusher).Flush()
					close(arrived)
					<-r.Context().Done()
					close(canceled)
				} else {
					fmt.Fprint(w, `{"access_token":"token","expires_in":3600}`)
				}
			}))
			t.Cleanup(server.Close)
			t.Cleanup(server.CloseClientConnections)
			svc := newOperationService(t, false, server.URL)
			state := startOperationSignIn(t, svc)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			result := runAuthOperation(func() error {
				_, err := svc.CompleteSignIn(ctx, CompleteSignInRequest{State: state, Code: "code"})
				return err
			})
			awaitAuthOperation(t, arrived)
			cancel()
			if err := awaitAuthOperation(t, result); !errors.Is(err, ErrAuthCanceled) {
				t.Fatalf("canceled response body = %v", err)
			}
			awaitAuthOperation(t, canceled)
		})
	}
}
