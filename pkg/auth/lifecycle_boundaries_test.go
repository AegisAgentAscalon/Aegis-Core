package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	devsecretstore "github.com/AegisAgentAscalon/aegis-core/internal/secretstore"
	"github.com/AegisAgentAscalon/aegis-core/pkg/secretstore"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestStrictRepeatedCompletedSignInsRemainUsableAndRejectReplay(t *testing.T) {
	tokenServer, profileServer := successOAuthServers(t)
	defer tokenServer.Close()
	defer profileServer.Close()
	cfg := testConfig(t)
	cfg.OAuth.Endpoints.TokenURL = tokenServer.URL
	cfg.OAuth.Endpoints.UserInfoURL = profileServer.URL
	svc, err := NewStrictService(cfg, devsecretstore.NewMemoryStore())
	if err != nil {
		t.Fatal(err)
	}
	var first, last string
	for i := 0; i < 12; i++ {
		start, err := svc.StartSignIn(context.Background())
		if err != nil {
			t.Fatalf("sign-in %d: %v", i, err)
		}
		last = mustState(t, start.AuthorizationURL)
		if i == 0 {
			first = last
		}
		if _, err := svc.CompleteSignIn(context.Background(), CompleteSignInRequest{State: last, Code: "code"}); err != nil {
			t.Fatal(err)
		}
	}
	for state, want := range map[string]error{first: ErrSessionNotFound, last: ErrSessionConsumed} {
		if _, err := svc.CompleteSignIn(context.Background(), CompleteSignInRequest{State: state, Code: "replayed"}); !errors.Is(err, want) {
			t.Fatalf("replay was not rejected: %v", err)
		}
	}
	sessions, err := svc.store.readProtectedSessions(context.Background())
	if err != nil || len(sessions) != maxPendingSessionFiles {
		t.Fatalf("unbounded session record: %d %v", len(sessions), err)
	}
	assertLegacySecretsRemoved(t, svc.store)
}
func TestPendingSessionBoundaryAndFiveLiveLimit(t *testing.T) {
	now := time.Now().UTC()
	var existing []pendingSession
	for i := 0; i < 5; i++ {
		s := migrationSession(fmt.Sprintf("s%d", i), fmt.Sprintf("state%d", i))
		s.CreatedAt = now.Add(-time.Minute)
		s.ExpiresAt = now
		existing = append(existing, s)
	}
	next := migrationSession("next", "next-state")
	if _, err := appendPendingSession(append([]pendingSession(nil), existing...), next, now); !errors.Is(err, ErrStorageUnavailable) {
		t.Fatalf("expiry equality changed: %v", err)
	}
	got, err := appendPendingSession(existing, next, now.Add(time.Nanosecond))
	if err != nil || len(got) != 1 {
		t.Fatalf("expired records retained: %d %v", len(got), err)
	}
	svc, err := NewStrictService(testConfig(t), devsecretstore.NewMemoryStore())
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		if _, err := svc.StartSignIn(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	before, err := svc.store.getProtected(context.Background(), svc.store.sessionsKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.StartSignIn(context.Background()); !errors.Is(err, ErrStorageUnavailable) {
		t.Fatalf("sixth live session accepted: %v", err)
	}
	after, err := svc.store.getProtected(context.Background(), svc.store.sessionsKey)
	if err != nil || string(before) != string(after) {
		t.Fatal("quota failure altered sessions")
	}
}

// Force both services to attempt the same revision, rather than rely on timing.
type sessionCASBarrier struct {
	secretstore.VersionedStore
	key     secretstore.Key
	calls   atomic.Int32
	arrived chan struct{}
	release chan struct{}
}

func (s *sessionCASBarrier) CompareAndSwap(ctx context.Context, key secretstore.Key, revision secretstore.Revision, value []byte) (secretstore.Revision, error) {
	if key == s.key && s.calls.Add(1) <= 2 {
		s.arrived <- struct{}{}
		<-s.release
	}
	return s.VersionedStore.CompareAndSwap(ctx, key, revision, value)
}
func TestStrictSessionPruneAndAppendShareCAS(t *testing.T) {
	for _, live := range []int{0, 4} {
		t.Run(fmt.Sprintf("live=%d", live), func(t *testing.T) {
			ctx := context.Background()
			cfg := testConfig(t)
			backend := devsecretstore.NewMemoryStore()
			first, err := NewStrictService(cfg, backend)
			if err != nil {
				t.Fatal(err)
			}
			second, err := NewStrictService(cfg, backend)
			if err != nil {
				t.Fatal(err)
			}
			var seed []pendingSession
			for i := 0; i < 5; i++ {
				s := migrationSession(fmt.Sprintf("seed%d", i), fmt.Sprintf("seed-state%d", i))
				if i >= live {
					s.CreatedAt = time.Now().Add(-time.Hour)
					s.ExpiresAt = time.Now().Add(-time.Minute)
				}
				seed = append(seed, s)
			}
			raw, err := encodeProtectedSessions(seed)
			if err != nil {
				t.Fatal(err)
			}
			if err := backend.Put(ctx, first.store.sessionsKey, raw); err != nil {
				t.Fatal(err)
			}
			gate := &sessionCASBarrier{VersionedStore: backend, key: first.store.sessionsKey, arrived: make(chan struct{}, 2), release: make(chan struct{})}
			first.store.versioned = gate
			second.store.versioned = gate
			type outcome struct {
				start SignInStartResult
				err   error
			}
			results := make(chan outcome, 2)
			for _, svc := range []*Service{first, second} {
				go func(s *Service) { v, e := s.StartSignIn(ctx); results <- outcome{v, e} }(svc)
			}
			for i := 0; i < 2; i++ {
				select {
				case <-gate.arrived:
				case <-time.After(3 * time.Second):
					close(gate.release)
					t.Fatal("CAS rendezvous timed out")
				}
			}
			close(gate.release)
			successes := map[string]bool{}
			for i := 0; i < 2; i++ {
				result := <-results
				if result.err == nil {
					successes[result.start.SessionID] = true
				} else if !errors.Is(result.err, ErrStorageUnavailable) {
					t.Fatal(result.err)
				}
			}
			want := 2
			if live == 4 {
				want = 1
			}
			if len(successes) != want {
				t.Fatalf("unexpected successful starts: %d", len(successes))
			}
			sessions, err := first.store.readProtectedSessions(context.Background())
			if err != nil || len(sessions) != live+want {
				t.Fatalf("lost CAS state: %d %v", len(sessions), err)
			}
			for _, s := range sessions {
				delete(successes, s.SessionID)
			}
			if len(successes) != 0 {
				t.Fatal("successful addition lost")
			}
		})
	}
}
func TestAuthStatusTokenProfileMatrix(t *testing.T) {
	for _, strict := range []bool{false, true} {
		for _, tokenState := range []string{"absent", "valid", "expired", "invalid"} {
			for _, profileState := range []string{"absent", "valid", "invalid", "empty"} {
				t.Run(fmt.Sprintf("strict=%t/token=%s/profile=%s", strict, tokenState, profileState), func(t *testing.T) {
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
					if tokenState == "valid" || tokenState == "expired" {
						expiry := time.Now().Add(time.Hour)
						if tokenState == "expired" {
							expiry = time.Now().Add(-time.Hour)
						}
						if err := svc.store.writeToken(context.Background(), token{AccessToken: "private-token-sentinel", Expiry: expiry}); err != nil {
							t.Fatal(err)
						}
					}
					if tokenState == "invalid" {
						if strict {
							err = svc.store.putProtected(context.Background(), svc.store.tokenKey, []byte("{invalid"))
						} else {
							err = os.WriteFile(svc.store.tokenPath(), []byte("{invalid"), 0600)
						}
						if err != nil {
							t.Fatal(err)
						}
					}
					if profileState == "valid" {
						err = svc.store.writeProfile(context.Background(), profileFile{Subject: "subject", Email: "user@example.test"})
					} else if profileState == "empty" {
						err = os.WriteFile(svc.store.profilePath(), []byte(`{}`), 0600)
					} else if profileState == "invalid" {
						err = os.WriteFile(svc.store.profilePath(), []byte("{invalid"), 0600)
					}
					if err != nil {
						t.Fatal(err)
					}
					st, err := svc.Status(context.Background())
					if strict && tokenState == "invalid" {
						if !errors.Is(err, ErrProtectedStorageCorrupt) {
							t.Fatalf("strict corruption must fail closed: %v", err)
						}
						return
					}
					if err != nil {
						t.Fatal(err)
					}
					signed := tokenState == "valid" || tokenState == "expired"
					reconnect := tokenState == "invalid" || tokenState == "expired" || (profileState == "invalid" || profileState == "empty") || (signed && profileState == "absent") || (tokenState == "absent" && profileState != "absent")
					if st.SignedIn != signed || st.NeedsReconnect != reconnect || st.TokenPresent != (tokenState != "absent") || st.ProfilePresent != (profileState != "absent") || st.AccessTokenExpired != (tokenState == "expired") {
						t.Fatalf("incoherent status: %+v", st)
					}
					raw, _ := json.Marshal(st)
					for _, secret := range []string{"private-token-sentinel", "{invalid", svc.store.dir} {
						if strings.Contains(string(raw), secret) {
							t.Fatalf("status exposed private storage data")
						}
					}
				})
			}
		}
	}
}

func TestStrictFailedAppendPreservesOriginalRecords(t *testing.T) {
	backend := newFaultStore()
	svc, err := NewStrictService(testConfig(t), backend)
	if err != nil {
		t.Fatal(err)
	}
	old := migrationSession("expired", "expired-state")
	old.CreatedAt = time.Now().Add(-time.Hour)
	old.ExpiresAt = time.Now().Add(-time.Minute)
	raw, err := encodeProtectedSessions([]pendingSession{old})
	if err != nil {
		t.Fatal(err)
	}
	if err := backend.Put(context.Background(), svc.store.sessionsKey, raw); err != nil {
		t.Fatal(err)
	}
	backend.failPut[svc.store.sessionsKey] = errors.New("protected append failed")
	if _, err := svc.StartSignIn(context.Background()); !errors.Is(err, ErrStorageUnavailable) {
		t.Fatalf("failed CAS: %v", err)
	}
	got, err := backend.Get(context.Background(), svc.store.sessionsKey)
	if err != nil || string(got) != string(raw) {
		t.Fatal("failed append pruned original record")
	}
	assertLegacySecretsRemoved(t, svc.store)
	consumed := migrationSession("consumed", "consumed-state")
	consumed.Consumed = true
	revived := consumed
	revived.Consumed = false
	if _, err := appendPendingSession([]pendingSession{consumed}, revived, time.Now()); !errors.Is(err, ErrSessionConsumed) {
		t.Fatalf("consumed marker was cleared: %v", err)
	}
}
