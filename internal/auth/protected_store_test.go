package auth

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	devsecretstore "github.com/AegisAgentAscalon/aegis-core/internal/secretstore"
	"github.com/AegisAgentAscalon/aegis-core/pkg/secretstore"
)

func TestStrictServiceKeepsTokenAndPKCESessionOutOfPlaintextStore(t *testing.T) {
	tokenServer, userInfoServer := successOAuthServers(t)
	defer tokenServer.Close()
	defer userInfoServer.Close()

	cfg := testConfig(t)
	cfg.OAuth.Endpoints.TokenURL = tokenServer.URL
	cfg.OAuth.Endpoints.UserInfoURL = userInfoServer.URL
	protected := devsecretstore.NewMemoryStore()
	svc, err := NewStrictService(cfg, protected)
	if err != nil {
		t.Fatal(err)
	}
	start, err := svc.StartSignIn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(svc.store.sessionsDir()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("strict pending session created plaintext storage: %v", err)
	}
	sessionRecord, err := protected.Get(context.Background(), svc.store.sessionsKey)
	if err != nil {
		t.Fatal(err)
	}
	sessions, err := decodeProtectedSessions(sessionRecord)
	if err != nil || len(sessions) != 1 {
		t.Fatalf("protected sessions = %+v, %v", sessions, err)
	}
	verifier := sessions[0].Verifier

	result, err := svc.CompleteSignIn(context.Background(), CompleteSignInRequest{
		State: mustState(t, start.AuthorizationURL),
		Code:  "code",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Status.SignedIn {
		t.Fatalf("expected signed-in status: %+v", result.Status)
	}
	if _, err := os.Stat(svc.store.tokenPath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("strict token created plaintext storage: %v", err)
	}
	protectedToken, err := protected.Get(context.Background(), svc.store.tokenKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeProtectedToken(protectedToken); err != nil {
		t.Fatalf("protected token is invalid: %v", err)
	}

	var plaintext strings.Builder
	err = filepath.Walk(cfg.TokenStore.BaseDir, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil || info.IsDir() {
			return walkErr
		}
		b, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		plaintext.Write(b)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"access-secret", "refresh-secret", "id-secret", verifier} {
		if strings.Contains(plaintext.String(), forbidden) {
			t.Fatalf("plaintext auth files contain protected value %q", forbidden)
		}
	}
	statusJSON, err := json.Marshal(result.Status)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"access-secret", "refresh-secret", "id-secret", verifier, cfg.OAuth.ClientSecret} {
		if strings.Contains(string(statusJSON), forbidden) {
			t.Fatalf("strict status leaked %q in %s", forbidden, statusJSON)
		}
	}
}

func TestStrictServiceMigratesLegacySecretsAndProtectedRecordsStayAuthoritative(t *testing.T) {
	cfg := testConfig(t)
	legacy, err := NewService(cfg)
	if err != nil {
		t.Fatal(err)
	}
	wantToken := token{AccessToken: "legacy-access", RefreshToken: "legacy-refresh", Expiry: time.Now().UTC().Add(time.Hour)}
	wantSession := migrationSession("legacy-session", "legacy-state")
	if err := legacy.store.writeToken(wantToken); err != nil {
		t.Fatal(err)
	}
	if err := legacy.store.writeSession(wantSession); err != nil {
		t.Fatal(err)
	}

	protected := devsecretstore.NewMemoryStore()
	strict, err := NewStrictService(cfg, protected)
	if err != nil {
		t.Fatal(err)
	}
	assertLegacySecretsRemoved(t, strict.store)
	if got, err := strict.store.readToken(); err != nil || got.AccessToken != wantToken.AccessToken {
		t.Fatalf("migrated token = %+v, %v", got, err)
	}
	if got, err := strict.store.readSession(wantSession.SessionID); err != nil || got.Verifier != wantSession.Verifier {
		t.Fatalf("migrated session = %+v, %v", got, err)
	}

	if err := legacy.store.writeToken(token{AccessToken: "stale-legacy-access", Expiry: time.Now().UTC().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if err := legacy.store.writeSession(migrationSession("stale-session", "stale-state")); err != nil {
		t.Fatal(err)
	}
	strict, err = NewStrictService(cfg, protected)
	if err != nil {
		t.Fatal(err)
	}
	assertLegacySecretsRemoved(t, strict.store)
	if got, err := strict.store.readToken(); err != nil || got.AccessToken != wantToken.AccessToken {
		t.Fatalf("protected token lost authority: %+v, %v", got, err)
	}
	if _, err := strict.store.readSession("stale-session"); !errors.Is(err, secretstore.ErrNotFound) {
		t.Fatalf("stale legacy session became authoritative: %v", err)
	}
	if _, err := NewStrictService(cfg, protected); err != nil {
		t.Fatalf("idempotent strict construction failed: %v", err)
	}
}

func TestStrictMigrationReadBackMismatchPreservesLegacy(t *testing.T) {
	t.Run("token", func(t *testing.T) {
		cfg := testConfig(t)
		legacy, err := NewService(cfg)
		if err != nil {
			t.Fatal(err)
		}
		if err := legacy.store.writeToken(token{AccessToken: "legacy-access", Expiry: time.Now().UTC().Add(time.Hour)}); err != nil {
			t.Fatal(err)
		}
		faults := newFaultStore()
		faults.corruptPut[protectedKey(cfg, "oauth-token")] = true
		_, err = NewStrictService(cfg, faults)
		if !errors.Is(err, ErrStorageUnavailable) {
			t.Fatalf("migration error = %v, want ErrStorageUnavailable", err)
		}
		if _, statErr := os.Stat(legacy.store.tokenPath()); statErr != nil {
			t.Fatalf("legacy token removed before verified read-back: %v", statErr)
		}
	})

	t.Run("pending sessions", func(t *testing.T) {
		cfg := testConfig(t)
		legacy, err := NewService(cfg)
		if err != nil {
			t.Fatal(err)
		}
		if err := legacy.store.writeSession(migrationSession("legacy-session", "legacy-state")); err != nil {
			t.Fatal(err)
		}
		faults := newFaultStore()
		faults.corruptPut[protectedKey(cfg, "pending-sessions")] = true
		_, err = NewStrictService(cfg, faults)
		if !errors.Is(err, ErrStorageUnavailable) {
			t.Fatalf("migration error = %v, want ErrStorageUnavailable", err)
		}
		if _, statErr := os.Stat(legacy.store.sessionsDir()); statErr != nil {
			t.Fatalf("legacy sessions removed before verified read-back: %v", statErr)
		}
	})
}

func TestStrictStoreAcceptsBase64URLSessionIDPrefixes(t *testing.T) {
	for _, prefix := range []string{"-", "_"} {
		cfg := testConfig(t)
		svc, err := NewStrictService(cfg, devsecretstore.NewMemoryStore())
		if err != nil {
			t.Fatal(err)
		}
		session := migrationSession(prefix+"base64url", prefix+"state")
		if err := svc.store.writeSession(session); err != nil {
			t.Fatalf("session id %q was rejected: %v", session.SessionID, err)
		}
	}
}

func TestStrictMigrationRejectsInvalidLegacyWithoutDeletingIt(t *testing.T) {
	t.Run("token", func(t *testing.T) {
		cfg := testConfig(t)
		legacy, err := NewService(cfg)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(legacy.store.tokenPath(), []byte(`{"access_token":"legacy-secret"`), 0o600); err != nil {
			t.Fatal(err)
		}
		protected := devsecretstore.NewMemoryStore()
		_, err = NewStrictService(cfg, protected)
		if !errors.Is(err, ErrStorageUnavailable) {
			t.Fatalf("invalid legacy token error = %v, want ErrStorageUnavailable", err)
		}
		if _, statErr := os.Stat(legacy.store.tokenPath()); statErr != nil {
			t.Fatalf("invalid legacy token was deleted: %v", statErr)
		}
		if _, getErr := protected.Get(context.Background(), protectedKey(cfg, "oauth-token")); !errors.Is(getErr, secretstore.ErrNotFound) {
			t.Fatalf("invalid legacy token was migrated: %v", getErr)
		}
	})

	t.Run("pending sessions", func(t *testing.T) {
		cfg := testConfig(t)
		legacy, err := NewService(cfg)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(legacy.store.sessionsDir(), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(legacy.store.sessionPath("invalid"), []byte(`{"session_id":"invalid"`), 0o600); err != nil {
			t.Fatal(err)
		}
		protected := devsecretstore.NewMemoryStore()
		_, err = NewStrictService(cfg, protected)
		if !errors.Is(err, ErrStorageUnavailable) {
			t.Fatalf("invalid legacy session error = %v, want ErrStorageUnavailable", err)
		}
		if _, statErr := os.Stat(legacy.store.sessionsDir()); statErr != nil {
			t.Fatalf("invalid legacy sessions were deleted: %v", statErr)
		}
		if _, getErr := protected.Get(context.Background(), protectedKey(cfg, "pending-sessions")); !errors.Is(getErr, secretstore.ErrNotFound) {
			t.Fatalf("invalid legacy session was migrated: %v", getErr)
		}
	})
}

func TestStrictProtectedCorruptionIsAuthoritativeAndFailsClosed(t *testing.T) {
	cfg := testConfig(t)
	legacy, err := NewService(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := legacy.store.writeToken(token{AccessToken: "legacy-access", Expiry: time.Now().UTC().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	protected := devsecretstore.NewMemoryStore()
	if err := protected.Put(context.Background(), protectedKey(cfg, "oauth-token"), []byte(`{"access_token":"protected-secret"`)); err != nil {
		t.Fatal(err)
	}
	_, err = NewStrictService(cfg, protected)
	if !errors.Is(err, ErrProtectedStorageCorrupt) {
		t.Fatalf("strict constructor error = %v, want ErrProtectedStorageCorrupt", err)
	}
	if _, statErr := os.Stat(legacy.store.tokenPath()); statErr != nil {
		t.Fatalf("authoritative protected corruption deleted legacy record: %v", statErr)
	}
	if strings.Contains(err.Error(), "protected-secret") {
		t.Fatalf("corruption error leaked record contents: %v", err)
	}
}

func TestStrictProtectedSessionCorruptionIsAuthoritativeAndFailsClosed(t *testing.T) {
	cfg := testConfig(t)
	legacy, err := NewService(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := legacy.store.writeSession(migrationSession("legacy-session", "legacy-state")); err != nil {
		t.Fatal(err)
	}
	protected := devsecretstore.NewMemoryStore()
	if err := protected.Put(context.Background(), protectedKey(cfg, "pending-sessions"), []byte(`{"version":1,"sessions":[{"verifier":"protected-secret"}]}`)); err != nil {
		t.Fatal(err)
	}
	_, err = NewStrictService(cfg, protected)
	if !errors.Is(err, ErrProtectedStorageCorrupt) {
		t.Fatalf("strict constructor error = %v, want ErrProtectedStorageCorrupt", err)
	}
	if _, statErr := os.Stat(legacy.store.sessionsDir()); statErr != nil {
		t.Fatalf("authoritative protected corruption deleted legacy sessions: %v", statErr)
	}
	if strings.Contains(err.Error(), "protected-secret") {
		t.Fatalf("corruption error leaked record contents: %v", err)
	}
}

func TestStrictProtectedStoreFailuresAndSignOutAreRedacted(t *testing.T) {
	t.Run("constructor get", func(t *testing.T) {
		cfg := testConfig(t)
		faults := newFaultStore()
		faults.failGet[protectedKey(cfg, "oauth-token")] = errors.New("backend path C:\\secrets access-secret")
		_, err := NewStrictService(cfg, faults)
		assertSafeStorageError(t, err, ErrStorageUnavailable)
	})

	t.Run("migration put", func(t *testing.T) {
		cfg := testConfig(t)
		legacy, err := NewService(cfg)
		if err != nil {
			t.Fatal(err)
		}
		if err := legacy.store.writeToken(token{AccessToken: "legacy-access", Expiry: time.Now().UTC().Add(time.Hour)}); err != nil {
			t.Fatal(err)
		}
		faults := newFaultStore()
		faults.failPut[protectedKey(cfg, "oauth-token")] = errors.New("backend rejected refresh-secret at C:\\secrets")
		_, err = NewStrictService(cfg, faults)
		assertSafeStorageError(t, err, ErrStorageUnavailable)
		if _, statErr := os.Stat(legacy.store.tokenPath()); statErr != nil {
			t.Fatalf("failed protected put deleted legacy token: %v", statErr)
		}
	})

	t.Run("runtime status", func(t *testing.T) {
		cfg := testConfig(t)
		faults := newFaultStore()
		svc, err := NewStrictService(cfg, faults)
		if err != nil {
			t.Fatal(err)
		}
		faults.failGet[svc.store.tokenKey] = errors.New("refresh-secret backend failure")
		_, err = svc.Status(context.Background())
		assertSafeStorageError(t, err, ErrStorageUnavailable)
	})

	t.Run("sign out retry and idempotency", func(t *testing.T) {
		cfg := testConfig(t)
		faults := newFaultStore()
		svc, err := NewStrictService(cfg, faults)
		if err != nil {
			t.Fatal(err)
		}
		if err := svc.store.writeToken(token{AccessToken: "access-secret", RefreshToken: "refresh-secret", Expiry: time.Now().UTC().Add(time.Hour)}); err != nil {
			t.Fatal(err)
		}
		if err := svc.store.writeSession(migrationSession("session", "state")); err != nil {
			t.Fatal(err)
		}
		faults.failDelete[svc.store.tokenKey] = errors.New("delete failed for access-secret")
		faults.failDelete[svc.store.sessionsKey] = errors.New("delete failed for verifier-secret")
		err = svc.SignOut(context.Background())
		assertSafeStorageError(t, err, ErrSignOutIncomplete)
		if got := svc.store.readLastError(); got != ErrSignOutIncomplete.Error() {
			t.Fatalf("stored sign-out error = %q, want redacted sentinel", got)
		}
		if faults.deleteCalls[svc.store.tokenKey] != 1 || faults.deleteCalls[svc.store.sessionsKey] != 1 {
			t.Fatalf("sign out did not attempt every protected delete: %+v", faults.deleteCalls)
		}
		delete(faults.failDelete, svc.store.tokenKey)
		delete(faults.failDelete, svc.store.sessionsKey)
		if err := svc.SignOut(context.Background()); err != nil {
			t.Fatalf("sign out retry failed: %v", err)
		}
		if err := svc.SignOut(context.Background()); err != nil {
			t.Fatalf("already signed out should be idempotent: %v", err)
		}
		if _, err := faults.Get(context.Background(), svc.store.tokenKey); !errors.Is(err, secretstore.ErrNotFound) {
			t.Fatalf("token remains after sign out: %v", err)
		}
		if _, err := faults.Get(context.Background(), svc.store.sessionsKey); !errors.Is(err, secretstore.ErrNotFound) {
			t.Fatalf("pending sessions remain after sign out: %v", err)
		}
	})
}

func migrationSession(id, state string) pendingSession {
	now := time.Now().UTC()
	return pendingSession{
		SessionID:   id,
		State:       state,
		Verifier:    "verifier-secret",
		RedirectURI: "http://127.0.0.1:56789/oauth/callback",
		Scopes:      []string{"openid", "email", "profile"},
		CreatedAt:   now,
		ExpiresAt:   now.Add(10 * time.Minute),
	}
}

func assertLegacySecretsRemoved(t *testing.T, store *store) {
	t.Helper()
	if _, err := os.Stat(store.tokenPath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("legacy token still exists: %v", err)
	}
	if _, err := os.Stat(store.sessionsDir()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("legacy pending sessions still exist: %v", err)
	}
}

func assertSafeStorageError(t *testing.T, err, want error) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("error = %v, want %v", err, want)
	}
	for _, forbidden := range []string{"access-secret", "refresh-secret", "verifier-secret", "C:\\secrets", "backend"} {
		if strings.Contains(err.Error(), forbidden) {
			t.Fatalf("error leaked %q in %q", forbidden, err)
		}
	}
}

type faultStore struct {
	delegate    secretstore.Store
	failGet     map[secretstore.Key]error
	failPut     map[secretstore.Key]error
	failDelete  map[secretstore.Key]error
	corruptPut  map[secretstore.Key]bool
	deleteCalls map[secretstore.Key]int
}

func newFaultStore() *faultStore {
	return &faultStore{
		delegate:    devsecretstore.NewMemoryStore(),
		failGet:     make(map[secretstore.Key]error),
		failPut:     make(map[secretstore.Key]error),
		failDelete:  make(map[secretstore.Key]error),
		corruptPut:  make(map[secretstore.Key]bool),
		deleteCalls: make(map[secretstore.Key]int),
	}
}

func (s *faultStore) Get(ctx context.Context, key secretstore.Key) ([]byte, error) {
	if err := s.failGet[key]; err != nil {
		return nil, err
	}
	return s.delegate.Get(ctx, key)
}

func (s *faultStore) Put(ctx context.Context, key secretstore.Key, value []byte) error {
	if err := s.failPut[key]; err != nil {
		return err
	}
	if s.corruptPut[key] {
		value = append(append([]byte(nil), value...), byte('x'))
	}
	return s.delegate.Put(ctx, key, value)
}

func (s *faultStore) Delete(ctx context.Context, key secretstore.Key) error {
	s.deleteCalls[key]++
	if err := s.failDelete[key]; err != nil {
		return err
	}
	return s.delegate.Delete(ctx, key)
}
