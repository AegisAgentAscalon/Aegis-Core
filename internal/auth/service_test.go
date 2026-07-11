package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func testConfig(t *testing.T) AppConfig {
	t.Helper()
	base := t.TempDir()
	return AppConfig{
		AppID:       "sample-app",
		DisplayName: "Sample App",
		ConfigPath:  filepath.Join(base, "oauth.json"),
		OAuth: OAuthClientConfig{
			ClientID:     "sample-client.apps.googleusercontent.com",
			ClientSecret: "do-not-leak",
			Scopes:       []string{"openid", "email", "profile", "email"},
		},
		TokenStore: TokenStoreConfig{BaseDir: base, Namespace: "sample-user"},
		Callback:   CallbackConfig{Host: "127.0.0.1", Path: "/oauth/callback", PortHint: 56789},
	}
}

func TestValidateConfigRequiresAppScopedIdentity(t *testing.T) {
	cfg := testConfig(t)
	cfg.AppID = ""
	if err := ValidateConfig(cfg); err == nil || !strings.Contains(err.Error(), "app id") {
		t.Fatalf("expected app id error, got %v", err)
	}

	cfg = testConfig(t)
	cfg.ConfigPath = ""
	if err := ValidateConfig(cfg); err == nil || !strings.Contains(err.Error(), "config path") {
		t.Fatalf("expected config path error, got %v", err)
	}

	cfg = testConfig(t)
	cfg.OAuth.ClientID = "invalid"
	if err := ValidateConfig(cfg); err == nil || !strings.Contains(err.Error(), "google OAuth client id") {
		t.Fatalf("expected client id shape error, got %v", err)
	}

	cfg = testConfig(t)
	cfg.Callback.Host = "example.com"
	if err := ValidateConfig(cfg); err == nil || !strings.Contains(err.Error(), "loopback") {
		t.Fatalf("expected loopback callback host error, got %v", err)
	}
}

func TestStartAndCompleteSignInAcceptNilContext(t *testing.T) {
	tokenServer, userInfoServer := successOAuthServers(t)
	defer tokenServer.Close()
	defer userInfoServer.Close()
	cfg := testConfig(t)
	cfg.OAuth.Endpoints.TokenURL = tokenServer.URL
	cfg.OAuth.Endpoints.UserInfoURL = userInfoServer.URL
	svc, err := NewService(cfg)
	if err != nil {
		t.Fatal(err)
	}
	start, err := svc.StartSignIn(nil)
	if err != nil {
		t.Fatalf("StartSignIn(nil) returned error: %v", err)
	}
	result, err := svc.CompleteSignIn(nil, CompleteSignInRequest{State: mustState(t, start.AuthorizationURL), Code: "code"})
	if err != nil || !result.Status.SignedIn {
		t.Fatalf("CompleteSignIn(nil) = %+v, %v", result, err)
	}
}

func TestAuthStoreRepairsPrivateDirectoryPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits are not authoritative on Windows")
	}
	cfg := testConfig(t)
	dir := namespacedStoreDir(cfg.TokenStore.BaseDir, cfg.AppID, cfg.TokenStore.Namespace)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	svc, err := NewService(cfg)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o700 {
		t.Fatalf("auth store permissions = %o, want 700", got)
	}
	if _, err := svc.StartSignIn(context.Background()); err != nil {
		t.Fatal(err)
	}
	sessionInfo, err := os.Stat(svc.store.sessionsDir())
	if err != nil {
		t.Fatal(err)
	}
	if got := sessionInfo.Mode().Perm(); got != 0o700 {
		t.Fatalf("pending session permissions = %o, want 700", got)
	}
}

func TestValidateConfigRejectsUnsafeAppIDAndNamespace(t *testing.T) {
	cases := []struct {
		name      string
		appID     string
		namespace string
	}{
		{name: "app traversal", appID: "../bad", namespace: "safe"},
		{name: "app slash", appID: "bad/app", namespace: "safe"},
		{name: "namespace traversal", appID: "safe-app", namespace: "..\\bad"},
		{name: "namespace slash", appID: "safe-app", namespace: "bad/ns"},
		{name: "reserved", appID: "safe-app", namespace: "CON"},
		{name: "too long", appID: "safe-app", namespace: strings.Repeat("a", 129)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := testConfig(t)
			cfg.AppID = tc.appID
			cfg.TokenStore.Namespace = tc.namespace
			if err := ValidateConfig(cfg); err == nil {
				t.Fatalf("expected validation error")
			}
		})
	}

	cfg := testConfig(t)
	cfg.AppID = "Aegis.Sample_01"
	cfg.TokenStore.Namespace = "User-01.profile"
	if err := ValidateConfig(cfg); err != nil {
		t.Fatalf("expected valid safe names, got %v", err)
	}
}

func TestNewServiceUsesNamespacedStore(t *testing.T) {
	cfgA := testConfig(t)
	cfgB := cfgA
	cfgB.TokenStore.Namespace = "other-user"

	svcA, err := NewService(cfgA)
	if err != nil {
		t.Fatal(err)
	}
	svcB, err := NewService(cfgB)
	if err != nil {
		t.Fatal(err)
	}

	if svcA.store.dir == svcB.store.dir {
		t.Fatalf("expected separate namespace directories")
	}
	if !strings.HasSuffix(filepath.ToSlash(svcA.store.dir), "sample-app/sample-user") {
		t.Fatalf("unexpected namespace dir: %s", svcA.store.dir)
	}
}

func TestStatusRedactsTokensAndSecrets(t *testing.T) {
	cfg := testConfig(t)
	svc, err := NewService(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.store.writeToken(token{
		AccessToken:  "access-secret",
		RefreshToken: "refresh-secret",
		TokenType:    "Bearer",
		Expiry:       time.Now().Add(time.Hour),
		IDToken:      "id-secret",
	}); err != nil {
		t.Fatal(err)
	}
	if err := svc.store.writeProfile(profileFile{Email: "person@example.com", DisplayName: "Person", Subject: "subject-1"}); err != nil {
		t.Fatal(err)
	}

	status, err := svc.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !status.SignedIn || !status.TokenPresent || !status.ProfilePresent {
		t.Fatalf("expected signed-in status, got %+v", status)
	}
	if status.Profile.Email != "person@example.com" {
		t.Fatalf("expected safe profile email, got %+v", status.Profile)
	}
	raw, err := json.Marshal(status)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"access-secret", "refresh-secret", "id-secret", "do-not-leak", "token_path"} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatalf("status leaked %q in %s", forbidden, string(raw))
		}
	}
}

func TestStatusHandlesCorruptTokenAndProfileSafely(t *testing.T) {
	svc, err := NewService(testConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(svc.store.tokenPath(), []byte(`{bad-token-json`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(svc.store.profilePath(), []byte(`{bad-profile-json`), 0o600); err != nil {
		t.Fatal(err)
	}
	status, err := svc.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if status.SignedIn {
		t.Fatalf("corrupt token should not report signed in")
	}
	if !status.NeedsReconnect {
		t.Fatalf("corrupt storage should request reconnect: %+v", status)
	}
	for _, forbidden := range []string{svc.store.dir, "google_token.json", "google_profile.json", "{bad"} {
		if strings.Contains(status.LastError, forbidden) {
			t.Fatalf("status leaked storage detail %q in %q", forbidden, status.LastError)
		}
	}
}

func TestProfileReturnsActionableMissingProfileError(t *testing.T) {
	svc, err := NewService(testConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	_, err = svc.Profile(context.Background())
	if err == nil {
		t.Fatalf("expected missing profile error")
	}
	if !strings.Contains(err.Error(), "profile is not available") {
		t.Fatalf("expected safe missing profile error, got %v", err)
	}
	for _, forbidden := range []string{svc.store.dir, "google_profile.json"} {
		if strings.Contains(err.Error(), forbidden) {
			t.Fatalf("missing profile error leaked path detail %q in %q", forbidden, err.Error())
		}
	}
}

func TestStartSignInReturnsSafeURLShape(t *testing.T) {
	cfg := testConfig(t)
	cfg.OAuth.UseClientSecret = true
	svc, err := NewService(cfg)
	if err != nil {
		t.Fatal(err)
	}
	result, err := svc.StartSignIn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(result.AuthorizationURL)
	if err != nil {
		t.Fatal(err)
	}
	q := parsed.Query()
	if parsed.Host != "accounts.google.com" {
		t.Fatalf("unexpected auth host: %s", parsed.Host)
	}
	if q.Get("client_id") != cfg.OAuth.ClientID {
		t.Fatalf("missing client id in auth URL")
	}
	if q.Get("redirect_uri") != "http://127.0.0.1:56789/oauth/callback" {
		t.Fatalf("unexpected redirect uri: %s", q.Get("redirect_uri"))
	}
	if q.Get("code_challenge") == "" || q.Get("code_challenge_method") != "S256" {
		t.Fatalf("missing PKCE challenge parameters")
	}
	if result.SessionID == "" {
		t.Fatalf("expected opaque session id")
	}
	if _, err := svc.store.readSession(result.SessionID); err != nil {
		t.Fatalf("expected pending private session: %v", err)
	}
	if strings.Contains(result.AuthorizationURL, cfg.OAuth.ClientSecret) || strings.Contains(result.AuthorizationURL, "code_verifier") {
		t.Fatalf("auth URL leaked private client secret or verifier: %s", result.AuthorizationURL)
	}
}

func TestStartSignInClearsPreviousPendingSessions(t *testing.T) {
	tokenServer, userInfoServer := successOAuthServers(t)
	cfg := testConfig(t)
	cfg.OAuth.Endpoints.TokenURL = tokenServer.URL
	cfg.OAuth.Endpoints.UserInfoURL = userInfoServer.URL
	svc, err := NewService(cfg)
	if err != nil {
		t.Fatal(err)
	}
	first, err := svc.StartSignIn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	firstState := mustState(t, first.AuthorizationURL)
	second, err := svc.StartSignIn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	secondState := mustState(t, second.AuthorizationURL)
	if first.SessionID == second.SessionID || firstState == secondState {
		t.Fatalf("expected new session/state")
	}
	if _, err := svc.CompleteSignIn(context.Background(), CompleteSignInRequest{State: firstState, Code: "old-code"}); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("expected old state to fail as not found, got %v", err)
	}
	if _, err := svc.CompleteSignIn(context.Background(), CompleteSignInRequest{State: secondState, Code: "new-code"}); err != nil {
		t.Fatalf("expected latest state to complete, got %v", err)
	}
}

func TestCompleteSignInRejectsMissingInputsAndStateProblems(t *testing.T) {
	svc, err := NewService(testConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CompleteSignIn(context.Background(), CompleteSignInRequest{}); err == nil || !strings.Contains(err.Error(), "state") {
		t.Fatalf("expected missing state error, got %v", err)
	}
	if _, err := svc.CompleteSignIn(context.Background(), CompleteSignInRequest{State: "state"}); err == nil || !strings.Contains(err.Error(), "authorization code") {
		t.Fatalf("expected missing code error, got %v", err)
	}
	if _, err := svc.CompleteSignIn(context.Background(), CompleteSignInRequest{State: "wrong", Code: "code"}); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("expected state mismatch/not found error, got %v", err)
	}
}

func TestCompleteSignInRejectsExpiredAndConsumedSessions(t *testing.T) {
	svc, err := NewService(testConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	expired := pendingSession{SessionID: "expired", State: "expired-state", Verifier: "verifier", RedirectURI: "http://127.0.0.1:56789/oauth/callback", CreatedAt: time.Now().Add(-20 * time.Minute), ExpiresAt: time.Now().Add(-10 * time.Minute)}
	if err := svc.store.writeSession(expired); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CompleteSignIn(context.Background(), CompleteSignInRequest{State: expired.State, Code: "code"}); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expected expired session error, got %v", err)
	}

	consumed := pendingSession{SessionID: "consumed", State: "consumed-state", Verifier: "verifier", RedirectURI: "http://127.0.0.1:56789/oauth/callback", CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Minute), Consumed: true}
	if err := svc.store.writeSession(consumed); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CompleteSignIn(context.Background(), CompleteSignInRequest{State: consumed.State, Code: "code"}); err == nil || !strings.Contains(err.Error(), "consumed") {
		t.Fatalf("expected consumed session error, got %v", err)
	}
}

func TestCompleteSignInRejectsCorruptPendingSessionSafely(t *testing.T) {
	svc, err := NewService(testConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(svc.store.sessionsDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(svc.store.sessionsDir(), "bad.json"), []byte(`{bad-session-json`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = svc.CompleteSignIn(context.Background(), CompleteSignInRequest{State: "any", Code: "code"})
	if !errors.Is(err, ErrInvalidProviderResponse) {
		t.Fatalf("expected invalid stored session response, got %v", err)
	}
	status, statusErr := svc.Status(context.Background())
	if statusErr != nil {
		t.Fatal(statusErr)
	}
	for _, forbidden := range []string{svc.store.dir, "bad.json", "{bad-session-json"} {
		if strings.Contains(err.Error(), forbidden) || strings.Contains(status.LastError, forbidden) {
			t.Fatalf("corrupt session leaked %q in err=%q status=%q", forbidden, err.Error(), status.LastError)
		}
	}
}

func TestCompleteSignInRejectsTooManyPendingSessions(t *testing.T) {
	svc, err := NewService(testConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < maxPendingSessionFiles+1; i++ {
		sess := pendingSession{
			SessionID:   "session-" + strconv.Itoa(i),
			State:       "state-" + strconv.Itoa(i),
			Verifier:    "verifier",
			RedirectURI: "http://127.0.0.1:56789/oauth/callback",
			CreatedAt:   time.Now().UTC(),
			ExpiresAt:   time.Now().UTC().Add(time.Minute),
		}
		if err := svc.store.writeSession(sess); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := svc.CompleteSignIn(context.Background(), CompleteSignInRequest{State: "missing-state", Code: "code"}); !errors.Is(err, ErrStorageUnavailable) {
		t.Fatalf("expected too many sessions to fail closed, got %v", err)
	}
	status, statusErr := svc.Status(context.Background())
	if statusErr != nil {
		t.Fatal(statusErr)
	}
	if status.LastError != ErrStorageUnavailable.Error() {
		t.Fatalf("LastError = %q, want %q", status.LastError, ErrStorageUnavailable.Error())
	}
}

func TestCompleteSignInUsesVerifierStoresTokenAndReturnsSafeProfile(t *testing.T) {
	var tokenForm string
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		tokenForm = r.Form.Encode()
		if r.Form.Get("code") != "auth-code" {
			t.Fatalf("unexpected code: %s", r.Form.Get("code"))
		}
		if r.Form.Get("code_verifier") == "" {
			t.Fatalf("missing private verifier")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"access-secret","refresh_token":"refresh-secret","token_type":"Bearer","expires_in":3600,"id_token":"id-secret"}`))
	}))
	defer tokenServer.Close()

	var authHeader string
	userInfoServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"subject-1","email":"person@example.com","name":"Person","picture":"https://example.test/avatar.png"}`))
	}))
	defer userInfoServer.Close()

	cfg := testConfig(t)
	cfg.OAuth.Endpoints.TokenURL = tokenServer.URL
	cfg.OAuth.Endpoints.UserInfoURL = userInfoServer.URL
	svc, err := NewService(cfg)
	if err != nil {
		t.Fatal(err)
	}
	start, err := svc.StartSignIn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	parsed, _ := url.Parse(start.AuthorizationURL)
	state := parsed.Query().Get("state")
	result, err := svc.CompleteSignIn(context.Background(), CompleteSignInRequest{State: state, Code: "auth-code"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(tokenForm, "code_verifier=") {
		t.Fatalf("token exchange did not include verifier form: %s", tokenForm)
	}
	if authHeader != "Bearer access-secret" {
		t.Fatalf("userinfo did not use stored access token, got %q", authHeader)
	}
	if !result.Status.SignedIn || result.Profile.Email != "person@example.com" || result.Profile.PictureURL == "" {
		t.Fatalf("unexpected complete result: %+v", result)
	}
	raw, _ := json.Marshal(result)
	for _, forbidden := range []string{"access-secret", "refresh-secret", "id-secret", "code_verifier", cfg.OAuth.ClientSecret} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatalf("complete result leaked %q in %s", forbidden, string(raw))
		}
	}
	if _, err := svc.CompleteSignIn(context.Background(), CompleteSignInRequest{State: state, Code: "auth-code"}); err == nil || !strings.Contains(err.Error(), "consumed") {
		t.Fatalf("expected replay to be rejected, got %v", err)
	}
}

func TestCompleteSignInAfterSignOutOrSessionCleanupFailsSafely(t *testing.T) {
	svc, err := NewService(testConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	start, err := svc.StartSignIn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	state := mustState(t, start.AuthorizationURL)
	if err := svc.SignOut(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CompleteSignIn(context.Background(), CompleteSignInRequest{State: state, Code: "code"}); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("expected callback after signout to fail safely, got %v", err)
	}

	start, err = svc.StartSignIn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	state = mustState(t, start.AuthorizationURL)
	if err := svc.store.clearSessions(); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CompleteSignIn(context.Background(), CompleteSignInRequest{State: state, Code: "code"}); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("expected callback after cleanup to fail safely, got %v", err)
	}
}

func TestCompleteSignInTokenExchangeFailureIsActionable(t *testing.T) {
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "bad code access-secret refresh-secret code_verifier do-not-leak", http.StatusBadRequest)
	}))
	defer tokenServer.Close()
	cfg := testConfig(t)
	cfg.OAuth.Endpoints.TokenURL = tokenServer.URL
	cfg.OAuth.Endpoints.UserInfoURL = tokenServer.URL
	svc, err := NewService(cfg)
	if err != nil {
		t.Fatal(err)
	}
	start, err := svc.StartSignIn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	parsed, _ := url.Parse(start.AuthorizationURL)
	_, err = svc.CompleteSignIn(context.Background(), CompleteSignInRequest{State: parsed.Query().Get("state"), Code: "bad"})
	if err == nil || !strings.Contains(err.Error(), "token exchange failed with HTTP 400") {
		t.Fatalf("expected actionable token exchange error, got %v", err)
	}
	status, statusErr := svc.Status(context.Background())
	if statusErr != nil {
		t.Fatal(statusErr)
	}
	if status.LastError != ErrTokenExchangeFailed.Error() || strings.Contains(status.LastError, "HTTP") {
		t.Fatalf("status LastError should use safe sentinel text, got %q", status.LastError)
	}
	for _, forbidden := range []string{"access-secret", "refresh-secret", "code_verifier", "do-not-leak", "bad code"} {
		if strings.Contains(err.Error(), forbidden) || strings.Contains(status.LastError, forbidden) {
			t.Fatalf("provider error leaked %q in err=%q status=%q", forbidden, err.Error(), status.LastError)
		}
	}
}

func TestCompleteSignInProfileHTTPFailureStoresSafeLastError(t *testing.T) {
	tokenServer, userInfoServer := successOAuthServers(t)
	defer tokenServer.Close()
	userInfoServer.Close()
	failingUserInfo := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "profile access_token refresh_token secret", http.StatusServiceUnavailable)
	}))
	defer failingUserInfo.Close()
	cfg := testConfig(t)
	cfg.OAuth.Endpoints.TokenURL = tokenServer.URL
	cfg.OAuth.Endpoints.UserInfoURL = failingUserInfo.URL
	svc, err := NewService(cfg)
	if err != nil {
		t.Fatal(err)
	}
	start, err := svc.StartSignIn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	_, err = svc.CompleteSignIn(context.Background(), CompleteSignInRequest{State: mustState(t, start.AuthorizationURL), Code: "code"})
	if err == nil || !errors.Is(err, errProfileFetchFailed) {
		t.Fatalf("expected profile fetch failure, got %v", err)
	}
	status, statusErr := svc.Status(context.Background())
	if statusErr != nil {
		t.Fatal(statusErr)
	}
	if status.LastError != errProfileFetchFailed.Error() {
		t.Fatalf("LastError = %q, want %q", status.LastError, errProfileFetchFailed.Error())
	}
	for _, forbidden := range []string{"HTTP 503", "access_token", "refresh_token", "secret"} {
		if strings.Contains(status.LastError, forbidden) {
			t.Fatalf("profile failure LastError leaked %q in %q", forbidden, status.LastError)
		}
	}
}

func TestProviderTimeoutCancelUnavailableAndMalformedResponses(t *testing.T) {
	t.Run("token timeout", func(t *testing.T) {
		slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(200 * time.Millisecond)
		}))
		defer slow.Close()
		cfg := testConfig(t)
		cfg.OAuth.Endpoints.TokenURL = slow.URL
		cfg.OAuth.Endpoints.UserInfoURL = slow.URL
		svc, err := NewService(cfg)
		if err != nil {
			t.Fatal(err)
		}
		start, _ := svc.StartSignIn(context.Background())
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		defer cancel()
		_, err = svc.CompleteSignIn(ctx, CompleteSignInRequest{State: mustState(t, start.AuthorizationURL), Code: "code"})
		if err == nil || !strings.Contains(err.Error(), "timed out") {
			t.Fatalf("expected timeout error, got %v", err)
		}
	})

	t.Run("canceled context", func(t *testing.T) {
		svc, err := NewService(testConfig(t))
		if err != nil {
			t.Fatal(err)
		}
		start, _ := svc.StartSignIn(context.Background())
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := svc.CompleteSignIn(ctx, CompleteSignInRequest{State: mustState(t, start.AuthorizationURL), Code: "code"}); !errors.Is(err, ErrAuthCanceled) {
			t.Fatalf("expected auth canceled, got %v", err)
		}
	})

	t.Run("provider unavailable", func(t *testing.T) {
		cfg := testConfig(t)
		cfg.OAuth.Endpoints.TokenURL = "http://127.0.0.1:1/token"
		svc, err := NewService(cfg)
		if err != nil {
			t.Fatal(err)
		}
		start, _ := svc.StartSignIn(context.Background())
		if _, err := svc.CompleteSignIn(context.Background(), CompleteSignInRequest{State: mustState(t, start.AuthorizationURL), Code: "code"}); !errors.Is(err, ErrProviderUnavailable) {
			t.Fatalf("expected provider unavailable, got %v", err)
		}
	})

	t.Run("malformed token json", func(t *testing.T) {
		tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{bad-token-json`))
		}))
		defer tokenServer.Close()
		cfg := testConfig(t)
		cfg.OAuth.Endpoints.TokenURL = tokenServer.URL
		svc, err := NewService(cfg)
		if err != nil {
			t.Fatal(err)
		}
		start, _ := svc.StartSignIn(context.Background())
		if _, err := svc.CompleteSignIn(context.Background(), CompleteSignInRequest{State: mustState(t, start.AuthorizationURL), Code: "code"}); !errors.Is(err, ErrInvalidProviderResponse) {
			t.Fatalf("expected invalid token response, got %v", err)
		}
	})

	t.Run("missing access token", func(t *testing.T) {
		tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{"expires_in":3600}`))
		}))
		defer tokenServer.Close()
		cfg := testConfig(t)
		cfg.OAuth.Endpoints.TokenURL = tokenServer.URL
		svc, err := NewService(cfg)
		if err != nil {
			t.Fatal(err)
		}
		start, _ := svc.StartSignIn(context.Background())
		if _, err := svc.CompleteSignIn(context.Background(), CompleteSignInRequest{State: mustState(t, start.AuthorizationURL), Code: "code"}); !errors.Is(err, ErrInvalidProviderResponse) {
			t.Fatalf("expected invalid missing token response, got %v", err)
		}
	})

	t.Run("malformed userinfo", func(t *testing.T) {
		tokenServer, userInfoServer := successOAuthServers(t)
		defer tokenServer.Close()
		userInfoServer.Close()
		badUserInfo := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{bad-userinfo-json`))
		}))
		defer badUserInfo.Close()
		cfg := testConfig(t)
		cfg.OAuth.Endpoints.TokenURL = tokenServer.URL
		cfg.OAuth.Endpoints.UserInfoURL = badUserInfo.URL
		svc, err := NewService(cfg)
		if err != nil {
			t.Fatal(err)
		}
		start, _ := svc.StartSignIn(context.Background())
		if _, err := svc.CompleteSignIn(context.Background(), CompleteSignInRequest{State: mustState(t, start.AuthorizationURL), Code: "code"}); !errors.Is(err, ErrInvalidProviderResponse) {
			t.Fatalf("expected invalid userinfo response, got %v", err)
		}
	})
}

func TestUserInfoMissingSubjectFailsButOptionalFieldsMayBeEmpty(t *testing.T) {
	tokenServer, userInfoServer := successOAuthServers(t)
	defer tokenServer.Close()
	userInfoServer.Close()

	noSubject := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"email":"person@example.com"}`))
	}))
	defer noSubject.Close()

	cfg := testConfig(t)
	cfg.OAuth.Endpoints.TokenURL = tokenServer.URL
	cfg.OAuth.Endpoints.UserInfoURL = noSubject.URL
	svc, err := NewService(cfg)
	if err != nil {
		t.Fatal(err)
	}
	start, _ := svc.StartSignIn(context.Background())
	if _, err := svc.CompleteSignIn(context.Background(), CompleteSignInRequest{State: mustState(t, start.AuthorizationURL), Code: "code"}); !errors.Is(err, ErrInvalidProviderResponse) {
		t.Fatalf("expected missing subject to fail, got %v", err)
	}
	if _, err := svc.store.readToken(); err == nil {
		t.Fatalf("token should not remain after profile fetch failure")
	}

	optionalEmpty := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"id":"subject-only"}`))
	}))
	defer optionalEmpty.Close()
	cfg = testConfig(t)
	cfg.OAuth.Endpoints.TokenURL = tokenServer.URL
	cfg.OAuth.Endpoints.UserInfoURL = optionalEmpty.URL
	svc, err = NewService(cfg)
	if err != nil {
		t.Fatal(err)
	}
	start, _ = svc.StartSignIn(context.Background())
	result, err := svc.CompleteSignIn(context.Background(), CompleteSignInRequest{State: mustState(t, start.AuthorizationURL), Code: "code"})
	if err != nil {
		t.Fatal(err)
	}
	if result.Profile.Subject != "subject-only" || result.Profile.Email != "" || result.Profile.DisplayName != "" || result.Profile.PictureURL != "" {
		t.Fatalf("unexpected optional-empty profile: %+v", result.Profile)
	}
}

func TestSignOutClearsOnlyCurrentNamespace(t *testing.T) {
	cfgA := testConfig(t)
	cfgB := cfgA
	cfgB.TokenStore.Namespace = "other-user"
	svcA, err := NewService(cfgA)
	if err != nil {
		t.Fatal(err)
	}
	svcB, err := NewService(cfgB)
	if err != nil {
		t.Fatal(err)
	}
	if err := svcA.store.writeToken(token{AccessToken: "a", Expiry: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if err := svcB.store.writeToken(token{AccessToken: "b", Expiry: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if err := svcA.SignOut(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := svcA.store.readToken(); err == nil {
		t.Fatalf("expected namespace A token cleared")
	}
	if _, err := svcB.store.readToken(); err != nil {
		t.Fatalf("expected namespace B token preserved: %v", err)
	}
}

func TestSignOutAlreadySignedOutIsSafe(t *testing.T) {
	svc, err := NewService(testConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.SignOut(context.Background()); err != nil {
		t.Fatalf("already signed out should be safe, got %v", err)
	}
	status, err := svc.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if status.SignedIn {
		t.Fatalf("expected signed out status")
	}
}

func TestConcurrentStartSignInDoesNotCorruptSessions(t *testing.T) {
	svc, err := NewService(testConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	errs := make(chan error, 6)
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := svc.StartSignIn(context.Background())
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent StartSignIn failed: %v", err)
		}
	}
	files, err := os.ReadDir(svc.store.sessionsDir())
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 {
		t.Fatalf("expected only latest pending session to remain, got %d", len(files))
	}
}

func successOAuthServers(t *testing.T) (*httptest.Server, *httptest.Server) {
	t.Helper()
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		if r.Form.Get("code_verifier") == "" {
			t.Fatal("missing code verifier")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"access-secret","refresh_token":"refresh-secret","token_type":"Bearer","expires_in":3600,"id_token":"id-secret"}`))
	}))
	userInfoServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"subject-1","email":"person@example.com","name":"Person","picture":"https://example.test/avatar.png"}`))
	}))
	return tokenServer, userInfoServer
}

func mustState(t *testing.T, authorizationURL string) string {
	t.Helper()
	parsed, err := url.Parse(authorizationURL)
	if err != nil {
		t.Fatal(err)
	}
	state := parsed.Query().Get("state")
	if state == "" {
		t.Fatal("missing state")
	}
	return state
}
