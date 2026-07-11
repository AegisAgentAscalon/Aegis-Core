package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Service owns app-scoped OAuth setup operations.
type Service struct {
	cfg   AppConfig
	store *store
	mu    sync.Mutex
}

// NewService creates a service with app-scoped token storage.
func NewService(cfg AppConfig) (*Service, error) {
	cfg = NormalizeConfig(cfg)
	if err := ValidateConfig(cfg); err != nil {
		return nil, err
	}
	st, err := newStore(cfg)
	if err != nil {
		return nil, err
	}
	return &Service{cfg: cfg, store: st}, nil
}

// ValidateConfig validates the service configuration.
func (s *Service) ValidateConfig() error {
	return ValidateConfig(s.cfg)
}

// Status returns safe UI-facing auth state.
func (s *Service) Status(context.Context) (AuthStatus, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.store.status(s.cfg), nil
}

// StartSignIn creates a safe Google authorization URL and private pending
// session for an app-scoped desktop PKCE flow.
func (s *Service) StartSignIn(ctx context.Context) (SignInStartResult, error) {
	ctx = normalizeContext(ctx)
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ValidateConfig(); err != nil {
		s.store.writeLastError(err)
		return SignInStartResult{}, err
	}
	if err := checkContext(ctx); err != nil {
		s.store.writeLastError(err)
		return SignInStartResult{}, err
	}
	if err := s.store.clearSessions(); err != nil {
		s.store.writeLastError(err)
		return SignInStartResult{}, err
	}
	redirectURI, err := s.redirectURI()
	if err != nil {
		s.store.writeLastError(err)
		return SignInStartResult{}, err
	}
	verifier, err := randomB64URL(32)
	if err != nil {
		s.store.writeLastError(err)
		return SignInStartResult{}, err
	}
	state, err := randomB64URL(24)
	if err != nil {
		s.store.writeLastError(err)
		return SignInStartResult{}, err
	}
	sessionID, err := randomB64URL(18)
	if err != nil {
		s.store.writeLastError(err)
		return SignInStartResult{}, err
	}
	expiresAt := time.Now().UTC().Add(10 * time.Minute)
	if err := s.store.writeSession(pendingSession{
		SessionID:   sessionID,
		State:       state,
		Verifier:    verifier,
		RedirectURI: redirectURI,
		Scopes:      append([]string{}, s.cfg.OAuth.Scopes...),
		CreatedAt:   time.Now().UTC(),
		ExpiresAt:   expiresAt,
	}); err != nil {
		s.store.writeLastError(err)
		return SignInStartResult{}, err
	}
	parsedAuthURL, err := url.Parse(s.cfg.OAuth.Endpoints.AuthorizationURL)
	if err != nil {
		s.store.writeLastError(err)
		return SignInStartResult{}, err
	}
	authURL := *parsedAuthURL
	q := authURL.Query()
	q.Set("client_id", s.cfg.OAuth.ClientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("response_type", "code")
	q.Set("scope", strings.Join(s.cfg.OAuth.Scopes, " "))
	q.Set("access_type", "offline")
	q.Set("prompt", "consent")
	q.Set("state", state)
	q.Set("code_challenge", pkceChallenge(verifier))
	q.Set("code_challenge_method", "S256")
	authURL.RawQuery = q.Encode()
	select {
	case <-ctx.Done():
		err := ErrAuthCanceled
		s.store.writeLastError(err)
		return SignInStartResult{}, err
	default:
	}
	s.store.writeLastError(nil)
	return SignInStartResult{
		AuthorizationURL: authURL.String(),
		RedirectURI:      redirectURI,
		ExpiresAt:        expiresAt,
		SessionID:        sessionID,
		Message:          "Open authorization_url in a browser, then pass callback code and state to CompleteSignIn.",
	}, nil
}

// CompleteSignIn validates the callback state, exchanges the code with the
// private PKCE verifier, stores tokens privately, fetches safe profile data, and
// returns safe status/profile summaries.
func (s *Service) CompleteSignIn(ctx context.Context, req CompleteSignInRequest) (CompleteSignInResult, error) {
	ctx = normalizeContext(ctx)
	s.mu.Lock()
	defer s.mu.Unlock()
	req.State = strings.TrimSpace(req.State)
	req.Code = strings.TrimSpace(req.Code)
	if err := checkContext(ctx); err != nil {
		s.store.writeLastError(err)
		return CompleteSignInResult{}, err
	}
	if req.State == "" {
		return CompleteSignInResult{}, errorsWithStore(s.store, "state is required")
	}
	if req.Code == "" {
		return CompleteSignInResult{}, errorsWithStore(s.store, "authorization code is required")
	}
	sess, err := s.store.findSessionByState(req.State)
	if err != nil {
		safeErr := safeStorageError(err)
		s.store.writeLastError(safeErr)
		return CompleteSignInResult{}, safeErr
	}
	if sess.Consumed {
		err := ErrSessionConsumed
		s.store.writeLastError(err)
		return CompleteSignInResult{}, err
	}
	if time.Now().UTC().After(sess.ExpiresAt) {
		err := ErrSessionExpired
		s.store.writeLastError(err)
		return CompleteSignInResult{}, err
	}
	if err := s.store.consumeSession(sess); err != nil {
		s.store.writeLastError(err)
		return CompleteSignInResult{}, err
	}
	tok, err := s.exchangeCode(ctx, req.Code, sess)
	if err != nil {
		s.store.writeLastError(err)
		return CompleteSignInResult{}, err
	}
	profile, err := s.fetchProfile(ctx, tok.AccessToken)
	if err != nil {
		_ = os.Remove(s.store.tokenPath())
		s.store.writeLastError(err)
		return CompleteSignInResult{}, err
	}
	if err := s.store.writeToken(tok); err != nil {
		s.store.writeLastError(err)
		return CompleteSignInResult{}, err
	}
	if err := s.store.writeProfile(profileFile{
		Email:       profile.Email,
		DisplayName: profile.DisplayName,
		Subject:     profile.Subject,
		PictureURL:  profile.PictureURL,
	}); err != nil {
		s.store.writeLastError(err)
		return CompleteSignInResult{}, err
	}
	s.store.writeLastError(nil)
	status := s.store.status(s.cfg)
	return CompleteSignInResult{Status: status, Profile: profile}, nil
}

// SignOut clears the app-scoped token/profile/error store.
func (s *Service) SignOut(context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	err := s.store.clear()
	if err != nil {
		s.store.writeLastError(err)
	}
	return err
}

// Profile returns the safe stored profile summary.
func (s *Service) Profile(context.Context) (ProfileSummary, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, err := s.store.readProfile()
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return ProfileSummary{}, ErrProfileNotFound
		}
		return ProfileSummary{}, safeStorageError(err)
	}
	return ProfileSummary{Email: p.Email, DisplayName: p.DisplayName, Subject: p.Subject, PictureURL: p.PictureURL}, nil
}

func (s *Service) redirectURI() (string, error) {
	host := s.cfg.Callback.Host
	port := s.cfg.Callback.PortHint
	if port == 0 {
		ln, err := net.Listen("tcp", net.JoinHostPort(host, "0"))
		if err != nil {
			return "", err
		}
		addr := ln.Addr().(*net.TCPAddr)
		port = addr.Port
		// This reserves a candidate port only long enough to build the URL.
		// Callers still own the loopback callback listener and retry policy.
		_ = ln.Close()
	}
	if port <= 0 || port > 65535 {
		return "", fmt.Errorf("callback port is out of range")
	}
	u := url.URL{
		Scheme: "http",
		Host:   net.JoinHostPort(host, strconv.Itoa(port)),
		Path:   s.cfg.Callback.Path,
	}
	return u.String(), nil
}

func randomB64URL(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func (s *Service) exchangeCode(ctx context.Context, code string, sess pendingSession) (token, error) {
	form := url.Values{}
	form.Set("client_id", s.cfg.OAuth.ClientID)
	if s.cfg.OAuth.UseClientSecret && strings.TrimSpace(s.cfg.OAuth.ClientSecret) != "" {
		form.Set("client_secret", s.cfg.OAuth.ClientSecret)
	}
	form.Set("code", code)
	form.Set("redirect_uri", sess.RedirectURI)
	form.Set("grant_type", "authorization_code")
	form.Set("code_verifier", sess.Verifier)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.cfg.OAuth.Endpoints.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return token{}, ErrTokenExchangeFailed
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	client := &http.Client{Timeout: 20 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return token{}, classifyProviderError(ctx, err, "token exchange")
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return token{}, fmt.Errorf("%w with HTTP %d", ErrTokenExchangeFailed, resp.StatusCode)
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var parsed struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		TokenType    string `json:"token_type"`
		IDToken      string `json:"id_token"`
		ExpiresIn    int    `json:"expires_in"`
	}
	if err := json.Unmarshal(b, &parsed); err != nil {
		return token{}, ErrInvalidProviderResponse
	}
	if strings.TrimSpace(parsed.AccessToken) == "" {
		return token{}, ErrInvalidProviderResponse
	}
	if parsed.ExpiresIn <= 0 {
		parsed.ExpiresIn = 3600
	}
	return token{
		AccessToken:  parsed.AccessToken,
		RefreshToken: parsed.RefreshToken,
		TokenType:    parsed.TokenType,
		IDToken:      parsed.IDToken,
		Expiry:       time.Now().UTC().Add(time.Duration(parsed.ExpiresIn) * time.Second),
	}, nil
}

func (s *Service) fetchProfile(ctx context.Context, accessToken string) (ProfileSummary, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.cfg.OAuth.Endpoints.UserInfoURL, nil)
	if err != nil {
		return ProfileSummary{}, ErrInvalidProviderResponse
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	client := &http.Client{Timeout: 20 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return ProfileSummary{}, classifyProviderError(ctx, err, "profile fetch")
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return ProfileSummary{}, fmt.Errorf("%w with HTTP %d", errProfileFetchFailed, resp.StatusCode)
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var parsed struct {
		Email       string `json:"email"`
		DisplayName string `json:"name"`
		Subject     string `json:"id"`
		PictureURL  string `json:"picture"`
	}
	if err := json.Unmarshal(b, &parsed); err != nil {
		return ProfileSummary{}, ErrInvalidProviderResponse
	}
	if strings.TrimSpace(parsed.Subject) == "" {
		return ProfileSummary{}, ErrInvalidProviderResponse
	}
	return ProfileSummary{Email: parsed.Email, DisplayName: parsed.DisplayName, Subject: parsed.Subject, PictureURL: parsed.PictureURL}, nil
}

func errorsWithStore(st *store, msg string) error {
	err := errors.New(msg)
	st.writeLastError(err)
	return err
}

func checkContext(ctx context.Context) error {
	if ctx == nil {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return ErrAuthCanceled
	}
	return nil
}

func normalizeContext(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}

func classifyProviderError(ctx context.Context, err error, op string) error {
	if ctx != nil && ctx.Err() != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			if op == "profile fetch" {
				return fmt.Errorf("profile fetch timed out")
			}
			return fmt.Errorf("token exchange timed out")
		}
		return ErrAuthCanceled
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		if op == "profile fetch" {
			return fmt.Errorf("profile fetch timed out")
		}
		return fmt.Errorf("token exchange timed out")
	}
	return ErrProviderUnavailable
}

func safeStorageError(err error) error {
	switch {
	case errors.Is(err, ErrSessionNotFound),
		errors.Is(err, ErrSessionExpired),
		errors.Is(err, ErrSessionConsumed),
		errors.Is(err, ErrInvalidProviderResponse),
		errors.Is(err, ErrStorageUnavailable):
		return err
	default:
		var pathErr *os.PathError
		if errors.As(err, &pathErr) {
			return ErrStorageUnavailable
		}
		return err
	}
}
