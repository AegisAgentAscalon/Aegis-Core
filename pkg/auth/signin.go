package auth

import (
	"context"
	"net/url"
	"strings"
	"time"
)

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
	if !s.store.isStrict() {
		if err := s.store.clearSessions(); err != nil {
			s.store.writeLastError(err)
			return SignInStartResult{}, err
		}
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
	sess, err := s.store.consumeSessionByState(req.State, time.Now().UTC())
	if err != nil {
		safeErr := safeStorageError(err)
		s.store.writeLastError(safeErr)
		return CompleteSignInResult{}, safeErr
	}
	tok, err := s.exchangeCode(ctx, req.Code, sess)
	if err != nil {
		s.store.writeLastError(err)
		return CompleteSignInResult{}, err
	}
	profile, err := s.fetchProfile(ctx, tok.AccessToken)
	if err != nil {
		if cleanupErr := s.store.deleteToken(); cleanupErr != nil && s.store.isStrict() {
			s.store.writeLastError(cleanupErr)
			return CompleteSignInResult{}, cleanupErr
		}
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
	status, err := s.store.status(s.cfg)
	if err != nil {
		s.store.writeLastError(err)
		return CompleteSignInResult{}, err
	}
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
