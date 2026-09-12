package auth

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"time"
)

// StartSignIn creates a safe Google authorization URL and private pending
// session for an app-scoped desktop PKCE flow.
func (s *Service) StartSignIn(ctx context.Context) (SignInStartResult, error) {
	op := s.beginOperation(ctx)
	defer op.finish()
	ctx = op.ctx
	if err := op.reserveStore(); err != nil {
		return SignInStartResult{}, err
	}
	defer s.releaseStore()
	if err := s.ValidateConfig(); err != nil {
		op.recordError(err)
		return SignInStartResult{}, err
	}
	if err := checkContext(ctx); err != nil {
		op.recordError(err)
		return SignInStartResult{}, err
	}
	if !s.store.isStrict() {
		if err := s.store.clearSessions(ctx); err != nil {
			op.recordError(err)
			return SignInStartResult{}, err
		}
	}
	redirectURI, err := s.redirectURI()
	if err != nil {
		op.recordError(err)
		return SignInStartResult{}, err
	}
	verifier, err := randomB64URL(32)
	if err != nil {
		op.recordError(err)
		return SignInStartResult{}, err
	}
	state, err := randomB64URL(24)
	if err != nil {
		op.recordError(err)
		return SignInStartResult{}, err
	}
	sessionID, err := randomB64URL(18)
	if err != nil {
		op.recordError(err)
		return SignInStartResult{}, err
	}
	expiresAt := time.Now().UTC().Add(10 * time.Minute)
	if err := s.store.writeSession(ctx, pendingSession{
		SessionID:   sessionID,
		State:       state,
		Verifier:    verifier,
		RedirectURI: redirectURI,
		Scopes:      append([]string{}, s.cfg.OAuth.Scopes...),
		CreatedAt:   time.Now().UTC(),
		ExpiresAt:   expiresAt,
	}); err != nil {
		op.recordError(err)
		return SignInStartResult{}, err
	}
	parsedAuthURL, err := url.Parse(s.cfg.OAuth.Endpoints.AuthorizationURL)
	if err != nil {
		op.recordError(err)
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
		op.recordError(err)
		return SignInStartResult{}, err
	default:
	}
	op.recordError(nil)
	return SignInStartResult{
		AuthorizationURL: authURL.String(),
		RedirectURI:      redirectURI,
		ExpiresAt:        expiresAt,
		SessionID:        sessionID,
		Message:          "Open authorization_url in a browser, then pass callback code and state to CompleteSignIn.",
	}, nil
}

// CompleteSignIn claims a session, performs cancellable HTTP outside the owner
// reservation, then commits only if its operation is still current.
func (s *Service) CompleteSignIn(ctx context.Context, req CompleteSignInRequest) (CompleteSignInResult, error) {
	op := s.beginOperation(ctx)
	defer op.finish()
	ctx = op.ctx
	fail := func(err error) (CompleteSignInResult, error) { op.recordError(err); return CompleteSignInResult{}, err }
	req.State, req.Code = strings.TrimSpace(req.State), strings.TrimSpace(req.Code)
	if err := op.check(); err != nil {
		return fail(err)
	}
	if req.State == "" {
		return fail(errors.New("state is required"))
	}
	if req.Code == "" {
		return fail(errors.New("authorization code is required"))
	}
	if err := op.reserveStore(); err != nil {
		return CompleteSignInResult{}, err
	}
	sess, err := func() (pendingSession, error) {
		defer s.releaseStore()
		sess, err := s.store.consumeSessionByState(ctx, req.State, time.Now().UTC())
		if err == nil {
			err = op.captureTokenRevision()
		}
		return sess, err
	}()
	if err = op.resultError(safeStorageError(err)); err != nil {
		return fail(err)
	}
	tok, err := s.exchangeCode(ctx, req.Code, sess)
	if err = op.resultError(err); err != nil {
		return fail(err)
	}
	profile, err := s.fetchProfile(ctx, tok.AccessToken)
	if err = op.resultError(err); err != nil {
		if op.check() != nil {
			return fail(err)
		}
		if reserveErr := op.reserveStore(); reserveErr != nil {
			return CompleteSignInResult{}, reserveErr
		}
		cleanupErr := func() error {
			defer s.releaseStore()
			return op.deletePreviousToken()
		}()
		if stale := op.resultError(nil); stale != nil {
			return fail(stale)
		}
		if cleanupErr != nil && s.store.isStrict() {
			return fail(cleanupErr)
		}
		return fail(err)
	}
	if err := op.reserveStore(); err != nil {
		return CompleteSignInResult{}, err
	}
	defer s.releaseStore()
	rollback, err := op.commitToken(tok)
	if err != nil {
		return fail(err)
	}
	if err := op.check(); err != nil {
		if cleanupErr := rollback(); cleanupErr != nil {
			return fail(cleanupErr)
		}
		return fail(err)
	}
	if err := op.publishProfile(profile); err != nil {
		if op.check() != nil {
			if cleanupErr := rollback(); cleanupErr != nil {
				return fail(cleanupErr)
			}
		}
		return fail(err)
	}
	status, err := s.store.status(ctx, s.cfg)
	if err = op.resultError(err); err != nil {
		if op.check() != nil {
			if cleanupErr := rollback(); cleanupErr != nil {
				return fail(cleanupErr)
			}
		}
		return fail(err)
	}
	return CompleteSignInResult{Status: status, Profile: profile}, nil
}

// SignOut invalidates pending HTTP immediately. A host callback already modifying
// storage makes cleanup incomplete; it must finish (and be retried) before sign-out
// can report success. This avoids waiting on a callback that reenters this owner.
func (s *Service) SignOut(ctx context.Context) error {
	ctx = normalizeContext(ctx)
	for {
		if err := checkContext(ctx); err != nil {
			return err
		}
		s.mu.Lock()
		s.invalidateLocked(nil)
		if !s.ioBusy {
			s.ioBusy = true
			s.ioDone = make(chan struct{})
			s.mu.Unlock()
			break
		}
		done := s.ioDone
		strict := s.store.isStrict()
		s.mu.Unlock()
		if strict {
			return ErrSignOutIncomplete
		}
		select {
		case <-ctx.Done():
			return ErrAuthCanceled
		case <-done:
		}
	}
	defer s.releaseStore()
	err := s.store.clear(ctx)
	if err != nil {
		s.store.writeLastError(err)
	}
	return err
}
