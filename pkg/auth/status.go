package auth

import (
	"context"
	"errors"
	"os"
	"strings"
	"time"

	"github.com/AegisAgentAscalon/aegis-core/pkg/secretstore"
)

// Status returns safe UI-facing auth state.
func (s *Service) Status(ctx context.Context) (AuthStatus, error) {
	op := s.beginOperation(ctx)
	defer op.finish()
	if err := op.reserveStore(); err != nil {
		return AuthStatus{}, err
	}
	defer s.releaseStore()
	result, err := s.store.status(op.ctx, s.cfg)
	if err = op.resultError(err); err != nil {
		return AuthStatus{}, err
	}
	return result, nil
}

// Profile returns the safe stored profile summary.
func (s *Service) Profile(ctx context.Context) (ProfileSummary, error) {
	op := s.beginOperation(ctx)
	defer op.finish()
	if err := op.reserveStore(); err != nil {
		return ProfileSummary{}, err
	}
	defer s.releaseStore()
	p, err := s.store.readProfile(op.ctx)
	if current := op.resultError(nil); current != nil {
		return ProfileSummary{}, current
	}
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return ProfileSummary{}, ErrProfileNotFound
		}
		return ProfileSummary{}, safeStorageError(err)
	}
	return ProfileSummary{Email: p.Email, DisplayName: p.DisplayName, Subject: p.Subject, PictureURL: p.PictureURL}, nil
}

func (s *store) status(ctx context.Context, cfg AppConfig) (AuthStatus, error) {
	st := AuthStatus{
		AppID:               cfg.AppID,
		DisplayName:         cfg.DisplayName,
		ClientIDPresent:     cfg.OAuth.ClientID != "",
		ClientIDShapeValid:  cfg.OAuth.ClientID != "" && strings.HasSuffix(cfg.OAuth.ClientID, ".apps.googleusercontent.com"),
		ClientIDFingerprint: fingerprint(cfg.OAuth.ClientID),
		UseClientSecret:     cfg.OAuth.UseClientSecret,
		Scopes:              append([]string{}, cfg.OAuth.Scopes...),
		TokenNamespace:      cfg.TokenStore.Namespace,
		LastError:           s.readLastError(),
	}
	// Profile and token validity contribute independently to reconnect state.
	p, profileErr := s.readProfile(ctx)
	st.ProfilePresent = !errors.Is(profileErr, os.ErrNotExist)
	profileInvalid := profileErr != nil && !errors.Is(profileErr, os.ErrNotExist)
	if profileErr == nil {
		st.Profile = ProfileSummary{Email: p.Email, DisplayName: p.DisplayName, Subject: p.Subject, PictureURL: p.PictureURL}
	}
	t, tokenErr := s.readToken(ctx)
	tokenMissing := errors.Is(tokenErr, os.ErrNotExist) || errors.Is(tokenErr, secretstore.ErrNotFound)
	if s.isStrict() && tokenErr != nil && !tokenMissing {
		return AuthStatus{}, tokenErr
	}
	st.TokenPresent = !tokenMissing
	st.SignedIn = tokenErr == nil
	tokenInvalid := tokenErr != nil && !tokenMissing
	if st.SignedIn {
		st.AccessTokenExpired = time.Until(t.Expiry) <= 90*time.Second
	}
	st.NeedsReconnect = profileInvalid || tokenInvalid || st.AccessTokenExpired ||
		(st.SignedIn && !st.ProfilePresent) || (st.ProfilePresent && !st.TokenPresent)
	if (profileInvalid || tokenInvalid) && st.LastError == "" {
		st.LastError = "stored auth data is invalid; sign in again"
	}
	st.Configured = st.ClientIDPresent && st.ClientIDShapeValid && len(st.Scopes) > 0
	return st, nil
}
