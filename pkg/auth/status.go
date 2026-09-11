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
func (s *Service) Status(context.Context) (AuthStatus, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.store.status(s.cfg)
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

func (s *store) status(cfg AppConfig) (AuthStatus, error) {
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
	if _, err := os.Stat(s.profilePath()); err == nil {
		st.ProfilePresent = true
	}
	if p, err := s.readProfile(); err == nil {
		st.Profile = ProfileSummary{Email: p.Email, DisplayName: p.DisplayName, Subject: p.Subject, PictureURL: p.PictureURL}
	} else if st.ProfilePresent {
		st.NeedsReconnect = true
		if st.LastError == "" {
			st.LastError = "stored auth data is invalid; sign in again"
		}
	}
	if s.isStrict() {
		t, err := s.readToken()
		switch {
		case err == nil:
			st.TokenPresent = true
			st.SignedIn = true
			st.AccessTokenExpired = time.Until(t.Expiry) <= 90*time.Second
			st.NeedsReconnect = st.AccessTokenExpired
		case errors.Is(err, secretstore.ErrNotFound):
		default:
			return AuthStatus{}, err
		}
	} else {
		if _, err := os.Stat(s.tokenPath()); err == nil {
			st.TokenPresent = true
		}
		if t, err := s.readToken(); err == nil {
			st.SignedIn = true
			st.AccessTokenExpired = time.Until(t.Expiry) <= 90*time.Second
			st.NeedsReconnect = st.AccessTokenExpired
		} else if st.TokenPresent {
			st.NeedsReconnect = true
			if st.LastError == "" {
				st.LastError = "stored auth data is invalid; sign in again"
			}
		}
	}
	st.Configured = st.ClientIDPresent && st.ClientIDShapeValid && len(st.Scopes) > 0
	if st.SignedIn && !st.ProfilePresent {
		st.NeedsReconnect = true
	}
	return st, nil
}
