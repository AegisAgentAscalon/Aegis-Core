// Package auth exposes the public, app-safe authentication surface for Aegis
// Setup Core.
//
// Consuming apps provide their own app identity, Google OAuth client identity,
// callback settings, config path, and token namespace. UI-facing APIs return
// safe status/profile summaries only.
package auth

import (
	"context"
	"errors"
	"time"

	internal "github.com/AegisAgentAscalon/aegis-core/internal/auth"
)

var (
	ErrNotConfigured           = internal.ErrNotConfigured
	ErrNotSignedIn             = internal.ErrNotSignedIn
	ErrProfileNotFound         = errors.New("profile is not available; sign in first")
	ErrSessionNotFound         = internal.ErrSessionNotFound
	ErrSessionExpired          = internal.ErrSessionExpired
	ErrSessionConsumed         = internal.ErrSessionConsumed
	ErrStateMismatch           = internal.ErrStateMismatch
	ErrTokenExchangeFailed     = internal.ErrTokenExchangeFailed
	ErrProviderUnavailable     = internal.ErrProviderUnavailable
	ErrInvalidProviderResponse = internal.ErrInvalidProviderResponse
	ErrStorageUnavailable      = internal.ErrStorageUnavailable
	ErrAuthCanceled            = internal.ErrAuthCanceled
	ErrSignOutIncomplete       = internal.ErrSignOutIncomplete
)

// AppConfig identifies one consuming app's auth boundary.
type AppConfig struct {
	AppID         string
	DisplayName   string
	ConfigPath    string
	OAuth         OAuthClientConfig
	TokenStore    TokenStoreConfig
	Callback      CallbackConfig
	DefaultScopes []string
}

// OAuthClientConfig is app-provided Google OAuth identity/config.
type OAuthClientConfig struct {
	ClientID        string
	ClientSecret    string
	UseClientSecret bool
	Scopes          []string
	Endpoints       OAuthEndpointConfig
}

// OAuthEndpointConfig allows tests or advanced callers to override Google
// OAuth endpoints without changing the auth flow contract.
type OAuthEndpointConfig struct {
	AuthorizationURL string
	TokenURL         string
	UserInfoURL      string
}

// TokenStoreConfig describes app-namespaced local auth storage.
type TokenStoreConfig struct {
	BaseDir   string
	Namespace string
}

// CallbackConfig controls desktop loopback callback URL construction.
type CallbackConfig struct {
	Host     string
	Path     string
	PortHint int
}

// AuthStatus is safe for UI-facing setup surfaces.
type AuthStatus struct {
	AppID               string         `json:"app_id"`
	DisplayName         string         `json:"display_name"`
	Configured          bool           `json:"configured"`
	SignedIn            bool           `json:"signed_in"`
	NeedsReconnect      bool           `json:"needs_reconnect"`
	TokenPresent        bool           `json:"token_present"`
	ProfilePresent      bool           `json:"profile_present"`
	AccessTokenExpired  bool           `json:"access_token_expired"`
	ClientIDPresent     bool           `json:"client_id_present"`
	ClientIDShapeValid  bool           `json:"client_id_shape_valid"`
	ClientIDFingerprint string         `json:"client_id_fingerprint,omitempty"`
	UseClientSecret     bool           `json:"use_client_secret"`
	Scopes              []string       `json:"scopes"`
	TokenNamespace      string         `json:"token_namespace"`
	Profile             ProfileSummary `json:"profile"`
	LastError           string         `json:"last_error,omitempty"`
}

// ProfileSummary is safe profile information for app setup surfaces.
type ProfileSummary struct {
	Email       string `json:"email,omitempty"`
	DisplayName string `json:"display_name,omitempty"`
	Subject     string `json:"subject,omitempty"`
	PictureURL  string `json:"picture_url,omitempty"`
}

// SignInStartResult contains safe browser-flow startup information.
type SignInStartResult struct {
	AuthorizationURL string    `json:"authorization_url"`
	RedirectURI      string    `json:"redirect_uri"`
	ExpiresAt        time.Time `json:"expires_at"`
	SessionID        string    `json:"session_id"`
	Message          string    `json:"message"`
}

// CompleteSignInRequest supplies callback values received by the consuming app.
type CompleteSignInRequest struct {
	State string
	Code  string
}

// CompleteSignInResult returns safe post-login status/profile state.
type CompleteSignInResult struct {
	Status  AuthStatus     `json:"status"`
	Profile ProfileSummary `json:"profile"`
}

// Service wraps private auth implementation behind a stable public boundary.
type Service struct {
	svc *internal.Service
}

// DefaultGoogleScopes returns conservative profile scopes.
func DefaultGoogleScopes() []string {
	return internal.DefaultGoogleScopes()
}

// NewService creates an app-scoped auth service and initializes its namespaced
// local store. It does not start OAuth.
func NewService(config AppConfig) (*Service, error) {
	svc, err := internal.NewService(toInternalConfig(config))
	if err != nil {
		return nil, err
	}
	return &Service{svc: svc}, nil
}

// ValidateConfig validates app identity, OAuth identity, callback settings, and
// token namespace.
func (s *Service) ValidateConfig() error {
	return s.svc.ValidateConfig()
}

// Status returns safe auth/profile status without exposing tokens or secrets.
func (s *Service) Status(ctx context.Context) (AuthStatus, error) {
	st, err := s.svc.Status(ctx)
	if err != nil {
		return AuthStatus{}, err
	}
	return fromInternalStatus(st), nil
}

// StartSignIn prepares a safe Google OAuth authorization URL and private
// pending session.
func (s *Service) StartSignIn(ctx context.Context) (SignInStartResult, error) {
	res, err := s.svc.StartSignIn(ctx)
	if err != nil {
		return SignInStartResult{}, err
	}
	return fromInternalStartResult(res), nil
}

// CompleteSignIn validates callback state, exchanges the code using the private
// PKCE verifier, stores private tokens, and returns safe status/profile data.
func (s *Service) CompleteSignIn(ctx context.Context, req CompleteSignInRequest) (CompleteSignInResult, error) {
	res, err := s.svc.CompleteSignIn(ctx, internal.CompleteSignInRequest{State: req.State, Code: req.Code})
	if err != nil {
		return CompleteSignInResult{}, err
	}
	return CompleteSignInResult{Status: fromInternalStatus(res.Status), Profile: fromInternalProfile(res.Profile)}, nil
}

// SignOut clears only this app's namespaced local auth state.
func (s *Service) SignOut(ctx context.Context) error {
	return s.svc.SignOut(ctx)
}

// Profile returns the safe stored profile summary for this app namespace.
func (s *Service) Profile(ctx context.Context) (ProfileSummary, error) {
	profile, err := s.svc.Profile(ctx)
	if err != nil {
		if errors.Is(err, internal.ErrProfileNotFound) {
			return ProfileSummary{}, ErrProfileNotFound
		}
		return ProfileSummary{}, err
	}
	return fromInternalProfile(profile), nil
}

func toInternalConfig(cfg AppConfig) internal.AppConfig {
	return internal.AppConfig{
		AppID:       cfg.AppID,
		DisplayName: cfg.DisplayName,
		ConfigPath:  cfg.ConfigPath,
		OAuth: internal.OAuthClientConfig{
			ClientID:        cfg.OAuth.ClientID,
			ClientSecret:    cfg.OAuth.ClientSecret,
			UseClientSecret: cfg.OAuth.UseClientSecret,
			Scopes:          append([]string{}, cfg.OAuth.Scopes...),
			Endpoints: internal.OAuthEndpointConfig{
				AuthorizationURL: cfg.OAuth.Endpoints.AuthorizationURL,
				TokenURL:         cfg.OAuth.Endpoints.TokenURL,
				UserInfoURL:      cfg.OAuth.Endpoints.UserInfoURL,
			},
		},
		TokenStore:    internal.TokenStoreConfig{BaseDir: cfg.TokenStore.BaseDir, Namespace: cfg.TokenStore.Namespace},
		Callback:      internal.CallbackConfig{Host: cfg.Callback.Host, Path: cfg.Callback.Path, PortHint: cfg.Callback.PortHint},
		DefaultScopes: append([]string{}, cfg.DefaultScopes...),
	}
}

func fromInternalStatus(st internal.AuthStatus) AuthStatus {
	return AuthStatus{
		AppID:               st.AppID,
		DisplayName:         st.DisplayName,
		Configured:          st.Configured,
		SignedIn:            st.SignedIn,
		NeedsReconnect:      st.NeedsReconnect,
		TokenPresent:        st.TokenPresent,
		ProfilePresent:      st.ProfilePresent,
		AccessTokenExpired:  st.AccessTokenExpired,
		ClientIDPresent:     st.ClientIDPresent,
		ClientIDShapeValid:  st.ClientIDShapeValid,
		ClientIDFingerprint: st.ClientIDFingerprint,
		UseClientSecret:     st.UseClientSecret,
		Scopes:              append([]string{}, st.Scopes...),
		TokenNamespace:      st.TokenNamespace,
		Profile:             fromInternalProfile(st.Profile),
		LastError:           st.LastError,
	}
}

func fromInternalProfile(p internal.ProfileSummary) ProfileSummary {
	return ProfileSummary{Email: p.Email, DisplayName: p.DisplayName, Subject: p.Subject, PictureURL: p.PictureURL}
}

func fromInternalStartResult(res internal.SignInStartResult) SignInStartResult {
	return SignInStartResult{
		AuthorizationURL: res.AuthorizationURL,
		RedirectURI:      res.RedirectURI,
		ExpiresAt:        res.ExpiresAt,
		SessionID:        res.SessionID,
		Message:          res.Message,
	}
}
