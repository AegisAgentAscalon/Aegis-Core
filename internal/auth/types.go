// Package auth contains private OAuth implementation details for the public
// Aegis Core auth package.
package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

var safeNamePattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$`)

var (
	ErrNotConfigured           = errors.New("auth is not configured")
	ErrNotSignedIn             = errors.New("not signed in")
	ErrProfileNotFound         = errors.New("profile is not available; sign in first")
	ErrSessionNotFound         = errors.New("pending OAuth session not found")
	ErrSessionExpired          = errors.New("pending OAuth session expired")
	ErrSessionConsumed         = errors.New("pending OAuth session already consumed")
	ErrStateMismatch           = errors.New("oauth state mismatch")
	ErrTokenExchangeFailed     = errors.New("token exchange failed")
	ErrProviderUnavailable     = errors.New("auth provider unavailable")
	ErrInvalidProviderResponse = errors.New("auth provider returned an invalid response")
	ErrStorageUnavailable      = errors.New("auth storage is unavailable; check app permissions")
	ErrAuthCanceled            = errors.New("auth request canceled")
	ErrSignOutIncomplete       = errors.New("sign-out cleanup incomplete")

	errProfileFetchFailed = errors.New("profile fetch failed")
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

// CallbackConfig controls desktop loopback callback URL construction. When
// PortHint is zero the service discovers an available port for URL construction
// only; the caller-owned callback listener must still handle bind retries.
type CallbackConfig struct {
	Host     string
	Path     string
	PortHint int
}

// ProfileSummary is safe profile information for app setup surfaces.
type ProfileSummary struct {
	Email       string `json:"email,omitempty"`
	DisplayName string `json:"display_name,omitempty"`
	Subject     string `json:"subject,omitempty"`
	PictureURL  string `json:"picture_url,omitempty"`
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

type token struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	TokenType    string    `json:"token_type"`
	Expiry       time.Time `json:"expiry"`
	IDToken      string    `json:"id_token,omitempty"`
}

type profileFile struct {
	Email       string `json:"email,omitempty"`
	DisplayName string `json:"display_name,omitempty"`
	Subject     string `json:"subject,omitempty"`
	PictureURL  string `json:"picture_url,omitempty"`
}

type pendingSession struct {
	SessionID   string    `json:"session_id"`
	State       string    `json:"state"`
	Verifier    string    `json:"verifier"`
	RedirectURI string    `json:"redirect_uri"`
	Scopes      []string  `json:"scopes"`
	CreatedAt   time.Time `json:"created_at"`
	ExpiresAt   time.Time `json:"expires_at"`
	Consumed    bool      `json:"consumed"`
}

// DefaultGoogleScopes returns conservative profile scopes.
func DefaultGoogleScopes() []string {
	return []string{"openid", "email", "profile"}
}

// NormalizeConfig trims and defaults an app config without touching files.
func NormalizeConfig(cfg AppConfig) AppConfig {
	cfg.AppID = strings.TrimSpace(cfg.AppID)
	cfg.DisplayName = strings.TrimSpace(cfg.DisplayName)
	cfg.ConfigPath = strings.TrimSpace(cfg.ConfigPath)
	cfg.OAuth.ClientID = strings.TrimSpace(cfg.OAuth.ClientID)
	cfg.OAuth.ClientSecret = strings.TrimSpace(cfg.OAuth.ClientSecret)
	cfg.OAuth.Scopes = compactScopes(cfg.OAuth.Scopes)
	cfg.OAuth.Endpoints.AuthorizationURL = strings.TrimSpace(cfg.OAuth.Endpoints.AuthorizationURL)
	if cfg.OAuth.Endpoints.AuthorizationURL == "" {
		cfg.OAuth.Endpoints.AuthorizationURL = "https://accounts.google.com/o/oauth2/v2/auth"
	}
	cfg.OAuth.Endpoints.TokenURL = strings.TrimSpace(cfg.OAuth.Endpoints.TokenURL)
	if cfg.OAuth.Endpoints.TokenURL == "" {
		cfg.OAuth.Endpoints.TokenURL = "https://oauth2.googleapis.com/token"
	}
	cfg.OAuth.Endpoints.UserInfoURL = strings.TrimSpace(cfg.OAuth.Endpoints.UserInfoURL)
	if cfg.OAuth.Endpoints.UserInfoURL == "" {
		cfg.OAuth.Endpoints.UserInfoURL = "https://www.googleapis.com/oauth2/v2/userinfo"
	}
	cfg.DefaultScopes = compactScopes(cfg.DefaultScopes)
	if len(cfg.OAuth.Scopes) == 0 {
		if len(cfg.DefaultScopes) > 0 {
			cfg.OAuth.Scopes = append([]string{}, cfg.DefaultScopes...)
		} else {
			cfg.OAuth.Scopes = DefaultGoogleScopes()
		}
	}
	cfg.TokenStore.Namespace = strings.TrimSpace(cfg.TokenStore.Namespace)
	cfg.Callback.Host = strings.TrimSpace(cfg.Callback.Host)
	if cfg.Callback.Host == "" {
		cfg.Callback.Host = "127.0.0.1"
	}
	cfg.Callback.Path = "/" + strings.Trim(strings.TrimSpace(cfg.Callback.Path), "/")
	if cfg.Callback.Path == "/" {
		cfg.Callback.Path = "/callback"
	}
	return cfg
}

// ValidateConfig validates app identity, OAuth identity, callback, and namespace.
func ValidateConfig(cfg AppConfig) error {
	cfg = NormalizeConfig(cfg)
	switch {
	case cfg.AppID == "":
		return errors.New("app id is required")
	case !validSafeName(cfg.AppID):
		return errors.New("app id must use only letters, numbers, dot, underscore, or hyphen")
	case cfg.DisplayName == "":
		return errors.New("display name is required")
	case cfg.ConfigPath == "":
		return errors.New("config path is required")
	case cfg.OAuth.ClientID == "":
		return errors.New("google OAuth client id is required")
	case !strings.HasSuffix(cfg.OAuth.ClientID, ".apps.googleusercontent.com"):
		return errors.New("google OAuth client id should end with .apps.googleusercontent.com")
	case cfg.OAuth.UseClientSecret && cfg.OAuth.ClientSecret == "":
		return errors.New("use_client_secret=true but client secret is empty")
	case len(cfg.OAuth.Scopes) == 0:
		return errors.New("at least one OAuth scope is required")
	case !validHTTPSOrHTTPTestURL(cfg.OAuth.Endpoints.AuthorizationURL):
		return errors.New("authorization endpoint URL is invalid")
	case !validHTTPSOrHTTPTestURL(cfg.OAuth.Endpoints.TokenURL):
		return errors.New("token endpoint URL is invalid")
	case !validHTTPSOrHTTPTestURL(cfg.OAuth.Endpoints.UserInfoURL):
		return errors.New("userinfo endpoint URL is invalid")
	case cfg.TokenStore.Namespace == "":
		return errors.New("token namespace is required")
	case !validSafeName(cfg.TokenStore.Namespace):
		return errors.New("token namespace must use only letters, numbers, dot, underscore, or hyphen")
	case cfg.Callback.Host == "":
		return errors.New("callback host is required")
	case !isLoopbackHost(cfg.Callback.Host):
		return errors.New("callback host must be loopback for desktop OAuth")
	case cfg.Callback.Path == "":
		return errors.New("callback path is required")
	case cfg.Callback.PortHint < 0 || cfg.Callback.PortHint > 65535:
		return errors.New("callback port hint must be between 0 and 65535")
	}
	return nil
}

// Fingerprint returns a short non-secret fingerprint for diagnostics.
func Fingerprint(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:12]
}

func compactScopes(scopes []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, scope := range scopes {
		scope = strings.TrimSpace(scope)
		if scope == "" || seen[scope] {
			continue
		}
		seen[scope] = true
		out = append(out, scope)
	}
	return out
}

func safePathPart(s string) string {
	return strings.TrimSpace(s)
}

func namespacedStoreDir(baseDir, appID, namespace string) string {
	return filepath.Join(baseDir, safePathPart(appID), safePathPart(namespace))
}

func validHTTPSOrHTTPTestURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return false
	}
	return u.Scheme == "https" || (u.Scheme == "http" && isLoopbackHost(u.Hostname()))
}

func isLoopbackHost(host string) bool {
	host = strings.Trim(strings.ToLower(strings.TrimSpace(host)), "[]")
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func validSafeName(s string) bool {
	s = strings.TrimSpace(s)
	if !safeNamePattern.MatchString(s) {
		return false
	}
	if strings.Contains(s, "..") || strings.ContainsAny(s, `/\`) {
		return false
	}
	upper := strings.ToUpper(s)
	if i := strings.IndexByte(upper, '.'); i >= 0 {
		upper = upper[:i]
	}
	reserved := map[string]bool{
		"CON": true, "PRN": true, "AUX": true, "NUL": true,
		"COM1": true, "COM2": true, "COM3": true, "COM4": true, "COM5": true, "COM6": true, "COM7": true, "COM8": true, "COM9": true,
		"LPT1": true, "LPT2": true, "LPT3": true, "LPT4": true, "LPT5": true, "LPT6": true, "LPT7": true, "LPT8": true, "LPT9": true,
	}
	return !reserved[upper]
}
