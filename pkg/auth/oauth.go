package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

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
