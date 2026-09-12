package updates

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

func normalizeAllowedAuthority(raw string) (string, error) {
	raw = strings.ToLower(strings.TrimSpace(raw))
	if raw == "" || strings.Contains(raw, "://") || strings.ContainsAny(raw, "/?#@") {
		return "", ErrInvalidProvider
	}
	// Parse through a URL so bracketed IPv6 and explicit ports are handled by
	// the standard library. Requiring the parsed Host to equal the input rejects
	// malformed double brackets and stray text.
	u, err := url.Parse("https://" + raw)
	if err != nil || u.Host != raw || u.Hostname() == "" || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return "", ErrInvalidProvider
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return "", ErrInvalidProvider
	}
	return canonicalAuthority(u.Scheme, u.Hostname(), strconv.Itoa(portNumber)), nil
}

func canonicalAuthority(scheme, host, port string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	if port == "" {
		if scheme == "http" {
			port = "80"
		} else {
			port = "443"
		}
	} else if portNumber, err := strconv.Atoi(port); err == nil && portNumber >= 1 && portNumber <= 65535 {
		port = strconv.Itoa(portNumber)
	}
	if strings.Contains(host, ":") {
		return net.JoinHostPort(host, port)
	}
	return host + ":" + port
}

func sourceAllowsURL(src SourceConfig, u *url.URL, redirected bool) bool {
	if u == nil || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
		return false
	}
	if u.Scheme != "https" {
		if u.Scheme != "http" || !isLoopbackHostname(u.Hostname()) {
			return false
		}
	}
	if !redirected && u.RawQuery != "" {
		// Credentials and expiring signatures belong in the app-owned client or
		// in an allowlisted redirect, not in persisted manifests/configuration.
		return false
	}
	if src.Access != SourceAccessAppOwnedAuthenticated && len(src.AllowedHTTPHosts) == 0 {
		return true
	}
	got := canonicalAuthority(u.Scheme, u.Hostname(), u.Port())
	for _, raw := range src.AllowedHTTPHosts {
		allowed, err := normalizeAllowedAuthority(raw)
		if err != nil {
			return false
		}
		if got == allowed {
			return true
		}
		// Loopback HTTP sources normally carry an explicit development port.
		// An allowlist entry without a port intentionally means HTTPS/443 only.
	}
	return false
}

func isLoopbackHostname(host string) bool {
	host = strings.Trim(strings.ToLower(strings.TrimSpace(host)), "[]")
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func clientForSource(cfg AppConfig, options ServiceOptions) (*http.Client, error) {
	var base *http.Client
	if cfg.Source.Access == SourceAccessAppOwnedAuthenticated {
		base = options.AuthenticatedHTTPClient
		if base == nil {
			return nil, ErrInvalidConfig
		}
	} else {
		base = options.HTTPClient
	}
	return cloneClientForSource(base, cfg.HTTPTimeout, cfg.Source), nil
}

func cloneClientForSource(base *http.Client, timeout time.Duration, src SourceConfig) *http.Client {
	if timeout <= 0 {
		timeout = defaultHTTPTimeout
	}
	client := http.Client{Timeout: timeout}
	if base != nil {
		client = *base
		if client.Timeout <= 0 {
			client.Timeout = timeout
		}
	}
	originalRedirect := client.CheckRedirect
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 10 || !sourceAllowsURL(src, req.URL, true) {
			return ErrProviderUnavailable
		}
		if originalRedirect != nil {
			return originalRedirect(req, via)
		}
		return nil
	}
	return &client
}

func validateSourceURL(src SourceConfig, raw string, redirected bool) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || !sourceAllowsURL(src, u, redirected) {
		return ErrInvalidManifest
	}
	return nil
}

func sourceOperationError(ctx context.Context, err error, fallback error) error {
	if contextError(ctx) != nil {
		return ErrContextCanceled
	}
	if errors.Is(err, ErrProviderUnavailable) {
		return ErrProviderUnavailable
	}
	return fallback
}
