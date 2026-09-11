package updates

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// SourceAccess describes how an update source may be reached. Credentials are
// always owned by the host application and are never stored in SourceConfig.
type SourceAccess string

const (
	SourceAccessLocal                 SourceAccess = "local"
	SourceAccessPublic                SourceAccess = "public"
	SourceAccessAppOwnedAuthenticated SourceAccess = "app_owned_authenticated"
)

// SourceSummary is safe, non-secret provenance suitable for status DTOs.
type SourceSummary struct {
	ID            string       `json:"id,omitempty"`
	Access        SourceAccess `json:"access"`
	Provider      ProviderKind `json:"provider"`
	Authenticated bool         `json:"authenticated"`
}

// LaneConfig switches channel, source and optionally trust policy as one
// transaction. A nil Policy preserves the current policy.
type LaneConfig struct {
	Channel Channel
	Source  SourceConfig
	Policy  *Policy
}

// ServiceOptions lets the host keep public and credential-scoped transports
// separate. AuthenticatedHTTPClient may inject credentials through its
// Transport or Jar; Aegis never reads or persists those credentials.
type ServiceOptions struct {
	HTTPClient              *http.Client
	AuthenticatedHTTPClient *http.Client
}

func sourceSummary(src SourceConfig) SourceSummary {
	return SourceSummary{
		ID:            src.SourceID,
		Access:        src.Access,
		Provider:      src.Provider,
		Authenticated: src.Access == SourceAccessAppOwnedAuthenticated,
	}
}

func normalizeSourceAccess(src SourceConfig) SourceConfig {
	src.SourceID = strings.ToLower(strings.TrimSpace(src.SourceID))
	src.RequiredManifestKeyID = strings.TrimSpace(src.RequiredManifestKeyID)
	if src.Access == "" {
		if src.Provider == ProviderFileManifest {
			src.Access = SourceAccessLocal
		} else {
			src.Access = SourceAccessPublic
		}
	}
	src.Access = SourceAccess(strings.TrimSpace(string(src.Access)))

	seen := map[string]struct{}{}
	hosts := make([]string, 0, len(src.AllowedHTTPHosts))
	for _, value := range src.AllowedHTTPHosts {
		value = strings.ToLower(strings.TrimSpace(value))
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		hosts = append(hosts, value)
	}
	sort.Strings(hosts)
	src.AllowedHTTPHosts = hosts
	return src
}

func validateSourceAccess(src SourceConfig, policy Policy) error {
	switch src.Access {
	case SourceAccessLocal:
		if src.Provider != ProviderFileManifest || len(src.AllowedHTTPHosts) != 0 {
			return ErrInvalidProvider
		}
	case SourceAccessPublic:
		if src.Provider == ProviderFileManifest {
			return ErrInvalidProvider
		}
		for _, host := range src.AllowedHTTPHosts {
			if _, err := normalizeAllowedAuthority(host); err != nil {
				return ErrInvalidProvider
			}
		}
	case SourceAccessAppOwnedAuthenticated:
		if src.Provider == ProviderFileManifest || src.SourceID == "" || src.SourceID != strings.ToLower(src.SourceID) || !validSafeName(src.SourceID) {
			return ErrInvalidProvider
		}
		if len(src.AllowedHTTPHosts) == 0 || src.RequiredManifestKeyID == "" {
			return ErrInvalidConfig
		}
		for _, host := range src.AllowedHTTPHosts {
			if _, err := normalizeAllowedAuthority(host); err != nil {
				return ErrInvalidProvider
			}
		}
	default:
		return ErrInvalidProvider
	}
	if src.SourceID != "" && (!validSafeName(src.SourceID) || src.SourceID != strings.ToLower(src.SourceID)) {
		return ErrInvalidProvider
	}
	if src.RequiredManifestKeyID != "" {
		if !validSafeName(src.RequiredManifestKeyID) || !policy.RequireManifestSignature {
			return ErrInvalidConfig
		}
		if _, ok := policy.ManifestVerificationKeys[src.RequiredManifestKeyID]; !ok {
			return ErrInvalidConfig
		}
	}
	return nil
}

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

func cloneConfig(cfg AppConfig) AppConfig {
	cfg.Source.AllowedHTTPHosts = append([]string(nil), cfg.Source.AllowedHTTPHosts...)
	cfg.Policy.ManifestVerificationKeys = cloneStringMap(cfg.Policy.ManifestVerificationKeys)
	return cfg
}

func sourceKey(src SourceConfig) string {
	src = normalizeSource(src)
	value := strings.Join([]string{
		string(src.Provider),
		src.ManifestPath,
		src.ManifestURL,
		src.Feed,
		src.GitHubOwner,
		src.GitHubRepo,
		src.GitHubRef,
		src.GitHubManifestPath,
		src.SourceID,
		string(src.Access),
		src.RequiredManifestKeyID,
		strings.Join(src.AllowedHTTPHosts, "\n"),
	}, "\x00")
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func policyKey(policy Policy) string {
	clone := policy
	clone.ManifestVerificationKeys = cloneStringMap(policy.ManifestVerificationKeys)
	payload, _ := json.Marshal(clone)
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

func stateScopeKey(cfg AppConfig) string {
	if cfg.Source.SourceID == "" {
		return ""
	}
	value := strings.Join([]string{sourceKey(cfg.Source), policyKey(cfg.Policy), string(cfg.Channel)}, "\x00")
	sum := sha256.Sum256([]byte(value))
	return filepath.Join("scopes", cfg.Source.SourceID, string(cfg.Channel), hex.EncodeToString(sum[:12]))
}

func requiredManifestKeyMatches(cfg AppConfig, manifest Manifest) bool {
	if cfg.Source.RequiredManifestKeyID == "" {
		return true
	}
	return manifest.Signature != nil && manifest.Signature.KeyID == cfg.Source.RequiredManifestKeyID
}

func sourceAndPolicyMatch(cfg AppConfig, sourceKeyValue, policyKeyValue string) bool {
	if sourceKeyValue != sourceKey(cfg.Source) {
		return false
	}
	// Metadata written before lane isolation did not carry a policy key. Keep
	// that legacy state readable when no explicit SourceID opted into scoped
	// storage. Explicit lanes always require exact policy provenance.
	if cfg.Source.SourceID == "" {
		return true
	}
	return policyKeyValue == policyKey(cfg.Policy)
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
