package updates

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"path/filepath"
	"sort"
	"strings"
)

type ProviderKind string

const (
	ProviderFileManifest      ProviderKind = "file_manifest"
	ProviderHTTPManifest      ProviderKind = "http_manifest"
	ProviderGitHubRawManifest ProviderKind = "github_raw_manifest"
	ProviderGitHubManifest    ProviderKind = "github_manifest"
)

type SourceConfig struct {
	Provider           ProviderKind
	ManifestPath       string
	ManifestURL        string
	Feed               string
	GitHubOwner        string
	GitHubRepo         string
	GitHubRef          string
	GitHubManifestPath string
	// SourceID is a non-secret stable lane identity used for safe provenance
	// and isolated persisted state. Authenticated sources require it.
	SourceID              string
	Access                SourceAccess
	RequiredManifestKeyID string
	AllowedHTTPHosts      []string
}

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

func normalizeSource(src SourceConfig) SourceConfig {
	src.ManifestPath = strings.TrimSpace(src.ManifestPath)
	src.ManifestURL = strings.TrimSpace(src.ManifestURL)
	src.Feed = strings.TrimSpace(src.Feed)
	src.GitHubOwner = strings.TrimSpace(src.GitHubOwner)
	src.GitHubRepo = strings.TrimSpace(src.GitHubRepo)
	src.GitHubRef = strings.TrimSpace(src.GitHubRef)
	src.GitHubManifestPath = strings.TrimSpace(src.GitHubManifestPath)
	if src.ManifestPath == "" && src.Provider == ProviderFileManifest {
		src.ManifestPath = src.Feed
	}
	if src.ManifestURL == "" && src.Provider == ProviderHTTPManifest {
		src.ManifestURL = src.Feed
	}
	if src.GitHubRef == "" {
		src.GitHubRef = "main"
	}
	return normalizeSourceAccess(src)
}

func validateSource(src SourceConfig) error {
	switch src.Provider {
	case ProviderFileManifest:
		if src.ManifestPath == "" || hasPathTraversal(src.ManifestPath) {
			return ErrInvalidProvider
		}
	case ProviderHTTPManifest:
		if src.ManifestURL == "" || validateSourceURL(src, src.ManifestURL, false) != nil {
			return ErrInvalidProvider
		}
	case ProviderGitHubRawManifest, ProviderGitHubManifest:
		if !validSafeName(src.GitHubOwner) || !validSafeName(src.GitHubRepo) || !validSafeName(src.GitHubRef) || !validManifestPath(src.GitHubManifestPath) {
			return ErrInvalidProvider
		}
		if validateSourceURL(src, githubRawManifestURL(src), false) != nil {
			return ErrInvalidProvider
		}
	default:
		return ErrInvalidProvider
	}
	return nil
}

func githubRawManifestURL(src SourceConfig) string {
	parts := []string{url.PathEscape(src.GitHubOwner), url.PathEscape(src.GitHubRepo), url.PathEscape(src.GitHubRef)}
	for _, part := range strings.Split(strings.Trim(src.GitHubManifestPath, "/"), "/") {
		parts = append(parts, url.PathEscape(part))
	}
	return "https://raw.githubusercontent.com/" + strings.Join(parts, "/")
}
