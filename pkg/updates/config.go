package updates

import (
	"net/http"
	"runtime"
	"strings"
	"time"
)

type Channel string

const (
	ChannelStable    Channel = "stable"
	ChannelPreview   Channel = "preview"
	ChannelDev       Channel = "dev"
	ChannelLocalTest Channel = "local-test"
)

type AppConfig struct {
	AppID          string
	DisplayName    string
	AppName        string
	CurrentVersion string
	Channel        Channel
	Platform       string
	Architecture   string
	Namespace      string
	Source         SourceConfig
	Policy         Policy
	StagingDir     string
	StateDir       string
	CacheDir       string
	HTTPTimeout    time.Duration
}

type Policy struct {
	// RequireSHA256 is always enforced; normalization sets it to true even
	// when callers leave it false.
	RequireSHA256            bool
	AllowPrerelease          bool
	MinimumVersion           string
	MaximumArtifactSize      int64
	RequireManifestSignature bool
	ManifestVerificationKeys map[string]string
	FreezeUpdates            bool
	RejectRollbackCandidates bool
	MaximumManifestAge       time.Duration
	MaximumFutureSkew        time.Duration
	MaximumStagedAge         time.Duration
}

// ServiceOptions lets the host keep public and credential-scoped transports
// separate. AuthenticatedHTTPClient may inject credentials through its
// Transport or Jar; Aegis never reads or persists those credentials.
type ServiceOptions struct {
	HTTPClient              *http.Client
	AuthenticatedHTTPClient *http.Client
}

func normalizeConfig(cfg AppConfig) AppConfig {
	cfg.AppID = strings.TrimSpace(cfg.AppID)
	cfg.DisplayName = strings.TrimSpace(cfg.DisplayName)
	cfg.AppName = strings.TrimSpace(cfg.AppName)
	if cfg.DisplayName == "" {
		cfg.DisplayName = cfg.AppName
	}
	cfg.CurrentVersion = strings.TrimSpace(cfg.CurrentVersion)
	cfg.Platform = strings.TrimSpace(cfg.Platform)
	cfg.Architecture = strings.TrimSpace(cfg.Architecture)
	cfg.Namespace = strings.TrimSpace(cfg.Namespace)
	if cfg.Namespace == "" {
		cfg.Namespace = cfg.AppID
	}
	if cfg.Platform == "" {
		cfg.Platform = runtime.GOOS
	}
	if cfg.Architecture == "" {
		cfg.Architecture = runtime.GOARCH
	}
	if cfg.StagingDir == "" {
		if cfg.CacheDir != "" {
			cfg.StagingDir = cfg.CacheDir
		} else {
			cfg.StagingDir = cfg.StateDir
		}
	}
	cfg.Source = normalizeSource(cfg.Source)
	cfg.Policy.ManifestVerificationKeys = cloneStringMap(cfg.Policy.ManifestVerificationKeys)
	if !cfg.Policy.RequireSHA256 {
		cfg.Policy.RequireSHA256 = true
	}
	return cfg
}

func validateConfig(cfg AppConfig) error {
	switch {
	case cfg.AppID == "", cfg.DisplayName == "", cfg.CurrentVersion == "", cfg.Channel == "", cfg.Platform == "", cfg.Architecture == "", cfg.Namespace == "", cfg.StagingDir == "":
		return ErrInvalidConfig
	case !validSafeName(cfg.AppID), !validSafeName(cfg.Namespace), !validSafeName(string(cfg.Channel)):
		return ErrInvalidConfig
	case !validVersion(cfg.CurrentVersion):
		return ErrInvalidConfig
	case cfg.Policy.MinimumVersion != "" && !validVersion(cfg.Policy.MinimumVersion):
		return ErrInvalidConfig
	case cfg.Policy.MaximumArtifactSize < 0:
		return ErrInvalidConfig
	case cfg.Policy.MaximumManifestAge < 0:
		return ErrInvalidConfig
	case cfg.Policy.MaximumFutureSkew < 0:
		return ErrInvalidConfig
	case cfg.Policy.MaximumStagedAge < 0:
		return ErrInvalidConfig
	}
	if err := validateManifestVerificationKeys(cfg.Policy.ManifestVerificationKeys); err != nil {
		return err
	}
	if cfg.Policy.RequireManifestSignature && len(cfg.Policy.ManifestVerificationKeys) == 0 {
		return ErrInvalidConfig
	}
	if err := validateSource(cfg.Source); err != nil {
		return err
	}
	return validateSourceAccess(cfg.Source, cfg.Policy)
}

func validateConfigWithOptions(cfg AppConfig, options ServiceOptions) error {
	if err := validateConfig(cfg); err != nil {
		return err
	}
	if cfg.Source.Access == SourceAccessAppOwnedAuthenticated && options.AuthenticatedHTTPClient == nil {
		return ErrInvalidConfig
	}
	return nil
}

func cloneConfig(cfg AppConfig) AppConfig {
	cfg.Source.AllowedHTTPHosts = append([]string(nil), cfg.Source.AllowedHTTPHosts...)
	cfg.Policy.ManifestVerificationKeys = cloneStringMap(cfg.Policy.ManifestVerificationKeys)
	return cfg
}

func cloneStringMap(in map[string]string) map[string]string {
	if in == nil {
		return nil
	}
	out := make(map[string]string, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}
