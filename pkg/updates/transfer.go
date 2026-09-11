package updates

import (
	"context"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

func (s *Service) selectArtifact(manifest Manifest) (Artifact, error) {
	s.mu.Lock()
	cfg := cloneConfig(s.cfg)
	s.mu.Unlock()
	return selectArtifactForConfig(cfg, manifest)
}

func (s *Service) downloadArtifact(ctx context.Context, artifact Artifact, target string) (int64, error) {
	s.mu.Lock()
	cfg := cloneConfig(s.cfg)
	client := s.client
	s.mu.Unlock()
	if client == nil {
		client, _ = clientForSource(cfg, s.options)
	}
	return downloadArtifactFor(normalizeContext(ctx), cfg, client, artifact, target)
}

func selectArtifactForConfig(cfg AppConfig, manifest Manifest) (Artifact, error) {
	if err := validateManifest(cfg, manifest); err != nil {
		return Artifact{}, err
	}
	for _, artifact := range sortedArtifacts(manifest.Artifacts) {
		if artifact.Platform != cfg.Platform || artifact.Architecture != cfg.Architecture {
			continue
		}
		if err := validateArtifact(cfg, artifact); err != nil {
			return Artifact{}, err
		}
		return artifact, nil
	}
	return Artifact{}, ErrNoCompatibleArtifact
}

func downloadArtifactFor(ctx context.Context, cfg AppConfig, client *http.Client, artifact Artifact, target string) (int64, error) {
	if filepath.IsAbs(artifact.DownloadURL) {
		if cfg.Source.Provider != ProviderFileManifest {
			return 0, ErrInvalidManifest
		}
		src, err := os.Open(artifact.DownloadURL)
		if err != nil {
			return 0, ErrDownloadFailed
		}
		defer src.Close()
		return writeStreamToFile(ctx, src, target, cfg.Policy.MaximumArtifactSize)
	}
	u, err := url.Parse(artifact.DownloadURL)
	if err != nil || artifact.DownloadURL == "" {
		return 0, ErrInvalidManifest
	}
	switch u.Scheme {
	case "", "file":
		if cfg.Source.Provider != ProviderFileManifest {
			return 0, ErrInvalidManifest
		}
		path := artifact.DownloadURL
		if u.Scheme == "file" {
			path = u.Path
			if runtime.GOOS == "windows" && strings.HasPrefix(path, "/") && len(path) > 2 && path[2] == ':' {
				path = strings.TrimPrefix(path, "/")
			}
		}
		src, err := os.Open(path)
		if err != nil {
			return 0, ErrDownloadFailed
		}
		defer src.Close()
		return writeStreamToFile(ctx, src, target, cfg.Policy.MaximumArtifactSize)
	case "http", "https":
		if err := validateSourceURL(cfg.Source, artifact.DownloadURL, false); err != nil {
			return 0, err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, artifact.DownloadURL, nil)
		if err != nil {
			return 0, ErrInvalidManifest
		}
		resp, err := client.Do(req)
		if err != nil {
			return 0, sourceOperationError(ctx, err, ErrDownloadFailed)
		}
		defer resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode > 299 {
			return 0, ErrDownloadFailed
		}
		if cfg.Policy.MaximumArtifactSize > 0 && resp.ContentLength > cfg.Policy.MaximumArtifactSize {
			return 0, ErrDownloadFailed
		}
		return writeStreamToFile(ctx, resp.Body, target, cfg.Policy.MaximumArtifactSize)
	default:
		return 0, ErrInvalidManifest
	}
}

type applyAdapterStrategy struct {
	adapter ApplyAdapter
}

func (s applyAdapterStrategy) Apply(ctx context.Context, staged StagedUpdate) (ApplyResult, error) {
	release := Release{
		Source:          staged.Source,
		AppID:           staged.AppID,
		Version:         staged.Version,
		Channel:         staged.Channel,
		Platform:        staged.Platform,
		Architecture:    staged.Architecture,
		RequiredRestart: staged.RequiredRestart,
		ApplyBehavior:   staged.ApplyBehavior,
		ArtifactName:    staged.ArtifactName,
		ArtifactSHA256:  staged.SHA256,
		ArtifactSize:    staged.Size,
	}
	return s.adapter.ApplyUpdate(ctx, staged.ArtifactPath, release)
}
