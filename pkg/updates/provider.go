package updates

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
)

type Provider interface {
	LoadManifest(ctx context.Context) (Manifest, error)
}

func newProvider(cfg AppConfig, client *http.Client) (Provider, error) {
	switch cfg.Source.Provider {
	case ProviderFileManifest:
		return fileManifestProvider{path: cfg.Source.ManifestPath}, nil
	case ProviderHTTPManifest:
		return httpManifestProvider{url: cfg.Source.ManifestURL, client: client, source: cfg.Source}, nil
	case ProviderGitHubRawManifest, ProviderGitHubManifest:
		return httpManifestProvider{url: githubRawManifestURL(cfg.Source), client: client, source: cfg.Source}, nil
	default:
		return nil, ErrInvalidProvider
	}
}

type fileManifestProvider struct{ path string }

func (p fileManifestProvider) LoadManifest(ctx context.Context) (Manifest, error) {
	if err := contextError(ctx); err != nil {
		return Manifest{}, err
	}
	f, err := os.Open(p.path)
	if err != nil {
		return Manifest{}, ErrProviderUnavailable
	}
	defer f.Close()
	return readAndDecodeManifest(f)
}

type httpManifestProvider struct {
	url    string
	client *http.Client
	source SourceConfig
}

func (p httpManifestProvider) LoadManifest(ctx context.Context) (Manifest, error) {
	ctx = normalizeContext(ctx)
	if err := contextError(ctx); err != nil {
		return Manifest{}, err
	}
	if p.client == nil || validateSourceURL(p.source, p.url, false) != nil {
		return Manifest{}, ErrInvalidProvider
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.url, nil)
	if err != nil {
		return Manifest{}, ErrInvalidProvider
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return Manifest{}, sourceOperationError(ctx, err, ErrProviderUnavailable)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return Manifest{}, ErrProviderUnavailable
	}
	return readAndDecodeManifest(resp.Body)
}

func readAndDecodeManifest(r io.Reader) (Manifest, error) {
	b, err := readManifestPayload(r)
	if err != nil {
		return Manifest{}, err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	var manifest Manifest
	if err := dec.Decode(&manifest); err != nil {
		return Manifest{}, ErrInvalidManifest
	}
	var trailing any
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Manifest{}, ErrInvalidManifest
	}
	return manifest, nil
}

func readManifestPayload(r io.Reader) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, maxManifestBytes+1))
	if err != nil {
		return nil, ErrProviderUnavailable
	}
	if len(b) == 0 || int64(len(b)) > maxManifestBytes || strings.TrimSpace(string(b)) == "" {
		return nil, ErrInvalidManifest
	}
	return b, nil
}
