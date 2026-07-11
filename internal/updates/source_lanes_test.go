package updates

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestAuthenticatedSourceUsesOnlyCredentialScopedClientAndIsolatesLaneState(t *testing.T) {
	artifact := []byte("private development artifact")
	sum := sha256.Sum256(artifact)
	keyID, publicKey, sign := testManifestSigner(t)

	var mu sync.Mutex
	privateRequests := 0
	publicRequests := 0
	privateServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer private-test-credential" {
			t.Errorf("private request missing app-owned credential: %q", r.Header.Get("Authorization"))
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		mu.Lock()
		privateRequests++
		mu.Unlock()
		switch r.URL.Path {
		case "/manifest":
			manifest := Manifest{
				SchemaVersion: SchemaVersion, AppID: "sample-app", Channel: ChannelDev, Version: "1.1.0-dev.1",
				ReleaseNotesURL: "http://" + r.Host + "/notes",
				Artifacts:       []Artifact{{Platform: "windows", Architecture: "amd64", Filename: "sample-1.1.0-dev.1.zip", DownloadURL: "http://" + r.Host + "/artifact", Size: int64(len(artifact)), SHA256: hex.EncodeToString(sum[:])}},
			}
			_ = json.NewEncoder(w).Encode(sign(manifest))
		case "/artifact":
			_, _ = w.Write(artifact)
		default:
			http.NotFound(w, r)
		}
	}))
	defer privateServer.Close()

	publicArtifact := []byte("public stable artifact")
	publicSum := sha256.Sum256(publicArtifact)
	publicServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "" {
			t.Errorf("credential leaked to public source: %q", got)
		}
		mu.Lock()
		publicRequests++
		mu.Unlock()
		switch r.URL.Path {
		case "/manifest":
			_ = json.NewEncoder(w).Encode(Manifest{
				SchemaVersion: SchemaVersion, AppID: "sample-app", Channel: ChannelStable, Version: "1.2.0",
				Artifacts: []Artifact{{Platform: "windows", Architecture: "amd64", Filename: "sample-1.2.0.zip", DownloadURL: "http://" + r.Host + "/artifact", Size: int64(len(publicArtifact)), SHA256: hex.EncodeToString(publicSum[:])}},
			})
		case "/artifact":
			_, _ = w.Write(publicArtifact)
		default:
			http.NotFound(w, r)
		}
	}))
	defer publicServer.Close()

	privateTransport := roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		clone := req.Clone(req.Context())
		clone.Header = req.Header.Clone()
		clone.Header.Set("Authorization", "Bearer private-test-credential")
		return http.DefaultTransport.RoundTrip(clone)
	})
	publicTransport := roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		if req.Header.Get("Authorization") != "" {
			t.Fatalf("public transport received authorization header")
		}
		return http.DefaultTransport.RoundTrip(req)
	})

	cfg := AppConfig{
		AppID: "sample-app", DisplayName: "Sample App", CurrentVersion: "1.0.0", Channel: ChannelDev,
		Platform: "windows", Architecture: "amd64", Namespace: "default", StagingDir: filepath.Join(t.TempDir(), "staging"),
		Source: SourceConfig{Provider: ProviderHTTPManifest, ManifestURL: privateServer.URL + "/manifest", SourceID: "dev", Access: SourceAccessAppOwnedAuthenticated, RequiredManifestKeyID: keyID, AllowedHTTPHosts: []string{mustURL(t, privateServer.URL).Host}},
		Policy: Policy{RequireSHA256: true, AllowPrerelease: true, RequireManifestSignature: true, ManifestVerificationKeys: map[string]string{keyID: publicKey}},
	}
	svc, err := NewServiceWithOptions(cfg, nil, ServiceOptions{
		HTTPClient: &http.Client{Transport: publicTransport}, AuthenticatedHTTPClient: &http.Client{Transport: privateTransport},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	check, err := svc.CheckForUpdates(ctx)
	if err != nil || !check.UpdateAvailable || check.LatestRelease == nil {
		t.Fatalf("private check = %+v, %v", check, err)
	}
	if !check.LatestRelease.Source.Authenticated || check.LatestRelease.Source.ID != "dev" || check.LatestRelease.ReleaseNotesURL != "" {
		t.Fatalf("unsafe/incorrect private release provenance: %+v", check.LatestRelease)
	}
	if _, err := svc.DownloadUpdate(ctx, "1.1.0-dev.1"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.VerifyUpdate(ctx, "1.1.0-dev.1"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.StageUpdate(ctx, "1.1.0-dev.1"); err != nil {
		t.Fatal(err)
	}
	devStatus, err := svc.GetStatus(ctx)
	if err != nil || devStatus.StagedVersion == "" || devStatus.Source.ID != "dev" {
		t.Fatalf("dev status = %+v, %v", devStatus, err)
	}
	assertUpdateJSONSafe(t, devStatus)

	stableSource := SourceConfig{Provider: ProviderHTTPManifest, ManifestURL: publicServer.URL + "/manifest", SourceID: "stable", Access: SourceAccessPublic, AllowedHTTPHosts: []string{mustURL(t, publicServer.URL).Host}}
	stablePolicy := Policy{RequireSHA256: true}
	stableStatus, err := svc.ConfigureLane(ctx, LaneConfig{Channel: ChannelStable, Source: stableSource, Policy: &stablePolicy})
	if err != nil {
		t.Fatal(err)
	}
	if stableStatus.StagedVersion != "" || stableStatus.Verified || stableStatus.Source.ID != "stable" {
		t.Fatalf("dev state crossed into stable lane: %+v", stableStatus)
	}
	if _, err := svc.CheckForUpdates(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.DownloadUpdate(ctx, "1.2.0"); err != nil {
		t.Fatal(err)
	}

	devPolicy := cfg.Policy
	restored, err := svc.ConfigureLane(ctx, LaneConfig{Channel: ChannelDev, Source: cfg.Source, Policy: &devPolicy})
	if err != nil {
		t.Fatal(err)
	}
	if restored.StagedVersion != "1.1.0-dev.1" || !restored.Verified {
		t.Fatalf("dev scoped state was not restored: %+v", restored)
	}
	mu.Lock()
	defer mu.Unlock()
	if privateRequests < 2 || publicRequests < 2 {
		t.Fatalf("expected manifest and artifact through each transport, private=%d public=%d", privateRequests, publicRequests)
	}
}

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func TestAuthenticatedSourceRequiresPinnedSigningKeyAndExactHost(t *testing.T) {
	keyID, publicKey, _ := testManifestSigner(t)
	cfg := testConfig(t)
	cfg.Source = SourceConfig{
		Provider: ProviderHTTPManifest, ManifestURL: "https://updates.example.test/manifest.json", SourceID: "dev", Access: SourceAccessAppOwnedAuthenticated,
		RequiredManifestKeyID: keyID, AllowedHTTPHosts: []string{"updates.example.test"},
	}
	cfg.Policy = Policy{RequireSHA256: true, RequireManifestSignature: true, ManifestVerificationKeys: map[string]string{keyID: publicKey}}
	if _, err := NewService(cfg, nil); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("missing authenticated client error = %v", err)
	}
	if _, err := NewServiceWithOptions(cfg, nil, ServiceOptions{AuthenticatedHTTPClient: &http.Client{}}); err != nil {
		t.Fatalf("valid authenticated source rejected: %v", err)
	}

	bad := cfg
	bad.Source.AllowedHTTPHosts = []string{"[[::1]]"}
	if _, err := NewServiceWithOptions(bad, nil, ServiceOptions{AuthenticatedHTTPClient: &http.Client{}}); !errors.Is(err, ErrInvalidProvider) {
		t.Fatalf("malformed IPv6 allowlist error = %v", err)
	}
	for _, host := range []string{"updates.example.test:https", "updates.example.test:0", "updates.example.test:65536"} {
		bad = cfg
		bad.Source.AllowedHTTPHosts = []string{host}
		if _, err := NewServiceWithOptions(bad, nil, ServiceOptions{AuthenticatedHTTPClient: &http.Client{}}); !errors.Is(err, ErrInvalidProvider) {
			t.Fatalf("invalid allowlist authority %q error = %v", host, err)
		}
	}
	bad = cfg
	bad.Source.ManifestURL = "https://user:password@updates.example.test/manifest.json"
	if _, err := NewServiceWithOptions(bad, nil, ServiceOptions{AuthenticatedHTTPClient: &http.Client{}}); !errors.Is(err, ErrInvalidProvider) {
		t.Fatalf("URL userinfo error = %v", err)
	}
	bad = cfg
	bad.Source.ManifestURL = "https://updates.example.test/manifest.json#secret"
	if _, err := NewServiceWithOptions(bad, nil, ServiceOptions{AuthenticatedHTTPClient: &http.Client{}}); !errors.Is(err, ErrInvalidProvider) {
		t.Fatalf("URL fragment error = %v", err)
	}
	bad = cfg
	bad.Source.RequiredManifestKeyID = "other-key"
	if _, err := NewServiceWithOptions(bad, nil, ServiceOptions{AuthenticatedHTTPClient: &http.Client{}}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("missing pinned key error = %v", err)
	}
}

func TestPublicSourceMayPinManifestSigningKey(t *testing.T) {
	keyID, publicKey, _ := testManifestSigner(t)
	cfg := testConfig(t)
	cfg.Source = SourceConfig{
		Provider:              ProviderHTTPManifest,
		ManifestURL:           "https://updates.example.test/manifest.json",
		SourceID:              "stable",
		Access:                SourceAccessPublic,
		RequiredManifestKeyID: keyID,
		AllowedHTTPHosts:      []string{"updates.example.test"},
	}
	cfg.Policy = Policy{
		RequireSHA256:            true,
		RequireManifestSignature: true,
		ManifestVerificationKeys: map[string]string{keyID: publicKey},
	}
	if _, err := NewServiceWithOptions(cfg, nil, ServiceOptions{HTTPClient: &http.Client{}}); err != nil {
		t.Fatalf("valid public pinned source rejected: %v", err)
	}

	bad := cfg
	bad.Policy.RequireManifestSignature = false
	if _, err := NewServiceWithOptions(bad, nil, ServiceOptions{HTTPClient: &http.Client{}}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("unsigned public pinned source error = %v", err)
	}
}

func TestConcurrentExplicitLaneChangeRejectsStaleCheck(t *testing.T) {
	keyID, publicKey, sign := testManifestSigner(t)
	started := make(chan struct{})
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-release
		artifact := []byte("artifact")
		sum := sha256.Sum256(artifact)
		_ = json.NewEncoder(w).Encode(sign(Manifest{
			SchemaVersion: SchemaVersion, AppID: "sample-app", Channel: ChannelDev, Version: "1.1.0-dev.1",
			Artifacts: []Artifact{{Platform: "windows", Architecture: "amd64", Filename: "dev.zip", DownloadURL: "http://" + r.Host + "/artifact", Size: int64(len(artifact)), SHA256: hex.EncodeToString(sum[:])}},
		}))
	}))
	defer server.Close()
	cfg := testConfig(t)
	cfg.Channel = ChannelDev
	cfg.Source = SourceConfig{Provider: ProviderHTTPManifest, ManifestURL: server.URL + "/manifest", SourceID: "dev", Access: SourceAccessAppOwnedAuthenticated, RequiredManifestKeyID: keyID, AllowedHTTPHosts: []string{mustURL(t, server.URL).Host}}
	cfg.Policy = Policy{RequireSHA256: true, AllowPrerelease: true, RequireManifestSignature: true, ManifestVerificationKeys: map[string]string{keyID: publicKey}}
	svc, err := NewServiceWithOptions(cfg, nil, ServiceOptions{AuthenticatedHTTPClient: &http.Client{}})
	if err != nil {
		t.Fatal(err)
	}
	errCh := make(chan error, 1)
	go func() { _, err := svc.CheckForUpdates(context.Background()); errCh <- err }()
	<-started
	localCfg, artifactPath, artifactHash := testUpdateFiles(t, "1.2.0")
	writeManifest(t, localCfg.Source.ManifestPath, testManifest(localCfg, "1.2.0", artifactPath, artifactHash))
	if _, err := svc.ConfigureLane(context.Background(), LaneConfig{Channel: ChannelStable, Source: SourceConfig{Provider: ProviderFileManifest, ManifestPath: localCfg.Source.ManifestPath, SourceID: "stable", Access: SourceAccessLocal}, Policy: &localCfg.Policy}); err != nil {
		t.Fatal(err)
	}
	close(release)
	if err := <-errCh; !errors.Is(err, ErrUpdateStateChanged) {
		t.Fatalf("stale check error = %v", err)
	}
}

type blockingApply struct {
	started chan struct{}
	release chan struct{}
}

func (b blockingApply) Apply(ctx context.Context, staged StagedUpdate) (ApplyResult, error) {
	close(b.started)
	select {
	case <-b.release:
		return ApplyResult{OK: true}, nil
	case <-ctx.Done():
		return ApplyResult{}, ctx.Err()
	}
}

func TestApplySerializesStagedStateAndLaneMutation(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	svc, _ := stageInternalUpdate(t, "1.2.0", blockingApply{started: started, release: release})
	resultCh := make(chan error, 1)
	go func() { _, err := svc.ApplyUpdate(context.Background()); resultCh <- err }()
	<-started
	if _, err := svc.ApplyUpdate(context.Background()); !errors.Is(err, ErrApplyInProgress) {
		t.Fatalf("second apply error = %v", err)
	}
	if _, err := svc.ClearStagedUpdate(context.Background()); !errors.Is(err, ErrApplyInProgress) {
		t.Fatalf("clear during apply error = %v", err)
	}
	if _, err := svc.ConfigureLane(context.Background(), LaneConfig{Channel: ChannelStable, Source: svc.cfg.Source}); !errors.Is(err, ErrApplyInProgress) {
		t.Fatalf("lane mutation during apply error = %v", err)
	}
	if _, err := svc.StageUpdate(context.Background(), "1.2.0"); !errors.Is(err, ErrApplyInProgress) {
		t.Fatalf("stage during apply error = %v", err)
	}
	close(release)
	if err := <-resultCh; err != nil {
		t.Fatal(err)
	}
}

func TestArtifactCannotCollideWithUpdateMetadata(t *testing.T) {
	cfg, artifactPath, hash := testUpdateFiles(t, "1.2.0")
	manifest := testManifest(cfg, "1.2.0", artifactPath, hash)
	manifest.Artifacts[0].Filename = "staged_update.json"
	writeManifest(t, cfg.Source.ManifestPath, manifest)
	svc, err := NewService(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CheckForUpdates(context.Background()); !errors.Is(err, ErrInvalidManifest) {
		t.Fatalf("metadata filename collision error = %v", err)
	}
}

func TestStoreRejectsIntermediateSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation requires platform-specific privileges")
	}
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, "sample-app")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	cfg := testConfig(t)
	cfg.StagingDir = root
	if _, err := NewService(cfg, nil); !errors.Is(err, ErrStorageUnavailable) {
		t.Fatalf("intermediate symlink error = %v", err)
	}
}

func TestExplicitLanePolicyChangeDoesNotReuseState(t *testing.T) {
	cfg, artifactPath, hash := testUpdateFiles(t, "1.2.0")
	cfg.Source.SourceID = "stable"
	writeManifest(t, cfg.Source.ManifestPath, testManifest(cfg, "1.2.0", artifactPath, hash))
	svc, err := NewService(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CheckForUpdates(context.Background()); err != nil {
		t.Fatal(err)
	}
	originalStore := svc.store.dir
	policy := cfg.Policy
	policy.MinimumVersion = "1.1.0"
	status, err := svc.ConfigureLane(context.Background(), LaneConfig{Channel: cfg.Channel, Source: cfg.Source, Policy: &policy})
	if err != nil {
		t.Fatal(err)
	}
	if svc.store.dir == originalStore || status.LatestRelease != nil {
		t.Fatalf("policy-scoped state reused: old=%s new=%s status=%+v", originalStore, svc.store.dir, status)
	}
}

func TestSourceAllowsOnlyAllowlistedRedirectDestination(t *testing.T) {
	src := normalizeSource(SourceConfig{Provider: ProviderHTTPManifest, SourceID: "dev", Access: SourceAccessAppOwnedAuthenticated, AllowedHTTPHosts: []string{"updates.example.test"}})
	allowed, _ := url.Parse("https://updates.example.test/artifact?X-Amz-Signature=value")
	blocked, _ := url.Parse("https://evil.example.test/artifact")
	if !sourceAllowsURL(src, allowed, true) {
		t.Fatal("allowlisted signed redirect rejected")
	}
	if sourceAllowsURL(src, allowed, false) {
		t.Fatal("signed query accepted in persisted manifest URL")
	}
	if sourceAllowsURL(src, blocked, true) {
		t.Fatal("unallowlisted redirect accepted")
	}
}

func TestSourceKeyIncludesAccessTrustAndDestinationPolicy(t *testing.T) {
	base := SourceConfig{
		Provider:              ProviderHTTPManifest,
		ManifestURL:           "https://updates.example.test/manifest.json",
		SourceID:              "stable",
		Access:                SourceAccessPublic,
		RequiredManifestKeyID: "stable-key",
		AllowedHTTPHosts:      []string{"updates.example.test"},
	}
	baseline := sourceKey(base)
	variants := []SourceConfig{
		func() SourceConfig { v := base; v.SourceID = "preview"; return v }(),
		func() SourceConfig { v := base; v.Access = SourceAccessAppOwnedAuthenticated; return v }(),
		func() SourceConfig { v := base; v.RequiredManifestKeyID = "preview-key"; return v }(),
		func() SourceConfig { v := base; v.AllowedHTTPHosts = []string{"cdn.example.test"}; return v }(),
	}
	for i, variant := range variants {
		if got := sourceKey(variant); got == baseline {
			t.Fatalf("variant %d did not change source provenance key", i)
		}
	}
}

func TestSafeSourceSummaryContainsNoLocation(t *testing.T) {
	summary := sourceSummary(normalizeSource(SourceConfig{Provider: ProviderHTTPManifest, ManifestURL: "https://updates.example.test/path", SourceID: "dev", Access: SourceAccessAppOwnedAuthenticated, RequiredManifestKeyID: "key", AllowedHTTPHosts: []string{"updates.example.test"}}))
	raw, err := json.Marshal(summary)
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for _, forbidden := range []string{"updates.example.test", "https://", "key"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("source summary leaked %q: %s", forbidden, text)
		}
	}
}
