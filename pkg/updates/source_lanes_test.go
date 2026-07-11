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
	"path/filepath"
	"strings"
	"testing"
)

type publicRoundTripperFunc func(*http.Request) (*http.Response, error)

func (f publicRoundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestPublicAuthenticatedLaneFacade(t *testing.T) {
	artifact := []byte("private artifact")
	sum := sha256.Sum256(artifact)
	signer := newPublicManifestSigner(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer app-owned" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/manifest":
			_ = json.NewEncoder(w).Encode(signer.sign(t, Manifest{
				SchemaVersion: 1, AppID: "aegis-test", Channel: ChannelDev, Version: "1.1.0-dev.1",
				ReleaseNotesURL: "http://" + r.Host + "/private-notes",
				Artifacts:       []Artifact{{Platform: "windows", Architecture: "amd64", Filename: "dev.zip", DownloadURL: "http://" + r.Host + "/artifact", Size: int64(len(artifact)), SHA256: hex.EncodeToString(sum[:])}},
			}))
		case "/artifact":
			_, _ = w.Write(artifact)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	u, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	transport := publicRoundTripperFunc(func(req *http.Request) (*http.Response, error) {
		clone := req.Clone(req.Context())
		clone.Header = req.Header.Clone()
		clone.Header.Set("Authorization", "Bearer app-owned")
		return http.DefaultTransport.RoundTrip(clone)
	})
	cfg := AppConfig{
		AppID: "aegis-test", DisplayName: "Aegis Test", CurrentVersion: "1.0.0", Channel: ChannelDev,
		Platform: "windows", Architecture: "amd64", Namespace: "update-lane-test", StagingDir: filepath.Join(t.TempDir(), "stage"),
		Source: SourceConfig{Provider: ProviderHTTPManifest, ManifestURL: server.URL + "/manifest", SourceID: "dev", Access: SourceAccessAppOwnedAuthenticated, RequiredManifestKeyID: signer.keyID, AllowedHTTPHosts: []string{u.Host}},
		Policy: Policy{RequireSHA256: true, AllowPrerelease: true, RequireManifestSignature: true, ManifestVerificationKeys: map[string]string{signer.keyID: signer.publicKey}},
	}
	if _, err := NewService(cfg, nil); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("missing app-owned client error = %v", err)
	}
	svc, err := NewServiceWithOptions(cfg, nil, ServiceOptions{AuthenticatedHTTPClient: &http.Client{Transport: transport}})
	if err != nil {
		t.Fatal(err)
	}
	check, err := svc.CheckForUpdates(context.Background())
	if err != nil || check.LatestRelease == nil || !check.LatestRelease.Source.Authenticated {
		t.Fatalf("check = %+v, %v", check, err)
	}
	if check.LatestRelease.ReleaseNotesURL != "" || check.LatestRelease.Source.ID != "dev" {
		t.Fatalf("private location leaked or provenance missing: %+v", check.LatestRelease)
	}
	if _, err := svc.DownloadUpdate(context.Background(), "1.1.0-dev.1"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.VerifyUpdate(context.Background(), "1.1.0-dev.1"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.StageUpdate(context.Background(), "1.1.0-dev.1"); err != nil {
		t.Fatal(err)
	}
	plan, err := svc.BuildApplyPlan(context.Background())
	if err != nil || plan.Source.ID != "dev" || !plan.Source.Authenticated {
		t.Fatalf("plan = %+v, %v", plan, err)
	}
	raw, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) == "" || containsAny(string(raw), server.URL, "Authorization", "Bearer app-owned") {
		t.Fatalf("unsafe public plan JSON: %s", raw)
	}
}

func TestPublicSetChannelStillRejectsEmptyChannel(t *testing.T) {
	cfg := AppConfig{
		AppID: "aegis-test", DisplayName: "Aegis Test", CurrentVersion: "1.0.0", Channel: ChannelStable,
		Platform: "windows", Architecture: "amd64", Namespace: "lane-test", StagingDir: t.TempDir(),
		Source: SourceConfig{Provider: ProviderFileManifest, ManifestPath: filepath.Join(t.TempDir(), "stable.json")},
		Policy: Policy{RequireSHA256: true},
	}
	svc, err := NewService(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.SetChannel(context.Background(), ""); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("empty channel error = %v", err)
	}
}

func TestPublicConfigureLanePreservesPolicyWhenOmitted(t *testing.T) {
	cfg := AppConfig{
		AppID: "aegis-test", DisplayName: "Aegis Test", CurrentVersion: "1.0.0", Channel: ChannelStable,
		Platform: "windows", Architecture: "amd64", Namespace: "lane-test", StagingDir: t.TempDir(),
		Source: SourceConfig{Provider: ProviderFileManifest, ManifestPath: filepath.Join(t.TempDir(), "stable.json"), SourceID: "stable"},
		Policy: Policy{RequireSHA256: true, MinimumVersion: "1.0.0"},
	}
	svc, err := NewService(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	state, err := svc.ConfigureLane(context.Background(), LaneConfig{Channel: ChannelDev, Source: SourceConfig{Provider: ProviderFileManifest, ManifestPath: filepath.Join(t.TempDir(), "dev.json"), SourceID: "dev"}})
	if err != nil {
		t.Fatal(err)
	}
	if state.Channel != ChannelDev || state.Source.ID != "dev" || state.Source.Access != SourceAccessLocal {
		t.Fatalf("lane state = %+v", state)
	}
}

type captureApplyAdapter struct {
	release Release
}

func (a *captureApplyAdapter) ApplyUpdate(_ context.Context, _ string, release Release) (ApplyResult, error) {
	a.release = release
	return ApplyResult{OK: true}, nil
}

func TestPublicApplyAdapterPreservesSourceAndChoreography(t *testing.T) {
	adapter := &captureApplyAdapter{}
	strategy := publicApplyAdapter{adapter: adapter}
	staged := StagedUpdate{
		Source:          SourceSummary{ID: "dev", Access: SourceAccessAppOwnedAuthenticated, Provider: ProviderHTTPManifest, Authenticated: true},
		AppID:           "aegis-test",
		Version:         "1.1.0-dev.1",
		Channel:         ChannelDev,
		Platform:        "windows",
		Architecture:    "amd64",
		ArtifactName:    "dev.zip",
		SHA256:          strings.Repeat("a", 64),
		Size:            42,
		RequiredRestart: true,
		ApplyBehavior:   "manual-restart",
	}
	if _, err := strategy.Apply(context.Background(), staged); err != nil {
		t.Fatal(err)
	}
	if adapter.release.Source != staged.Source || !adapter.release.RequiredRestart || adapter.release.ApplyBehavior != staged.ApplyBehavior {
		t.Fatalf("adapter release lost source/choreography: %+v", adapter.release)
	}
}

func TestPublicManualApplyStrategyHonorsCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := (ManualApplyStrategy{}).Apply(ctx, StagedUpdate{Version: "1.2.0"}); !errors.Is(err, ErrContextCanceled) {
		t.Fatalf("canceled manual apply error = %v", err)
	}
}

func containsAny(value string, candidates ...string) bool {
	for _, candidate := range candidates {
		if candidate != "" && len(value) >= len(candidate) {
			for i := 0; i+len(candidate) <= len(value); i++ {
				if value[i:i+len(candidate)] == candidate {
					return true
				}
			}
		}
	}
	return false
}
