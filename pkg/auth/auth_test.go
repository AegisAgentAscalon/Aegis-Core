package auth_test

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	devsecretstore "github.com/AegisAgentAscalon/aegis-core/internal/secretstore"
	"github.com/AegisAgentAscalon/aegis-core/pkg/auth"
	"github.com/AegisAgentAscalon/aegis-core/pkg/secretstore"
)

func TestPublicServiceStatusUsesSafeAppConfig(t *testing.T) {
	base := t.TempDir()
	svc, err := auth.NewService(auth.AppConfig{
		AppID:       "sample-app",
		DisplayName: "Sample App",
		ConfigPath:  filepath.Join(base, "oauth.json"),
		OAuth: auth.OAuthClientConfig{
			ClientID: "sample-client.apps.googleusercontent.com",
			Scopes:   auth.DefaultGoogleScopes(),
		},
		TokenStore: auth.TokenStoreConfig{BaseDir: base, Namespace: "sample-user"},
		Callback:   auth.CallbackConfig{Host: "127.0.0.1", Path: "/callback", PortHint: 45678},
	})
	if err != nil {
		t.Fatal(err)
	}
	status, err := svc.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !status.Configured {
		t.Fatalf("expected configured status, got %+v", status)
	}
	if status.TokenNamespace != "sample-user" {
		t.Fatalf("expected namespace to be preserved, got %q", status.TokenNamespace)
	}
}

func TestPublicProfileMissingErrorIsSafe(t *testing.T) {
	base := t.TempDir()
	svc, err := auth.NewService(auth.AppConfig{
		AppID:       "sample-app",
		DisplayName: "Sample App",
		ConfigPath:  filepath.Join(base, "oauth.json"),
		OAuth: auth.OAuthClientConfig{
			ClientID: "sample-client.apps.googleusercontent.com",
			Scopes:   auth.DefaultGoogleScopes(),
		},
		TokenStore: auth.TokenStoreConfig{BaseDir: base, Namespace: "sample-user"},
		Callback:   auth.CallbackConfig{Host: "127.0.0.1", Path: "/callback", PortHint: 45678},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = svc.Profile(context.Background())
	if !errors.Is(err, auth.ErrProfileNotFound) {
		t.Fatalf("expected ErrProfileNotFound, got %v", err)
	}
	for _, forbidden := range []string{base, "google_profile.json"} {
		if strings.Contains(err.Error(), forbidden) {
			t.Fatalf("public missing profile error leaked %q in %q", forbidden, err.Error())
		}
	}
}

func TestPublicStrictProtectedStorageConstructors(t *testing.T) {
	base := t.TempDir()
	cfg := auth.AppConfig{
		AppID:       "sample-app",
		DisplayName: "Sample App",
		ConfigPath:  filepath.Join(base, "oauth.json"),
		OAuth: auth.OAuthClientConfig{
			ClientID: "sample-client.apps.googleusercontent.com",
			Scopes:   auth.DefaultGoogleScopes(),
		},
		TokenStore: auth.TokenStoreConfig{BaseDir: base, Namespace: "sample-user"},
		Callback:   auth.CallbackConfig{Host: "127.0.0.1", Path: "/callback", PortHint: 45678},
	}
	protected := devsecretstore.NewMemoryStore()
	svc, err := auth.NewServiceWithOptions(cfg, auth.WithStrictProtectedStorage(protected))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.StartSignIn(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := auth.NewStrictService(cfg, protected); err != nil {
		t.Fatalf("explicit strict constructor failed: %v", err)
	}
	if _, err := auth.NewStrictService(cfg, nil); !errors.Is(err, auth.ErrStorageUnavailable) {
		t.Fatalf("nil protected store error = %v, want ErrStorageUnavailable", err)
	}
	var typedNil *devsecretstore.MemoryStore
	if _, err := auth.NewStrictService(cfg, typedNil); !errors.Is(err, auth.ErrStorageUnavailable) {
		t.Fatalf("typed-nil protected store error = %v, want ErrStorageUnavailable", err)
	}
	baseOnly := struct{ secretstore.Store }{Store: protected}
	if _, err := auth.NewStrictService(cfg, baseOnly); !errors.Is(err, auth.ErrStorageUnavailable) {
		t.Fatalf("base-only protected store error = %v, want ErrStorageUnavailable", err)
	}
}
