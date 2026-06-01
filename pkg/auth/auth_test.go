package auth_test

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/AegisAgentAscalon/aegis-core/pkg/auth"
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
