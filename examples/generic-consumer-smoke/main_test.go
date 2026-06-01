package main

import (
	"context"
	"encoding/json"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunSmokeUsesPublicAPIsAndSafeOutput(t *testing.T) {
	summary, err := RunSmoke(context.Background(), t.TempDir())
	if err != nil {
		t.Fatalf("RunSmoke returned error: %v", err)
	}
	assertSmokeComplete(t, summary)
	assertSmokeJSONSafe(t, summary)
}

func TestGoRunSmokeProducesSafeJSON(t *testing.T) {
	cmd := exec.Command("go", "run", ".")
	raw, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go run failed: %v\n%s", err, string(raw))
	}
	var summary SmokeSummary
	if err := json.Unmarshal(raw, &summary); err != nil {
		t.Fatalf("smoke output is not JSON: %v\n%s", err, string(raw))
	}
	assertSmokeComplete(t, summary)
	assertSmokeJSONSafe(t, summary)
}

func TestSmokeImportsPublicPackagesOnly(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob go files: %v", err)
	}
	modulePrefix := "github.com/AegisAgentAscalon/aegis-core/"
	for _, file := range files {
		fset := token.NewFileSet()
		parsed, err := parser.ParseFile(fset, file, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse %s: %v", file, err)
		}
		for _, spec := range parsed.Imports {
			path := strings.Trim(spec.Path.Value, `"`)
			if strings.HasPrefix(path, ".") {
				t.Fatalf("%s imports local relative path %q", file, path)
			}
			if strings.Contains(path, "/internal/") || strings.Contains(path, "/examples/") {
				t.Fatalf("%s imports forbidden path %q", file, path)
			}
			if strings.HasPrefix(path, modulePrefix) && !strings.HasPrefix(path, modulePrefix+"pkg/") {
				t.Fatalf("%s imports non-public module path %q", file, path)
			}
		}
	}
}

func TestSmokeHasNoNamedConsumerReferences(t *testing.T) {
	for _, file := range []string{"main.go", "README.md"} {
		raw, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("read %s: %v", file, err)
		}
		text := strings.ToLower(string(raw))
		for _, forbidden := range []string{
			"named-consumer-app",
			"named-consumer-current",
			"named-consumer.local",
			"consumer-secret-fixture",
			"specific external current-app",
			"specific external local domain",
		} {
			if strings.Contains(text, forbidden) {
				t.Fatalf("%s contains forbidden consumer reference %q", file, forbidden)
			}
		}
	}
}

func assertSmokeComplete(t *testing.T, summary SmokeSummary) {
	t.Helper()
	if !summary.SafeOutput {
		t.Fatalf("summary is not marked safe: %+v", summary)
	}
	if !summary.AppBridge.OverviewReady || !summary.AppBridge.DisabledCardsNonFatal || !summary.AppBridge.RelayDegradedNonFatal ||
		!summary.AppBridge.StatusBridgeReady || !summary.AppBridge.StatusBridgeDegradedNonFatal || !summary.AppBridge.StatusBridgeProfileSyncVisible {
		t.Fatalf("app bridge smoke incomplete: %+v", summary.AppBridge)
	}
	if !summary.SetupState.OverviewReady || !summary.SetupState.WarningSafe {
		t.Fatalf("setupstate smoke incomplete: %+v", summary.SetupState)
	}
	if !summary.Updates.StatusConfigured || !summary.Updates.UpdateAvailable || !summary.Updates.Downloaded ||
		!summary.Updates.Verified || !summary.Updates.Staged || !summary.Updates.StagedSummarySafe ||
		!summary.Updates.ApplyPlanAppOwned || !summary.Updates.ApplyPlanSafe ||
		!summary.Updates.NoApplyExecuted || !summary.Updates.ClearedStagedState {
		t.Fatalf("update smoke incomplete: %+v", summary.Updates)
	}
	if !summary.Relay.ProviderAvailable || !summary.Relay.EnvelopeDelivered || !summary.Relay.ReceiptSafe {
		t.Fatalf("relay smoke incomplete: %+v", summary.Relay)
	}
	if !summary.ProfileSync.DisabledNonFatal || !summary.ProfileSync.MissingTransportDegraded ||
		!summary.ProfileSync.RelayTransportStatusSafe || !summary.ProfileSync.StoreOnlyPlanSafe ||
		!summary.ProfileSync.NoProfileTruthPromotion || !summary.ProfileSync.NoAutomaticMergePerformed {
		t.Fatalf("profile sync smoke incomplete: %+v", summary.ProfileSync)
	}
	if !summary.CloudSync.MissingProviderDegraded || !summary.CloudSync.ObjectStored ||
		!summary.CloudSync.ManifestVerified || !summary.CloudSync.SameManifestClassified ||
		!summary.CloudSync.NoProfileTruthPromotion {
		t.Fatalf("cloud sync smoke incomplete: %+v", summary.CloudSync)
	}
}

func assertSmokeJSONSafe(t *testing.T, value any) {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal smoke value: %v", err)
	}
	text := strings.ToLower(string(raw))
	for _, forbidden := range []string{
		`:\`,
		"/users/",
		"/home/",
		"appdata",
		"generic update artifact",
		"generic relay smoke payload",
		"client_secret",
		"access_token",
		"refresh_token",
		"private_key",
		"token=",
		"secret=",
	} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("smoke summary leaked forbidden text %q: %s", forbidden, string(raw))
		}
	}
}
