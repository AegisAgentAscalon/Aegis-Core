package main

import (
	"context"
	"encoding/json"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunProofUsesPublicAPIsAndSafeOutput(t *testing.T) {
	summary, err := RunProof(context.Background(), t.TempDir())
	if err != nil {
		t.Fatalf("RunProof returned error: %v", err)
	}
	if !summary.SafeOutput {
		t.Fatalf("summary is not marked safe: %+v", summary)
	}
	if !summary.AppBridge.OverviewReady || summary.AppBridge.DisabledCards == 0 {
		t.Fatalf("app bridge proof did not show ready overview plus disabled cards: %+v", summary.AppBridge)
	}
	if !summary.AppBridge.RelayDegradedNonFatal || !summary.AppBridge.RelayDisabledNonFatal {
		t.Fatalf("app bridge proof did not show disabled/degraded non-fatal behavior: %+v", summary.AppBridge)
	}
	if !summary.Relay.LocalProviderAvailable || !summary.Relay.MailboxOpened || !summary.Relay.EnvelopeDelivered || !summary.Relay.DuplicateRejected {
		t.Fatalf("relay proof incomplete: %+v", summary.Relay)
	}
	if !summary.ProfileSync.LocalStoreAvailable || !summary.ProfileSync.PushedSnapshot || !summary.ProfileSync.PushedProposal ||
		!summary.ProfileSync.DuplicatePushIdempotent || !summary.ProfileSync.PulledSnapshot || !summary.ProfileSync.PulledProposal ||
		!summary.ProfileSync.ConflictReviewRequired || !summary.ProfileSync.ExchangeCompleted ||
		!summary.ProfileSync.PersistedAcrossStoreOpen || !summary.ProfileSync.LastExchangePersisted {
		t.Fatalf("profile sync proof incomplete: %+v", summary.ProfileSync)
	}
	if !summary.PartialFailure.DisabledSyncNonFatal || !summary.PartialFailure.MissingTransportSafe ||
		!summary.PartialFailure.CorruptStoreSafe || !summary.PartialFailure.NoPrivatePathLeak ||
		!summary.PartialFailure.NoRawPayloadLeak {
		t.Fatalf("partial failure proof incomplete: %+v", summary.PartialFailure)
	}
	assertProofJSONSafe(t, summary)
}

func TestExampleImportsPublicPackagesOnly(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob go files: %v", err)
	}
	modulePrefix := "github.com/AegisAgentAscalon/aegis-core/"
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		fset := token.NewFileSet()
		parsed, err := parser.ParseFile(fset, file, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse %s: %v", file, err)
		}
		for _, spec := range parsed.Imports {
			path := strings.Trim(spec.Path.Value, `"`)
			if strings.Contains(path, "/internal/") || strings.Contains(path, "/examples/") {
				t.Fatalf("%s imports forbidden path %q", file, path)
			}
			if strings.HasPrefix(path, modulePrefix) && !strings.HasPrefix(path, modulePrefix+"pkg/") {
				t.Fatalf("%s imports non-public module path %q", file, path)
			}
		}
	}
}

func TestExampleHasNoNamedConsumerReferences(t *testing.T) {
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

func assertProofJSONSafe(t *testing.T, value any) {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal proof summary: %v", err)
	}
	text := strings.ToLower(string(raw))
	for _, forbidden := range []string{
		`:\`,
		"/users/",
		"/home/",
		"appdata",
		"generic metadata proof payload",
		"client_secret",
		"access_token",
		"refresh_token",
		"private_key",
		"token=",
		"secret=",
	} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("proof summary leaked forbidden text %q: %s", forbidden, string(raw))
		}
	}
}
