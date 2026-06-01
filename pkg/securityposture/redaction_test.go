package securityposture

import (
	"strings"
	"testing"
)

func TestRedactPublicSurfaceTextPreservesSafeText(t *testing.T) {
	value := "updates capability is degraded; caller review is required"
	if ContainsUnsafePublicSurfaceMarkers(value) {
		t.Fatalf("safe public status text should not be marked unsafe")
	}
	if got := RedactPublicSurfaceText(value); got != value {
		t.Fatalf("safe public status text changed: got %q want %q", got, value)
	}
}

func TestRedactPublicSurfaceTextRedactsUnsafeMarkers(t *testing.T) {
	cases := map[string]string{
		"authorization header":        "authorization: bearer sample",
		"bearer marker":               "provider returned Bearer sample-value",
		"refresh token marker":        "refresh_token sample-value",
		"credential marker":           "credential=sample-value",
		"private key marker":          "BEGIN PRIVATE KEY sample-value",
		"signing secret marker":       "signing secret sample-value",
		"windows private path":        `failed under C:\Users\sample\AppData\Local`,
		"unix private path":           "failed under /home/sample/.config/aegis",
		"raw manifest marker":         "raw manifest body was not safe for output",
		"raw object payload marker":   "raw_object_payload bytes were rejected",
		"raw provider payload marker": "raw provider payload should not be public",
		"raw update payload marker":   "raw_update_payload should not be public",
		"provider internal marker":    "provider_internal request state should stay private",
		"machine-local marker":        "machine-local state should stay private",
		"stack trace marker":          "panic: sample failure\ngoroutine 1 [running]",
		"profile data marker":         "private_profile_raw_content: sample private note",
		"consumer state marker":       "consumer_private_state: sample local app state",
		"app-owned state marker":      "app_owned_state_payload: sample app state",
	}

	for name, value := range cases {
		t.Run(name, func(t *testing.T) {
			if !ContainsUnsafePublicSurfaceMarkers(value) {
				t.Fatalf("expected unsafe marker detection for %q", value)
			}
			got := RedactPublicSurfaceText(value)
			if got != publicSurfaceRedactionText {
				t.Fatalf("unexpected redaction: got %q want %q", got, publicSurfaceRedactionText)
			}
			for _, forbidden := range []string{"sample-value", "sample private note", "sample local app state", "C:", "Users", "AppData", "/home/sample", "goroutine 1"} {
				if forbidden != "" && strings.Contains(got, forbidden) {
					t.Fatalf("redaction echoed unsafe substring %q in %q", forbidden, got)
				}
			}
		})
	}
}

func TestRedactPublicSurfaceTextIsDeterministicAndIdempotent(t *testing.T) {
	unsafe := "authorization: bearer sample-value"
	first := RedactPublicSurfaceText(unsafe)
	second := RedactPublicSurfaceText(unsafe)
	if first != second {
		t.Fatalf("redaction is not deterministic: first %q second %q", first, second)
	}
	third := RedactPublicSurfaceText(first)
	if third != first {
		t.Fatalf("redaction is not idempotent: got %q want %q", third, first)
	}
	if ContainsUnsafePublicSurfaceMarkers(first) {
		t.Fatalf("redaction replacement must not itself be unsafe")
	}
}

func TestRedactionHelpersDoNotExposeCategorySpecificLabels(t *testing.T) {
	got := RedactPublicSurfaceText("client_secret sample-value")
	for _, forbidden := range []string{
		"secret",
		"token",
		"credential",
		"private",
		"path",
		"manifest",
		"payload",
		"provider",
		"stack",
		"profile",
		"consumer",
		"app-owned",
	} {
		if strings.Contains(strings.ToLower(got), forbidden) {
			t.Fatalf("redaction replacement exposed category label %q in %q", forbidden, got)
		}
	}
}

func TestRedactionHelpersDoNotServiceSecurityProductActions(t *testing.T) {
	forbidden := []string{
		"Scan",
		"Quarantine",
		"Remediate",
		"Delete",
		"Clean",
		"Defender",
		"Malware",
		"Antivirus",
		"Threat",
		"Monitor",
		"Execute",
	}

	for _, name := range []string{
		"ContainsUnsafePublicSurfaceMarkers",
		"RedactPublicSurfaceText",
	} {
		for _, term := range forbidden {
			if strings.Contains(name, term) {
				t.Fatalf("helper %s must not service security-product action term %s", name, term)
			}
		}
	}
}
