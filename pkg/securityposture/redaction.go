package securityposture

import "strings"

const publicSurfaceRedactionText = "[redacted-public-surface]"

var unsafePublicSurfaceMarkers = []string{
	"authorization:",
	"bearer ",
	"access_token",
	"refresh_token",
	"id_token",
	"auth_code",
	"client_secret",
	"api_key",
	"apikey",
	"github_pat",
	"ghp_",
	"token=",
	"password=",
	"secret=",
	"private_key",
	"begin private key",
	"signing_secret",
	"signing secret",
	"credential=",
	"credentials=",
	"raw_manifest",
	"raw manifest",
	"raw_object_payload",
	"raw object payload",
	"raw_provider_payload",
	"raw provider payload",
	"raw_update_payload",
	"raw update payload",
	"provider_internal",
	"provider internal",
	"machine_local_state",
	"machine-local state",
	"private_profile_raw_content",
	"profile kb raw content",
	"consumer_private_state",
	"consumer private state",
	"app_owned_state_payload",
	"app-owned state payload",
	"goroutine ",
	"panic:",
	"stack trace",
	"traceback",
	"runtime/debug.stack",
}

var unsafePublicSurfacePathMarkers = []string{
	"c:\\users\\",
	"c:/users/",
	"\\desktop\\",
	"/desktop/",
	"\\downloads\\",
	"/downloads/",
	"\\appdata\\",
	"/users/",
	"/home/",
}

// ContainsUnsafePublicSurfaceMarkers reports whether value includes obvious
// marker text that should not be emitted through public status, error, issue,
// or summary surfaces.
//
// This helper is deterministic public-surface hygiene only. It does not read
// files, inspect objects, call providers, scan arbitrary content, discover
// secrets, make trust decisions, or remediate anything.
func ContainsUnsafePublicSurfaceMarkers(value string) bool {
	if value == "" || value == publicSurfaceRedactionText {
		return false
	}

	lower := strings.ToLower(value)
	for _, marker := range unsafePublicSurfaceMarkers {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	for _, marker := range unsafePublicSurfacePathMarkers {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

// RedactPublicSurfaceText returns value unchanged when it does not contain
// obvious unsafe public-surface markers. When unsafe markers are present, it
// returns a stable generic replacement that does not echo the unsafe substring
// or reveal a category-specific finding.
//
// Callers are still responsible for avoiding raw private/internal data in
// public DTOs. This helper reduces accidental leakage in public text; it is not
// a data-loss-prevention product, scanner, vault, or security control plane.
func RedactPublicSurfaceText(value string) string {
	if ContainsUnsafePublicSurfaceMarkers(value) {
		return publicSurfaceRedactionText
	}
	return value
}
