package profilesync

import (
	"strings"

	"github.com/AegisAgentAscalon/aegis-core/pkg/relay"
)

func sanitizeReceipt(receipt relay.DeliveryReceipt) relay.DeliveryReceipt {
	receipt.MessageID = safeID(receipt.MessageID)
	receipt.Summary = safeSummary(receipt.Summary, "relay accepted envelope metadata")
	return receipt
}

func syncIssue(code, message string, blocking bool) SyncIssue {
	code = safeID(code)
	if code == "" {
		code = "profile_sync_issue"
	}
	return SyncIssue{Code: code, Message: safeSummary(message, "profile sync issue"), Blocking: blocking}
}

func safeID(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || unsafeSyncText(value) {
		return ""
	}
	return value
}

func safeSummary(value, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" || unsafeSyncText(value) {
		return fallback
	}
	return value
}

func validSyncName(value string) bool {
	value = strings.TrimSpace(value)
	return syncNamePattern.MatchString(value) && !strings.Contains(value, "..") && !strings.ContainsAny(value, `/\`) && !reservedName(value) && !unsafeSyncText(value)
}

func validExactSyncName(value string) bool {
	return value == strings.TrimSpace(value) && validSyncName(value)
}

func validSyncID(value string) bool {
	value = strings.TrimSpace(value)
	return syncIDPattern.MatchString(value) && !strings.Contains(value, "..") && !strings.ContainsAny(value, `/\`) && !unsafeSyncText(value)
}

func validExactSyncID(value string) bool {
	return value == strings.TrimSpace(value) && validSyncID(value)
}

func unsafeSyncText(value string) bool {
	lower := strings.ToLower(strings.TrimSpace(value))
	if lower == "" {
		return false
	}
	// Status and exchange summaries never need filesystem paths. Reject any
	// separator so absolute, UNC, drive-relative, and relative forms are covered
	// consistently on every host OS.
	if strings.ContainsAny(value, `/\`) {
		return true
	}
	for _, marker := range []string{"client_secret", "refresh_token", "access_token", "id_token", "auth_code", "pkce", "verifier", "private_key", "begin private key", "github_pat", "ghp_", "api_key", "apikey", "access_key", "secret_key", "authorization:", "authorization=", "bearer ", "x-api-key", "token=", "password=", "secret=", `:\`, `/users/`, `/home/`, `/tmp/`, `\\`, "appdata", "downloads", "desktop"} {
		if strings.Contains(lower, strings.ToLower(marker)) {
			return true
		}
	}
	return false
}

func reservedName(value string) bool {
	switch strings.ToUpper(strings.TrimSpace(value)) {
	case "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9":
		return true
	default:
		return false
	}
}
