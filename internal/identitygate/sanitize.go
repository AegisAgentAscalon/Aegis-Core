package identitygate

import "strings"

func secretish(value string) bool {
	lower := strings.ToLower(value)
	for _, bad := range []string{"password", "secret", "token", "oauth", "private key", "vault key", "biometric"} {
		if strings.Contains(lower, bad) {
			return true
		}
	}
	return false
}

func safe(value string) string {
	if secretish(value) {
		return "redacted"
	}
	if len(value) > 160 {
		return value[:160]
	}
	return value
}
