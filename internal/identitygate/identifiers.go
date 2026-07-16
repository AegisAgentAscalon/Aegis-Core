package identitygate

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
	"unicode"
)

const opaqueIDBytes = 18

func newOpaqueID(prefix string) (string, error) {
	random := make([]byte, opaqueIDBytes)
	if _, err := rand.Read(random); err != nil {
		return "", fmt.Errorf("identitygate: generate %s id: %w", prefix, err)
	}
	return prefix + "_" + base64.RawURLEncoding.EncodeToString(random), nil
}

func validOpaqueReference(value string) bool {
	if value == "" || len(value) > 256 || strings.TrimSpace(value) != value {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) || unicode.IsSpace(r) {
			return false
		}
	}
	return true
}

func validProviderName(value string) bool {
	return validOpaqueReference(value) && len(value) <= 128
}
