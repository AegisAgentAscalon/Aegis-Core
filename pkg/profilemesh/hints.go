package profilemesh

import (
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

var zeroHintTime time.Time

func validateRawHints(snapshot ProfileMeshSnapshot, now time.Time) error {
	return validateHintFields(snapshot, now, true)
}
func validateHintFields(snapshot ProfileMeshSnapshot, now time.Time, admission bool) error {
	if len(snapshot.RelayHints) > 1024 || len(snapshot.EndpointHints) > 1024 {
		return ErrInvalidProfileSnapshot
	}
	if len(snapshot.RelayHints)+len(snapshot.EndpointHints) > 0 && snapshot.SchemaVersion != ProfileMeshSnapshotSchemaVersion {
		return ErrInvalidProfileSnapshot
	}
	devices := make(map[string]bool, len(snapshot.Devices))
	for _, d := range snapshot.Devices {
		devices[d.DeviceID] = true
	}
	common := func(profile, device string, kind ProfileEndpointType, expires, seen time.Time, caps []string, metadata map[string]string) bool {
		if !hintID(profile) || profile != snapshot.Profile.ProfileID || !hintID(device) || !devices[device] || !validHintType(kind) {
			return false
		}
		if !expires.IsZero() && !seen.IsZero() && !expires.After(seen) {
			return false
		}
		if admission && !seen.IsZero() && seen.After(now.Add(defaultFutureSkew)) {
			return false
		}
		if len(caps) > 128 || len(metadata) > 64 {
			return false
		}
		for _, capability := range caps {
			if !hintText(capability, 128) || unsafeProfileSyncDetail(capability) {
				return false
			}
		}
		keys := make(map[string]bool, len(metadata))
		for key, value := range metadata {
			if !hintText(key, 128) || !hintText(value, 1024) {
				return false
			}
			normalized := strings.TrimSpace(key)
			if normalized == "" || keys[normalized] {
				return false
			}
			keys[normalized] = true
			joined := strings.ToLower(normalized + " " + strings.TrimSpace(value))
			if strings.Contains(joined, "secret") || strings.Contains(joined, "token") || strings.Contains(joined, "private") || unsafeProfileSyncDetail(joined) {
				return false
			}
		}
		return true
	}
	relayKeys := map[[4]string]bool{}
	for _, hint := range snapshot.RelayHints {
		if !common(hint.ProfileID, hint.DeviceID, hint.EndpointType, hint.ExpiresAt, hint.LastSeen, hint.Capabilities, hint.Metadata) || hint.EndpointType != EndpointRelay || !hintID(hint.RelayProviderID) {
			return ErrInvalidProfileSnapshot
		}
		key := [4]string{hint.ProfileID, hint.DeviceID, hint.RelayProviderID, string(hint.EndpointType)}
		if relayKeys[key] {
			return ErrInvalidProfileSnapshot
		}
		relayKeys[key] = true
	}
	endpointKeys := map[[4]string]bool{}
	for _, hint := range snapshot.EndpointHints {
		if !common(hint.ProfileID, hint.DeviceID, hint.EndpointType, hint.ExpiresAt, hint.LastSeen, hint.Capabilities, hint.Metadata) || !validHintAddress(hint.Address) {
			return ErrInvalidProfileSnapshot
		}
		key := [4]string{hint.ProfileID, hint.DeviceID, string(hint.EndpointType), hint.Address}
		if endpointKeys[key] {
			return ErrInvalidProfileSnapshot
		}
		endpointKeys[key] = true
	}
	return nil
}
func hintID(value string) bool {
	return value == strings.TrimSpace(value) && hintText(value, 128) && validID(value)
}
func hintText(value string, limit int) bool {
	if len(value) > limit || !utf8.ValidString(value) {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}
func validHintType(kind ProfileEndpointType) bool {
	return kind == EndpointLocal || kind == EndpointDirect || kind == EndpointRelay
}
func validHintAddress(address string) bool {
	if address == "" {
		return true
	}
	if address != strings.TrimSpace(address) || !hintText(address, 2048) || unsafeProfileSyncDetail(address) || strings.Contains(address, `\`) {
		return false
	}
	if strings.Contains(address, "://") {
		parsed, err := url.Parse(address)
		if err != nil || parsed.User != nil || parsed.ForceQuery || parsed.RawQuery != "" || strings.Contains(address, "?") || strings.Contains(address, "#") || parsed.Opaque != "" || !validHintAuthority(parsed.Host) {
			return false
		}
		if parsed.Scheme != "https" && parsed.Scheme != "http" {
			return false
		}
		if parsed.Scheme == "http" {
			host := parsed.Hostname()
			ip := net.ParseIP(host)
			if !strings.EqualFold(host, "localhost") && (ip == nil || (!ip.IsLoopback() && !ip.IsPrivate())) {
				return false
			}
		}
		path := parsed.Path
		if !hintText(path, 2048) || unsafeProfileSyncDetail(path) || strings.ContainsAny(path, `\?#@`) {
			return false
		}
		for _, part := range strings.Split(path, "/") {
			if part == "." || part == ".." {
				return false
			}
		}
		return true
	}
	return validHintAuthority(address)
}
func validHintAuthority(authority string) bool {
	if authority == "" || strings.ContainsAny(authority, "/?#@%") {
		return false
	}
	if net.ParseIP(authority) != nil {
		return true
	}
	if strings.HasPrefix(authority, "[") && strings.HasSuffix(authority, "]") {
		return net.ParseIP(authority[1:len(authority)-1]) != nil
	}
	host := authority
	if strings.Contains(authority, ":") {
		var port string
		var err error
		host, port, err = net.SplitHostPort(authority)
		if err != nil || port == "" {
			return false
		}
		for _, c := range port {
			if c < '0' || c > '9' {
				return false
			}
		}
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return false
		}
	}
	if net.ParseIP(host) != nil {
		return true
	}
	if len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
		for i, c := range label {
			letterDigit := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
			if !letterDigit && (c != '-' || i == 0 || i == len(label)-1) {
				return false
			}
		}
	}
	return true
}
