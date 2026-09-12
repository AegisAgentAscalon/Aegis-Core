package updates

import (
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
)

var (
	safeNamePattern     = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$`)
	safeFilenamePattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,180}$`)
	versionPattern      = regexp.MustCompile(`^v?[0-9]+(\.[0-9]+){0,3}(-[A-Za-z0-9._-]+)?$`)
	sha256Pattern       = regexp.MustCompile(`^[a-fA-F0-9]{64}$`)
)

func validSafeName(s string) bool {
	s = strings.TrimSpace(s)
	if !safeNamePattern.MatchString(s) {
		return false
	}
	if strings.Contains(s, "..") || strings.ContainsAny(s, `/\`) {
		return false
	}
	return !windowsReservedName(s)
}

func validArtifactFilename(name string) bool {
	return validFilenameSegment(name) && !reservedUpdateMetadataName(name)
}

func validFilenameSegment(name string) bool {
	name = strings.TrimSpace(name)
	return safeFilenamePattern.MatchString(name) && filepath.Base(name) == name && !strings.Contains(name, "..") && !strings.ContainsAny(name, `/\`) && !windowsReservedName(name)
}

func reservedUpdateMetadataName(name string) bool {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "selected_update.json", "downloaded_update.json", "verified_update.json", "staged_update.json", "lifecycle_envelope.json":
		return true
	default:
		return false
	}
}

func windowsReservedName(name string) bool {
	upper := strings.ToUpper(strings.TrimSpace(name))
	if i := strings.IndexByte(upper, '.'); i >= 0 {
		upper = upper[:i]
	}
	switch upper {
	case "CON", "PRN", "AUX", "NUL":
		return true
	}
	if len(upper) == 4 && (strings.HasPrefix(upper, "COM") || strings.HasPrefix(upper, "LPT")) {
		return upper[3] >= '1' && upper[3] <= '9'
	}
	return false
}

func validManifestPath(path string) bool {
	path = strings.TrimSpace(path)
	if path == "" || strings.HasPrefix(path, "/") || strings.Contains(path, `\`) {
		return false
	}
	for _, part := range strings.Split(path, "/") {
		if !validFilenameSegment(part) {
			return false
		}
	}
	return true
}

func hasPathTraversal(path string) bool {
	normalized := strings.ReplaceAll(path, `\`, "/")
	for _, part := range strings.Split(normalized, "/") {
		if part == ".." {
			return true
		}
	}
	return false
}

func validHTTPURL(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != "" && u.User == nil && !unsafeUpdateDetail(raw)
}
