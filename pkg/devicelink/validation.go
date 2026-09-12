package devicelink

import (
	"sort"
	"strings"
)

func trustError(status TrustStatus) error {
	switch status {
	case TrustRevoked:
		return ErrDeviceRevoked
	case TrustStale:
		return ErrDeviceStale
	default:
		return ErrDeviceNotTrusted
	}
}

func validResourceType(rt ResourceType) bool {
	switch rt {
	case ResourceService, ResourceData, ResourceConnector, ResourceRuntime, ResourceTool, ResourceOther:
		return true
	default:
		return false
	}
}

func compactStrings(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, item := range in {
		item = strings.TrimSpace(item)
		if item == "" || seen[item] {
			continue
		}
		seen[item] = true
		out = append(out, item)
	}
	sort.Strings(out)
	return out
}

func summarizeResources(resources []ResourceDescriptor) []ResourceSummary {
	counts := map[ResourceType]int{}
	for _, res := range resources {
		counts[res.Type]++
	}
	out := make([]ResourceSummary, 0)
	for rt, count := range counts {
		out = append(out, ResourceSummary{Type: rt, Count: count})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Type < out[j].Type })
	return out
}
