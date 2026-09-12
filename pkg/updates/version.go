package updates

import (
	"strings"
)

func validVersion(v string) bool {
	v = strings.TrimSpace(v)
	return len(v) <= 128 && versionPattern.MatchString(v)
}

func compareVersions(a, b string) int {
	ap, apre := versionParts(a)
	bp, bpre := versionParts(b)
	for i := 0; i < len(ap) || i < len(bp); i++ {
		av, bv := "0", "0"
		if i < len(ap) {
			av = ap[i]
		}
		if i < len(bp) {
			bv = bp[i]
		}
		if len(av) > len(bv) || (len(av) == len(bv) && av > bv) {
			return 1
		}
		if len(av) < len(bv) || (len(av) == len(bv) && av < bv) {
			return -1
		}
	}
	if apre == bpre {
		return 0
	}
	if apre == "" {
		return 1
	}
	if bpre == "" {
		return -1
	}
	return strings.Compare(apre, bpre)
}

func versionParts(v string) ([]string, string) {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	pre := ""
	if i := strings.Index(v, "-"); i >= 0 {
		pre = v[i+1:]
		v = v[:i]
	}
	raw := strings.Split(v, ".")
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		item = strings.TrimLeft(item, "0")
		if item == "" {
			item = "0"
		}
		out = append(out, item)
	}
	return out, pre
}
