package profilemesh

import "testing"

// Storage names, authorization IDs and public sync metadata deliberately have
// different policies even when they share syntax or reserved-name checks.
func TestSharedValidationPreservesDomainPolicies(t *testing.T) {
	for _, tc := range []struct {
		value                                  string
		storageName, syncName, ownerID, syncID bool
	}{
		{"profile-1", true, true, true, true},
		{"  profile-1  ", true, true, true, true},
		{"CON", false, false, true, true},
		{"con.txt", false, true, true, true},
		{"Lpt9.cache", false, true, true, true},
		{"device:1", false, false, true, true},
		{"secret-device", true, false, true, false},
		{"a..b", false, false, false, false},
		{"a/b", false, false, false, false},
		{"", false, false, false, false},
	} {
		t.Run(tc.value, func(t *testing.T) {
			got := [4]bool{validSafeName(tc.value), validProfileSyncNamespace(tc.value), validID(tc.value), validProfileSyncID(tc.value)}
			want := [4]bool{tc.storageName, tc.syncName, tc.ownerID, tc.syncID}
			if got != want {
				t.Fatalf("policy results %v; want %v", got, want)
			}
		})
	}
}
