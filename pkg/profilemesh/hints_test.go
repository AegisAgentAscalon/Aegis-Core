package profilemesh

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

func w14HintSnapshot(t *testing.T) (*Service, ProfileMeshSnapshot) {
	t.Helper()
	s, snapshot := w08Service(t)
	now := s.clock.Now()
	snapshot.RelayHints = []ProfileRelayHint{{ProfileID: snapshot.Profile.ProfileID, DeviceID: "device-a", RelayProviderID: "relay-secret", EndpointType: EndpointRelay, LastSeen: now, ExpiresAt: now.Add(time.Hour), Capabilities: []string{" tools ", "tools"}, Metadata: map[string]string{" safe ": " value "}}}
	snapshot.EndpointHints = []ProfileEndpointHint{{ProfileID: snapshot.Profile.ProfileID, DeviceID: "device-a", EndpointType: EndpointLocal, Address: "127.0.0.1", LastSeen: now, ExpiresAt: now.Add(time.Hour), Capabilities: []string{"lan"}}}
	snapshot.SnapshotFingerprint = snapshotFingerprint(snapshot)
	return s, snapshot
}

func TestW14HintsRoundTripRetainClearAndOwnValues(t *testing.T) {
	s, snapshot := w14HintSnapshot(t)
	ctx := context.Background()
	if err := s.ImportProfileMeshSnapshot(ctx, snapshot); err != nil {
		t.Fatal(err)
	}
	snapshot.RelayHints[0].Metadata[" safe "] = "caller mutation"
	snapshot.EndpointHints[0].Capabilities[0] = "caller mutation"
	reopened, err := NewService(s.cfg, WithClock(s.clock))
	if err != nil {
		t.Fatal(err)
	}
	exported, err := reopened.ExportProfileMeshSnapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(exported.RelayHints) != 1 || len(exported.EndpointHints) != 1 || exported.RelayHints[0].Metadata["safe"] != "value" || exported.RelayHints[0].RelayProviderID != "relay-secret" || exported.EndpointHints[0].Capabilities[0] != "lan" {
		t.Fatal("hints lost or aliased", exported)
	}
	original := publicProfileMeshSnapshot(exported)
	if err = reopened.ImportProfileMeshSnapshot(ctx, exported); err != nil {
		t.Fatal(err)
	}
	again, err := reopened.ExportProfileMeshSnapshot(ctx)
	if err != nil || !reflect.DeepEqual(again, original) {
		t.Fatal("hint round trip fingerprint or timestamps changed", err)
	}
	exported.RelayHints[0].Metadata["safe"] = "returned mutation"
	exported.EndpointHints[0].Capabilities[0] = "returned mutation"
	registerDevice(t, reopened, "device-c")
	after, err := reopened.ExportProfileMeshSnapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(after.RelayHints, original.RelayHints) || !reflect.DeepEqual(after.EndpointHints, original.EndpointHints) {
		t.Fatal("ordinary mutation lost or aliased hints")
	}
	updatedAt := after.UpdatedAt
	oldFingerprint := after.SnapshotFingerprint
	after.EndpointHints[0].Metadata = map[string]string{"route": "replacement"}
	after.SnapshotFingerprint = snapshotFingerprint(after)
	if err = reopened.ImportProfileMeshSnapshot(ctx, after); err != nil {
		t.Fatal(err)
	}
	after, err = reopened.ExportProfileMeshSnapshot(ctx)
	if err != nil || !after.UpdatedAt.Equal(updatedAt) || after.SnapshotFingerprint == oldFingerprint || after.EndpointHints[0].Metadata["route"] != "replacement" {
		t.Fatal("hint-only import changed public time or did not replace hints", err)
	}
	after.RelayHints = nil
	after.EndpointHints = nil
	after.SnapshotFingerprint = snapshotFingerprint(after)
	if err = reopened.ImportProfileMeshSnapshot(ctx, after); err != nil {
		t.Fatal(err)
	}
	cleared, err := reopened.ExportProfileMeshSnapshot(ctx)
	if err != nil || len(cleared.RelayHints) != 0 || len(cleared.EndpointHints) != 0 || cleared.RelayHints == nil || cleared.EndpointHints == nil {
		t.Fatal("empty snapshot did not clear owned hints", err)
	}
}

func TestW14ZeroHintTimeWithBackwardClock(t *testing.T) {
	original, snapshot := w08Service(t)
	now := time.Time{}.Add(-time.Hour)
	service, err := NewService(original.cfg, WithClock(sampledClock{now}))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	snapshot.HostingConfig.PrimaryProfileDeviceID = ""
	snapshot.HostingConfig.ProfileDataHostDeviceID = ""
	snapshot.Resources = nil
	snapshot.SnapshotFingerprint = snapshotFingerprint(snapshot)
	if err = service.ImportProfileMeshSnapshot(ctx, snapshot); err != nil {
		t.Fatal("no-hint control rejected under backward clock", err)
	}
	snapshot.EndpointHints = []ProfileEndpointHint{{ProfileID: snapshot.Profile.ProfileID, DeviceID: "device-a", EndpointType: EndpointDirect, Address: "example.test"}}
	snapshot.SnapshotFingerprint = snapshotFingerprint(snapshot)
	if err = service.ImportProfileMeshSnapshot(ctx, snapshot); err != nil {
		t.Fatal("unspecified hint timestamps rejected under backward clock", err)
	}
	stored, err := service.ExportProfileMeshSnapshot(ctx)
	if err != nil || len(stored.EndpointHints) != 1 || !stored.EndpointHints[0].LastSeen.IsZero() || !stored.EndpointHints[0].ExpiresAt.IsZero() {
		t.Fatal("unspecified hint timestamps did not remain zero", stored.EndpointHints, err)
	}
	before := w08Bytes(t, service)
	snapshot.EndpointHints[0].LastSeen = now.Add(defaultFutureSkew + time.Second)
	snapshot.SnapshotFingerprint = snapshotFingerprint(snapshot)
	if err = service.ImportProfileMeshSnapshot(ctx, snapshot); !errors.Is(err, ErrInvalidProfileSnapshot) {
		t.Fatal("nonzero future hint timestamp bypassed admission", err)
	}
	w08Unchanged(t, service, before)
}

func TestW14RawHintRejectionsAreAtomic(t *testing.T) {
	s, base := w14HintSnapshot(t)
	before := w08Bytes(t, s)
	cases := []struct {
		name string
		edit func(*ProfileMeshSnapshot)
	}{
		{"schema-one", func(v *ProfileMeshSnapshot) { v.SchemaVersion = 1 }},
		{"profile", func(v *ProfileMeshSnapshot) { v.EndpointHints[0].ProfileID = "other" }},
		{"device", func(v *ProfileMeshSnapshot) { v.EndpointHints[0].DeviceID = "missing" }},
		{"identity-trim", func(v *ProfileMeshSnapshot) { v.EndpointHints[0].DeviceID = " device-a " }},
		{"type", func(v *ProfileMeshSnapshot) { v.EndpointHints[0].EndpointType = "unsupported" }},
		{"relay-type", func(v *ProfileMeshSnapshot) { v.RelayHints[0].EndpointType = EndpointDirect }},
		{"provider", func(v *ProfileMeshSnapshot) { v.RelayHints[0].RelayProviderID = "../provider" }},
		{"time-reversed", func(v *ProfileMeshSnapshot) { v.EndpointHints[0].ExpiresAt = v.EndpointHints[0].LastSeen }},
		{"future-seen", func(v *ProfileMeshSnapshot) {
			v.EndpointHints[0].LastSeen = v.EndpointHints[0].LastSeen.Add(5 * time.Minute)
		}},
		{"sensitive-capability", func(v *ProfileMeshSnapshot) { v.EndpointHints[0].Capabilities = []string{"secret"} }},
		{"sensitive-metadata", func(v *ProfileMeshSnapshot) { v.EndpointHints[0].Metadata = map[string]string{"private": "value"} }},
		{"blank-key", func(v *ProfileMeshSnapshot) { v.EndpointHints[0].Metadata = map[string]string{" ": "value"} }},
		{"trim-collision", func(v *ProfileMeshSnapshot) {
			v.EndpointHints[0].Metadata = map[string]string{"key": "one", " key ": "two"}
		}},
		{"equal-trim-collision", func(v *ProfileMeshSnapshot) {
			v.EndpointHints[0].Metadata = map[string]string{"key": "one", " key ": "one"}
		}},
		{"invalid-utf8", func(v *ProfileMeshSnapshot) { v.EndpointHints[0].Capabilities = []string{string([]byte{0xff})} }},
		{"control", func(v *ProfileMeshSnapshot) { v.EndpointHints[0].Metadata = map[string]string{"key": "bad\nvalue"} }},
		{"duplicate-endpoint", func(v *ProfileMeshSnapshot) { v.EndpointHints = append(v.EndpointHints, v.EndpointHints[0]) }},
		{"conflicting-relay", func(v *ProfileMeshSnapshot) {
			hint := v.RelayHints[0]
			hint.ExpiresAt = hint.ExpiresAt.Add(time.Hour)
			v.RelayHints = append(v.RelayHints, hint)
		}},
		{"oversized-address", func(v *ProfileMeshSnapshot) { v.EndpointHints[0].Address = strings.Repeat("a", 2049) }},
		{"oversized-capability", func(v *ProfileMeshSnapshot) { v.EndpointHints[0].Capabilities = []string{strings.Repeat("a", 129)} }},
		{"capability-count", func(v *ProfileMeshSnapshot) { v.EndpointHints[0].Capabilities = make([]string, 129) }},
		{"hint-count", func(v *ProfileMeshSnapshot) { v.EndpointHints = make([]ProfileEndpointHint, 1025) }},
		{"metadata-count", func(v *ProfileMeshSnapshot) {
			v.EndpointHints[0].Metadata = map[string]string{}
			for i := 0; i < 65; i++ {
				v.EndpointHints[0].Metadata[strings.Repeat("a", i+1)] = "value"
			}
		}},
		{"metadata-key-limit", func(v *ProfileMeshSnapshot) {
			v.EndpointHints[0].Metadata = map[string]string{strings.Repeat("a", 129): "value"}
		}},
		{"metadata-value-limit", func(v *ProfileMeshSnapshot) {
			v.EndpointHints[0].Metadata = map[string]string{"key": strings.Repeat("a", 1025)}
		}},
		{"userinfo", func(v *ProfileMeshSnapshot) { v.EndpointHints[0].Address = "https://user:password@example.test/route" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			value := publicProfileMeshSnapshot(base)
			tc.edit(&value)
			value.Profile.DisplayName = "must not persist"
			value.SnapshotFingerprint = snapshotFingerprint(value)
			if err := s.ImportProfileMeshSnapshot(context.Background(), value); !errors.Is(err, ErrInvalidProfileSnapshot) {
				t.Fatal("invalid hint accepted or wrong error", err)
			}
			w08Unchanged(t, s, before)
		})
	}
}

func TestW14HintAddressGrammar(t *testing.T) {
	valid := []string{"", "127.0.0.1", "127.0.0.1:1", "localhost:65535", "workstation.local", "2001:db8::1", "[2001:db8::1]", "[2001:db8::1]:443", "https://[2001:db8::1]/route", "http://[::1]/route", "https://example.test/route", "http://localhost:8080/route", "http://192.168.1.1/route"}
	invalid := []string{"host:0", "host:65536", "host:", "-host", "host-", "a..b", "https://example.test?", "https://example.test#", "https://user@example.test", "http://example.test", "ftp://example.test", "https://example.test/%00", "https://example.test/%3Ftoken", "https://example.test/%5Croute", "https://example.test/%2e%2e/route", "C:\\Users\\user", "/tmp/endpoint", "https://example.test/%zz", "example.test/path", "example.test:abc", " host ", "*.example.test"}
	for _, address := range valid {
		if !validHintAddress(address) {
			t.Errorf("valid address rejected: %q", address)
		}
	}
	for _, address := range invalid {
		if validHintAddress(address) {
			t.Errorf("invalid address accepted: %q", address)
		}
	}
}
