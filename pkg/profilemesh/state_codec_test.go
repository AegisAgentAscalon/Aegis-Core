package profilemesh

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

func TestW14NativePayloadRejectsAliasesAndOmissions(t *testing.T) {
	object := func(raw []byte, edit func(map[string]json.RawMessage)) []byte {
		t.Helper()
		var value map[string]json.RawMessage
		if err := json.Unmarshal(raw, &value); err != nil {
			t.Fatal(err)
		}
		edit(value)
		out, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	cases := []struct {
		name         string
		edit         func([]byte) []byte
		storageError bool
	}{
		{"control-known-payload", func(raw []byte) []byte { return raw }, false},
		{"case-alias-version-conflict", func(raw []byte) []byte {
			return []byte(strings.Replace(string(raw), `"version":1`, `"version":0,"Version":1`, 1))
		}, true},
		{"case-alias-version-only", func(raw []byte) []byte { return []byte(strings.Replace(string(raw), `"version":1`, `"VERSION":1`, 1)) }, true},
		{"case-alias-nested-trust-and-status", func(raw []byte) []byte {
			text := strings.Replace(string(raw), `"trust_status":"trusted"`, `"trust_status":"revoked","TRUST_STATUS":"trusted"`, 1)
			return []byte(strings.Replace(text, `"status":"active"`, `"status":"removed","STATUS":"active"`, 1))
		}, true},
		{"case-alias-registry-schema-conflict", func(raw []byte) []byte {
			return object(raw, func(value map[string]json.RawMessage) {
				value["devices"] = []byte(strings.Replace(string(value["devices"]), `"schema_version":1`, `"schema_version":0,"SCHEMA_VERSION":1`, 1))
			})
		}, true},
		{"omitted-hosting", func(raw []byte) []byte {
			return object(raw, func(value map[string]json.RawMessage) { delete(value, "hosting") })
		}, true},
		{"omitted-profile-empty-state", func(raw []byte) []byte {
			return object(raw, func(value map[string]json.RawMessage) {
				delete(value, "profile")
				value["hosting"] = []byte(`null`)
				value["devices"] = []byte(`{"schema_version":1,"devices":[],"updated_at":"0001-01-01T00:00:00Z"}`)
				value["resources"] = []byte(`{"schema_version":1,"resources":[],"updated_at":"0001-01-01T00:00:00Z"}`)
			})
		}, true},
		{"omitted-device-entries", func(raw []byte) []byte {
			return object(raw, func(value map[string]json.RawMessage) {
				value["devices"] = object(value["devices"], func(reg map[string]json.RawMessage) { delete(reg, "devices") })
			})
		}, true},
		{"omitted-resource-entries", func(raw []byte) []byte {
			return object(raw, func(value map[string]json.RawMessage) {
				value["resources"] = object(value["resources"], func(reg map[string]json.RawMessage) { delete(reg, "resources") })
			})
		}, true},
		{"omitted-hint-collections", func(raw []byte) []byte {
			return object(raw, func(value map[string]json.RawMessage) { delete(value, "relay_hints"); delete(value, "endpoint_hints") })
		}, true},
		{"omitted-registry-updated-at", func(raw []byte) []byte {
			return object(raw, func(value map[string]json.RawMessage) {
				value["devices"] = object(value["devices"], func(reg map[string]json.RawMessage) { delete(reg, "updated_at") })
			})
		}, true},
		{"control-unknown-key", func(raw []byte) []byte {
			return object(raw, func(value map[string]json.RawMessage) { value["unknown"] = []byte(`true`) })
		}, true},
		{"control-missing-version", func(raw []byte) []byte {
			return object(raw, func(value map[string]json.RawMessage) { delete(value, "version") })
		}, true},
		{"control-omitted-whole-registry", func(raw []byte) []byte {
			return object(raw, func(value map[string]json.RawMessage) { delete(value, "devices") })
		}, true},
		{"control-null-whole-registry", func(raw []byte) []byte {
			return object(raw, func(value map[string]json.RawMessage) { value["devices"] = []byte(`null`) })
		}, true},
		{"control-omitted-profile-with-records", func(raw []byte) []byte {
			return object(raw, func(value map[string]json.RawMessage) { delete(value, "profile") })
		}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, _ := w08Service(t)
			ctx := context.Background()
			if _, err := s.RegisterProfileResource(ctx, RegisterProfileResourceRequest{ResourceID: "tool", ResourceType: ResourceTool}); err != nil {
				t.Fatal(err)
			}
			guard, err := s.store.generations.Lock(ctx)
			if err != nil {
				t.Fatal(err)
			}
			prior, err := guard.Read()
			if err != nil {
				_ = guard.Close()
				t.Fatal(err)
			}
			_, err = guard.Commit(prior.Token, tc.edit(prior.Data), nil)
			closeErr := guard.Close()
			if err != nil || closeErr != nil {
				t.Fatal("fixture envelope failed", err, closeErr)
			}
			profile, profileErr := s.GetProfile(ctx)
			devices, deviceErr := s.ListProfileDevices(ctx)
			resources, resourceErr := s.ListProfileResources(ctx)
			if errors.Is(profileErr, ErrStorageUnavailable) != tc.storageError || errors.Is(deviceErr, ErrStorageUnavailable) != tc.storageError || errors.Is(resourceErr, ErrStorageUnavailable) != tc.storageError {
				t.Fatal("unexpected reader disposition", profileErr, deviceErr, resourceErr)
			}
			trust, status := "", ""
			if len(devices) > 0 {
				trust = string(devices[0].TrustStatus)
				status = string(devices[0].Status)
			}
			t.Logf("storage_error=%t profile=%q profile_error=%v devices=%d first_trust=%q first_status=%q resources=%d", tc.storageError, profile.ProfileID, profileErr, len(devices), trust, status, len(resources))
		})
	}
}

func TestW14NativePayloadScalarPresenceAndNulls(t *testing.T) {
	state := w14LegacyState(time.Time{})
	state.Hosting.LocalCacheEnabled = false
	state.Resources.Resources[0].Metadata = map[string]string{"A": "one", "a": "two"}
	raw, err := encodeMesh(state)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, before, after string }{
		{"missing-required-false", `"local_cache_enabled":false,`, ``},
		{"null-required-false", `"local_cache_enabled":false`, `"local_cache_enabled":null`},
		{"missing-profile-version", `"schema_version":1,`, ``},
		{"null-profile-version", `"schema_version":1`, `"schema_version":null`},
		{"null-custom-time", `"registered_at":"0001-01-01T00:00:00Z"`, `"registered_at":null`},
		{"null-map-value", `"A":"one"`, `"A":null`},
		{"alias-map-container", `"metadata":{"A":"one","a":"two"}`, `"METADATA":{"A":"one","a":"two"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			changed := strings.Replace(string(raw), tc.before, tc.after, 1)
			if changed == string(raw) {
				t.Fatal("fixture did not change")
			}
			if _, err := decodeMesh([]byte(changed)); err == nil {
				t.Fatal("native scalar/field shape accepted")
			}
		})
	}
	decoded, err := decodeMesh(raw)
	if err != nil || !decoded.Profile.CreatedAt.IsZero() || decoded.Resources.Resources[0].Metadata["A"] != "one" || decoded.Resources.Resources[0].Metadata["a"] != "two" {
		t.Fatal("declared zero time or case-distinct metadata rejected", err)
	}
	for _, nilCollections := range []bool{false, true} {
		empty := emptyMesh()
		if nilCollections {
			empty.Devices.Devices = nil
			empty.Resources.Resources = nil
			empty.RelayHints = nil
			empty.EndpointHints = nil
		}
		raw, err := encodeMesh(empty)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := decodeMesh(raw)
		if err != nil || decoded.Profile != nil || decoded.Hosting != nil || (decoded.Devices.Devices == nil) != nilCollections || (decoded.Resources.Resources == nil) != nilCollections || (decoded.EndpointHints == nil) != nilCollections || (decoded.RelayHints == nil) != nilCollections {
			t.Fatal("nullable identity/hosting or collection shape changed", err)
		}
	}
}

func TestW14NativeStrictnessKeepsLegacyAndPublicDecoding(t *testing.T) {
	var public ProfileDeviceRecord
	if err := json.Unmarshal([]byte(`{"DEVICE_ID":"device-a","TRUST_STATUS":"trusted","STATUS":"active"}`), &public); err != nil || public.DeviceID != "device-a" || public.TrustStatus != DeviceTrustTrusted || public.Status != DeviceStatusActive {
		t.Fatal("public DTO grammar changed", public, err)
	}
	s := newTestService(t, "legacy", WithClock(sampledClock{time.Time{}}))
	w14WriteLegacy(t, s, w14LegacyState(time.Time{}))
	raw, err := os.ReadFile(s.store.devicesPath())
	if err != nil {
		t.Fatal(err)
	}
	raw = []byte(strings.Replace(string(raw), `"trust_status":"trusted"`, `"trust_status":"revoked","TRUST_STATUS":"trusted"`, 1))
	if err := os.WriteFile(s.store.devicesPath(), raw, 0600); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	devices, err := s.ListProfileDevices(ctx)
	if err != nil || len(devices) != 1 || devices[0].TrustStatus != DeviceTrustTrusted {
		t.Fatal("historical loose-file grammar changed", devices, err)
	}
	if _, err := s.RegisterProfileDevice(ctx, RegisterProfileDeviceRequest{DeviceID: "device-b", PublicKeyFingerprint: "fp-device-b"}); err != nil {
		t.Fatal(err)
	}
	devices, err = s.ListProfileDevices(ctx)
	if err != nil || len(devices) != 2 || devices[0].TrustStatus != DeviceTrustTrusted {
		t.Fatal("legacy state did not encode into exact native fields", devices, err)
	}
}
