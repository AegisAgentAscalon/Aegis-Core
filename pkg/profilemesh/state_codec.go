package profilemesh

import (
	"bytes"
	"encoding/json"
	"io"
	"reflect"
	"strings"
	"time"
)

// Native payloads use exact declared JSON names. Keep this check local to the
// private format: legacy records and public DTO decoding retain their grammar.
func decodeMesh(raw []byte) (*meshState, error) {
	if err := validateMeshJSON(raw); err != nil {
		return nil, err
	}
	var state meshState
	if err := json.Unmarshal(raw, &state); err != nil {
		return nil, err
	}
	return &state, nil
}

func validateMeshJSON(raw []byte) error {
	type field struct {
		kind     reflect.Type
		required bool
	}
	// Cache declarations only for this decode; no aggregate state is retained.
	declarations := map[reflect.Type]map[string]field{}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value func(reflect.Type) error
	value = func(kind reflect.Type) error {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		if token == nil {
			switch kind.Kind() {
			case reflect.Pointer, reflect.Slice, reflect.Map:
				return nil
			default:
				return ErrStorageUnavailable
			}
		}
		for kind.Kind() == reflect.Pointer {
			kind = kind.Elem()
		}
		if kind == reflect.TypeOf(time.Time{}) {
			// Leave timestamp syntax and historical zero values to time's codec.
			if _, ok := token.(string); !ok {
				return ErrStorageUnavailable
			}
			return nil
		}
		switch kind.Kind() {
		case reflect.Struct, reflect.Map:
			if token != json.Delim('{') {
				return ErrStorageUnavailable
			}
			fields := declarations[kind]
			if kind.Kind() == reflect.Struct && fields == nil {
				fields = map[string]field{}
				for i := 0; i < kind.NumField(); i++ {
					member := kind.Field(i)
					if !member.IsExported() {
						continue
					}
					name, options, _ := strings.Cut(member.Tag.Get("json"), ",")
					if name == "-" {
						continue
					}
					if name == "" {
						name = member.Name
					}
					fields[name] = field{member.Type, !strings.Contains(","+options+",", ",omitempty,")}
				}
				declarations[kind] = fields
			}
			seen := map[string]bool{}
			for decoder.More() {
				token, err := decoder.Token()
				if err != nil {
					return err
				}
				key, ok := token.(string)
				if !ok || seen[key] {
					return ErrStorageUnavailable
				}
				seen[key] = true
				var child reflect.Type
				if kind.Kind() == reflect.Map {
					// Metadata keys are data: case-distinct spellings stay distinct.
					child = kind.Elem()
				} else {
					member, ok := fields[key]
					if !ok {
						return ErrStorageUnavailable
					}
					child = member.kind
				}
				if err := value(child); err != nil {
					return err
				}
			}
			for name, member := range fields {
				if member.required && !seen[name] {
					return ErrStorageUnavailable
				}
			}
			_, err = decoder.Token()
			return err
		case reflect.Slice, reflect.Array:
			if token != json.Delim('[') {
				return ErrStorageUnavailable
			}
			for decoder.More() {
				if err := value(kind.Elem()); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		default:
			if _, compound := token.(json.Delim); compound {
				return ErrStorageUnavailable
			}
			return nil // Typed decoding checks primitive values and ranges.
		}
	}
	if err := value(reflect.TypeOf(meshState{})); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return ErrStorageUnavailable
	}
	return nil
}
