package updates

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"
	"time"
)

// Native JSON has exact tagged names and explicit required members. Go's
// case-insensitive struct matching and null-to-zero conversion are not the
// native storage grammar. Legacy/provider/public decoding stays unchanged.
// Walk tokens without retaining another tree of potentially large manifests.
func validateNativeStateJSON(raw []byte) error {
	if int64(len(raw)) > maxMetadataBytes {
		return ErrStorageUnavailable
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	v := nativeJSONValidator{decoder: d, fields: make(map[reflect.Type]map[string]nativeJSONField)}
	if err := v.value(reflect.TypeOf(stateRecord{})); err != nil {
		return ErrStorageUnavailable
	}
	if _, err := d.Token(); !errors.Is(err, io.EOF) {
		return ErrStorageUnavailable
	}
	return nil
}

type nativeJSONField struct {
	typeOf   reflect.Type
	required bool
}
type nativeJSONValidator struct {
	decoder *json.Decoder
	fields  map[reflect.Type]map[string]nativeJSONField
}

func (v *nativeJSONValidator) declared(t reflect.Type) map[string]nativeJSONField {
	if fields, ok := v.fields[t]; ok {
		return fields
	}
	fields := make(map[string]nativeJSONField)
	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		tag := field.Tag.Get("json")
		if field.Anonymous && tag == "" && field.Type.Kind() == reflect.Struct {
			for name, nested := range v.declared(field.Type) {
				fields[name] = nested
			}
			continue
		}
		if field.PkgPath != "" || tag == "-" {
			continue
		}
		parts := strings.Split(tag, ",")
		name := parts[0]
		if name == "" {
			name = field.Name
		}
		required := true
		for _, option := range parts[1:] {
			if option == "omitempty" {
				required = false
			}
		}
		fields[name] = nativeJSONField{field.Type, required}
	}
	v.fields[t] = fields
	return fields
}

func (v *nativeJSONValidator) value(t reflect.Type) error {
	// References may be omitted according to their tag but must resolve to an
	// actual object when present. Nil maps/slices retain their JSON null meaning.
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	token, err := v.decoder.Token()
	if err != nil {
		return err
	}
	if token == nil {
		if t.Kind() == reflect.Map || t.Kind() == reflect.Slice {
			return nil
		}
		return ErrStorageUnavailable
	}
	if t == reflect.TypeOf(time.Time{}) {
		if _, ok := token.(string); !ok {
			return ErrStorageUnavailable
		}
		return nil // Typed decoding checks the timestamp syntax.
	}
	switch t.Kind() {
	case reflect.Struct, reflect.Map:
		if token != json.Delim('{') {
			return ErrStorageUnavailable
		}
		var fields map[string]nativeJSONField
		if t.Kind() == reflect.Struct {
			fields = v.declared(t)
		}
		seen := make(map[string]bool)
		for v.decoder.More() {
			keyToken, err := v.decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok || seen[key] {
				return ErrStorageUnavailable
			}
			seen[key] = true
			var element reflect.Type
			if t.Kind() == reflect.Map {
				element = t.Elem()
			} else {
				field, ok := fields[key]
				if !ok {
					return ErrStorageUnavailable
				}
				element = field.typeOf
			}
			if err := v.value(element); err != nil {
				return err
			}
		}
		if end, err := v.decoder.Token(); err != nil || end != json.Delim('}') {
			return ErrStorageUnavailable
		}
		for key, field := range fields {
			if field.required && !seen[key] {
				return ErrStorageUnavailable
			}
		}
	case reflect.Slice:
		if token != json.Delim('[') {
			return ErrStorageUnavailable
		}
		for v.decoder.More() {
			if err := v.value(t.Elem()); err != nil {
				return err
			}
		}
		if end, err := v.decoder.Token(); err != nil || end != json.Delim(']') {
			return ErrStorageUnavailable
		}
	case reflect.String:
		if _, ok := token.(string); !ok {
			return ErrStorageUnavailable
		}
	case reflect.Bool:
		if _, ok := token.(bool); !ok {
			return ErrStorageUnavailable
		}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		if _, ok := token.(json.Number); !ok {
			return ErrStorageUnavailable
		}
	default:
		return ErrStorageUnavailable
	}
	return nil
}
