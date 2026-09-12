package generation

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"unicode/utf8"

	"github.com/AegisAgentAscalon/aegis-core/internal/filepersist"
)

type formatRecord struct {
	Version int    `json:"version"`
	Owner   string `json:"owner"`
}

type pointerRecord struct {
	Version     int    `json:"version"`
	Owner       string `json:"owner"`
	Revision    uint64 `json:"revision"`
	ID          string `json:"generation"`
	Bytes       int64  `json:"bytes"`
	SHA256      string `json:"sha256"`
	Previous    string `json:"previous"`
	ParentToken string `json:"parent_token"`
}

type generationHeader struct {
	Version     int    `json:"version"`
	Owner       string `json:"owner"`
	Revision    uint64 `json:"revision"`
	ID          string `json:"generation"`
	ParentToken string `json:"parent_token"`
}

type generationRecord struct {
	generationHeader
	Data json.RawMessage `json:"data"`
}

func validHex(value string, bytes int) bool {
	if len(value) != bytes*2 {
		return false
	}
	for _, c := range value {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func (p pointerRecord) valid(owner string) bool {
	if p.Version != formatVersion || p.Owner != owner || p.Revision == 0 || !validHex(p.ID, 16) ||
		!validHex(p.SHA256, 32) || p.Bytes <= 0 || p.Bytes > generationLimit {
		return false
	}
	if p.Revision == 1 {
		return p.Previous == "" && p.ParentToken == ""
	}
	return validHex(p.Previous, 16) && p.Previous != p.ID && validHex(p.ParentToken, 32)
}

func newID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw[:]), nil
}

func generationName(id string) string { return "generation-" + id + ".json" }
func digest(raw []byte) string        { sum := sha256.Sum256(raw); return hex.EncodeToString(sum[:]) }

func encodeGeneration(header generationHeader, data []byte) ([]byte, error) {
	if len(data) > generationLimit {
		return nil, ErrTooLarge
	}
	if err := uniqueJSON(data); err != nil {
		return nil, err
	}
	prefix, err := json.Marshal(header)
	if err != nil {
		return nil, err
	}
	// Copy the already bounded raw JSON without marshaling/escaping another
	// potentially much larger representation of its strings.
	n := len(prefix) - 1 + len(`,"data":`) + len(data) + 1
	if n > generationLimit {
		return nil, ErrTooLarge
	}
	out := make([]byte, 0, n)
	out = append(out, prefix[:len(prefix)-1]...)
	out = append(out, `,"data":`...)
	out = append(out, data...)
	return append(out, '}'), nil
}

func decodeFile(ctx context.Context, path string, limit int64, out any) ([]byte, error) {
	raw, err := readBounded(ctx, path, limit)
	if err != nil {
		return nil, err
	}
	// encoding/json accepts case-insensitive field aliases. Private envelope
	// keys are exact and all fields are required, including empty parent fields.
	var names []string
	switch out.(type) {
	case *formatRecord:
		names = []string{"version", "owner"}
	case *pointerRecord:
		names = []string{"version", "owner", "revision", "generation", "bytes", "sha256", "previous", "parent_token"}
	case *generationRecord:
		names = []string{"version", "owner", "revision", "generation", "parent_token", "data"}
	default:
		return nil, ErrInvalid
	}
	if err = checkJSON(raw, names); err != nil {
		return nil, err
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err = d.Decode(out); err != nil {
		return nil, errors.Join(ErrInvalid, err)
	}
	return raw, nil
}

func readBounded(ctx context.Context, path string, limit int64) ([]byte, error) {
	f, err := filepersist.OpenRegular(ctx, path)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil {
		return nil, errors.Join(err, f.Close())
	}
	if info.Size() > limit {
		return nil, errors.Join(ErrTooLarge, f.Close())
	}
	raw, err := io.ReadAll(io.LimitReader(contextReader{ctx, f}, limit+1))
	if err = errors.Join(err, f.Close()); err != nil {
		return nil, err
	}
	if int64(len(raw)) > limit {
		return nil, ErrTooLarge
	}
	return raw, ctx.Err()
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(p)
}

// Private records reject duplicate keys, including escaped spellings of a key.
// Decode's usual last-key-wins rule must not select an authority or domain field.
func uniqueJSON(raw []byte) error { return checkJSON(raw, nil) }

func checkJSON(raw []byte, rootKeys []string) error {
	if !utf8.Valid(raw) || !json.Valid(raw) {
		return ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var value func(bool) error
	value = func(root bool) error {
		t, err := d.Token()
		if err != nil {
			return ErrInvalid
		}
		delim, compound := t.(json.Delim)
		if root && rootKeys != nil && (!compound || delim != '{') {
			return ErrInvalid
		}
		if !compound {
			return nil
		}
		switch delim {
		case '{':
			keys := make(map[string]struct{})
			for d.More() {
				key, err := d.Token()
				if err != nil {
					return ErrInvalid
				}
				text, ok := key.(string)
				if !ok {
					return ErrInvalid
				}
				if _, exists := keys[text]; exists {
					return ErrInvalid
				}
				keys[text] = struct{}{}
				if err := value(false); err != nil {
					return err
				}
			}
			if root && rootKeys != nil {
				if len(keys) != len(rootKeys) {
					return ErrInvalid
				}
				for _, name := range rootKeys {
					if _, ok := keys[name]; !ok {
						return ErrInvalid
					}
				}
			}
		case '[':
			for d.More() {
				if err := value(false); err != nil {
					return err
				}
			}
		default:
			return ErrInvalid
		}
		_, err = d.Token()
		return err
	}
	if err := value(true); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return ErrInvalid
	}
	return nil
}
