package generation

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/AegisAgentAscalon/aegis-core/internal/filepersist"
)

// Commit publishes only against expected authority. Backups are raw owner
// metadata captured under this guard; nil means absent and empty means present.
// A failure before publication leaves old authority intact. A successful commit
// remains successful if cancellation or optional cleanup occurs afterward.
func (g *Guard) Commit(expected string, data []byte, backup map[string][]byte) (Snapshot, error) {
	prior, err := g.inspect(true)
	if err != nil {
		return Snapshot{}, err
	}
	if prior.token != expected {
		return Snapshot{}, ErrConflict
	}
	if prior.pointer.Revision == math.MaxUint64 {
		return Snapshot{}, ErrInvalid
	}
	id, err := newID()
	if err != nil {
		return Snapshot{}, err
	}
	header := generationHeader{formatVersion, g.store.owner, prior.pointer.Revision + 1, id, prior.token}
	raw, err := encodeGeneration(header, data)
	if err != nil {
		return Snapshot{}, err
	}
	if err = g.step("encoded"); err != nil {
		return Snapshot{}, err
	}
	pointer := pointerRecord{formatVersion, g.store.owner, header.Revision, id, int64(len(raw)), digest(raw), prior.pointer.ID, prior.token}
	pointerRaw, err := json.Marshal(pointer)
	if err != nil {
		return Snapshot{}, err
	}
	if len(pointerRaw) > metadataLimit {
		return Snapshot{}, ErrTooLarge
	}
	if prior.token == "" {
		err = g.activate(raw, pointerRaw, id, backup)
	} else {
		err = g.publish(raw, pointerRaw, id)
	}
	if err != nil {
		return Snapshot{}, err
	}
	// Once authority moved, a subsequent cancellation/fault is not a rollback.
	if g.store.checkpoint != nil {
		_ = g.store.checkpoint("committed")
	}
	g.cleanup(pointer)
	return Snapshot{Token: digest(pointerRaw), Revision: header.Revision, Data: bytes.Clone(data)}, nil
}

type backupEntry struct {
	Path    string `json:"path"`
	Present bool   `json:"present"`
	Bytes   int    `json:"bytes"`
	SHA256  string `json:"sha256"`
}

type backupInventory struct {
	Version int           `json:"version"`
	Entries []backupEntry `json:"entries"`
}

func backupRecords(backup map[string][]byte) (backupInventory, error) {
	out := backupInventory{Version: formatVersion, Entries: []backupEntry{}}
	if len(backup) > 8 {
		return out, ErrTooLarge
	}
	for path, raw := range backup {
		// Fixed metadata paths use portable names. Validate each component before
		// joining, including Windows alias spellings and inventory collisions.
		if len(path) > 256 || strings.Contains(path, "\\") || !filepath.IsLocal(path) || filepath.ToSlash(filepath.Clean(path)) != path || path == "." || path == "inventory.json" {
			return out, ErrInvalid
		}
		for _, part := range strings.Split(path, "/") {
			if part == "" || part == "." || part == ".." || strings.TrimRight(part, ". ") != part {
				return out, ErrInvalid
			}
			for _, c := range part {
				if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == '-' || c == '.') {
					return out, ErrInvalid
				}
			}
			stem, _, _ := strings.Cut(part, ".")
			if stem == "con" || stem == "prn" || stem == "aux" || stem == "nul" || len(stem) == 4 && (strings.HasPrefix(stem, "com") || strings.HasPrefix(stem, "lpt")) && stem[3] >= '1' && stem[3] <= '9' {
				return out, ErrInvalid
			}
		}
		if len(raw) > generationLimit {
			return out, ErrTooLarge
		}
		entry := backupEntry{Path: path, Present: raw != nil, Bytes: len(raw)}
		if raw != nil {
			entry.SHA256 = digest(raw)
		}
		out.Entries = append(out.Entries, entry)
	}
	sort.Slice(out.Entries, func(i, j int) bool { return out.Entries[i].Path < out.Entries[j].Path })
	return out, nil
}

func (g *Guard) activate(raw, pointer []byte, id string, backup map[string][]byte) error {
	inventory, err := backupRecords(backup)
	if err != nil {
		return err
	}
	format, err := json.Marshal(formatRecord{formatVersion, g.store.owner})
	if err != nil {
		return err
	}
	index, err := json.Marshal(inventory)
	if err != nil {
		return err
	}
	if len(format) > metadataLimit || len(index) > metadataLimit {
		return ErrTooLarge
	}
	prep := filepath.Join(g.store.root, ".state-prepare-"+id)
	if err = os.Mkdir(prep, 0700); err != nil {
		return err
	}
	// Abandoned preparation directories have no authority. Retain them on
	// failure; there is no speculative cleanup of an uncertain activation.
	if err = g.step("prepared-directory"); err != nil {
		return err
	}
	backupDir := filepath.Join(prep, "backup")
	if err = os.Mkdir(backupDir, 0700); err != nil {
		return err
	}
	for _, record := range inventory.Entries {
		if !record.Present {
			continue
		}
		path := filepath.Join(backupDir, filepath.FromSlash(record.Path))
		if err = filepersist.EnsureDir(g.ctx, filepath.Dir(path)); err != nil {
			return err
		}
		if err = g.writeChecked(path, backup[record.Path], "backup:"+record.Path); err != nil {
			return err
		}
	}
	for _, record := range []struct {
		name  string
		data  []byte
		label string
	}{
		{"backup/inventory.json", index, "backup-inventory"},
		{"format.json", format, "format"},
		{generationName(id), raw, "generation"},
		{"current.json", pointer, "pointer"},
	} {
		if err = g.writeChecked(filepath.Join(prep, filepath.FromSlash(record.name)), record.data, record.label); err != nil {
			return err
		}
	}
	if err = g.step("before-activation"); err != nil {
		return err
	}
	if _, err = os.Lstat(g.store.livePath()); !os.IsNotExist(err) {
		if err != nil {
			return err
		}
		return ErrConflict
	}
	if err = g.check(); err != nil {
		return err
	}
	// One same-filesystem directory rename publishes the already verified set.
	// A post-rename context check would misreport a committed mutation as failure.
	return os.Rename(prep, g.store.livePath())
}

func (g *Guard) publish(raw, pointer []byte, id string) error {
	live := g.store.livePath()
	if err := g.writeChecked(filepath.Join(live, generationName(id)), raw, "generation"); err != nil {
		return err
	}
	tmp := filepath.Join(live, ".current-"+id)
	if err := g.writeChecked(tmp, pointer, "pointer"); err != nil {
		return err
	}
	defer os.Remove(tmp)
	if err := g.step("before-pointer-replace"); err != nil {
		return err
	}
	return filepersist.Replace(g.ctx, tmp, filepath.Join(live, "current.json"))
}

func (g *Guard) writeChecked(path string, raw []byte, label string) (err error) {
	if err = g.step(label + ":before-write"); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	closed := false
	defer func() {
		if !closed {
			err = errors.Join(err, f.Close())
		}
	}()
	n, err := f.Write(raw)
	if err != nil {
		return err
	}
	if n != len(raw) {
		return io.ErrShortWrite
	}
	if err = g.step(label + ":written"); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = g.step(label + ":synced"); err != nil {
		return err
	}
	err = f.Close()
	closed = true
	if err != nil {
		return err
	}
	if err = g.step(label + ":closed"); err != nil {
		return err
	}
	check, err := readBounded(g.ctx, path, int64(len(raw)))
	if err != nil {
		return err
	}
	if !bytes.Equal(raw, check) {
		return ErrInvalid
	}
	return g.step(label + ":readback")
}

func (g *Guard) cleanup(current pointerRecord) {
	if g.ctx.Err() != nil {
		return
	}
	entries, err := os.ReadDir(g.store.livePath())
	if err != nil {
		return
	}
	for _, entry := range entries {
		if g.ctx.Err() != nil {
			return
		}
		name := entry.Name()
		id := strings.TrimSuffix(strings.TrimPrefix(name, "generation-"), ".json")
		if name != generationName(id) || !validHex(id, 16) || id == current.ID || id == current.Previous || !entry.Type().IsRegular() {
			continue
		}
		_ = os.Remove(filepath.Join(g.store.livePath(), name))
	}
}
