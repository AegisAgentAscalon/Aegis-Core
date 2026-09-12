package generation

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/AegisAgentAscalon/aegis-core/internal/filelock"
)

func testStore(t *testing.T, root string) *Store {
	t.Helper()
	s, err := New(root, "test/owner/scope")
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func testGuard(t *testing.T, s *Store) *Guard {
	t.Helper()
	g, err := s.Lock(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := g.Close(); err != nil {
			t.Error(err)
		}
	})
	return g
}

func testCommit(t *testing.T, g *Guard, expected, data string, backup map[string][]byte) Snapshot {
	t.Helper()
	snapshot, err := g.Commit(expected, []byte(data), backup)
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func mustWrite(t *testing.T, path string, raw []byte) {
	t.Helper()
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
}

func diskBytes(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestActivationBackupReopenAndOwnedSnapshots(t *testing.T) {
	root := t.TempDir()
	legacy := []byte("  {\"old\":true}\n")
	mustWrite(t, filepath.Join(root, "legacy.json"), legacy)
	s := testStore(t, root)
	g := testGuard(t, s)
	initial, err := g.Read()
	if err != nil || initial.Token != "" || initial.Revision != 0 || initial.Data != nil {
		t.Fatalf("legacy: %#v %v", initial, err)
	}
	input := []byte(`{"trusted":false,"records":[1,2]}`)
	first, err := g.Commit("", input, map[string][]byte{"legacy.json": legacy, "absent.json": nil, "empty.json": {}})
	if err != nil {
		t.Fatal(err)
	}
	input[2] = 'X'
	first.Data[2] = 'Y'
	if err := g.Close(); err != nil {
		t.Fatal(err)
	}
	other := testGuard(t, testStore(t, root))
	read, err := other.Read()
	if err != nil || string(read.Data) != `{"trusted":false,"records":[1,2]}` || read.Token != first.Token || read.Revision != 1 {
		t.Fatalf("reopen: %#v %v", read, err)
	}
	read.Data[2] = 'Z'
	again, err := other.Read()
	if err != nil || again.Data[2] != 't' {
		t.Fatal("snapshot aliases persisted state")
	}
	if !bytes.Equal(diskBytes(t, filepath.Join(root, "legacy.json")), legacy) || !bytes.Equal(diskBytes(t, filepath.Join(s.livePath(), "backup/legacy.json")), legacy) {
		t.Fatal("raw legacy changed")
	}
	var inventory backupInventory
	if err := json.Unmarshal(diskBytes(t, filepath.Join(s.livePath(), "backup/inventory.json")), &inventory); err != nil {
		t.Fatal(err)
	}
	if len(inventory.Entries) != 3 || inventory.Entries[0].Present || !inventory.Entries[1].Present || inventory.Entries[1].Bytes != 0 || inventory.Entries[1].SHA256 != digest(nil) || inventory.Entries[2].SHA256 != digest(legacy) {
		t.Fatalf("inventory %#v", inventory)
	}
	if _, err := os.Stat(filepath.Join(s.livePath(), "backup/absent.json")); !os.IsNotExist(err) {
		t.Fatal("absent entry materialized")
	}
}

func TestStaleWriterCannotReplaceNewerGeneration(t *testing.T) {
	root := t.TempDir()
	s1, s2 := testStore(t, root), testStore(t, root)
	g1 := testGuard(t, s1)
	if _, err := s2.TryLock(context.Background()); !errors.Is(err, filelock.ErrBusy) {
		t.Fatalf("owner exclusion: %v", err)
	}
	first := testCommit(t, g1, "", `{"a":1}`, nil)
	g1.Close()
	g2 := testGuard(t, s2)
	second := testCommit(t, g2, first.Token, `{"a":2}`, nil)
	g2.Close()
	g1 = testGuard(t, s1)
	if _, err := g1.Commit(first.Token, []byte(`{"a":3}`), nil); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale writer: %v", err)
	}
	read, err := g1.Read()
	if err != nil || read.Token != second.Token || string(read.Data) != `{"a":2}` {
		t.Fatalf("new authority lost: %#v %v", read, err)
	}
}

func TestRetentionNeverPromotesOrphans(t *testing.T) {
	s := testStore(t, t.TempDir())
	g := testGuard(t, s)
	first := testCommit(t, g, "", `{"v":1}`, map[string][]byte{"old.json": []byte("old")})
	second := testCommit(t, g, first.Token, `{"v":2}`, nil)
	testCommit(t, g, second.Token, `{"v":3}`, nil)
	entries, err := filepath.Glob(filepath.Join(s.livePath(), "generation-*.json"))
	if err != nil || len(entries) != 2 {
		t.Fatalf("retention: %v %v", entries, err)
	}
	id, err := newID()
	if err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(s.livePath(), generationName(id)), []byte(`{"uncommitted":true}`))
	read, err := g.Read()
	if err != nil || string(read.Data) != `{"v":3}` {
		t.Fatal("orphan promoted")
	}
	if string(diskBytes(t, filepath.Join(s.livePath(), "backup/old.json"))) != "old" {
		t.Fatal("backup lost")
	}
}

func TestEstablishedAuthorityFailsClosed(t *testing.T) {
	for _, kind := range []string{"format-missing", "format-owner", "format-case", "pointer-missing", "pointer-duplicate", "pointer-unknown", "pointer-trailing", "pointer-parent", "pointer-size", "generation-missing", "generation-digest", "generation-binding", "generation-unknown"} {
		t.Run(kind, func(t *testing.T) {
			s := testStore(t, t.TempDir())
			g := testGuard(t, s)
			first := testCommit(t, g, "", `{"revoked":false}`, map[string][]byte{"legacy.json": []byte(`{"revoked":false}`)})
			testCommit(t, g, first.Token, `{"revoked":true}`, nil)
			ptrPath := filepath.Join(s.livePath(), "current.json")
			var p pointerRecord
			if err := json.Unmarshal(diskBytes(t, ptrPath), &p); err != nil {
				t.Fatal(err)
			}
			genPath := filepath.Join(s.livePath(), generationName(p.ID))
			switch kind {
			case "format-missing":
				if err := os.Remove(filepath.Join(s.livePath(), "format.json")); err != nil {
					t.Fatal(err)
				}
			case "format-owner":
				mustWrite(t, filepath.Join(s.livePath(), "format.json"), []byte(`{"version":1,"owner":"other"}`))
			case "format-case":
				mustWrite(t, filepath.Join(s.livePath(), "format.json"), []byte(`{"version":1,"Owner":"test/owner/scope"}`))
			case "pointer-missing":
				if err := os.Remove(ptrPath); err != nil {
					t.Fatal(err)
				}
			case "pointer-duplicate":
				mustWrite(t, ptrPath, bytes.Replace(diskBytes(t, ptrPath), []byte(`"version":1`), []byte(`"version":1,"\u0076ersion":1`), 1))
			case "pointer-unknown":
				mustWrite(t, ptrPath, append([]byte(`{"unexpected":1,`), diskBytes(t, ptrPath)[1:]...))
			case "pointer-trailing":
				mustWrite(t, ptrPath, append(diskBytes(t, ptrPath), []byte(`{}`)...))
			case "pointer-parent":
				p.ParentToken = ""
				raw, _ := json.Marshal(p)
				mustWrite(t, ptrPath, raw)
			case "pointer-size":
				p.Bytes++
				raw, _ := json.Marshal(p)
				mustWrite(t, ptrPath, raw)
			case "generation-missing":
				if err := os.Remove(genPath); err != nil {
					t.Fatal(err)
				}
			case "generation-digest":
				mustWrite(t, genPath, bytes.Replace(diskBytes(t, genPath), []byte(`true`), []byte(`null`), 1))
			case "generation-binding", "generation-unknown":
				var fields map[string]json.RawMessage
				if err := json.Unmarshal(diskBytes(t, genPath), &fields); err != nil {
					t.Fatal(err)
				}
				if kind == "generation-binding" {
					fields["owner"] = json.RawMessage(`"other"`)
				} else {
					fields["extra"] = json.RawMessage(`true`)
				}
				raw, _ := json.Marshal(fields)
				mustWrite(t, genPath, raw)
				p.Bytes, p.SHA256 = int64(len(raw)), digest(raw)
				encoded, _ := json.Marshal(p)
				mustWrite(t, ptrPath, encoded)
			}
			if _, err := g.Read(); !errors.Is(err, ErrInvalid) {
				t.Fatalf("corruption accepted: %v", err)
			}
			if _, err := g.Commit("", []byte(`{}`), nil); !errors.Is(err, ErrInvalid) {
				t.Fatalf("corruption overwritten: %v", err)
			}
		})
	}
}

func TestRejectedInitialPayloadLeavesLegacyAuthority(t *testing.T) {
	for _, data := range []string{`{`, `{"a":1,"a":2}`, `{} {}`, "\"\xff\""} {
		s := testStore(t, t.TempDir())
		g := testGuard(t, s)
		if _, err := g.Commit("", []byte(data), nil); !errors.Is(err, ErrInvalid) {
			t.Fatalf("accepted %q: %v", data, err)
		}
		entries, err := os.ReadDir(s.root)
		if err != nil || len(entries) != 1 || entries[0].Name() != ".state.lock" {
			t.Fatalf("rejected request wrote state: %v %v", entries, err)
		}
	}
	for _, path := range []string{"../escape", "/absolute", "a\\b", "a/../b", "a//b", "inventory.json", "nul", "bad:stream", "bad.", "UPPER.json"} {
		if _, err := backupRecords(map[string][]byte{path: []byte("x")}); !errors.Is(err, ErrInvalid) {
			t.Fatalf("backup path %q: %v", path, err)
		}
	}
}

func TestWholeGenerationBoundAndOverflow(t *testing.T) {
	header := generationHeader{formatVersion, "test/owner/scope", 1, strings.Repeat("a", 32), ""}
	prefix, _ := json.Marshal(header)
	room := generationLimit - (len(prefix) - 1 + len(`,"data":`) + 1)
	data := append([]byte{'"'}, bytes.Repeat([]byte{'a'}, room-2)...)
	data = append(data, '"')
	encoded, err := encodeGeneration(header, data)
	if err != nil || len(encoded) != generationLimit {
		t.Fatalf("exact bound: %d %v", len(encoded), err)
	}
	data = append(data[:len(data)-1], 'a', '"')
	if _, err := encodeGeneration(header, data); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("wrapper not counted: %v", err)
	}
	s := testStore(t, t.TempDir())
	g := testGuard(t, s)
	testCommit(t, g, "", `{}`, nil)
	ptrPath := filepath.Join(s.livePath(), "current.json")
	var p pointerRecord
	if err := json.Unmarshal(diskBytes(t, ptrPath), &p); err != nil {
		t.Fatal(err)
	}
	p.Revision, p.Previous, p.ParentToken = math.MaxUint64, strings.Repeat("b", 32), strings.Repeat("c", 64)
	raw, err := encodeGeneration(generationHeader{formatVersion, s.owner, p.Revision, p.ID, p.ParentToken}, []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	p.Bytes, p.SHA256 = int64(len(raw)), digest(raw)
	mustWrite(t, filepath.Join(s.livePath(), generationName(p.ID)), raw)
	ptr, _ := json.Marshal(p)
	mustWrite(t, ptrPath, ptr)
	if _, err := g.Commit(digest(ptr), []byte(`{}`), nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("revision wrapped: %v", err)
	}
	if !bytes.Equal(diskBytes(t, ptrPath), ptr) {
		t.Fatal("overflow changed authority")
	}
}
