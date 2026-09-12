package generation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func prepareBoundaryCase(t *testing.T, native bool) (*Store, string) {
	t.Helper()
	s := testStore(t, t.TempDir())
	mustWrite(t, filepath.Join(s.root, "legacy.json"), []byte(" original legacy bytes\n"))
	if !native {
		return s, ""
	}
	g := testGuard(t, s)
	prior := testCommit(t, g, "", `{"value":"old"}`, map[string][]byte{"legacy.json": []byte(" original legacy bytes\n")})
	g.Close()
	return s, prior.Token
}

func boundaryNames(t *testing.T, native bool) []string {
	t.Helper()
	s, token := prepareBoundaryCase(t, native)
	var points []string
	s.checkpoint = func(point string) error { points = append(points, point); return nil }
	testCommit(t, testGuard(t, s), token, `{"value":"new"}`, map[string][]byte{"legacy.json": []byte(" original legacy bytes\n"), "absent.json": nil})
	return points
}

func assertBoundaryAuthority(t *testing.T, s *Store, token string, committed bool) {
	t.Helper()
	g := testGuard(t, testStore(t, s.root))
	read, err := g.Read()
	if err != nil {
		t.Fatal(err)
	}
	if committed {
		if string(read.Data) != `{"value":"new"}` || read.Token == "" || read.Token == token {
			t.Fatalf("new authority: %#v", read)
		}
	} else if read.Token != token || token == "" && read.Data != nil || token != "" && string(read.Data) != `{"value":"old"}` {
		t.Fatalf("old authority lost: %#v", read)
	}
	if string(diskBytes(t, filepath.Join(s.root, "legacy.json"))) != " original legacy bytes\n" {
		t.Fatal("legacy modified")
	}
}

func TestFailureAndCancellationAtCommitBoundaries(t *testing.T) {
	injected := errors.New("injected persistence failure")
	for _, native := range []bool{false, true} {
		for _, point := range boundaryNames(t, native) {
			for _, cancelMode := range []bool{false, true} {
				t.Run(fmt.Sprintf("native=%v/%s/cancel=%v", native, point, cancelMode), func(t *testing.T) {
					s, token := prepareBoundaryCase(t, native)
					ctx, cancel := context.WithCancel(context.Background())
					defer cancel()
					hit := false
					s.checkpoint = func(current string) error {
						if current != point {
							return nil
						}
						hit = true
						if cancelMode {
							cancel()
							return nil
						}
						return injected
					}
					g, err := s.Lock(ctx)
					if err != nil {
						t.Fatal(err)
					}
					_, err = g.Commit(token, []byte(`{"value":"new"}`), map[string][]byte{"legacy.json": []byte(" original legacy bytes\n"), "absent.json": nil})
					g.Close()
					if !hit {
						t.Fatal("fault boundary not exercised")
					}
					if point == "committed" {
						if err != nil {
							t.Fatalf("committed mutation reported rollback: %v", err)
						}
					} else {
						want := injected
						if cancelMode {
							want = context.Canceled
						}
						if !errors.Is(err, want) {
							t.Fatalf("failure mapping: %v", err)
						}
					}
					assertBoundaryAuthority(t, s, token, point == "committed")
				})
			}
		}
	}
}

func TestReadbackCorruptionCannotActivateOrReplace(t *testing.T) {
	for _, native := range []bool{false, true} {
		s, token := prepareBoundaryCase(t, native)
		s.checkpoint = func(point string) error {
			if point != "generation:closed" {
				return nil
			}
			base := s.livePath()
			if !native {
				matches, err := filepath.Glob(filepath.Join(s.root, ".state-prepare-*"))
				if err != nil || len(matches) != 1 {
					t.Fatalf("prepare path: %v %v", matches, err)
				}
				base = matches[0]
			}
			matches, err := filepath.Glob(filepath.Join(base, "generation-*.json"))
			if err != nil {
				t.Fatal(err)
			}
			for _, path := range matches {
				raw := diskBytes(t, path)
				if strings.Contains(string(raw), `"value":"new"`) {
					mustWrite(t, path, []byte(strings.Replace(string(raw), `"new"`, `"bad"`, 1)))
				}
			}
			return nil
		}
		g := testGuard(t, s)
		if _, err := g.Commit(token, []byte(`{"value":"new"}`), nil); !errors.Is(err, ErrInvalid) {
			t.Fatalf("unchecked readback: %v", err)
		}
		g.Close()
		assertBoundaryAuthority(t, s, token, false)
	}
}

func childCommand(t *testing.T, root, mode, token, point string) *exec.Cmd {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestGenerationChildProcess$", "-test.count=1")
	cmd.Env = append(os.Environ(), "AEGIS_GENERATION_CHILD="+mode, "AEGIS_GENERATION_ROOT="+root, "AEGIS_GENERATION_TOKEN="+token, "AEGIS_GENERATION_POINT="+point)
	return cmd
}

// Child exit bypasses all Go defers: recovery must depend on committed disk
// authority and kernel lock release, not in-process cleanup or cached objects.
func TestProcessExitAtEveryCommitBoundary(t *testing.T) {
	for _, native := range []bool{false, true} {
		for _, point := range boundaryNames(t, native) {
			t.Run(fmt.Sprintf("native=%v/%s", native, point), func(t *testing.T) {
				s, token := prepareBoundaryCase(t, native)
				output, err := childCommand(t, s.root, "exit", token, point).CombinedOutput()
				var exit *exec.ExitError
				if !errors.As(err, &exit) || exit.ExitCode() != 71 {
					t.Fatalf("child did not exit at boundary: %v %s", err, output)
				}
				assertBoundaryAuthority(t, s, token, point == "committed")
			})
		}
	}
}

func TestSeparateProcessesPreserveOneCoherentGeneration(t *testing.T) {
	s := testStore(t, t.TempDir())
	g := testGuard(t, s)
	initial := testCommit(t, g, "", `{"count":0,"mirror":0}`, nil)
	g.Close()
	children := make([]*exec.Cmd, 3)
	for i := range children {
		children[i] = childCommand(t, s.root, "increment", "", "")
		if err := children[i].Start(); err != nil {
			t.Fatal(err)
		}
	}
	for _, child := range children {
		if err := child.Wait(); err != nil {
			t.Fatal(err)
		}
	}
	g = testGuard(t, s)
	read, err := g.Read()
	if err != nil {
		t.Fatal(err)
	}
	var result struct{ Count, Mirror int }
	if err := json.Unmarshal(read.Data, &result); err != nil {
		t.Fatal(err)
	}
	if result.Count != 15 || result.Mirror != 15 || read.Revision != 16 {
		t.Fatalf("lost/mixed process writes: %#v rev%d", result, read.Revision)
	}
	g.Close()
	output, err := childCommand(t, s.root, "stale", initial.Token, "").CombinedOutput()
	if err != nil {
		t.Fatalf("separate stale writer: %v %s", err, output)
	}
}

func TestGenerationChildProcess(t *testing.T) {
	mode := os.Getenv("AEGIS_GENERATION_CHILD")
	if mode == "" {
		return
	}
	s, err := New(os.Getenv("AEGIS_GENERATION_ROOT"), "test/owner/scope")
	if err != nil {
		t.Fatal(err)
	}
	if mode == "increment" {
		for i := 0; i < 5; i++ {
			g, err := s.Lock(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			read, err := g.Read()
			if err != nil {
				t.Fatal(err)
			}
			var old struct{ Count, Mirror int }
			if err := json.Unmarshal(read.Data, &old); err != nil || old.Count != old.Mirror {
				t.Fatalf("mixed read: %v %#v", err, old)
			}
			value := strconv.Itoa(old.Count + 1)
			if _, err := g.Commit(read.Token, []byte(`{"count":`+value+`,"mirror":`+value+`}`), nil); err != nil {
				t.Fatal(err)
			}
			if err := g.Close(); err != nil {
				t.Fatal(err)
			}
		}
		return
	}
	g, err := s.Lock(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	if mode == "exit" {
		s.checkpoint = func(point string) error {
			if point == os.Getenv("AEGIS_GENERATION_POINT") {
				os.Exit(71)
			}
			return nil
		}
	}
	_, err = g.Commit(os.Getenv("AEGIS_GENERATION_TOKEN"), []byte(`{"value":"new"}`), map[string][]byte{"legacy.json": []byte(" original legacy bytes\n"), "absent.json": nil})
	if mode == "stale" && errors.Is(err, ErrConflict) {
		return
	}
	t.Fatalf("child missed intended outcome: %s %v", mode, err)
}
