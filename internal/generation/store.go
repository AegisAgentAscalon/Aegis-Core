// Package generation commits one bounded JSON state for cooperating local writers.
// The owner validates its domain data. Directory activation and pointer replacement
// are commit points; neither file Sync nor this package promises power-loss safety.
package generation

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"unicode/utf8"

	"github.com/AegisAgentAscalon/aegis-core/internal/filelock"
	"github.com/AegisAgentAscalon/aegis-core/internal/filepersist"
)

var (
	ErrConflict = errors.New("generation: state changed")
	ErrInvalid  = errors.New("generation: invalid authority")
	ErrTooLarge = errors.New("generation: size limit exceeded")
)

const (
	metadataLimit   = 16 << 10
	generationLimit = 64 << 20
	formatVersion   = 1
)

// Store binds an exact owner identity to an existing private root. Callers must
// quiesce older writers before the first commit; legacy files are never mirrored.
type Store struct {
	root, owner string
	// checkpoint is a per-store fault/exit seam used by the protocol tests.
	checkpoint func(string) error
}

type Snapshot struct {
	Token    string
	Revision uint64
	Data     []byte
}

// Guard exclusively coordinates a root until Close. It is not safe to share
// between goroutines. Callers must defer Close, including across domain panics.
type Guard struct {
	store *Store
	ctx   context.Context
	lock  *filelock.Lock
}

func New(root, owner string) (*Store, error) {
	if owner == "" || len(owner) > metadataLimit/4 || !utf8.ValidString(owner) {
		return nil, ErrInvalid
	}
	if err := filepersist.EnsureDir(context.Background(), root); err != nil {
		return nil, err
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	s := &Store{root: abs, owner: owner}
	// Create/validate the stable sentinel before callers record a no-write
	// baseline. A busy, validated sentinel needs no initialization.
	l, err := filelock.TryAcquire(context.Background(), s.lockPath())
	if errors.Is(err, filelock.ErrBusy) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	return s, l.Close()
}

func (s *Store) lockPath() string { return filepath.Join(s.root, ".state.lock") }
func (s *Store) livePath() string { return filepath.Join(s.root, "state-v2") }

func (s *Store) Lock(ctx context.Context) (*Guard, error)    { return s.acquire(ctx, false) }
func (s *Store) TryLock(ctx context.Context) (*Guard, error) { return s.acquire(ctx, true) }

func (s *Store) acquire(ctx context.Context, try bool) (*Guard, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	acquire := filelock.Acquire
	if try {
		acquire = filelock.TryAcquire
	}
	l, err := acquire(ctx, s.lockPath())
	if err != nil {
		return nil, err
	}
	return &Guard{store: s, ctx: ctx, lock: l}, nil
}

func (g *Guard) Close() error {
	if g.lock == nil {
		return nil
	}
	l := g.lock
	g.lock = nil
	return l.Close()
}

func (g *Guard) check() error {
	if g.lock == nil {
		return ErrInvalid
	}
	return g.ctx.Err()
}

func (g *Guard) step(name string) error {
	if err := g.check(); err != nil {
		return err
	}
	if g.store.checkpoint != nil {
		if err := g.store.checkpoint(name); err != nil {
			return err
		}
	}
	return g.check()
}

func (g *Guard) Token() (string, error) {
	p, err := g.inspect(false)
	return p.token, err
}

func (g *Guard) Read() (Snapshot, error) {
	p, err := g.inspect(true)
	if err != nil {
		return Snapshot{}, err
	}
	return Snapshot{Token: p.token, Revision: p.pointer.Revision, Data: p.data}, err
}

type inspected struct {
	pointer pointerRecord
	token   string
	data    []byte
}

func (g *Guard) inspect(full bool) (inspected, error) {
	var out inspected
	if err := g.check(); err != nil {
		return out, err
	}
	live := g.store.livePath()
	info, err := os.Lstat(live)
	if os.IsNotExist(err) {
		return out, nil
	}
	if err != nil {
		return out, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return out, ErrInvalid
	}
	var format formatRecord
	if _, err = decodeFile(g.ctx, filepath.Join(live, "format.json"), metadataLimit, &format); err != nil {
		return out, invalid(err)
	}
	if format.Version != formatVersion || format.Owner != g.store.owner {
		return out, ErrInvalid
	}
	raw, err := decodeFile(g.ctx, filepath.Join(live, "current.json"), metadataLimit, &out.pointer)
	if err != nil {
		return out, invalid(err)
	}
	p := out.pointer
	if !p.valid(g.store.owner) {
		return inspected{}, ErrInvalid
	}
	path := filepath.Join(live, generationName(p.ID))
	f, err := filepersist.OpenRegular(g.ctx, path)
	if err != nil {
		return inspected{}, invalid(err)
	}
	stat, statErr := f.Stat()
	closeErr := f.Close()
	if err = errors.Join(statErr, closeErr); err != nil {
		return inspected{}, invalid(err)
	}
	if stat.Size() != p.Bytes {
		return inspected{}, ErrInvalid
	}
	out.token = digest(raw)
	if !full {
		return out, g.check()
	}
	var generation generationRecord
	raw, err = decodeFile(g.ctx, path, generationLimit, &generation)
	if err != nil {
		return inspected{}, invalid(err)
	}
	if int64(len(raw)) != p.Bytes || digest(raw) != p.SHA256 || generation.Version != p.Version ||
		generation.Owner != p.Owner || generation.ID != p.ID || generation.Revision != p.Revision ||
		generation.ParentToken != p.ParentToken || len(generation.Data) == 0 {
		return inspected{}, ErrInvalid
	}
	out.data = generation.Data
	return out, g.check()
}

func invalid(err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	return errors.Join(ErrInvalid, err)
}
