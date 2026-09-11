package filepersist

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
)

func ReadJSON(ctx context.Context, path string, limit int64, out any) error {
	if limit <= 0 || limit > 64<<20 {
		return ErrTooLarge
	}
	f, err := OpenRegular(ctx, path)
	if err != nil {
		return err
	}
	raw, err := io.ReadAll(io.LimitReader(contextReader{ctx, f}, limit+1))
	err = errors.Join(err, f.Close())
	if err != nil {
		return err
	}
	if int64(len(raw)) > limit {
		return ErrTooLarge
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	if !json.Valid(raw) {
		return ErrInvalidJSON
	}
	if err = json.Unmarshal(raw, out); err != nil {
		return ErrInvalidJSON
	}
	return ctx.Err()
}

type contextReader struct {
	ctx context.Context
	r   io.Reader
}

func (r contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.r.Read(p)
}

type checkedWriter struct {
	ctx       context.Context
	w         io.Writer
	remaining int64
}

func (w *checkedWriter) Write(p []byte) (int, error) {
	if err := w.ctx.Err(); err != nil {
		return 0, err
	}
	if w.remaining >= 0 && int64(len(p)) > w.remaining {
		return 0, ErrTooLarge
	}
	n, err := w.w.Write(p)
	if w.remaining >= 0 {
		w.remaining -= int64(n)
	}
	if err == nil && n != len(p) {
		err = io.ErrShortWrite
	}
	return n, err
}

type tempFile interface {
	io.Writer
	Name() string
	Chmod(os.FileMode) error
	Sync() error
	Close() error
}
type operations struct {
	create  func(string) (tempFile, error)
	replace func(context.Context, string, string) error
	remove  func(string) error
}

func diskOperations() operations {
	return operations{
		create:  func(dir string) (tempFile, error) { return os.CreateTemp(dir, ".tmp-*") },
		replace: Replace, remove: os.Remove,
	}
}

// Write commits only after encoding, Sync and Close succeed. limit=-1 permits
// an externally bounded artifact stream. The callback must propagate IO errors.
func Write(ctx context.Context, path string, perm os.FileMode, limit int64, encode func(io.Writer) error) error {
	return write(ctx, path, perm, limit, encode, diskOperations())
}

func write(ctx context.Context, path string, perm os.FileMode, limit int64, encode func(io.Writer) error, ops operations) (err error) {
	if err = ctx.Err(); err != nil {
		return err
	}
	abs, err := absolute(path)
	if err != nil {
		return err
	}
	if err = EnsureDir(ctx, filepath.Dir(abs)); err != nil {
		return err
	}
	if _, err = regular(ctx, abs, true); err != nil {
		return err
	}
	f, err := ops.create(filepath.Dir(abs))
	if err != nil {
		return err
	}
	closed, committed := false, false
	defer func() {
		if !closed {
			err = errors.Join(err, f.Close())
		}
		if !committed {
			if e := ops.remove(f.Name()); e != nil && !os.IsNotExist(e) {
				err = errors.Join(err, e)
			}
		}
	}()
	if err = f.Chmod(perm); err != nil {
		return err
	}
	if err = encode(&checkedWriter{ctx: ctx, w: f, remaining: limit}); err != nil {
		return err
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	err = f.Close()
	closed = true
	if err != nil {
		return err
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	if err = ops.replace(ctx, f.Name(), abs); err != nil {
		return err
	}
	committed = true
	return nil
}

// Replace consumes a prepared, flushed and closed same-directory source. It
// never deletes dst to retry. Success is the commit point, even if ctx is then
// canceled. os.Rename uses MoveFileEx(REPLACE_EXISTING) on Windows and rename on
// Linux; neither this wrapper nor File.Sync claims parent-directory durability.
func Replace(ctx context.Context, src, dst string) error {
	src, err := absolute(src)
	if err != nil {
		return err
	}
	dst, err = absolute(dst)
	if err != nil {
		return err
	}
	a, err := regular(ctx, src, false)
	if err != nil {
		return err
	}
	b, err := regular(ctx, dst, true)
	if err != nil {
		return err
	}
	parentA, err := os.Stat(filepath.Dir(src))
	if err != nil {
		return err
	}
	parentB, err := os.Stat(filepath.Dir(dst))
	if err != nil {
		return err
	}
	if !os.SameFile(parentA, parentB) || (b != nil && os.SameFile(a, b)) {
		return ErrUnsafePath
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	return os.Rename(src, dst)
}
