// Package filepersist provides single-file IO for trusted, single-writer roots.
// It does not provide cross-process transactions or power-loss durability.
package filepersist

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

var (
	ErrUnsafePath  = errors.New("filepersist: unsafe path")
	ErrInvalidJSON = errors.New("filepersist: invalid JSON")
	ErrTooLarge    = errors.New("filepersist: size limit exceeded")
)

func absolute(path string) (string, error) {
	if path == "" {
		return "", ErrUnsafePath
	}
	for _, part := range strings.FieldsFunc(path, func(r rune) bool { return r == '/' || r == '\\' }) {
		if part == ".." {
			return "", ErrUnsafePath
		}
	}
	if runtime.GOOS == "windows" {
		volume := filepath.VolumeName(path)
		if strings.HasPrefix(volume, `\\`) {
			return "", ErrUnsafePath
		}
		for _, part := range strings.FieldsFunc(strings.TrimPrefix(path, volume), func(r rune) bool { return r == '/' || r == '\\' }) {
			stem, _, _ := strings.Cut(strings.ToUpper(part), ".")
			reserved := stem == "CON" || stem == "PRN" || stem == "AUX" || stem == "NUL" || stem == "CONIN$" || stem == "CONOUT$" || len(stem) == 4 && (strings.HasPrefix(stem, "COM") || strings.HasPrefix(stem, "LPT")) && stem[3] >= '1' && stem[3] <= '9'
			if reserved || !filepath.IsLocal(part) || strings.Contains(part, ":") || part != "." && strings.TrimRight(part, ". ") != part {
				return "", ErrUnsafePath
			}
		}
	}
	return filepath.Abs(path)
}

// EnsureDir creates private directories without chmodding caller-owned ancestors.
func EnsureDir(ctx context.Context, path string) error {
	abs, err := absolute(path)
	if err != nil {
		return err
	}
	return directory(ctx, abs, true, true)
}

func directory(ctx context.Context, path string, create, final bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if os.IsNotExist(err) && create {
		parent := filepath.Dir(path)
		if parent == path {
			return err
		}
		if err = directory(ctx, parent, true, false); err != nil {
			return err
		}
		if err = os.Mkdir(path, 0700); err != nil && !os.IsExist(err) {
			return err
		}
		info, err = os.Lstat(path)
	} else if err == nil && filepath.Dir(path) != path {
		if err = directory(ctx, filepath.Dir(path), false, false); err != nil {
			return err
		}
	}
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return ErrUnsafePath
	}
	if final && create {
		return os.Chmod(path, 0700)
	}
	return nil
}

func regular(ctx context.Context, path string, missingOK bool) (os.FileInfo, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := directory(ctx, filepath.Dir(path), false, false); err != nil {
		return nil, err
	}
	info, err := os.Lstat(path)
	if os.IsNotExist(err) && missingOK {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, ErrUnsafePath
	}
	return info, nil
}

func OpenRegular(ctx context.Context, path string) (*os.File, error) {
	abs, err := absolute(path)
	if err != nil {
		return nil, err
	}
	before, err := regular(ctx, abs, false)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(abs)
	if err != nil {
		return nil, err
	}
	after, err := f.Stat()
	if err == nil && (!after.Mode().IsRegular() || !os.SameFile(before, after)) {
		err = ErrUnsafePath
	}
	if err != nil {
		return nil, errors.Join(err, f.Close())
	}
	return f, nil
}
