package updates

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"github.com/AegisAgentAscalon/aegis-core/internal/filepersist"
	"io"
	"path/filepath"
	"runtime"
	"strings"
)

func samePath(a, b string) bool {
	a = filepath.Clean(a)
	b = filepath.Clean(b)
	if runtime.GOOS == "windows" {
		return strings.EqualFold(a, b)
	}
	return a == b
}

func writeStreamToFile(ctx context.Context, r io.Reader, path string, max int64) (int64, error) {
	var written int64
	limit := max
	if limit <= 0 {
		limit = -1
	}
	err := filepersist.Write(ctx, path, 0600, limit, func(w io.Writer) error {
		var err error
		written, err = io.Copy(w, downloadReader{r})
		return err
	})
	if errors.Is(err, filepersist.ErrTooLarge) || errors.Is(err, ErrDownloadFailed) {
		return 0, ErrDownloadFailed
	}
	if err != nil {
		return 0, persistenceError(err)
	}
	return written, nil
}

type downloadReader struct{ io.Reader }

func (r downloadReader) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	if err != nil && !errors.Is(err, io.EOF) {
		err = ErrDownloadFailed
	}
	return n, err
}

func hashFile(ctx context.Context, path string) (string, error) {
	f, err := filepersist.OpenRegular(ctx, path)
	if err != nil {
		if canceled := contextError(ctx); canceled != nil {
			return "", canceled
		}
		return "", ErrVerificationFailed
	}
	h := sha256.New()
	_, readErr := io.Copy(h, contextReader{ctx, f})
	err = errors.Join(readErr, f.Close())
	if canceled := contextError(ctx); canceled != nil {
		return "", canceled
	}
	if err != nil {
		return "", ErrVerificationFailed
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func copyFileAtomic(ctx context.Context, src, dst string) error {
	in, err := filepersist.OpenRegular(ctx, src)
	if err != nil {
		if contextError(ctx) != nil {
			return ErrContextCanceled
		}
		return ErrVerificationFailed
	}
	defer in.Close()
	_, err = writeStreamToFile(ctx, in, dst, 0)
	return err
}
