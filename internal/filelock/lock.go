// Package filelock excludes cooperating processes through stable OS file locks.
// Lock files are never unlinked, replaced, truncated or initialized. The owner
// must keep the file and its trusted local parent at a stable path.
package filelock

import (
	"context"
	"errors"
	"os"
	"sync"
	"time"

	"github.com/AegisAgentAscalon/aegis-core/internal/filepersist"
)

var ErrBusy = errors.New("filelock: already locked")

type Lock struct {
	file *os.File
	once sync.Once
	err  error
}

// Close releases the OS lock and handle once, including when deferred through a
// panic. Process exit also releases the lock; its sentinel file remains intact.
func (lock *Lock) Close() error {
	if lock == nil {
		return nil
	}
	lock.once.Do(func() { lock.err = errors.Join(unlockFile(lock.file), lock.file.Close()) })
	return lock.err
}

func Acquire(ctx context.Context, path string) (*Lock, error) {
	return acquire(ctx, path, true)
}

func TryAcquire(ctx context.Context, path string) (*Lock, error) {
	return acquire(ctx, path, false)
}

func acquire(ctx context.Context, path string, wait bool) (*Lock, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	f, err := filepersist.OpenOrCreateRegular(ctx, path)
	if err != nil {
		return nil, err
	}
	for {
		if err := ctx.Err(); err != nil {
			return nil, errors.Join(err, f.Close())
		}
		err := tryLockFile(f)
		if err == nil {
			lock := &Lock{file: f}
			if err := ctx.Err(); err != nil {
				return nil, errors.Join(err, lock.Close())
			}
			return lock, nil
		}
		if !wait || !errors.Is(err, ErrBusy) {
			return nil, errors.Join(err, f.Close())
		}
		timer := time.NewTimer(10 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, errors.Join(ctx.Err(), f.Close())
		case <-timer.C:
		}
	}
}
