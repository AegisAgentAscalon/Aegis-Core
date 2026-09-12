//go:build !windows && !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd

package filelock

import (
	"errors"
	"os"
)

func tryLockFile(*os.File) error { return errors.New("filelock: unsupported platform") }
func unlockFile(*os.File) error  { return errors.New("filelock: unsupported platform") }
