package filelock

import (
	"os"
	"syscall"
	"unsafe"
)

var (
	lockFileEx   = syscall.NewLazyDLL("kernel32.dll").NewProc("LockFileEx")
	unlockFileEx = syscall.NewLazyDLL("kernel32.dll").NewProc("UnlockFileEx")
)

func tryLockFile(file *os.File) error {
	var overlap syscall.Overlapped
	// FAIL_IMMEDIATELY | EXCLUSIVE_LOCK, byte [0,1), including beyond EOF.
	ok, _, err := lockFileEx.Call(file.Fd(), 3, 0, 1, 0, uintptr(unsafe.Pointer(&overlap)))
	if ok != 0 {
		return nil
	}
	if err == syscall.Errno(33) { // ERROR_LOCK_VIOLATION
		return ErrBusy
	}
	return err
}

func unlockFile(file *os.File) error {
	var overlap syscall.Overlapped
	ok, _, err := unlockFileEx.Call(file.Fd(), 0, 1, 0, uintptr(unsafe.Pointer(&overlap)))
	if ok != 0 {
		return nil
	}
	return err
}
