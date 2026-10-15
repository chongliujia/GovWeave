package instance

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

// LockDataDir enforces the single-process storage contract on Linux/macOS.
// The OS releases the lock on crash; the file itself deliberately remains.
func LockDataDir(dir string) (*os.File, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(dir, ".instance.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, errors.New("data directory is already in use or cannot be locked; use one process per data directory")
	}
	return f, nil
}
