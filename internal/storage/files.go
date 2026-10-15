package storage

import (
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
)

func ID(prefix string, size int) (string, error) {
	b := make([]byte, size)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return prefix + base64.RawURLEncoding.EncodeToString(b), nil
}

// AtomicWrite commits a complete private file without exposing a partial JSON document.
func AtomicWrite(path string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".govweave-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}
