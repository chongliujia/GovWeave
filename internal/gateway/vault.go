package gateway

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"os"
	"path/filepath"
)

func openVault(dir string, existing bool) (cipher.AEAD, error) {
	path := filepath.Join(dir, "gateway.key")
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		if existing {
			return nil, errors.New("gateway.key is missing; restore the encryption key from backup")
		}
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return nil, err
		}
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return nil, err
		}
		_, err = f.WriteString(base64.RawStdEncoding.EncodeToString(key) + "\n")
		if err == nil {
			err = f.Sync()
		}
		closeErr := f.Close()
		if err != nil {
			return nil, err
		}
		if closeErr != nil {
			return nil, closeErr
		}
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 128 {
		return nil, errors.New("gateway.key must be a private regular file (0600)")
	}
	data, err := io.ReadAll(io.LimitReader(f, 129))
	if err != nil {
		return nil, err
	}
	if len(data) > 0 && data[len(data)-1] == '\n' {
		data = data[:len(data)-1]
	}
	key, err := base64.RawStdEncoding.DecodeString(string(data))
	if err != nil || len(key) != 32 {
		return nil, errors.New("invalid gateway encryption key")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func seal(aead cipher.AEAD, id, value string) (string, error) {
	if value == "" {
		return "", nil
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	sealed := aead.Seal(nonce, nonce, []byte(value), []byte(id))
	return base64.RawStdEncoding.EncodeToString(sealed), nil
}

func unseal(aead cipher.AEAD, id, value string) (string, error) {
	if value == "" {
		return "", nil
	}
	data, err := base64.RawStdEncoding.DecodeString(value)
	if err != nil || len(data) < aead.NonceSize() {
		return "", errors.New("invalid encrypted credential")
	}
	plain, err := aead.Open(nil, data[:aead.NonceSize()], data[aead.NonceSize():], []byte(id))
	if err != nil {
		return "", errors.New("cannot decrypt upstream credential; restore the correct gateway.key")
	}
	return string(plain), nil
}
