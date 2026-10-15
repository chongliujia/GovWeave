// Package auth manages the single local administrator and revocable browser sessions.
package auth

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
	"unicode/utf8"

	"govweave/internal/config"
)

const SessionLifetime = 8 * time.Hour
const iterations = 600000

var (
	ErrConfigured     = errors.New("管理员密码已设置，请直接登录")
	ErrPassword       = errors.New("密码错误，请重试")
	ErrPasswordLength = errors.New("密码须为 12–128 个字符")
	ErrRateLimited    = errors.New("登录尝试过于频繁，请稍后再试")
	ErrPersistence    = errors.New("无法保存管理员密码，请检查数据目录权限和磁盘空间")
)

type credential struct {
	Version    int    `json:"version"`
	Algorithm  string `json:"algorithm"`
	Iterations int    `json:"iterations"`
	Salt       []byte `json:"salt"`
	Hash       []byte `json:"hash"`
}

type Manager struct {
	mu       sync.Mutex
	loginMu  sync.Mutex
	path     string
	password *credential
	sessions map[[32]byte]time.Time
	window   time.Time
	attempts int
	now      func() time.Time
	// Existing token installations require local ownership when choosing a password.
	// The old token itself is never accepted as a management credential.
	legacy bool
}

func Open(dataDir, legacyPath string) (*Manager, error) {
	m := &Manager{path: filepath.Join(dataDir, "admin.password.json"), sessions: make(map[[32]byte]time.Time), now: time.Now}
	f, err := os.Open(m.path)
	if errors.Is(err, os.ErrNotExist) {
		explicitLegacyPath := legacyPath != ""
		if legacyPath == "" {
			legacyPath = filepath.Join(dataDir, "admin.token")
		}
		_, err = os.Lstat(legacyPath)
		m.legacy = !errors.Is(err, os.ErrNotExist)
		if err != nil && (explicitLegacyPath || !errors.Is(err, os.ErrNotExist)) {
			return nil, err
		}
		return m, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > 4096 || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("admin.password.json must be a private regular file (chmod 600)")
	}
	var c credential
	if config.DecodeStrict(io.LimitReader(f, 4097), &c) != nil || c.Version != 1 || c.Algorithm != "pbkdf2-sha256" || c.Iterations != iterations || len(c.Salt) != 16 || len(c.Hash) != 32 {
		return nil, errors.New("invalid administrator password file; restore from backup, refusing to reset")
	}
	m.password = &c
	return m, nil
}

func (m *Manager) SetupRequired() bool { m.mu.Lock(); defer m.mu.Unlock(); return m.password == nil }
func (m *Manager) LegacySetup() bool   { return m.legacy }

// Limits expensive password derivations globally for this single-admin instance.
// Proxy-provided client addresses are deliberately not trusted for rate limiting.
func (m *Manager) beginAttempt() bool {
	if !m.loginMu.TryLock() {
		return false
	}
	now := m.now()
	if now.Sub(m.window) >= time.Minute {
		m.window, m.attempts = now, 0
	}
	if m.attempts >= 10 {
		m.loginMu.Unlock()
		return false
	}
	m.attempts++
	return true
}

func validLength(password string) bool {
	return len(password) <= 512 && utf8.ValidString(password) && utf8.RuneCountInString(password) >= 12 && utf8.RuneCountInString(password) <= 128
}

func (m *Manager) Setup(password string) error {
	if !m.beginAttempt() {
		return ErrRateLimited
	}
	defer m.loginMu.Unlock()
	if !m.SetupRequired() {
		return ErrConfigured
	}
	if !validLength(password) {
		return ErrPasswordLength
	}
	c := credential{Version: 1, Algorithm: "pbkdf2-sha256", Iterations: iterations, Salt: make([]byte, 16)}
	if _, err := rand.Read(c.Salt); err != nil {
		return ErrPersistence
	}
	var err error
	c.Hash, err = pbkdf2.Key(sha256.New, password, c.Salt, c.Iterations, 32)
	if err != nil {
		return ErrPersistence
	}
	data, _ := json.Marshal(c)
	f, err := os.CreateTemp(filepath.Dir(m.path), ".admin-password-*")
	if err != nil {
		return ErrPersistence
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(append(data, '\n')); err != nil {
		f.Close()
		return ErrPersistence
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return ErrPersistence
	}
	if err = f.Close(); err != nil {
		return ErrPersistence
	}
	// Publish atomically, without ever replacing an existing password file.
	if err = os.Link(f.Name(), m.path); err != nil {
		return ErrPersistence
	}
	m.mu.Lock()
	m.password = &c
	m.mu.Unlock()
	return nil
}

func (m *Manager) Login(password string) error {
	if !m.beginAttempt() {
		return ErrRateLimited
	}
	defer m.loginMu.Unlock()
	m.mu.Lock()
	c := m.password
	m.mu.Unlock()
	if c == nil || !validLength(password) {
		return ErrPassword
	}
	hash, err := pbkdf2.Key(sha256.New, password, c.Salt, c.Iterations, 32)
	if err != nil || subtle.ConstantTimeCompare(c.Hash, hash) != 1 {
		return ErrPassword
	}
	return nil
}

func (m *Manager) NewSession(previous string) (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	value := base64.RawURLEncoding.EncodeToString(buf)
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.sessions, sha256.Sum256([]byte(previous)))
	now := m.now()
	for hash, expires := range m.sessions {
		if !now.Before(expires) {
			delete(m.sessions, hash)
		}
	}
	if len(m.sessions) >= 128 {
		return "", ErrRateLimited
	}
	m.sessions[sha256.Sum256([]byte(value))] = now.Add(SessionLifetime)
	return value, nil
}

func (m *Manager) Valid(value string) bool {
	if len(value) != 43 {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	hash := sha256.Sum256([]byte(value))
	expires, ok := m.sessions[hash]
	if !ok {
		return false
	}
	if !m.now().Before(expires) {
		delete(m.sessions, hash)
		return false
	}
	return true
}

func (m *Manager) Logout(value string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.sessions, sha256.Sum256([]byte(value)))
}
