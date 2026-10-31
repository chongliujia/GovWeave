package gateway

import (
	"crypto/cipher"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"govweave/internal/config"
	"govweave/internal/storage"
)

var ErrBusy = errors.New("gateway_busy")
var ErrConflict = errors.New("The configuration revision has changed. Refresh and try again.")
var ErrNotFound = errors.New("The record does not exist.")
var ErrInvalidKey = errors.New("invalid_api_key")
var ErrDenied = errors.New("model_not_allowed")
var ErrDisabled = errors.New("connection_disabled")
var ErrPersistence = errors.New("Could not save. Check the data directory.")

type ConnectionInput struct {
	Revision          uint64  `json:"revision"`
	Name              string  `json:"name"`
	BaseURL           string  `json:"base_url"`
	Model             string  `json:"model"`
	Alias             string  `json:"alias"`
	APIKey            *string `json:"api_key,omitempty"`
	Enabled           bool    `json:"enabled"`
	AllowInsecureHTTP bool    `json:"allow_insecure_http"`
	TimeoutSeconds    int     `json:"timeout_seconds"`
}

type Connection struct {
	ID                string `json:"id"`
	Revision          uint64 `json:"revision"`
	Name              string `json:"name"`
	BaseURL           string `json:"base_url"`
	Model             string `json:"model"`
	Alias             string `json:"alias"`
	Enabled           bool   `json:"enabled"`
	AllowInsecureHTTP bool   `json:"allow_insecure_http"`
	TimeoutSeconds    int    `json:"timeout_seconds"`
	HasCredential     bool   `json:"has_credential"`
	CreatedAt         string `json:"created_at"`
}

type storedConnection struct {
	Connection
	Credential string `json:"credential_ciphertext"`
}

type ApplicationInput struct {
	Revision           uint64   `json:"revision"`
	Name               string   `json:"name"`
	AllowedConnections []string `json:"allowed_connections"`
}

type Application struct {
	ID                 string   `json:"id"`
	Revision           uint64   `json:"revision"`
	Name               string   `json:"name"`
	AllowedConnections []string `json:"allowed_connections"`
	KeyPrefix          string   `json:"key_prefix"`
	Revoked            bool     `json:"revoked"`
	CreatedAt          string   `json:"created_at"`
}

type storedApplication struct {
	Application
	KeyHash string `json:"key_hash"`
}
type gatewayState struct {
	SchemaVersion int                 `json:"schema_version"`
	Revision      uint64              `json:"revision"`
	Connections   []storedConnection  `json:"connections"`
	Applications  []storedApplication `json:"applications"`
}

type Snapshot struct {
	Revision     uint64        `json:"revision"`
	Connections  []Connection  `json:"connections"`
	Applications []Application `json:"applications"`
}

type Store struct {
	mu    sync.RWMutex
	path  string
	vault cipher.AEAD
	state gatewayState
}

func OpenStore(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, "gateway.json")
	_, statErr := os.Stat(path)
	if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
		return nil, statErr
	}
	// A tool can be configured before any model/application is saved. Its
	// credentials still depend on this key even if gateway.json does not exist.
	_, toolStatErr := os.Stat(filepath.Join(dir, "tools.json"))
	if toolStatErr != nil && !errors.Is(toolStatErr, os.ErrNotExist) {
		return nil, toolStatErr
	}
	vault, err := openVault(dir, statErr == nil || toolStatErr == nil)
	if err != nil {
		return nil, err
	}
	s := &Store{path: path, vault: vault, state: gatewayState{SchemaVersion: 1, Connections: []storedConnection{}, Applications: []storedApplication{}}}
	if statErr != nil {
		return s, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 4<<20 || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("gateway.json must be private and smaller than 4 MiB")
	}
	if err := config.DecodeStrict(f, &s.state); err != nil || s.state.SchemaVersion != 1 {
		return nil, errors.New("invalid gateway state; refusing to reset")
	}
	ids, aliases := map[string]bool{}, map[string]bool{}
	if len(s.state.Connections) > 256 || len(s.state.Applications) > 1024 {
		return nil, errors.New("gateway state exceeds supported limits")
	}
	for _, c := range s.state.Connections {
		key, err := unseal(vault, c.ID, c.Credential)
		if err != nil {
			return nil, err
		}
		input := ConnectionInput{Name: c.Name, BaseURL: c.BaseURL, Model: c.Model, Alias: c.Alias, APIKey: &key, Enabled: c.Enabled, AllowInsecureHTTP: c.AllowInsecureHTTP, TimeoutSeconds: c.TimeoutSeconds}
		if _, err := validateConnection(input); err != nil || c.ID == "" || ids[c.ID] || aliases[c.Alias] || c.Revision == 0 || c.Revision > s.state.Revision || c.HasCredential != (c.Credential != "") {
			return nil, errors.New("invalid persisted model connection")
		}
		ids[c.ID], aliases[c.Alias] = true, true
	}
	appIDs, hashes := map[string]bool{}, map[string]bool{}
	for _, app := range s.state.Applications {
		hash, err := hex.DecodeString(app.KeyHash)
		_, nameErr := config.NormalizeName(app.Name)
		if err != nil || len(hash) != 32 || nameErr != nil || app.ID == "" || appIDs[app.ID] || hashes[app.KeyHash] || app.Revision == 0 || app.Revision > s.state.Revision {
			return nil, errors.New("invalid persisted application")
		}
		if _, err := s.validateAllowed(app.AllowedConnections); err != nil {
			return nil, errors.New("invalid persisted application permissions")
		}
		appIDs[app.ID], hashes[app.KeyHash] = true, true
	}
	return s, nil
}

func validateConnection(in ConnectionInput) (ConnectionInput, error) {
	var err error
	in.Name, err = config.NormalizeName(in.Name)
	if err != nil {
		return in, err
	}
	in.BaseURL, err = NormalizeUpstreamURL(in.BaseURL)
	if err != nil {
		return in, err
	}
	if strings.HasPrefix(in.BaseURL, "http://") && !in.AllowInsecureHTTP {
		return in, errors.New("HTTP providers are unencrypted. Explicitly allow HTTP on a trusted network, or use HTTPS.")
	}
	if !regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._/-]{0,99}$`).MatchString(in.Alias) {
		return in, errors.New("Model aliases must contain 1–100 letters, digits, dots, underscores, hyphens or slashes.")
	}
	if len(in.Model) == 0 || len(in.Model) > 200 || strings.ContainsAny(in.Model, "\r\n\t") {
		return in, errors.New("Invalid upstream model name.")
	}
	if in.TimeoutSeconds < 1 || in.TimeoutSeconds > 300 {
		return in, errors.New("The request timeout must be between 1 and 300 seconds.")
	}
	if in.APIKey != nil {
		if len(*in.APIKey) > 4096 {
			return in, errors.New("The upstream credential is too long.")
		}
		for _, c := range *in.APIKey {
			if c < 33 || c > 126 {
				return in, errors.New("The upstream credential must not contain whitespace or control characters.")
			}
		}
	}
	return in, nil
}

func (s *Store) Snapshot() Snapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v := Snapshot{Revision: s.state.Revision, Connections: []Connection{}, Applications: []Application{}}
	for _, c := range s.state.Connections {
		v.Connections = append(v.Connections, c.Connection)
	}
	for _, a := range s.state.Applications {
		copy := a.Application
		copy.AllowedConnections = append([]string{}, a.AllowedConnections...)
		v.Applications = append(v.Applications, copy)
	}
	return v
}

func (s *Store) commit(next gatewayState) error {
	data, err := json.MarshalIndent(next, "", "  ")
	if err != nil || len(data) > 4<<20 {
		return ErrPersistence
	}
	if err := storage.AtomicWrite(s.path, append(data, '\n')); err != nil {
		return ErrPersistence
	}
	s.state = next
	return nil
}

func (s *Store) clone() gatewayState {
	next := s.state
	next.Revision++
	next.Connections = append([]storedConnection{}, s.state.Connections...)
	next.Applications = append([]storedApplication{}, s.state.Applications...)
	return next
}

func (s *Store) SaveConnection(id string, input ConnectionInput) (Connection, error) {
	in, err := validateConnection(input)
	if err != nil {
		return Connection{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	index := -1
	var old storedConnection
	for i, c := range s.state.Connections {
		if c.ID == id {
			index, old = i, c
		}
		if c.Alias == in.Alias && c.ID != id {
			return Connection{}, errors.New("This model alias already exists.")
		}
	}
	if id != "" && index < 0 {
		return Connection{}, ErrNotFound
	}
	if id != "" && old.Revision != in.Revision {
		return Connection{}, ErrConflict
	}
	if id == "" {
		if len(s.state.Connections) >= 256 {
			return Connection{}, errors.New("A maximum of 256 model connections is supported.")
		}
		id, err = storage.ID("conn_", 12)
		if err != nil {
			return Connection{}, err
		}
		old.CreatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	}
	credential := old.Credential
	if in.APIKey != nil {
		credential, err = seal(s.vault, id, *in.APIKey)
		if err != nil {
			return Connection{}, errors.New("Could not encrypt the credential.")
		}
	}
	next := s.clone()
	c := storedConnection{Connection: Connection{ID: id, Revision: next.Revision, Name: in.Name, BaseURL: in.BaseURL, Model: in.Model, Alias: in.Alias, Enabled: in.Enabled, AllowInsecureHTTP: in.AllowInsecureHTTP, TimeoutSeconds: in.TimeoutSeconds, HasCredential: credential != "", CreatedAt: old.CreatedAt}, Credential: credential}
	if index < 0 {
		next.Connections = append(next.Connections, c)
	} else {
		next.Connections[index] = c
	}
	if err := s.commit(next); err != nil {
		return Connection{}, err
	}
	return c.Connection, nil
}

func (s *Store) validateAllowed(ids []string) ([]string, error) {
	if len(ids) > 256 {
		return nil, errors.New("Grant access to at most 256 model connections.")
	}
	seen := map[string]bool{}
	for _, id := range ids {
		found := false
		for _, c := range s.state.Connections {
			if c.ID == id {
				found = true
				break
			}
		}
		if !found || seen[id] {
			return nil, errors.New("The model grants are invalid or contain duplicates.")
		}
		seen[id] = true
	}
	out := append([]string{}, ids...)
	sort.Strings(out)
	return out, nil
}

func tokenHash(value string) string {
	hash := sha256.Sum256([]byte(value))
	return hex.EncodeToString(hash[:])
}

func (s *Store) SaveApplication(id string, in ApplicationInput) (Application, string, error) {
	name, err := config.NormalizeName(in.Name)
	if err != nil {
		return Application{}, "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	allowed, err := s.validateAllowed(in.AllowedConnections)
	if err != nil {
		return Application{}, "", err
	}
	next := s.clone()
	index := -1
	var app storedApplication
	key := ""
	for i, a := range s.state.Applications {
		if a.ID == id {
			index, app = i, a
			break
		}
	}
	if id != "" {
		if index < 0 {
			return Application{}, "", ErrNotFound
		}
		if app.Revision != in.Revision {
			return Application{}, "", ErrConflict
		}
		if app.Revoked {
			return Application{}, "", errors.New("This application has been revoked. Create a new application.")
		}
	} else {
		if len(s.state.Applications) >= 1024 {
			return Application{}, "", errors.New("A maximum of 1,024 applications is supported.")
		}
		id, err = storage.ID("app_", 12)
		if err != nil {
			return Application{}, "", err
		}
		key, err = storage.ID("gw_app_", 32)
		if err != nil {
			return Application{}, "", err
		}
		app.KeyHash = tokenHash(key)
		app.KeyPrefix = key[:15]
		app.CreatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	}
	app.ID, app.Name, app.AllowedConnections, app.Revision = id, name, allowed, next.Revision
	if index < 0 {
		next.Applications = append(next.Applications, app)
	} else {
		next.Applications[index] = app
	}
	if err := s.commit(next); err != nil {
		return Application{}, "", err
	}
	return app.Application, key, nil
}

func (s *Store) ChangeKey(id string, revision uint64, revoke bool) (Application, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, app := range s.state.Applications {
		if app.ID != id {
			continue
		}
		if app.Revision != revision {
			return Application{}, "", ErrConflict
		}
		if app.Revoked {
			return Application{}, "", errors.New("This application has been revoked.")
		}
		next := s.clone()
		key := ""
		if revoke {
			app.Revoked = true
		} else {
			var err error
			key, err = storage.ID("gw_app_", 32)
			if err != nil {
				return Application{}, "", err
			}
			app.KeyHash, app.KeyPrefix = tokenHash(key), key[:15]
		}
		app.Revision = next.Revision
		next.Applications[i] = app
		if err := s.commit(next); err != nil {
			return Application{}, "", err
		}
		return app.Application, key, nil
	}
	return Application{}, "", ErrNotFound
}

func (s *Store) authenticateLocked(header string) (Application, error) {
	if !strings.HasPrefix(header, "Bearer gw_app_") || len(header) > 256 {
		return Application{}, ErrInvalidKey
	}
	hash := tokenHash(strings.TrimPrefix(header, "Bearer "))
	for _, a := range s.state.Applications {
		if subtle.ConstantTimeCompare([]byte(hash), []byte(a.KeyHash)) == 1 && !a.Revoked {
			copy := a.Application
			copy.AllowedConnections = append([]string{}, a.AllowedConnections...)
			return copy, nil
		}
	}
	return Application{}, ErrInvalidKey
}

func (s *Store) Authenticate(header string) (Application, uint64, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	a, err := s.authenticateLocked(header)
	return a, s.state.Revision, err
}

type Resolved struct {
	Connection     Connection
	Credential     string
	Application    Application
	PolicyRevision uint64
}

func (s *Store) Resolve(header, alias string) (Resolved, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	a, err := s.authenticateLocked(header)
	return s.resolveLocked(a, alias, err)
}

// ResolveAssessment is for administrator-authorized, in-process test jobs.
// It does not expose or require an application key; grants and revocation still apply.
func (s *Store) ResolveAssessment(applicationID, alias string) (Resolved, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, app := range s.state.Applications {
		if app.ID == applicationID && !app.Revoked {
			copy := app.Application
			copy.AllowedConnections = append([]string{}, app.AllowedConnections...)
			return s.resolveLocked(copy, alias, nil)
		}
	}
	return Resolved{}, ErrInvalidKey
}

func (s *Store) resolveLocked(a Application, alias string, err error) (Resolved, error) {
	out := Resolved{Application: a, PolicyRevision: s.state.Revision}
	if err != nil {
		return out, err
	}
	for _, c := range s.state.Connections {
		if c.Alias != alias {
			continue
		}
		allowed := false
		for _, id := range a.AllowedConnections {
			if id == c.ID {
				allowed = true
				break
			}
		}
		if !allowed {
			return out, ErrDenied
		}
		out.Connection = c.Connection
		if !c.Enabled {
			return out, ErrDisabled
		}
		out.Credential, err = unseal(s.vault, c.ID, c.Credential)
		return out, err
	}
	return out, ErrDenied
}

func (s *Store) Connection(id string) (Resolved, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, c := range s.state.Connections {
		if c.ID == id {
			key, err := unseal(s.vault, c.ID, c.Credential)
			return Resolved{Connection: c.Connection, Credential: key, PolicyRevision: s.state.Revision}, err
		}
	}
	return Resolved{}, ErrNotFound
}

func (s *Store) Models(header string) ([]Connection, Application, uint64, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	a, err := s.authenticateLocked(header)
	if err != nil {
		return nil, a, s.state.Revision, err
	}
	models := []Connection{}
	for _, c := range s.state.Connections {
		for _, id := range a.AllowedConnections {
			if c.ID == id && c.Enabled {
				models = append(models, c.Connection)
				break
			}
		}
	}
	return models, a, s.state.Revision, nil
}
