package instance

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"govweave/internal/config"
)

var ErrConflict = errors.New("配置已更新，请重新加载后再保存")
var ErrManaged = errors.New("此字段由部署文件或环境变量管理，请通过部署配置修改")

type State struct {
	SchemaVersion int    `json:"schema_version"`
	Revision      uint64 `json:"revision"`
	config.Settings
	UpdatedAt string `json:"updated_at,omitempty"`
}

type View struct {
	State
	Configured bool                `json:"configured"`
	Sources    map[string]string   `json:"sources"`
	ListenAddr string              `json:"listen_addr"`
	Endpoints  map[string]Endpoint `json:"endpoints"`
}

type Endpoint struct {
	URL    string `json:"url"`
	Status string `json:"status"`
}

type Store struct {
	mu         sync.Mutex
	path       string
	deployment config.Deployment
	state      State
}

func Open(d config.Deployment) (*Store, error) {
	if err := os.MkdirAll(d.DataDir, 0700); err != nil {
		return nil, err
	}
	s := &Store{path: filepath.Join(d.DataDir, "instance.json"), deployment: d, state: State{SchemaVersion: config.SchemaVersion}}
	f, err := os.Open(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || info.Size() > 65536 {
		return nil, errors.New("invalid persisted instance file")
	}
	if err := config.DecodeStrict(f, &s.state); err != nil {
		return nil, errors.New("invalid persisted instance JSON; restore from backup, refusing to overwrite")
	}
	if s.state.SchemaVersion != config.SchemaVersion || s.state.Revision == 0 {
		return nil, errors.New("unsupported persisted instance schema or revision")
	}
	normalized, err := config.Normalize(s.state.Settings)
	if err != nil {
		return nil, fmt.Errorf("invalid persisted settings: %w", err)
	}
	s.state.Settings = normalized
	return s, nil
}

func (s *Store) viewLocked() View {
	state := s.state
	sources := map[string]string{"organization_name": "unconfigured", "public_url": "unconfigured"}
	if state.Revision > 0 {
		sources["organization_name"], sources["public_url"] = "console", "console"
	}
	if s.deployment.OrganizationName != "" {
		state.OrganizationName = s.deployment.OrganizationName
		sources["organization_name"] = s.deployment.Sources["organization_name"]
	}
	if s.deployment.PublicURL != "" {
		state.PublicURL = s.deployment.PublicURL
		sources["public_url"] = s.deployment.Sources["public_url"]
	}
	endpoints := map[string]Endpoint{"console": {Status: "available"}, "models": {Status: "available"}, "mcp": {Status: "planned"}}
	if state.PublicURL != "" {
		endpoints["console"] = Endpoint{URL: state.PublicURL, Status: "available"}
		endpoints["models"] = Endpoint{URL: state.PublicURL + "/v1", Status: "available"}
		endpoints["mcp"] = Endpoint{URL: state.PublicURL + "/mcp", Status: "planned"}
	}
	return View{State: state, Configured: state.OrganizationName != "" && state.PublicURL != "", Sources: sources, ListenAddr: s.deployment.ListenAddr, Endpoints: endpoints}
}

func (s *Store) View() View { s.mu.Lock(); defer s.mu.Unlock(); return s.viewLocked() }

func (s *Store) Update(expected uint64, settings config.Settings) (View, error) {
	normalized, err := config.Normalize(settings)
	if err != nil {
		return View{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if expected != s.state.Revision {
		return View{}, ErrConflict
	}
	if (s.deployment.PublicURL != "" && normalized.PublicURL != s.deployment.PublicURL) || (s.deployment.OrganizationName != "" && normalized.OrganizationName != s.deployment.OrganizationName) {
		return View{}, ErrManaged
	}
	next := State{SchemaVersion: config.SchemaVersion, Revision: s.state.Revision + 1, Settings: normalized, UpdatedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	data, err := json.MarshalIndent(next, "", "  ")
	if err != nil {
		return View{}, err
	}
	if err := atomicWrite(s.path, append(data, '\n')); err != nil {
		return View{}, fmt.Errorf("persist instance: %w", err)
	}
	s.state = next
	return s.viewLocked(), nil
}

func atomicWrite(path string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".instance-*")
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
