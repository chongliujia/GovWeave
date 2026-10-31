package compliance

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"govweave/internal/config"
)

const MaxPackBytes = 256 << 10
const MaxPacks = 32
const MaxConcurrentEvaluations = 64

var ErrPackNotFound = errors.New("the requested rule pack version is not installed")
var ErrBusy = errors.New("the concurrent evaluation limit has been reached")

type Descriptor struct {
	ID            string `json:"id"`
	Version       string `json:"version"`
	Name          string `json:"name"`
	FrameworkKind string `json:"framework_kind"`
	ReviewStatus  string `json:"review_status"`
	SHA256        string `json:"sha256"`
	ControlCount  int    `json:"control_count"`
}

type installedPack struct {
	pack       Pack
	descriptor Descriptor
}

// Engine is immutable after startup and safe for concurrent evaluations.
type Engine struct {
	packs map[string]installedPack
	slots chan struct{}
}

func packKey(id, version string) string { return id + "/" + version }

// Open installs data-only plugins from a local directory. Missing directories
// yield an empty catalog. Invalid plugins abort startup, never silently vanish.
func Open(dir string) (*Engine, error) {
	engine := &Engine{packs: map[string]installedPack{}, slots: make(chan struct{}, MaxConcurrentEvaluations)}
	directory, err := os.Open(dir)
	if errors.Is(err, os.ErrNotExist) {
		return engine, nil
	}
	if err != nil {
		return nil, err
	}
	defer directory.Close()
	entries, err := directory.ReadDir(MaxPacks*2 + 1)
	if err != nil && err != io.EOF {
		return nil, err
	}
	if len(entries) > MaxPacks*2 {
		return nil, errors.New("rule pack directory entry limit exceeded")
	}
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		if len(engine.packs) >= MaxPacks || entry.Type()&os.ModeSymlink != 0 {
			return nil, errors.New("rule pack count exceeded or symlink detected")
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() || info.Size() > MaxPackBytes {
			return nil, errors.New("rule packs must be regular files no larger than 256 KiB")
		}
		f, err := os.Open(filepath.Join(dir, entry.Name()))
		if err != nil {
			return nil, err
		}
		data, readErr := io.ReadAll(io.LimitReader(f, MaxPackBytes+1))
		closeErr := f.Close()
		if readErr != nil || closeErr != nil || len(data) > MaxPackBytes {
			return nil, errors.New("could not read bounded rule pack")
		}
		var pack Pack
		if config.DecodeStrict(bytes.NewReader(data), &pack) != nil {
			return nil, errors.New("invalid rule pack JSON")
		}
		if err := ValidatePack(pack); err != nil {
			return nil, err
		}
		key := packKey(pack.ID, pack.Version)
		if _, duplicate := engine.packs[key]; duplicate {
			return nil, errors.New("duplicate rule pack ID and version")
		}
		canonical, _ := json.Marshal(pack)
		digest := sha256.Sum256(canonical)
		descriptor := Descriptor{ID: pack.ID, Version: pack.Version, Name: pack.Name, FrameworkKind: pack.FrameworkKind, ReviewStatus: pack.Review.Status, SHA256: hex.EncodeToString(digest[:]), ControlCount: len(pack.Controls)}
		engine.packs[key] = installedPack{pack: pack, descriptor: descriptor}
	}
	return engine, nil
}

func (e *Engine) Catalog() []Descriptor {
	items := []Descriptor{}
	for _, installed := range e.packs {
		items = append(items, installed.descriptor)
	}
	sort.Slice(items, func(i, j int) bool {
		return packKey(items[i].ID, items[i].Version) < packKey(items[j].ID, items[j].Version)
	})
	return items
}

func (e *Engine) Evaluate(input Input) (Evaluation, error) {
	select {
	case e.slots <- struct{}{}:
		defer func() { <-e.slots }()
	default:
		return Evaluation{}, ErrBusy
	}
	if err := validateInput(input); err != nil {
		return Evaluation{}, err
	}
	installed, ok := e.packs[packKey(input.PackID, input.PackVersion)]
	if !ok {
		return Evaluation{}, ErrPackNotFound
	}
	return evaluate(installed.pack, installed.descriptor.SHA256, input, time.Now()), nil
}
