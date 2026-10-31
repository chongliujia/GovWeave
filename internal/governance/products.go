// Package governance connects product profiles and gateway-owned evidence to
// the advisory compliance evaluator. It never controls inference admission.
package governance

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"govweave/internal/compliance"
	"govweave/internal/config"
	"govweave/internal/gateway"
	"govweave/internal/storage"
)

const MaxProducts = 64
const maxProductBytes = 4 << 20

var identifier = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$`)

type ProductInput struct {
	Revision       uint64                     `json:"revision"`
	Name           string                     `json:"name"`
	Version        string                     `json:"version"`
	ApplicationIDs []string                   `json:"application_ids"`
	PackID         string                     `json:"pack_id"`
	PackVersion    string                     `json:"pack_version"`
	Facts          map[string]compliance.Fact `json:"facts"`
}

type Product struct {
	SchemaVersion int    `json:"schema_version"`
	ID            string `json:"id"`
	CreatedAt     string `json:"created_at"`
	UpdatedAt     string `json:"updated_at"`
	ProductInput
}

type productState struct {
	SchemaVersion int       `json:"schema_version"`
	Products      []Product `json:"products"`
}

type Products struct {
	mu    sync.RWMutex
	path  string
	state productState
}

func openProducts(dir string) (*Products, error) {
	p := &Products{path: filepath.Join(dir, "products.json"), state: productState{SchemaVersion: 1, Products: []Product{}}}
	f, err := os.Open(p.path)
	if errors.Is(err, os.ErrNotExist) {
		return p, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > maxProductBytes {
		return nil, errors.New("products.json must be private and no larger than 4 MiB")
	}
	data, err := io.ReadAll(io.LimitReader(f, maxProductBytes+1))
	if err != nil || len(data) > maxProductBytes || config.DecodeStrict(bytes.NewReader(data), &p.state) != nil || p.state.SchemaVersion != 1 || p.state.Products == nil || len(p.state.Products) > MaxProducts {
		return nil, errors.New("invalid product registry; refusing to reset")
	}
	seen := map[string]bool{}
	for _, product := range p.state.Products {
		if !identifier.MatchString(product.ID) || seen[product.ID] || product.Revision == 0 {
			return nil, errors.New("invalid persisted product identity")
		}
		seen[product.ID] = true
		if err := validateProduct(product.ProductInput); err != nil {
			return nil, err
		}
		created, e1 := time.Parse(time.RFC3339Nano, product.CreatedAt)
		updated, e2 := time.Parse(time.RFC3339Nano, product.UpdatedAt)
		if product.SchemaVersion != 1 || e1 != nil || e2 != nil || updated.Before(created) {
			return nil, errors.New("invalid product metadata")
		}
	}
	return p, nil
}

func cloneProduct(product Product) Product {
	product.ApplicationIDs = slices.Clone(product.ApplicationIDs)
	facts := make(map[string]compliance.Fact, len(product.Facts))
	for key, fact := range product.Facts {
		fact.Value = slices.Clone(fact.Value)
		facts[key] = fact
	}
	product.Facts = facts
	return product
}

func validateProduct(in ProductInput) error {
	if _, err := config.NormalizeName(in.Name); err != nil {
		return err
	}
	if len(in.ApplicationIDs) < 1 || len(in.ApplicationIDs) > 64 || len(in.Facts) > 112 {
		return errors.New("products require 1–64 applications and at most 112 profile facts")
	}
	seen := map[string]bool{}
	for _, id := range in.ApplicationIDs {
		if !identifier.MatchString(id) || seen[id] {
			return errors.New("invalid or duplicate product application ID")
		}
		seen[id] = true
	}
	for key, fact := range in.Facts {
		if strings.HasPrefix(key, "runtime.") || strings.HasPrefix(key, "testing.") || fact.Source == "runtime" {
			return errors.New("runtime and testing evidence are reserved for server adapters")
		}
	}
	return compliance.ValidateInput(compliance.Input{PackID: in.PackID, PackVersion: in.PackVersion, ProductID: "profile", ProductVersion: in.Version, Facts: in.Facts})
}

func (p *Products) List() []Product {
	p.mu.RLock()
	defer p.mu.RUnlock()
	items := make([]Product, 0, len(p.state.Products))
	for _, product := range p.state.Products {
		items = append(items, cloneProduct(product))
	}
	return items
}

func (p *Products) Get(id string) (Product, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	for _, product := range p.state.Products {
		if product.ID == id {
			return cloneProduct(product), nil
		}
	}
	return Product{}, gateway.ErrNotFound
}

func (p *Products) save(id string, in ProductInput, resources gateway.Snapshot, packs []compliance.Descriptor) (Product, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := validateProduct(in); err != nil {
		return Product{}, err
	}
	known := map[string]bool{}
	for _, app := range resources.Applications {
		known[app.ID] = true
	}
	for _, appID := range in.ApplicationIDs {
		if !known[appID] {
			return Product{}, errors.New("product application does not exist")
		}
	}
	if !slices.ContainsFunc(packs, func(pack compliance.Descriptor) bool { return pack.ID == in.PackID && pack.Version == in.PackVersion }) {
		return Product{}, compliance.ErrPackNotFound
	}
	index := -1
	var next Product
	if id == "" {
		if in.Revision != 0 {
			return Product{}, gateway.ErrConflict
		}
		if len(p.state.Products) >= MaxProducts {
			return Product{}, errors.New("product registry capacity has been reached")
		}
		var err error
		id, err = storage.ID("prod_", 12)
		if err != nil {
			return Product{}, gateway.ErrPersistence
		}
		next = Product{SchemaVersion: 1, ID: id, CreatedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	} else {
		for i, product := range p.state.Products {
			if product.ID == id {
				index, next = i, product
				break
			}
		}
		if index < 0 {
			return Product{}, gateway.ErrNotFound
		}
		if in.Revision != next.Revision || in.Revision == ^uint64(0) {
			return Product{}, gateway.ErrConflict
		}
	}
	in.Name, _ = config.NormalizeName(in.Name)
	next.ProductInput = in
	next.Revision++
	next.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	next = cloneProduct(next)
	state := productState{SchemaVersion: 1, Products: slices.Clone(p.state.Products)}
	if index < 0 {
		state.Products = append(state.Products, next)
	} else {
		state.Products[index] = next
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil || len(data)+1 > maxProductBytes || storage.AtomicWrite(p.path, append(data, '\n')) != nil {
		return Product{}, gateway.ErrPersistence
	}
	p.state = state
	return cloneProduct(next), nil
}
