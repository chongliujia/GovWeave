package gateway

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"govweave/internal/config"
	"govweave/internal/instruction"
	"govweave/internal/storage"
)

const maxToolSnapshots = 128
const maxToolsBytes = 4 << 20

var ErrToolDenied = errors.New("tool_not_allowed")
var ErrToolHistoryFull = errors.New("Tool history capacity has been reached. The current configuration remains active.")

var toolIdentifier = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,99}$`)
var toolStoredID = regexp.MustCompile(`^tool_[A-Za-z0-9_-]{16}$`)

// ToolResource is an operator-owned resource grant. Invocation requests cannot
// supply or override sensitivity, application identity, or permissions.
type ToolResource struct {
	InstructionReview   *InstructionReview `json:"instruction_review,omitempty"`
	ID                  string             `json:"resource_id"`
	Sensitivity         string             `json:"sensitivity"`
	AllowedApplications []string           `json:"allowed_applications"`
}

type ToolInput struct {
	InstructionPolicy *InstructionPolicy `json:"instruction_policy,omitempty"`
	Revision          uint64             `json:"revision"`
	Name              string             `json:"name"`
	Alias             string             `json:"alias"`
	Endpoint          string             `json:"endpoint"`
	APIKey            *string            `json:"api_key,omitempty"`
	Enabled           bool               `json:"enabled"`
	AllowInsecureHTTP bool               `json:"allow_insecure_http"`
	TimeoutSeconds    int                `json:"timeout_seconds"`
	OutputMode        string             `json:"output_mode"`
	Resources         []ToolResource     `json:"resources"`
}

type Tool struct {
	InstructionPolicy *InstructionPolicy `json:"instruction_policy,omitempty"`
	ID                string             `json:"id"`
	Revision          uint64             `json:"revision"`
	Name              string             `json:"name"`
	Alias             string             `json:"alias"`
	Endpoint          string             `json:"endpoint"`
	Enabled           bool               `json:"enabled"`
	AllowInsecureHTTP bool               `json:"allow_insecure_http"`
	TimeoutSeconds    int                `json:"timeout_seconds"`
	OutputMode        string             `json:"output_mode"`
	Resources         []ToolResource     `json:"resources"`
	HasCredential     bool               `json:"has_credential"`
	CreatedAt         string             `json:"created_at"`
	SnapshotSHA256    string             `json:"snapshot_sha256"`
}

type ToolSnapshot struct {
	SchemaVersion int    `json:"schema_version"`
	Revision      uint64 `json:"revision"`
	Tools         []Tool `json:"tools"`
}

type ResolvedTool struct {
	Tool     Tool
	Resource ToolResource
	APIKey   string
}

type storedTool struct {
	Tool
	Credential string `json:"credential_ciphertext"`
}

// Keeping active configuration and its immutable history in one replacement
// prevents a successful change from lacking the snapshot used by an invocation.
type toolsState struct {
	SchemaVersion int          `json:"schema_version"`
	Revision      uint64       `json:"revision"`
	Snapshots     []storedTool `json:"snapshots"`
}

type ToolStore struct {
	mu    sync.RWMutex
	path  string
	store *Store
	state toolsState
}

func OpenTools(dir string, store *Store) (*ToolStore, error) {
	if store == nil {
		return nil, errors.New("tool configuration requires a gateway store")
	}
	s := &ToolStore{path: filepath.Join(dir, "tools.json"), store: store, state: toolsState{SchemaVersion: 1, Snapshots: []storedTool{}}}
	f, err := os.Open(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > maxToolsBytes {
		return nil, errors.New("tools.json must be private and no larger than 4 MiB")
	}
	data, err := io.ReadAll(io.LimitReader(f, maxToolsBytes+1))
	if err != nil || len(data) > maxToolsBytes || config.DecodeStrict(bytes.NewReader(data), &s.state) != nil {
		return nil, errors.New("invalid tool configuration; refusing to reset")
	}
	if s.state.SchemaVersion != 1 || len(s.state.Snapshots) > maxToolSnapshots || s.state.Revision != uint64(len(s.state.Snapshots)) {
		return nil, errors.New("invalid tool history metadata")
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	latest := map[string]Tool{}
	for i, entry := range s.state.Snapshots {
		key, err := unseal(store.vault, toolCredentialBinding(entry.ID, entry.Revision), entry.Credential)
		if err != nil {
			return nil, errors.New("could not decrypt tool credential")
		}
		in, err := normalizeTool(toolInput(entry.Tool, &key))
		if err != nil || !toolStoredID.MatchString(entry.ID) || entry.Revision != uint64(i+1) || entry.HasCredential != (entry.Credential != "") || entry.SnapshotSHA256 != toolHash(entry.Tool) {
			return nil, errors.New("invalid tool snapshot")
		}
		if !reflect.DeepEqual(in, toolInput(entry.Tool, &key)) || validateToolApplications(in.Resources, store.state.Applications, false) != nil {
			return nil, errors.New("invalid persisted tool grants or settings")
		}
		if _, err := time.Parse(time.RFC3339Nano, entry.CreatedAt); err != nil {
			return nil, errors.New("invalid tool creation timestamp")
		}
		if old, exists := latest[entry.ID]; exists && entry.CreatedAt != old.CreatedAt {
			return nil, errors.New("tool creation timestamp changed")
		}
		for id, other := range latest {
			if other.Alias == entry.Alias && id != entry.ID {
				return nil, errors.New("duplicate tool alias in history")
			}
		}
		latest[entry.ID] = entry.Tool
		if len(latest) > 32 {
			return nil, errors.New("tool configuration exceeds supported limits")
		}
	}
	return s, nil
}

func normalizeTool(in ToolInput) (ToolInput, error) {
	in.InstructionPolicy = cloneInstructionPolicy(in.InstructionPolicy)
	if p := in.InstructionPolicy; p != nil && (!instruction.SupportedVersion(p.Version) || p.Mode != "block" && p.Mode != "observe") {
		return in, errors.New("Instruction policy requires a supported detector version and block or observe mode.")
	}
	var err error
	in.Name, err = config.NormalizeName(in.Name)
	if err != nil {
		return in, errors.New("Invalid tool name.")
	}
	in.Endpoint, err = NormalizeUpstreamURL(in.Endpoint)
	if err != nil {
		return in, errors.New("Invalid tool endpoint. Use an HTTP(S) URL without credentials, query or fragment.")
	}
	if strings.HasPrefix(in.Endpoint, "http://") && !in.AllowInsecureHTTP {
		return in, errors.New("HTTP tool endpoints require explicit permission for an unencrypted trusted network.")
	}
	if !toolIdentifier.MatchString(in.Alias) {
		return in, errors.New("Tool aliases must contain 1–100 letters, digits, dots, underscores or hyphens, starting with a letter or digit.")
	}
	if in.TimeoutSeconds < 1 || in.TimeoutSeconds > 30 {
		return in, errors.New("The tool timeout must be between 1 and 30 seconds.")
	}
	if in.OutputMode != "block" && in.OutputMode != "observe" {
		return in, errors.New("The tool output mode must be block or observe.")
	}
	if in.APIKey != nil {
		if len(*in.APIKey) > 4096 {
			return in, errors.New("The tool credential is too long.")
		}
		for _, c := range *in.APIKey {
			if c < 33 || c > 126 {
				return in, errors.New("The tool credential must not contain whitespace or control characters.")
			}
		}
	}
	if len(in.Resources) < 1 || len(in.Resources) > 32 {
		return in, errors.New("Configure between 1 and 32 tool resources.")
	}
	in.Resources = cloneToolResources(in.Resources)
	seen := map[string]bool{}
	for i := range in.Resources {
		r := &in.Resources[i]
		if r.InstructionReview != nil {
			sort.Strings(r.InstructionReview.RuleIDs)
		}
		if err := validateInstructionReview(r.InstructionReview, in.InstructionPolicy); err != nil {
			return in, err
		}
		if !toolIdentifier.MatchString(r.ID) || seen[r.ID] {
			return in, errors.New("Tool resource identifiers are invalid or duplicated.")
		}
		seen[r.ID] = true
		if r.Sensitivity != "public" && r.Sensitivity != "internal" && r.Sensitivity != "restricted" {
			return in, errors.New("Resource sensitivity must be public, internal or restricted.")
		}
		if len(r.AllowedApplications) > 32 {
			return in, errors.New("Each tool resource supports at most 32 application grants.")
		}
		sort.Strings(r.AllowedApplications)
		for j, id := range r.AllowedApplications {
			if !toolIdentifier.MatchString(id) || j > 0 && id == r.AllowedApplications[j-1] {
				return in, errors.New("Tool application grants are invalid or duplicated.")
			}
		}
	}
	sort.Slice(in.Resources, func(i, j int) bool { return in.Resources[i].ID < in.Resources[j].ID })
	return in, nil
}

func validateToolApplications(resources []ToolResource, apps []storedApplication, active bool) error {
	known := map[string]bool{}
	for _, app := range apps {
		if !active || !app.Revoked {
			known[app.ID] = true
		}
	}
	for _, resource := range resources {
		for _, id := range resource.AllowedApplications {
			if !known[id] {
				return errors.New("Tool grants must reference existing, active applications.")
			}
		}
	}
	return nil
}

func toolInput(t Tool, key *string) ToolInput {
	return ToolInput{InstructionPolicy: cloneInstructionPolicy(t.InstructionPolicy), Revision: t.Revision, Name: t.Name, Alias: t.Alias, Endpoint: t.Endpoint, APIKey: key, Enabled: t.Enabled, AllowInsecureHTTP: t.AllowInsecureHTTP, TimeoutSeconds: t.TimeoutSeconds, OutputMode: t.OutputMode, Resources: t.Resources}
}

func toolHash(t Tool) string {
	t.SnapshotSHA256 = ""
	data, _ := json.Marshal(t)
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

func toolCredentialBinding(id string, revision uint64) string {
	return id + ":" + strconv.FormatUint(revision, 10)
}

func cloneToolResources(resources []ToolResource) []ToolResource {
	out := make([]ToolResource, len(resources))
	for i, r := range resources {
		out[i] = r
		out[i].InstructionReview = cloneInstructionReview(r.InstructionReview)
		out[i].AllowedApplications = append([]string{}, r.AllowedApplications...)
	}
	return out
}

func cloneTool(t Tool) Tool {
	t.InstructionPolicy = cloneInstructionPolicy(t.InstructionPolicy)
	t.Resources = cloneToolResources(t.Resources)
	return t
}

func (s *ToolStore) latestLocked() []storedTool {
	out := []storedTool{}
	indexes := map[string]int{}
	for _, entry := range s.state.Snapshots {
		if i, exists := indexes[entry.ID]; exists {
			out[i] = entry
		} else {
			indexes[entry.ID] = len(out)
			out = append(out, entry)
		}
	}
	return out
}

func (s *ToolStore) Snapshot() ToolSnapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := ToolSnapshot{SchemaVersion: 1, Revision: s.state.Revision, Tools: []Tool{}}
	for _, entry := range s.latestLocked() {
		out.Tools = append(out.Tools, cloneTool(entry.Tool))
	}
	return out
}

func (s *ToolStore) History(id string) ([]Tool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []Tool{}
	for i := len(s.state.Snapshots) - 1; i >= 0; i-- {
		if s.state.Snapshots[i].ID == id {
			out = append(out, cloneTool(s.state.Snapshots[i].Tool))
		}
	}
	if len(out) == 0 {
		return nil, ErrNotFound
	}
	return out, nil
}

func (s *ToolStore) Save(id string, input ToolInput) (Tool, error) {
	in, err := normalizeTool(input)
	if err != nil {
		return Tool{}, err
	}
	// All operations needing both locks use this order, including admission.
	s.store.mu.RLock()
	defer s.store.mu.RUnlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	if in.Revision != s.state.Revision {
		return Tool{}, ErrConflict
	}
	if err := validateToolApplications(in.Resources, s.store.state.Applications, true); err != nil {
		return Tool{}, err
	}
	current := s.latestLocked()
	var old storedTool
	for _, entry := range current {
		if entry.Alias == in.Alias && entry.ID != id {
			return Tool{}, errors.New("This tool alias already exists.")
		}
		if entry.ID == id {
			old = entry
		}
	}
	if id != "" && old.ID == "" {
		return Tool{}, ErrNotFound
	}
	if len(s.state.Snapshots) >= maxToolSnapshots {
		return Tool{}, ErrToolHistoryFull
	}
	if id == "" {
		if len(current) >= 32 {
			return Tool{}, errors.New("A maximum of 32 tools is supported.")
		}
		id, err = storage.ID("tool_", 12)
		if err != nil {
			return Tool{}, errors.New("Could not create a tool identifier.")
		}
		old.CreatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	}
	key := ""
	if in.APIKey != nil {
		key = *in.APIKey
	} else if old.Credential != "" {
		key, err = unseal(s.store.vault, toolCredentialBinding(old.ID, old.Revision), old.Credential)
		if err != nil {
			return Tool{}, errors.New("Could not decrypt the tool credential.")
		}
	}
	revision := s.state.Revision + 1
	credential, err := seal(s.store.vault, toolCredentialBinding(id, revision), key)
	if err != nil {
		return Tool{}, errors.New("Could not encrypt the tool credential.")
	}
	t := Tool{InstructionPolicy: in.InstructionPolicy, ID: id, Revision: revision, Name: in.Name, Alias: in.Alias, Endpoint: in.Endpoint, Enabled: in.Enabled, AllowInsecureHTTP: in.AllowInsecureHTTP, TimeoutSeconds: in.TimeoutSeconds, OutputMode: in.OutputMode, Resources: in.Resources, HasCredential: credential != "", CreatedAt: old.CreatedAt}
	t.SnapshotSHA256 = toolHash(t)
	next := toolsState{SchemaVersion: 1, Revision: revision, Snapshots: append(append([]storedTool{}, s.state.Snapshots...), storedTool{Tool: t, Credential: credential})}
	data, err := json.MarshalIndent(next, "", "  ")
	if err != nil || len(data)+1 > maxToolsBytes {
		return Tool{}, ErrToolHistoryFull
	}
	if err := storage.AtomicWrite(s.path, append(data, '\n')); err != nil {
		return Tool{}, ErrPersistence
	}
	s.state = next
	return cloneTool(t), nil
}

// ResolveAuthorized atomically checks key validity, app revocation and the
// resource grant. Configuration changes after admission affect later calls.
func (s *ToolStore) ResolveAuthorized(header, alias, resourceID string) (ResolvedTool, Application, uint64, error) {
	s.store.mu.RLock()
	defer s.store.mu.RUnlock()
	app, err := s.store.authenticateLocked(header)
	if err != nil {
		return ResolvedTool{}, Application{}, s.store.state.Revision, err
	}
	out, err := s.resolve(alias, resourceID, app.ID)
	return out, app, s.store.state.Revision, err
}

// Resolve is for trusted in-process callers already holding an application ID.
// External requests must use ResolveAuthorized rather than supply an identity.
func (s *ToolStore) Resolve(alias, resourceID, applicationID string) (ResolvedTool, error) {
	s.store.mu.RLock()
	defer s.store.mu.RUnlock()
	for _, app := range s.store.state.Applications {
		if app.ID == applicationID && !app.Revoked {
			return s.resolve(alias, resourceID, applicationID)
		}
	}
	return ResolvedTool{}, ErrToolDenied
}

// ResolveAssessment is process-only. It applies the same application/tool
// lock order and grants as key-authenticated invocation, without exposing keys.
func (s *ToolStore) ResolveAssessment(applicationID, alias, resourceID string) (ResolvedTool, Application, uint64, error) {
	s.store.mu.RLock()
	defer s.store.mu.RUnlock()
	for _, entry := range s.store.state.Applications {
		if entry.ID == applicationID && !entry.Revoked {
			app := entry.Application
			app.AllowedConnections = append([]string{}, app.AllowedConnections...)
			resolved, err := s.resolve(alias, resourceID, applicationID)
			return resolved, app, s.store.state.Revision, err
		}
	}
	return ResolvedTool{}, Application{}, s.store.state.Revision, ErrInvalidKey
}

func (s *ToolStore) resolve(alias, resourceID, applicationID string) (ResolvedTool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, entry := range s.latestLocked() {
		if entry.Alias != alias {
			continue
		}
		out := ResolvedTool{Tool: cloneTool(entry.Tool)}
		if !entry.Enabled {
			return out, ErrToolDenied
		}
		for _, resource := range out.Tool.Resources {
			if resource.ID != resourceID {
				continue
			}
			out.Resource = resource
			for _, id := range resource.AllowedApplications {
				if id == applicationID {
					var err error
					out.APIKey, err = unseal(s.store.vault, toolCredentialBinding(entry.ID, entry.Revision), entry.Credential)
					if err != nil {
						return ResolvedTool{Tool: out.Tool, Resource: out.Resource}, errors.New("tool_credential_unavailable")
					}
					return out, nil
				}
			}
			return out, ErrToolDenied
		}
		return out, ErrToolDenied
	}
	return ResolvedTool{}, ErrToolDenied
}
