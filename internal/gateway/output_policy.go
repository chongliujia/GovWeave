package gateway

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"time"

	"govweave/internal/config"
	"govweave/internal/sensitive"
	"govweave/internal/storage"
)

const outputPolicyID = "sensitive-output"
const maxOutputSnapshots = 128
const maxOutputHistoryBytes = 2 << 20

var ErrOutputHistoryFull = errors.New("Sensitive-output policy history capacity has been reached. The current policy remains active.")

type OutputPolicyInput struct {
	PublicEmails    []string `json:"public_emails,omitempty"`
	DetectorVersion string   `json:"detector_version,omitempty"`
	Revision        uint64   `json:"revision"`
	Mode            string   `json:"mode"`
	Categories      []string `json:"categories"`
	ApplicationIDs  []string `json:"application_ids"`
}

type OutputPolicySnapshot struct {
	ApplicationPolicies []ApplicationOutputPolicy `json:"application_policies,omitempty"`
	RedactionVersion    string                    `json:"redaction_version,omitempty"`
	SchemaVersion       int                       `json:"schema_version"`
	ID                  string                    `json:"id"`
	UpdatedAt           string                    `json:"updated_at,omitempty"`
	OutputPolicyInput
}

// Application policies replace the default settings for exactly one application.
// All settings and bindings share one atomic revision and immutable history.
type ApplicationOutputPolicy struct {
	ApplicationID   string   `json:"application_id"`
	Mode            string   `json:"mode"`
	DetectorVersion string   `json:"detector_version"`
	Categories      []string `json:"categories"`
	PublicEmails    []string `json:"public_emails,omitempty"`
}

type outputPolicyState struct {
	SchemaVersion int                    `json:"schema_version"`
	Snapshots     []OutputPolicySnapshot `json:"snapshots"`
}

type OutputPolicyStore struct {
	mu      sync.RWMutex
	path    string
	history []OutputPolicySnapshot
}

func defaultOutputPolicy() OutputPolicySnapshot {
	return OutputPolicySnapshot{SchemaVersion: 1, ID: outputPolicyID,
		OutputPolicyInput: OutputPolicyInput{DetectorVersion: sensitive.Version, Mode: "disabled", Categories: []string{"credential", "email", "phone"}, ApplicationIDs: []string{}}}
}

func cloneOutputPolicy(snapshot OutputPolicySnapshot) OutputPolicySnapshot {
	snapshot.PublicEmails = slices.Clone(snapshot.PublicEmails)
	snapshot.Categories = append([]string{}, snapshot.Categories...)
	snapshot.ApplicationIDs = append([]string{}, snapshot.ApplicationIDs...)
	snapshot.ApplicationPolicies = slices.Clone(snapshot.ApplicationPolicies)
	for i := range snapshot.ApplicationPolicies {
		snapshot.ApplicationPolicies[i].Categories = slices.Clone(snapshot.ApplicationPolicies[i].Categories)
		snapshot.ApplicationPolicies[i].PublicEmails = slices.Clone(snapshot.ApplicationPolicies[i].PublicEmails)
	}
	return snapshot
}

func normalizeOutputPolicy(input OutputPolicyInput, resources Snapshot) (OutputPolicyInput, error) {
	if len(input.PublicEmails) > 16 {
		return input, errors.New("Configure at most 16 exact public email addresses.")
	}
	input.PublicEmails = slices.Clone(input.PublicEmails)
	slices.Sort(input.PublicEmails)
	for i, value := range input.PublicEmails {
		r := sensitive.Detect([]byte(value))
		if len(value) > 254 || strings.ContainsAny(value, "*?") || r.State != "observed" || len(r.Findings) != 1 || r.Findings[0].Category != "email" || r.Findings[0].StartByte != 0 || r.Findings[0].EndByte != len(value) || i > 0 && value == input.PublicEmails[i-1] {
			return input, errors.New("Public emails must be unique exact ASCII addresses, without wildcards or credential patterns.")
		}
	}
	if !sensitive.Supports(input.DetectorVersion) {
		return input, errors.New("Select a supported sensitive-text detector version.")
	}
	if input.Mode != "disabled" && input.Mode != "observe" && input.Mode != "block" && input.Mode != "redact" {
		return input, errors.New("Select disabled, observe, block or redact for the sensitive-output policy.")
	}
	if len(input.Categories) < 1 || len(input.Categories) > 3 {
		return input, errors.New("Select between one and three sensitive-output categories.")
	}
	input.Categories = append([]string{}, input.Categories...)
	slices.Sort(input.Categories)
	for i, category := range input.Categories {
		if !slices.Contains([]string{"credential", "email", "phone"}, category) || i > 0 && category == input.Categories[i-1] {
			return input, errors.New("Unknown or duplicate sensitive-output category.")
		}
	}
	if len(input.ApplicationIDs) > 64 {
		return input, errors.New("Select at most 64 applications, or leave the scope empty for all applications.")
	}
	known := map[string]bool{}
	for _, application := range resources.Applications {
		known[application.ID] = true
	}
	input.ApplicationIDs = append([]string{}, input.ApplicationIDs...)
	slices.Sort(input.ApplicationIDs)
	for i, id := range input.ApplicationIDs {
		if !known[id] || i > 0 && id == input.ApplicationIDs[i-1] {
			return input, errors.New("Sensitive-output scope contains an unknown or duplicate application.")
		}
	}
	return input, nil
}

func OpenOutputPolicies(dir string, resources Snapshot) (*OutputPolicyStore, error) {
	p := &OutputPolicyStore{path: filepath.Join(dir, "output-policies.json"), history: []OutputPolicySnapshot{defaultOutputPolicy()}}
	f, err := os.Open(p.path)
	if errors.Is(err, os.ErrNotExist) {
		return p, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > maxOutputHistoryBytes {
		return nil, errors.New("output-policies.json must be private and no larger than 2 MiB")
	}
	data, err := io.ReadAll(io.LimitReader(f, maxOutputHistoryBytes+1))
	var state outputPolicyState
	if err != nil || len(data) > maxOutputHistoryBytes || config.DecodeStrict(bytes.NewReader(data), &state) != nil || (state.SchemaVersion != 1 && state.SchemaVersion != 2) || len(state.Snapshots) < 1 || len(state.Snapshots) > maxOutputSnapshots {
		return nil, errors.New("invalid sensitive-output policy history; refusing to reset protection")
	}
	for i, snapshot := range state.Snapshots {
		input, err := normalizeOutputPolicy(snapshot.OutputPolicyInput, resources)
		if err != nil || (snapshot.SchemaVersion != 1 && snapshot.SchemaVersion != 2) || snapshot.ID != outputPolicyID || !sensitive.Supports(snapshot.DetectorVersion) || snapshot.Revision != uint64(i) || !slices.Equal(input.Categories, snapshot.Categories) || !slices.Equal(input.ApplicationIDs, snapshot.ApplicationIDs) || !slices.Equal(input.PublicEmails, snapshot.PublicEmails) {
			return nil, errors.New("invalid sensitive-output policy snapshot")
		}
		if len(snapshot.ApplicationPolicies) > 64 || snapshot.SchemaVersion == 1 && len(snapshot.ApplicationPolicies) != 0 || i > 0 && snapshot.SchemaVersion < state.Snapshots[i-1].SchemaVersion {
			return nil, errors.New("invalid application policy history")
		}
		for j, policy := range snapshot.ApplicationPolicies {
			normalized, err := normalizeApplicationOutputPolicy(policy, resources)
			if err != nil || !reflect.DeepEqual(normalized, policy) || j > 0 && policy.ApplicationID <= snapshot.ApplicationPolicies[j-1].ApplicationID {
				return nil, errors.New("invalid application output policy")
			}
		}
		if snapshot.Mode == "redact" && snapshot.RedactionVersion != redactionVersion || snapshot.Mode != "redact" && snapshot.RedactionVersion != "" {
			return nil, errors.New("invalid sensitive-output redaction generation")
		}
		if i == 0 {
			if snapshot.SchemaVersion != 1 || snapshot.DetectorVersion != sensitive.Version || snapshot.Mode != "disabled" || snapshot.UpdatedAt != "" || !slices.Equal(snapshot.Categories, defaultOutputPolicy().Categories) || len(snapshot.ApplicationIDs) != 0 || len(snapshot.PublicEmails) != 0 {
				return nil, errors.New("invalid initial sensitive-output policy snapshot")
			}
		} else if _, err := time.Parse(time.RFC3339Nano, snapshot.UpdatedAt); err != nil {
			return nil, errors.New("invalid sensitive-output policy timestamp")
		}
	}
	if state.SchemaVersion != state.Snapshots[len(state.Snapshots)-1].SchemaVersion {
		return nil, errors.New("invalid sensitive-output history schema")
	}
	p.history = state.Snapshots
	return p, nil
}

func (snapshot OutputPolicySnapshot) Applies(applicationID string) bool {
	snapshot = snapshot.ForApplication(applicationID)
	return snapshot.Mode != "disabled" && (len(snapshot.ApplicationIDs) == 0 || slices.Contains(snapshot.ApplicationIDs, applicationID))
}

func (snapshot OutputPolicySnapshot) HasApplicationPolicy(applicationID string) bool {
	return slices.ContainsFunc(snapshot.ApplicationPolicies, func(p ApplicationOutputPolicy) bool { return p.ApplicationID == applicationID })
}

// ForApplication projects only the effective policy, so other applications'
// settings never enter this application's content response or evidence bundle.
func (snapshot OutputPolicySnapshot) ForApplication(applicationID string) OutputPolicySnapshot {
	for _, policy := range snapshot.ApplicationPolicies {
		if policy.ApplicationID == applicationID {
			snapshot.Mode, snapshot.DetectorVersion = policy.Mode, policy.DetectorVersion
			snapshot.Categories, snapshot.PublicEmails = policy.Categories, policy.PublicEmails
			snapshot.ApplicationIDs = []string{applicationID}
			snapshot.RedactionVersion = ""
			if policy.Mode == "redact" {
				snapshot.RedactionVersion = redactionVersion
			}
			break
		}
	}
	snapshot.ApplicationPolicies = nil
	snapshot.SchemaVersion = 1
	return cloneOutputPolicy(snapshot)
}

func normalizeApplicationOutputPolicy(policy ApplicationOutputPolicy, resources Snapshot) (ApplicationOutputPolicy, error) {
	if policy.ApplicationID == "" {
		return policy, errors.New("Select an existing application.")
	}
	input, err := normalizeOutputPolicy(OutputPolicyInput{Mode: policy.Mode, DetectorVersion: policy.DetectorVersion,
		Categories: policy.Categories, PublicEmails: policy.PublicEmails, ApplicationIDs: []string{policy.ApplicationID}}, resources)
	policy.Categories, policy.PublicEmails = input.Categories, input.PublicEmails
	return policy, err
}

func (p *OutputPolicyStore) Snapshot() OutputPolicySnapshot {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return cloneOutputPolicy(p.history[len(p.history)-1])
}

func (p *OutputPolicyStore) Save(input OutputPolicyInput, resources Snapshot) (OutputPolicySnapshot, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if input.Revision != p.history[len(p.history)-1].Revision {
		return OutputPolicySnapshot{}, ErrConflict
	}
	if input.DetectorVersion == "" {
		input.DetectorVersion = p.history[len(p.history)-1].DetectorVersion
	}
	input, err := normalizeOutputPolicy(input, resources)
	if err != nil {
		return OutputPolicySnapshot{}, err
	}
	input.Revision++
	next := cloneOutputPolicy(p.history[len(p.history)-1])
	next.OutputPolicyInput = input
	return p.saveLocked(next)
}

func (p *OutputPolicyStore) saveLocked(next OutputPolicySnapshot) (OutputPolicySnapshot, error) {
	if len(p.history) >= maxOutputSnapshots {
		return OutputPolicySnapshot{}, ErrOutputHistoryFull
	}
	next.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	next.RedactionVersion = ""
	if len(next.ApplicationPolicies) > 0 {
		next.SchemaVersion = 2
	}
	if next.Mode == "redact" {
		next.RedactionVersion = redactionVersion
	}
	history := append(slices.Clone(p.history), next)
	data, err := json.MarshalIndent(outputPolicyState{SchemaVersion: next.SchemaVersion, Snapshots: history}, "", "  ")
	if err != nil {
		return OutputPolicySnapshot{}, ErrPersistence
	}
	if len(data)+1 > maxOutputHistoryBytes {
		return OutputPolicySnapshot{}, ErrOutputHistoryFull
	}
	if err := storage.AtomicWrite(p.path, append(data, '\n')); err != nil {
		return OutputPolicySnapshot{}, ErrPersistence
	}
	p.history = history
	return cloneOutputPolicy(next), nil
}

// SaveApplication changes one binding. A nil policy resumes the default policy.
func (p *OutputPolicyStore) SaveApplication(applicationID string, revision uint64, policy *ApplicationOutputPolicy, resources Snapshot) (OutputPolicySnapshot, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !slices.ContainsFunc(resources.Applications, func(a Application) bool { return a.ID == applicationID }) {
		return OutputPolicySnapshot{}, ErrNotFound
	}
	next := cloneOutputPolicy(p.history[len(p.history)-1])
	if revision != next.Revision {
		return OutputPolicySnapshot{}, ErrConflict
	}
	if policy != nil {
		if policy.ApplicationID != applicationID {
			return OutputPolicySnapshot{}, errors.New("Application policy identity does not match.")
		}
		validated, err := normalizeApplicationOutputPolicy(*policy, resources)
		if err != nil {
			return OutputPolicySnapshot{}, err
		}
		policy = &validated
	}
	next.ApplicationPolicies = slices.DeleteFunc(next.ApplicationPolicies, func(p ApplicationOutputPolicy) bool { return p.ApplicationID == applicationID })
	if policy != nil {
		next.ApplicationPolicies = append(next.ApplicationPolicies, *policy)
	}
	if len(next.ApplicationPolicies) > 64 {
		return OutputPolicySnapshot{}, errors.New("Configure at most 64 application output policies.")
	}
	slices.SortFunc(next.ApplicationPolicies, func(a, b ApplicationOutputPolicy) int { return strings.Compare(a.ApplicationID, b.ApplicationID) })
	next.Revision++
	return p.saveLocked(next)
}

func (p *OutputPolicyStore) History() []OutputPolicySnapshot {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make([]OutputPolicySnapshot, 0, len(p.history))
	for i := len(p.history) - 1; i >= 0; i-- {
		out = append(out, cloneOutputPolicy(p.history[i]))
	}
	return out
}

func (p *OutputPolicyStore) Revision(revision uint64) (OutputPolicySnapshot, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if revision >= uint64(len(p.history)) {
		return OutputPolicySnapshot{}, ErrNotFound
	}
	return cloneOutputPolicy(p.history[revision]), nil
}
