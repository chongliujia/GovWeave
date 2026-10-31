package gateway

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"regexp"
	"slices"
	"sync"
	"time"

	"govweave/internal/storage"
)

const credentialPolicyID = "credential-egress"
const credentialRuleset = "credentials-v1"

// Patterns identify credential-like text, not valid credentials. No network
// validation, entropy service, user regex or matched value is used or stored.
var credentialRules = []struct {
	id      string
	pattern *regexp.Regexp
}{
	{"private_key", regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----`)},
	{"api_key", regexp.MustCompile(`\b(?:sk-[A-Za-z0-9_-]{20,}|gw_app_[A-Za-z0-9_-]{43}|gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,}|AKIA[A-Z0-9]{16}\b)`)},
}

type PolicyInput struct {
	Revision       uint64   `json:"revision"`
	Mode           string   `json:"mode"`
	Rules          []string `json:"rules"`
	ApplicationIDs []string `json:"application_ids"`
	ConnectionIDs  []string `json:"connection_ids"`
}

type PolicySnapshot struct {
	SchemaVersion  int    `json:"schema_version"`
	ID             string `json:"id"`
	RulesetVersion string `json:"ruleset_version"`
	UpdatedAt      string `json:"updated_at,omitempty"`
	PolicyInput
}

// Fixed identifiers only: no text excerpts, positions, field names, or hashes
// of secrets. The maximum number of matched rules is two.
type PolicyAssessment struct {
	ID              string   `json:"id"`
	Revision        uint64   `json:"revision"`
	RulesetVersion  string   `json:"ruleset_version"`
	Mode            string   `json:"mode"`
	Result          string   `json:"result"`
	MatchedRules    []string `json:"matched_rules"`
	CheckDurationUS int64    `json:"check_duration_us"`
}

type PolicyStore struct {
	mu      sync.RWMutex
	path    string
	state   PolicySnapshot
	history []PolicySnapshot
}

func OpenPolicies(dir string, gateway Snapshot) (*PolicyStore, error) {
	p := &PolicyStore{path: filepath.Join(dir, "policies.json"), state: defaultPolicy()}
	history, err := readPolicyHistory(p.path, gateway)
	if err != nil {
		return nil, err
	}
	p.history = history
	p.state = clonePolicy(history[len(history)-1])
	return p, nil
}

func defaultPolicy() PolicySnapshot {
	return PolicySnapshot{
		SchemaVersion: 1, ID: credentialPolicyID, RulesetVersion: credentialRuleset,
		PolicyInput: PolicyInput{Mode: "disabled", Rules: []string{"private_key", "api_key"}, ApplicationIDs: []string{}, ConnectionIDs: []string{}},
	}
}

func clonePolicy(s PolicySnapshot) PolicySnapshot {
	s.Rules = slices.Clone(s.Rules)
	s.ApplicationIDs = slices.Clone(s.ApplicationIDs)
	s.ConnectionIDs = slices.Clone(s.ConnectionIDs)
	return s
}

func (p *PolicyStore) Snapshot() PolicySnapshot {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return clonePolicy(p.state)
}

func validatePolicy(in PolicyInput, gateway Snapshot) error {
	if in.Mode != "disabled" && in.Mode != "observe" && in.Mode != "block" {
		return errors.New("Choose Disabled, Observe or Block for the policy mode.")
	}
	if len(in.Rules) < 1 || len(in.Rules) > len(credentialRules) {
		return errors.New("Select at least one credential detection rule.")
	}
	seen := map[string]bool{}
	for _, rule := range in.Rules {
		if (rule != "private_key" && rule != "api_key") || seen[rule] {
			return errors.New("Unknown or duplicate credential detection rule.")
		}
		seen[rule] = true
	}
	apps, connections := map[string]bool{}, map[string]bool{}
	for _, a := range gateway.Applications {
		apps[a.ID] = true
	}
	for _, c := range gateway.Connections {
		connections[c.ID] = true
	}
	for _, scope := range []struct {
		ids   []string
		known map[string]bool
	}{{in.ApplicationIDs, apps}, {in.ConnectionIDs, connections}} {
		if len(scope.ids) > 64 {
			return errors.New("Select up to 64 applications and 64 model connections, or use all.")
		}
		seen = map[string]bool{}
		for _, id := range scope.ids {
			if !scope.known[id] || seen[id] {
				return errors.New("Policy scope contains an unknown or duplicate application or model connection.")
			}
			seen[id] = true
		}
	}
	return nil
}

// The gateway currently has no deletion API: scope IDs stay valid after the
// snapshot is taken. Renames do not change scope; grants still apply separately.
func (p *PolicyStore) Save(in PolicyInput, gateway Snapshot) (PolicySnapshot, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if in.Revision != p.state.Revision {
		return PolicySnapshot{}, ErrConflict
	}
	if err := validatePolicy(in, gateway); err != nil {
		return PolicySnapshot{}, err
	}
	if len(p.history) >= maxPolicySnapshots || in.Revision == ^uint64(0) {
		return PolicySnapshot{}, ErrPolicyHistoryFull
	}
	next := clonePolicy(PolicySnapshot{SchemaVersion: 1, ID: credentialPolicyID, RulesetVersion: credentialRuleset, UpdatedAt: time.Now().UTC().Format(time.RFC3339Nano), PolicyInput: in})
	if next.ApplicationIDs == nil {
		next.ApplicationIDs = []string{}
	}
	if next.ConnectionIDs == nil {
		next.ConnectionIDs = []string{}
	}
	next.Revision++
	history := append(slices.Clone(p.history), next)
	data, err := json.MarshalIndent(policyHistoryState{SchemaVersion: 2, Snapshots: history}, "", "  ")
	if err != nil {
		return PolicySnapshot{}, ErrPersistence
	}
	if len(data)+1 > maxPolicyHistoryBytes {
		return PolicySnapshot{}, ErrPolicyHistoryFull
	}
	if storage.AtomicWrite(p.path, append(data, '\n')) != nil {
		return PolicySnapshot{}, ErrPersistence
	}
	p.state = next
	p.history = history
	return clonePolicy(next), nil
}

// Evaluate uses one immutable policy snapshot. JSON tokens include object keys,
// duplicate keys, tool arguments and extension fields; escapes are decoded by
// the standard library. Only strings are inspected. Encoded/binary attachments,
// external URLs, obfuscation and model output are outside this rule set.
func (p *PolicyStore) Evaluate(body []byte, applicationID, connectionID string) (result *PolicyAssessment, err error) {
	start := time.Now()
	s := p.Snapshot()
	result = &PolicyAssessment{ID: s.ID, Revision: s.Revision, RulesetVersion: s.RulesetVersion, Mode: s.Mode, Result: "disabled", MatchedRules: []string{}}
	defer func() { result.CheckDurationUS = time.Since(start).Microseconds() }()
	if s.Mode == "disabled" {
		return result, nil
	}
	if (len(s.ApplicationIDs) > 0 && !slices.Contains(s.ApplicationIDs, applicationID)) || (len(s.ConnectionIDs) > 0 && !slices.Contains(s.ConnectionIDs, connectionID)) {
		result.Result = "not_applicable"
		return result, nil
	}
	result.Result = "allow"
	hits := make([]bool, len(credentialRules))
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	for {
		token, decodeErr := decoder.Token()
		if decodeErr == io.EOF {
			break
		}
		if decodeErr != nil {
			result.Result = "error"
			return result, decodeErr
		}
		value, ok := token.(string)
		if !ok {
			continue
		}
		for i, rule := range credentialRules {
			if !hits[i] && slices.Contains(s.Rules, rule.id) && rule.pattern.MatchString(value) {
				hits[i] = true
			}
		}
	}
	for i, rule := range credentialRules {
		if hits[i] {
			result.MatchedRules = append(result.MatchedRules, rule.id)
		}
	}
	if len(result.MatchedRules) > 0 {
		result.Result = s.Mode
	}
	return result, nil
}
