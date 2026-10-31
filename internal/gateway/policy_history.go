package gateway

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"slices"
	"time"

	"govweave/internal/config"
)

const maxPolicySnapshots = 1024
const maxPolicyHistoryBytes = 8 << 20

var ErrPolicyHistoryFull = errors.New("Policy history capacity has been reached. The current policy remains active.")

// One atomic replacement commits both the history and its active (last) revision.
// Existing revisions are never overwritten or silently evicted.
type policyHistoryState struct {
	SchemaVersion int              `json:"schema_version"`
	Snapshots     []PolicySnapshot `json:"snapshots"`
}

type PolicyHistory struct {
	Snapshots          []PolicySnapshot `json:"snapshots"`
	Total              int              `json:"total"`
	NextBeforeRevision *uint64          `json:"next_before_revision,omitempty"`
}

func readPolicyHistory(path string, gateway Snapshot) ([]PolicySnapshot, error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return []PolicySnapshot{defaultPolicy()}, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > maxPolicyHistoryBytes {
		return nil, errors.New("policies.json must be private and no larger than 8 MiB")
	}
	data, err := io.ReadAll(io.LimitReader(f, maxPolicyHistoryBytes+1))
	if err != nil || len(data) > maxPolicyHistoryBytes {
		return nil, errors.New("could not read bounded policy history")
	}
	var header struct {
		SchemaVersion int `json:"schema_version"`
	}
	if json.Unmarshal(data, &header) != nil {
		return nil, errors.New("invalid policy state; refusing to disable protection")
	}
	var history []PolicySnapshot
	switch header.SchemaVersion {
	case 1:
		// Older installations retained only the active revision. Do not invent
		// configurations for requests predating that revision; migrate on save.
		var legacy PolicySnapshot
		if len(data) > 16<<10 || config.DecodeStrict(bytes.NewReader(data), &legacy) != nil || legacy.Revision == 0 {
			return nil, errors.New("invalid legacy policy state")
		}
		history = []PolicySnapshot{legacy}
	case 2:
		var state policyHistoryState
		if config.DecodeStrict(bytes.NewReader(data), &state) != nil || len(state.Snapshots) == 0 || len(state.Snapshots) > maxPolicySnapshots {
			return nil, errors.New("invalid policy history")
		}
		history = state.Snapshots
	default:
		return nil, errors.New("unsupported policy state; refusing to disable protection")
	}
	for i, snapshot := range history {
		if err := validatePolicySnapshot(snapshot, gateway); err != nil {
			return nil, err
		}
		if i > 0 && (history[i-1].Revision == ^uint64(0) || snapshot.Revision != history[i-1].Revision+1) {
			return nil, errors.New("policy history revisions must be consecutive and increasing")
		}
	}
	return history, nil
}

func validatePolicySnapshot(s PolicySnapshot, gateway Snapshot) error {
	if s.SchemaVersion != 1 || s.ID != credentialPolicyID || s.RulesetVersion != credentialRuleset {
		return errors.New("invalid policy snapshot metadata")
	}
	if err := validatePolicy(s.PolicyInput, gateway); err != nil {
		return err
	}
	if s.Revision == 0 {
		if s.Mode != "disabled" || !slices.Equal(s.Rules, defaultPolicy().Rules) || len(s.ApplicationIDs) != 0 || len(s.ConnectionIDs) != 0 || s.UpdatedAt != "" {
			return errors.New("invalid initial policy snapshot")
		}
	} else if _, err := time.Parse(time.RFC3339Nano, s.UpdatedAt); err != nil {
		return errors.New("invalid policy timestamp")
	}
	return nil
}

func (p *PolicyStore) Revision(revision uint64) (PolicySnapshot, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	for _, snapshot := range p.history {
		if snapshot.Revision == revision {
			return clonePolicy(snapshot), nil
		}
	}
	return PolicySnapshot{}, ErrNotFound
}

// History returns newest first. The exclusive revision cursor is stable while
// administrators append newer snapshots; pagination cannot skip older entries.
func (p *PolicyStore) History(limit int, before *uint64) PolicyHistory {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if limit < 1 || limit > 100 {
		limit = 20
	}
	view := PolicyHistory{Snapshots: []PolicySnapshot{}, Total: len(p.history)}
	for i := len(p.history) - 1; i >= 0; i-- {
		snapshot := p.history[i]
		if before != nil && snapshot.Revision >= *before {
			continue
		}
		if len(view.Snapshots) == limit {
			cursor := view.Snapshots[len(view.Snapshots)-1].Revision
			view.NextBeforeRevision = &cursor
			break
		}
		view.Snapshots = append(view.Snapshots, clonePolicy(snapshot))
	}
	return view
}
