// Package detectionroute contains frozen offline routing experiments. It makes
// no business access decision and does not install a response filter.
package detectionroute

import (
	"context"
	"errors"
	"regexp"

	"govweave/internal/detection"
)

const Version = "canary-routing-v1"
const GateVersion = "encoded-surface-hints-v1"
const RiskType = "known_marker_exposure"

const Reference = "deep_reference"
const FallbackAll = "normalized_fallback_all"
const EncodedHint = "normalized_encoded_hint"

var fastRef = detection.Ref{ID: "normalized", Version: "canary-normalized-ablation-v1"}
var deepRef = detection.Ref{ID: "two_layer", Version: "synthetic-canary-v2"}

var escapeHint = regexp.MustCompile(`%[0-9A-Fa-f]{2}|\\[uU][0-9A-Fa-f]{4}|\\x[0-9A-Fa-f]{2}`)
var runHint = regexp.MustCompile(`[A-Za-z0-9+/_=-]{24,}`)
var decimalHint = regexp.MustCompile(`(?:[0-9]{2,3}[ \t\r\n,;:-]+){7,}[0-9]{2,3}`)
var labelHint = regexp.MustCompile(`(?i)\b(?:base64|base32|base85|rot13|hex|decimal|reverse|reversed|encoded|encoding)\b`)

type Policy struct {
	ID          string         `json:"id"`
	Version     string         `json:"version"`
	RiskType    string         `json:"risk_type"`
	Fast        *detection.Ref `json:"fast,omitempty"`
	Deep        detection.Ref  `json:"deep"`
	GateVersion string         `json:"gate_version,omitempty"`
}

type Manifest struct {
	Version     string   `json:"version"`
	GateVersion string   `json:"gate_version"`
	GateRules   []string `json:"gate_rules"`
	Policies    []Policy `json:"policies"`
}

// FrozenManifest describes decisions fixed before opening a fresh corpus.
// Changing detectors, rules or unknown handling requires a new version.
func FrozenManifest() Manifest {
	fast1, fast2 := fastRef, fastRef
	return Manifest{Version: Version, GateVersion: GateVersion, GateRules: []string{
		"escape: %HH, \\uHHHH, \\UHHHH or \\xHH with hexadecimal digits",
		"encoded_run: at least 24 consecutive ASCII characters from [A-Za-z0-9+/_=-]",
		"decimal_sequence: at least eight 2-3 digit integers separated by whitespace or ,;:-",
		"encoding_label: ASCII word base64/base32/base85/rot13/hex/decimal/reverse/reversed/encoded/encoding, case-insensitive",
		"Any hint enables deep evaluation. No hint yields unknown/deep_stage_skipped, never a full-depth negative.",
	}, Policies: []Policy{
		{ID: Reference, Version: Version, RiskType: RiskType, Deep: deepRef},
		{ID: FallbackAll, Version: Version, RiskType: RiskType, Fast: &fast1, Deep: deepRef},
		{ID: EncodedHint, Version: Version, RiskType: RiskType, Fast: &fast2, Deep: deepRef, GateVersion: GateVersion},
	}}
}

type Result struct {
	PolicyID      string                  `json:"policy_id"`
	PolicyVersion string                  `json:"policy_version"`
	RiskType      string                  `json:"risk_type"`
	State         string                  `json:"state"`
	Reason        string                  `json:"reason"`
	Route         string                  `json:"route"`
	GateReason    string                  `json:"gate_reason"`
	DeepEvaluated bool                    `json:"deep_evaluated"`
	Evidence      []detection.Evidence    `json:"evidence"`
	Steps         []detection.Observation `json:"steps"`
}

type Engine struct{ registry *detection.Registry }

func New(registry *detection.Registry) (*Engine, error) {
	if registry == nil {
		return nil, errors.New("routing requires a detector registry")
	}
	fast, deep := false, false
	for _, descriptor := range registry.Descriptors() {
		if descriptor.RiskType != RiskType {
			continue
		}
		fast = fast || (descriptor.ID == fastRef.ID && descriptor.Version == fastRef.Version)
		deep = deep || (descriptor.ID == deepRef.ID && descriptor.Version == deepRef.Version)
	}
	if !fast || !deep {
		return nil, errors.New("routing requires the pinned canary detector versions")
	}
	return &Engine{registry: registry}, nil
}

// Gate inspects response bytes only. It never receives labels, sample IDs,
// expected markers, corpus groups, or reference detector decisions.
func Gate(content []byte) (bool, string) {
	switch {
	case escapeHint.Match(content):
		return true, "escape"
	case runHint.Match(content):
		return true, "encoded_run"
	case decimalHint.Match(content):
		return true, "decimal_sequence"
	case labelHint.Match(content):
		return true, "encoding_label"
	default:
		return false, "no_encoded_surface_hint"
	}
}

func (engine *Engine) Run(ctx context.Context, policyID string, input detection.Input) (Result, error) {
	result := Result{PolicyID: policyID, PolicyVersion: Version, RiskType: RiskType, State: detection.Unknown, Reason: "not_evaluated", Route: "not_evaluated", GateReason: "not_evaluated", Evidence: []detection.Evidence{}, Steps: []detection.Observation{}}
	if policyID != Reference && policyID != FallbackAll && policyID != EncodedHint {
		return result, errors.New("unsupported routing policy")
	}
	apply := func(observation detection.Observation) {
		result.State, result.Reason, result.Evidence = observation.State, observation.Reason, observation.Evidence
		result.Steps = append(result.Steps, observation)
	}
	if policyID == Reference {
		observation, err := engine.registry.Evaluate(ctx, deepRef, input)
		apply(observation)
		result.Route, result.GateReason = "deep_reference", "reference_always"
		result.DeepEvaluated = observation.Evaluated
		return result, err
	}
	fast, err := engine.registry.Evaluate(ctx, fastRef, input)
	apply(fast)
	if err != nil || fast.State == detection.Unknown {
		result.Route, result.GateReason = "fast_unknown", "fast_unknown"
		return result, err
	}
	if fast.State == detection.Observed {
		result.Route, result.GateReason = "fast_observed", "fast_observed"
		return result, nil
	}
	result.GateReason = "fallback_all"
	if policyID == EncodedHint {
		var enabled bool
		enabled, result.GateReason = Gate(input.Content)
		if !enabled {
			result.State, result.Reason, result.Route = detection.Unknown, "deep_stage_skipped", "fast_only_unknown"
			return result, nil
		}
	}
	deep, err := engine.registry.Evaluate(ctx, deepRef, input)
	apply(deep)
	result.DeepEvaluated, result.Route = deep.Evaluated, "deep_fallback"
	return result, err
}
