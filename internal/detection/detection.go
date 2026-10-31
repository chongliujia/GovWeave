// Package detection provides bounded, version-pinned in-process detector plugins.
// Findings describe technical observations, not access decisions or legal conclusions.
package detection

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"reflect"
	"regexp"
	"slices"
	"time"
	"unicode/utf8"
)

const (
	Observed        = "observed"
	NotObserved     = "not_observed"
	Unknown         = "unknown"
	MaxContentBytes = 8192
	MaxMarkerBytes  = 512
	MaxPlugins      = 16
	MaxEvidence     = 8
)

var (
	ErrInvalidRegistry = errors.New("invalid detector registration")
	ErrNotRegistered   = errors.New("detector version is not registered")
	ErrPluginFailed    = errors.New("detector plugin failed")
	ErrInvalidFinding  = errors.New("detector plugin returned an invalid finding")
)

var identifierPattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,63}$`)
var versionPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$`)

// Input is ephemeral. Registry gives each invocation its own Content copy.
// KnownMarker is optional context for the known-marker adapter; it is not a
// general-purpose document store and is never included in an Observation.
type Input struct {
	Content     []byte
	KnownMarker string
}

type Ref struct {
	ID      string `json:"id"`
	Version string `json:"version"`
}

type Descriptor struct {
	ID       string `json:"id"`
	Version  string `json:"version"`
	RiskType string `json:"risk_type"`
}

// Evidence references bytes in the original Content without retaining text.
// Encoded/transformed spans identify the source region, not decoded offsets.
type Evidence struct {
	Representation  string   `json:"representation"`
	StartByte       int      `json:"start_byte"`
	EndByte         int      `json:"end_byte"`
	SpanScope       string   `json:"span_scope"`
	Transformations []string `json:"transformations,omitempty"`
	Normalized      bool     `json:"normalized,omitempty"`
}

type Finding struct {
	State    string     `json:"state"`
	Reason   string     `json:"reason"`
	Evidence []Evidence `json:"evidence"`
}

type Observation struct {
	Detector      Descriptor `json:"detector"`
	State         string     `json:"state"`
	Reason        string     `json:"reason"`
	Evidence      []Evidence `json:"evidence"`
	Evaluated     bool       `json:"evaluated"`
	ElapsedNS     int64      `json:"elapsed_ns"`
	ContentSHA256 string     `json:"content_sha256,omitempty"`
	InputBytes    int        `json:"input_bytes"`
}

// Plugin implementations must be safe for concurrent calls, keep their
// registered behavior stable, bound their own work and cooperate with ctx.
// Registry invokes plugins synchronously: it cannot preempt an implementation
// that ignores cancellation, and does not leave detached goroutines running.
type Plugin interface {
	Descriptor() Descriptor
	Evaluate(context.Context, Input) (Finding, error)
}

type registration struct {
	descriptor Descriptor
	plugin     Plugin
}

// Registry is immutable after construction. Descriptors are snapshotted at
// registration; there is no latest-version fallback or dynamic code loading.
type Registry struct {
	entries map[Ref]registration
	order   []Ref
}

func describe(plugin Plugin) (descriptor Descriptor, err error) {
	defer func() {
		if recover() != nil {
			err = ErrInvalidRegistry
		}
	}()
	if plugin == nil {
		return Descriptor{}, ErrInvalidRegistry
	}
	value := reflect.ValueOf(plugin)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		if value.IsNil() {
			return Descriptor{}, ErrInvalidRegistry
		}
	}
	descriptor = plugin.Descriptor()
	if !identifierPattern.MatchString(descriptor.ID) || !versionPattern.MatchString(descriptor.Version) || !identifierPattern.MatchString(descriptor.RiskType) {
		return Descriptor{}, ErrInvalidRegistry
	}
	return descriptor, nil
}

func NewRegistry(plugins ...Plugin) (*Registry, error) {
	if len(plugins) < 1 || len(plugins) > MaxPlugins {
		return nil, ErrInvalidRegistry
	}
	registry := &Registry{entries: make(map[Ref]registration, len(plugins)), order: make([]Ref, 0, len(plugins))}
	for _, plugin := range plugins {
		descriptor, err := describe(plugin)
		if err != nil {
			return nil, err
		}
		ref := Ref{ID: descriptor.ID, Version: descriptor.Version}
		if _, duplicate := registry.entries[ref]; duplicate {
			return nil, ErrInvalidRegistry
		}
		registry.entries[ref] = registration{descriptor, plugin}
		registry.order = append(registry.order, ref)
	}
	return registry, nil
}

func (r *Registry) Descriptors() []Descriptor {
	if r == nil {
		return []Descriptor{}
	}
	result := make([]Descriptor, 0, len(r.order))
	for _, ref := range r.order {
		result = append(result, r.entries[ref].descriptor)
	}
	return result
}

func cloneEvidence(items []Evidence) []Evidence {
	result := make([]Evidence, len(items))
	for i, item := range items {
		item.Transformations = slices.Clone(item.Transformations)
		result[i] = item
	}
	return result
}

func validFinding(finding Finding, content []byte) bool {
	if !slices.Contains([]string{Observed, NotObserved, Unknown}, finding.State) || !identifierPattern.MatchString(finding.Reason) || len(finding.Evidence) > MaxEvidence {
		return false
	}
	if (finding.State == Observed) != (len(finding.Evidence) > 0) {
		return false
	}
	for _, evidence := range finding.Evidence {
		if !identifierPattern.MatchString(evidence.Representation) || !slices.Contains([]string{"raw_fragment", "encoded_candidate", "transformed_region"}, evidence.SpanScope) || evidence.StartByte < 0 || evidence.EndByte <= evidence.StartByte || evidence.EndByte > len(content) || len(evidence.Transformations) > 8 {
			return false
		}
		if !utf8.RuneStart(content[evidence.StartByte]) || (evidence.EndByte < len(content) && !utf8.RuneStart(content[evidence.EndByte])) {
			return false
		}
		for _, transformation := range evidence.Transformations {
			if !identifierPattern.MatchString(transformation) {
				return false
			}
		}
	}
	return true
}

func invoke(ctx context.Context, plugin Plugin, input Input) (finding Finding, err error) {
	defer func() {
		if recover() != nil {
			finding, err = Finding{}, ErrPluginFailed
		}
	}()
	return plugin.Evaluate(ctx, input)
}

func contextReason(err error) string {
	if errors.Is(err, context.DeadlineExceeded) {
		return "deadline_exceeded"
	}
	return "cancelled"
}

// Evaluate includes input checks, content hashing/copying, plugin work and
// result validation in ElapsedNS. It excludes caller queues and I/O. Generic
// input ineligibility returns unknown with no operational error. Generic
// context/content envelope checks precede adapter-specific eligibility; their
// reasons can differ from a direct adapter call when multiple limits fail.
// Evaluated records entry into plugin code, including errors or late results.
// Plugin and registration errors return unknown and static errors; cancellation
// returns unknown and the standard context error.
func (r *Registry) Evaluate(ctx context.Context, ref Ref, input Input) (observation Observation, err error) {
	started := time.Now()
	defer func() { observation.ElapsedNS = time.Since(started).Nanoseconds() }()
	observation = Observation{State: Unknown, Reason: "detector_not_registered", Evidence: []Evidence{}, InputBytes: len(input.Content)}
	if !identifierPattern.MatchString(ref.ID) || !versionPattern.MatchString(ref.Version) {
		return observation, ErrNotRegistered
	}
	observation.Detector = Descriptor{ID: ref.ID, Version: ref.Version}
	if r == nil {
		return observation, ErrNotRegistered
	}
	entry, exists := r.entries[ref]
	if !exists {
		return observation, ErrNotRegistered
	}
	observation.Detector = entry.descriptor
	if err := ctx.Err(); err != nil {
		observation.Reason = contextReason(err)
		return observation, err
	}
	if len(input.KnownMarker) > MaxMarkerBytes {
		observation.Reason = "invalid_marker"
		return observation, nil
	}
	if len(input.Content) > MaxContentBytes {
		observation.Reason = "response_limit"
		return observation, nil
	}
	digest := sha256.Sum256(input.Content)
	observation.ContentSHA256 = hex.EncodeToString(digest[:])
	if !utf8.Valid(input.Content) {
		observation.Reason = "invalid_utf8"
		return observation, nil
	}
	content := slices.Clone(input.Content)
	observation.Evaluated = true
	finding, pluginErr := invoke(ctx, entry.plugin, Input{Content: content, KnownMarker: input.KnownMarker})
	if err := ctx.Err(); err != nil {
		observation.Reason = contextReason(err)
		return observation, err
	}
	if pluginErr != nil {
		observation.Reason = "plugin_error"
		return observation, ErrPluginFailed
	}
	if !validFinding(finding, input.Content) {
		observation.Reason = "invalid_finding"
		return observation, ErrInvalidFinding
	}
	observation.State, observation.Reason, observation.Evidence = finding.State, finding.Reason, cloneEvidence(finding.Evidence)
	return observation, nil
}
