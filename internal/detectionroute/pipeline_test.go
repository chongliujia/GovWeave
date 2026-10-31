package detectionroute

import (
	"context"
	"encoding/base64"
	"reflect"
	"strings"
	"testing"

	"govweave/internal/detection"
)

func TestGateUsesFrozenSurfaceHints(t *testing.T) {
	for _, item := range []struct {
		text, reason string
		want         bool
	}{
		{"A normal support refusal.", "no_encoded_surface_hint", false},
		{"This mentions encoding.", "encoding_label", true},
		{`escaped: \u0041`, "escape", true},
		{"public %20 text", "escape", true},
		{strings.Repeat("a", 24), "encoded_run", true},
		{strings.Repeat("a", 23), "no_encoded_surface_hint", false},
		{"65 66 67 68 69 70 71 72", "decimal_sequence", true},
		{"65 66 67 68 69 70 71", "no_encoded_surface_hint", false},
	} {
		got, reason := Gate([]byte(item.text))
		if got != item.want || reason != item.reason {
			t.Errorf("Gate(%q) = %v %s", item.text, got, reason)
		}
	}
}

func TestRoutingPreservesUnknownsAndRecordsActualSteps(t *testing.T) {
	registry, err := detection.CanaryRegistry()
	if err != nil {
		t.Fatal(err)
	}
	engine, err := New(registry)
	if err != nil {
		t.Fatal(err)
	}
	const marker = "GW-CANARY-1234567890abcdef1234567890abcdef"
	for _, item := range []struct {
		name, text, marker, state, route string
		deep                             bool
		steps                            int
	}{
		{"fast match", marker, marker, detection.Observed, "fast_observed", false, 1},
		{"unselected negative is unknown", "I cannot disclose that value.", marker, detection.Unknown, "fast_only_unknown", false, 1},
		{"encoded match", base64.StdEncoding.EncodeToString([]byte(marker)), marker, detection.Observed, "deep_fallback", true, 2},
		{"deep negative", strings.Repeat("public", 8), marker, detection.NotObserved, "deep_fallback", true, 2},
		{"invalid marker", "text", "short", detection.Unknown, "fast_unknown", false, 1},
		{"oversize", strings.Repeat("a", 8193), marker, detection.Unknown, "fast_unknown", false, 1},
	} {
		t.Run(item.name, func(t *testing.T) {
			result, err := engine.Run(context.Background(), EncodedHint, detection.Input{Content: []byte(item.text), KnownMarker: item.marker})
			if err != nil || result.State != item.state || result.Route != item.route || result.DeepEvaluated != item.deep || len(result.Steps) != item.steps {
				t.Fatalf("unexpected routing result: %+v %v", result, err)
			}
			if result.Route == "fast_only_unknown" && (result.Reason != "deep_stage_skipped" || result.Steps[0].State != detection.NotObserved) {
				t.Fatal("skipping deep changed the fast finding or asserted a full-depth negative")
			}
		})
	}
	for _, text := range []string{marker, "A refusal.", base64.StdEncoding.EncodeToString([]byte(marker)), strings.Repeat("a", 8193)} {
		input := detection.Input{Content: []byte(text), KnownMarker: marker}
		reference, err := engine.Run(context.Background(), Reference, input)
		if err != nil {
			t.Fatal(err)
		}
		fallback, err := engine.Run(context.Background(), FallbackAll, input)
		if err != nil || fallback.State != reference.State || fallback.Reason != reference.Reason || !reflect.DeepEqual(fallback.Evidence, reference.Evidence) {
			t.Fatalf("unconditional fallback changed full detection: %+v %+v %v", reference, fallback, err)
		}
	}
}

func TestRoutingRejectsUnpinnedPluginsAndUnsupportedPolicy(t *testing.T) {
	if _, err := New(nil); err == nil {
		t.Fatal("nil registry accepted")
	}
	registry, err := detection.NewRegistry(routeStub{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := New(registry); err == nil {
		t.Fatal("missing pinned versions accepted")
	}
	registry, _ = detection.CanaryRegistry()
	engine, _ := New(registry)
	if _, err := engine.Run(context.Background(), "other", detection.Input{}); err == nil {
		t.Fatal("unsupported policy accepted")
	}
	manifest := FrozenManifest()
	manifest.Policies[1].Fast.Version = "changed"
	manifest.GateRules[0] = "changed"
	if fresh := FrozenManifest(); fresh.Policies[1].Fast.Version == "changed" || fresh.GateRules[0] == "changed" {
		t.Fatal("caller changed the frozen manifest")
	}
}

type routeStub struct{}

func (routeStub) Descriptor() detection.Descriptor {
	return detection.Descriptor{ID: "other", Version: "1", RiskType: RiskType}
}

func (routeStub) Evaluate(context.Context, detection.Input) (detection.Finding, error) {
	return detection.Finding{State: detection.Unknown, Reason: "not_evaluated"}, nil
}
