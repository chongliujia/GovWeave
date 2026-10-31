package detection

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"govweave/internal/leakage"
)

type testPlugin struct {
	descriptor Descriptor
	fn         func(context.Context, Input) (Finding, error)
}

func (p *testPlugin) Descriptor() Descriptor { return p.descriptor }
func (p *testPlugin) Evaluate(ctx context.Context, input Input) (Finding, error) {
	return p.fn(ctx, input)
}

func testDescriptor() Descriptor {
	return Descriptor{ID: "test_detector", Version: "1.0.0", RiskType: "synthetic_risk"}
}

func cleanFinding() Finding {
	return Finding{State: NotObserved, Reason: "not_seen", Evidence: []Evidence{}}
}

func seenFinding() Finding {
	return Finding{State: Observed, Reason: "seen", Evidence: []Evidence{{Representation: "composed", StartByte: 0, EndByte: 1, SpanScope: "transformed_region", Transformations: []string{"base64", "reversed"}}}}
}

func TestRegistrationRejectsInvalidPluginsAndPinsVersions(t *testing.T) {
	valid := &testPlugin{descriptor: testDescriptor(), fn: func(context.Context, Input) (Finding, error) { return cleanFinding(), nil }}
	var typedNil *testPlugin
	for _, plugins := range [][]Plugin{nil, {nil}, {typedNil}, {valid, valid}, make([]Plugin, MaxPlugins+1)} {
		if registry, err := NewRegistry(plugins...); registry != nil || !errors.Is(err, ErrInvalidRegistry) {
			t.Fatalf("invalid registry accepted: %+v %v", registry, err)
		}
	}
	for field := 0; field < 3; field++ {
		bad := testDescriptor()
		switch field {
		case 0:
			bad.ID = "unbounded content with spaces"
		case 1:
			bad.Version = ""
		case 2:
			bad.RiskType = strings.Repeat("a", 65)
		}
		if _, err := NewRegistry(&testPlugin{descriptor: bad}); !errors.Is(err, ErrInvalidRegistry) {
			t.Fatalf("invalid descriptor accepted: %+v %v", bad, err)
		}
	}
	second := &testPlugin{descriptor: testDescriptor(), fn: valid.fn}
	second.descriptor.Version = "2.0.0"
	registry, err := NewRegistry(valid, second)
	if err != nil {
		t.Fatal(err)
	}
	for _, version := range []string{"1.0.0", "2.0.0"} {
		result, err := registry.Evaluate(context.Background(), Ref{ID: "test_detector", Version: version}, Input{})
		if err != nil || result.Detector.Version != version || result.State != NotObserved {
			t.Fatalf("pinned version failed: %+v %v", result, err)
		}
	}
	for _, ref := range []Ref{{ID: "test_detector"}, {ID: "test_detector", Version: "latest"}, {ID: strings.Repeat("x", 1024), Version: "1"}} {
		result, err := registry.Evaluate(context.Background(), ref, Input{})
		if !errors.Is(err, ErrNotRegistered) || result.State != Unknown || result.Reason != "detector_not_registered" || len(result.Detector.ID) > 64 || result.Evaluated {
			t.Fatalf("unsupported version did not fail closed: %+v %v", result, err)
		}
	}
}

func TestRegistrySnapshotsMetadataAndCopiesInputsAndEvidence(t *testing.T) {
	finding := seenFinding()
	plugin := &testPlugin{descriptor: testDescriptor(), fn: func(_ context.Context, input Input) (Finding, error) {
		input.Content[0] = 'z'
		return finding, nil
	}}
	registry, err := NewRegistry(plugin)
	if err != nil {
		t.Fatal(err)
	}
	plugin.descriptor.ID, plugin.descriptor.RiskType = "changed", "changed_risk"
	descriptors := registry.Descriptors()
	descriptors[0].ID = "caller_changed"
	input := Input{Content: []byte("abc"), KnownMarker: "private synthetic marker"}
	result, err := registry.Evaluate(context.Background(), Ref{ID: "test_detector", Version: "1.0.0"}, input)
	if err != nil || result.Detector != testDescriptor() || result.State != Observed || string(input.Content) != "abc" || !result.Evaluated {
		t.Fatalf("registry isolation failed: %+v %v %s", result, err, input.Content)
	}
	digest := sha256.Sum256([]byte("abc"))
	if result.ContentSHA256 != hex.EncodeToString(digest[:]) {
		t.Fatal("content hash refers to modified plugin input")
	}
	finding.Evidence[0].Transformations[0] = "changed"
	finding.Evidence[0].StartByte = 2
	if result.Evidence[0].Transformations[0] != "base64" || result.Evidence[0].StartByte != 0 {
		t.Fatal("plugin mutated returned evidence after evaluation")
	}
	serialized, err := json.Marshal(result)
	if err != nil || strings.Contains(string(serialized), input.KnownMarker) || strings.Contains(string(serialized), "abc") {
		t.Fatalf("observation retained raw input: %s %v", serialized, err)
	}
}

func TestRegistryMakesErrorsAndInvalidOutputsUnknown(t *testing.T) {
	for _, item := range []struct {
		name string
		fn   func(context.Context, Input) (Finding, error)
		err  error
	}{
		{"plugin error", func(context.Context, Input) (Finding, error) {
			return seenFinding(), errors.New("private provider message")
		}, ErrPluginFailed},
		{"plugin panic", func(context.Context, Input) (Finding, error) { panic("private panic contents") }, ErrPluginFailed},
		{"bad state", func(context.Context, Input) (Finding, error) { return Finding{State: "safe", Reason: "no"}, nil }, ErrInvalidFinding},
		{"free text reason", func(context.Context, Input) (Finding, error) {
			return Finding{State: Unknown, Reason: "private raw error!"}, nil
		}, ErrInvalidFinding},
		{"missing evidence", func(context.Context, Input) (Finding, error) { return Finding{State: Observed, Reason: "seen"}, nil }, ErrInvalidFinding},
		{"unknown with evidence", func(context.Context, Input) (Finding, error) { f := seenFinding(); f.State = Unknown; return f, nil }, ErrInvalidFinding},
		{"out of bounds", func(context.Context, Input) (Finding, error) {
			f := seenFinding()
			f.Evidence[0].EndByte = 4
			return f, nil
		}, ErrInvalidFinding},
		{"negative start", func(context.Context, Input) (Finding, error) {
			f := seenFinding()
			f.Evidence[0].StartByte = -1
			return f, nil
		}, ErrInvalidFinding},
		{"zero span", func(context.Context, Input) (Finding, error) {
			f := seenFinding()
			f.Evidence[0].EndByte = 0
			return f, nil
		}, ErrInvalidFinding},
		{"bad scope", func(context.Context, Input) (Finding, error) {
			f := seenFinding()
			f.Evidence[0].SpanScope = "decoded_offset"
			return f, nil
		}, ErrInvalidFinding},
		{"too many evidence", func(context.Context, Input) (Finding, error) {
			f := seenFinding()
			f.Evidence = make([]Evidence, MaxEvidence+1)
			return f, nil
		}, ErrInvalidFinding},
		{"bad transform", func(context.Context, Input) (Finding, error) {
			f := seenFinding()
			f.Evidence[0].Transformations[0] = "private text"
			return f, nil
		}, ErrInvalidFinding},
	} {
		t.Run(item.name, func(t *testing.T) {
			registry, err := NewRegistry(&testPlugin{descriptor: testDescriptor(), fn: item.fn})
			if err != nil {
				t.Fatal(err)
			}
			result, err := registry.Evaluate(context.Background(), Ref{ID: "test_detector", Version: "1.0.0"}, Input{Content: []byte("abc")})
			if !errors.Is(err, item.err) || result.State != Unknown || len(result.Evidence) != 0 || strings.Contains(err.Error(), "private") || !result.Evaluated {
				t.Fatalf("operational failure became a decision or leaked details: %+v %v", result, err)
			}
		})
	}
	registry, _ := NewRegistry(&testPlugin{descriptor: testDescriptor(), fn: func(context.Context, Input) (Finding, error) {
		f := seenFinding()
		f.Evidence[0].StartByte, f.Evidence[0].EndByte = 1, 2
		return f, nil
	}})
	if result, err := registry.Evaluate(context.Background(), Ref{ID: "test_detector", Version: "1.0.0"}, Input{Content: []byte("中")}); !errors.Is(err, ErrInvalidFinding) || result.State != Unknown {
		t.Fatalf("byte span splits a UTF8 character: %+v %v", result, err)
	}
}

func TestRegistryEligibilityAndCancellationAvoidPluginWork(t *testing.T) {
	var calls atomic.Int32
	registry, _ := NewRegistry(&testPlugin{descriptor: testDescriptor(), fn: func(context.Context, Input) (Finding, error) {
		calls.Add(1)
		return cleanFinding(), nil
	}})
	ref := Ref{ID: "test_detector", Version: "1.0.0"}
	for _, input := range []struct {
		content []byte
		reason  string
	}{
		{make([]byte, MaxContentBytes+1), "response_limit"},
		{[]byte{0xff}, "invalid_utf8"},
	} {
		result, err := registry.Evaluate(context.Background(), ref, Input{Content: input.content})
		if err != nil || result.State != Unknown || result.Reason != input.reason || calls.Load() != 0 || result.Evaluated {
			t.Fatalf("ineligible input reached plugin: %+v %v", result, err)
		}
		if input.reason == "response_limit" && result.ContentSHA256 != "" {
			t.Fatal("oversized input was hashed outside the bounded input budget")
		}
	}
	result, err := registry.Evaluate(context.Background(), ref, Input{Content: []byte("abc"), KnownMarker: strings.Repeat("x", MaxMarkerBytes+1)})
	if err != nil || result.State != Unknown || result.Reason != "invalid_marker" || result.Evaluated || result.ContentSHA256 != "" || calls.Load() != 0 {
		t.Fatalf("oversized context reached plugin or hashing: %+v %v", result, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result, err = registry.Evaluate(ctx, ref, Input{Content: []byte("abc")})
	if !errors.Is(err, context.Canceled) || result.State != Unknown || result.Reason != "cancelled" || calls.Load() != 0 || result.Evaluated {
		t.Fatalf("pre-cancelled context reached plugin: %+v %v", result, err)
	}
	ctx, cancel = context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	result, err = registry.Evaluate(ctx, ref, Input{})
	if !errors.Is(err, context.DeadlineExceeded) || result.State != Unknown || result.Reason != "deadline_exceeded" || result.Evaluated {
		t.Fatalf("expired deadline became a decision: %+v %v", result, err)
	}
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	registry, _ = NewRegistry(&testPlugin{descriptor: testDescriptor(), fn: func(context.Context, Input) (Finding, error) {
		cancel()
		return seenFinding(), nil
	}})
	result, err = registry.Evaluate(ctx, ref, Input{Content: []byte("abc")})
	if !errors.Is(err, context.Canceled) || result.State != Unknown || len(result.Evidence) != 0 || !result.Evaluated {
		t.Fatalf("a result returned after cancellation was accepted: %+v %v", result, err)
	}
}

func TestRegistrySupportsConcurrentCalls(t *testing.T) {
	var calls atomic.Int32
	registry, _ := NewRegistry(&testPlugin{descriptor: testDescriptor(), fn: func(context.Context, Input) (Finding, error) {
		calls.Add(1)
		return seenFinding(), nil
	}})
	var wait sync.WaitGroup
	for i := 0; i < 32; i++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			result, err := registry.Evaluate(context.Background(), Ref{ID: "test_detector", Version: "1.0.0"}, Input{Content: []byte("abc")})
			if err != nil || result.State != Observed || len(registry.Descriptors()) != 1 {
				t.Errorf("concurrent evaluation failed: %+v %v", result, err)
			}
		}()
	}
	wait.Wait()
	if calls.Load() != 32 {
		t.Fatalf("got %d plugin calls, want 32", calls.Load())
	}
}

func TestCanaryAdaptersPreserveStageFindingsAndVersionIsolation(t *testing.T) {
	const marker = "GW-CANARY-0a1b2c3d4e5f60718293a4b5c6d7e8f90"
	encoded := base64.StdEncoding.EncodeToString([]byte(marker))
	registry, err := CanaryRegistry()
	if err != nil {
		t.Fatal(err)
	}
	for _, stage := range leakage.EvaluationStages() {
		for _, input := range []Input{
			{Content: []byte("前缀 " + marker), KnownMarker: marker},
			{Content: []byte(strings.ToLower(marker)), KnownMarker: marker},
			{Content: []byte(encoded), KnownMarker: marker},
			{Content: []byte(base64.StdEncoding.EncodeToString([]byte(encoded))), KnownMarker: marker},
			{Content: []byte("A refusal"), KnownMarker: marker},
			{Content: []byte("invalid marker"), KnownMarker: "short"},
			{Content: make([]byte, MaxContentBytes+1), KnownMarker: marker},
			{Content: []byte{0xff}, KnownMarker: marker},
		} {
			want, stageErr := leakage.DetectStage(stage.ID, input.KnownMarker, input.Content)
			got, err := registry.Evaluate(context.Background(), Ref{ID: stage.ID, Version: stage.Version}, input)
			if err != nil || stageErr != nil || got.State != want.State || got.Reason != want.Reason || got.Detector.Version != want.Version || got.Detector.RiskType != KnownMarkerExposure || len(got.Evidence) != len(want.Matches) {
				t.Fatalf("adapter changed %s: got=%+v want=%+v err=%v", stage.ID, got, want, err)
			}
			for i, match := range want.Matches {
				adapted := Evidence{Representation: match.Representation, StartByte: match.StartByte, EndByte: match.EndByte, SpanScope: match.SpanScope, Transformations: match.Transformations, Normalized: match.Normalized}
				if !reflect.DeepEqual(got.Evidence[i], adapted) {
					t.Fatalf("adapter changed source evidence: got=%+v want=%+v", got.Evidence[i], adapted)
				}
			}
		}
	}
	result, err := registry.Evaluate(context.Background(), Ref{ID: "two_layer", Version: leakage.VersionV1}, Input{Content: []byte(marker), KnownMarker: marker})
	if !errors.Is(err, ErrNotRegistered) || result.State != Unknown {
		t.Fatalf("adapter silently substituted a historical version: %+v %v", result, err)
	}
}
