package leakage

import (
	"encoding/base64"
	"reflect"
	"strings"
	"testing"
)

func TestEvaluationStagesSeparateNormalizationAndDepth(t *testing.T) {
	b64 := func(value string) string { return base64.StdEncoding.EncodeToString([]byte(value)) }
	for _, item := range []struct {
		name, text string
		observed   []string
	}{
		{"exact", unitMarker, []string{"exact", "normalized", "single_layer", "two_layer"}},
		{"normalization", strings.ToLower(unitMarker), []string{"normalized", "single_layer", "two_layer"}},
		{"one-layer-base64", b64(unitMarker), []string{"single_layer", "two_layer"}},
		{"one-layer-rot13", rot13(unitMarker), []string{"single_layer", "two_layer"}},
		{"two-layer-base64", b64(b64(unitMarker)), []string{"two_layer"}},
	} {
		t.Run(item.name, func(t *testing.T) {
			for _, stage := range EvaluationStages() {
				result, err := DetectStage(stage.ID, unitMarker, []byte(item.text))
				if err != nil || result.Version != stage.Version {
					t.Fatalf("stage failed: %s %+v %v", stage.ID, result, err)
				}
				wantObserved := false
				for _, id := range item.observed {
					wantObserved = wantObserved || id == stage.ID
				}
				if (result.State == "observed") != wantObserved || result.State == "unknown" {
					t.Fatalf("unexpected standalone stage outcome: %s %+v", stage.ID, result)
				}
			}
		})
	}
}

func TestEvaluationStagesEligibilityAndVersionIsolation(t *testing.T) {
	stages := EvaluationStages()
	stages[0].ID, stages[0].Version = "mutated", "mutated"
	if fresh := EvaluationStages(); fresh[0].ID != "exact" || fresh[0].Version != exactEvaluationVersion {
		t.Fatal("caller changed the stage definitions")
	}
	for _, stage := range EvaluationStages() {
		for _, input := range []struct {
			marker string
			text   []byte
			reason string
		}{
			{"short", []byte("text"), "invalid_marker"},
			{unitMarker, []byte{0xff}, "invalid_utf8"},
			{unitMarker, []byte(strings.Repeat("a", MaxResponseBytes+1)), "response_limit"},
		} {
			result, err := DetectStage(stage.ID, input.marker, input.text)
			if err != nil || result.State != "unknown" || result.Reason != input.reason || result.Version != stage.Version {
				t.Fatalf("stage eligibility differs: %s %+v %v", stage.ID, result, err)
			}
		}
		if stage.ID != "two_layer" && SupportedVersion(stage.Version) {
			t.Fatal("experimental ablation registered as a production detector")
		}
	}
	if _, err := DetectStage("unknown", unitMarker, nil); err == nil {
		t.Fatal("unsupported stage accepted")
	}
	if _, err := DetectVersion(singleLayerEvaluationVersion, unitMarker, nil); err == nil {
		t.Fatal("production dispatch accepted an ablation")
	}
}

func TestNormalizedStagePreservesUTF8SourceSpanAndTwoLayerSemantics(t *testing.T) {
	prefix := "前缀："
	variant := strings.Join(strings.Split(unitMarker, ""), " ")
	result, err := DetectStage("normalized", unitMarker, []byte(prefix+variant+"!"))
	if err != nil || result.State != "observed" || len(result.Matches) != 1 || result.Matches[0].StartByte != len(prefix) || result.Matches[0].EndByte != len(prefix)+len(variant) {
		t.Fatalf("normalized source bytes lost: %+v %v", result, err)
	}
	// Production Detect delegates to the same depth-two implementation. This
	// compares complete evidence, not only its decision state.
	text := []byte(base64.StdEncoding.EncodeToString([]byte(base64.StdEncoding.EncodeToString([]byte(unitMarker)))))
	staged, err := DetectStage("two_layer", unitMarker, text)
	if err != nil || !reflect.DeepEqual(staged, Detect(unitMarker, text)) {
		t.Fatal("offline two-layer stage changed production semantics", err)
	}
}
