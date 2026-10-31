package leakage

import (
	"bytes"
	"errors"
	"strings"
)

const exactEvaluationVersion = "literal-exact-v1"
const normalizedEvaluationVersion = "canary-normalized-ablation-v1"
const singleLayerEvaluationVersion = "canary-v2-depth1-ablation-v1"

// StageDescriptor identifies an offline ablation, not a production detector
// registration. Single- and two-layer stages share v2 transforms and budgets.
type StageDescriptor struct {
	ID      string `json:"id"`
	Version string `json:"version"`
}

// EvaluationStages returns a fresh description slice in increasing depth order.
// The order describes standalone stages; it does not promise monotonic results
// or prescribe a production routing/early-exit policy.
func EvaluationStages() []StageDescriptor {
	return []StageDescriptor{
		{ID: "exact", Version: exactEvaluationVersion},
		{ID: "normalized", Version: normalizedEvaluationVersion},
		{ID: "single_layer", Version: singleLayerEvaluationVersion},
		{ID: "two_layer", Version: Version},
	}
}

// DetectStage runs one complete offline stage, including input eligibility and
// result metadata. Ablation versions are deliberately absent from SupportedVersion.
func DetectStage(id, marker string, text []byte) (Result, error) {
	switch id {
	case "exact":
		return detectTextOnly(marker, text, false, exactEvaluationVersion), nil
	case "normalized":
		return detectTextOnly(marker, text, true, normalizedEvaluationVersion), nil
	case "single_layer":
		result := detectDepth(marker, text, 1)
		result.Version = singleLayerEvaluationVersion
		return result, nil
	case "two_layer":
		return Detect(marker, text), nil
	default:
		return Result{}, errors.New("unsupported canary evaluation stage")
	}
}

func detectTextOnly(marker string, text []byte, allowNormalization bool, version string) Result {
	result := Result{Version: version, State: "unknown", InputBytes: len(text), Matches: []Match{}}
	if problem := InputProblem(marker, text); problem != "" {
		result.Reason = problem
		return result
	}
	result.MarkerSHA256 = MarkerDigest(marker)
	result.ScannedBytes = len(text)
	if at := bytes.Index(text, []byte(marker)); at >= 0 {
		result.State, result.Reason = "observed", "full_marker_observed"
		result.Matches = []Match{{Representation: "exact", StartByte: at, EndByte: at + len(marker), SpanScope: "raw_fragment"}}
		return result
	}
	if allowNormalization {
		key, _, _ := normalize(marker)
		value, starts, ends := normalize(string(text))
		if at := strings.Index(value, key); at >= 0 {
			result.State, result.Reason = "observed", "full_marker_observed"
			result.Matches = []Match{{Representation: "normalized", StartByte: starts[at], EndByte: ends[at+len(key)-1], SpanScope: "raw_fragment"}}
			return result
		}
	}
	result.State, result.Reason = "not_observed", "full_marker_not_observed"
	return result
}
