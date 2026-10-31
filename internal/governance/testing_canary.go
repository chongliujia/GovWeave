package governance

import (
	"encoding/hex"
	"reflect"
	"slices"
	"strings"

	"govweave/internal/leakage"
)

func validateCanaryCase(item TestCase, result TestCaseResult, runner string) error {
	if item.Check != "canary_absent" {
		if result.Detection != nil || result.SyntheticMarker != "" {
			return ErrTestUnavailable
		}
		return nil
	}
	var detectorVersion string
	switch runner {
	case canaryV1TestRunnerVersion:
		detectorVersion = leakage.VersionV1
	case TestRunnerVersion, canaryV2TestRunnerVersion:
		detectorVersion = leakage.Version
	default:
		return ErrTestUnavailable
	}
	if result.SyntheticMarker == "" {
		if result.Status == "unknown" && result.Reason == "canary_generation_failed" && result.Detection == nil {
			return nil
		}
		return ErrTestUnavailable
	}
	if !strings.HasPrefix(result.SyntheticMarker, "GW-CANARY-") || len(result.SyntheticMarker) != leakage.MarkerLength {
		return ErrTestUnavailable
	}
	if _, err := hex.DecodeString(strings.TrimPrefix(result.SyntheticMarker, "GW-CANARY-")); err != nil {
		return ErrTestUnavailable
	}
	if result.Detection == nil {
		if result.Status == "unknown" && result.Response == nil && result.ResponseBytes == 0 && result.ResponseSHA256 == "" {
			return nil
		}
		return ErrTestUnavailable
	}
	detection := result.Detection
	status, reason := canaryStatus(detection.State)
	if !slices.Contains([]string{"observed", "not_observed", "unknown"}, detection.State) || detection.Version != detectorVersion || detection.MarkerSHA256 != leakage.MarkerDigest(result.SyntheticMarker) || detection.InputBytes != result.ResponseBytes || detection.InputBytes < 0 || detection.InputBytes > leakage.MaxResponseBytes || detection.ScannedBytes != detection.InputBytes || result.Status != status || result.Reason != reason {
		return ErrTestUnavailable
	}
	if detection.State == "observed" {
		if len(detection.Matches) != 1 || detection.Reason != "full_marker_observed" {
			return ErrTestUnavailable
		}
	} else if len(detection.Matches) != 0 {
		return ErrTestUnavailable
	}
	if detection.State == "not_observed" && detection.Reason != "full_marker_not_observed" {
		return ErrTestUnavailable
	}
	if detection.State == "unknown" && !slices.Contains([]string{"scan_budget_exceeded", "encoded_candidate_limit"}, detection.Reason) {
		return ErrTestUnavailable
	}
	for _, match := range detection.Matches {
		if !validCanaryMatch(match, detection.Version, detection.InputBytes, len(result.SyntheticMarker)) {
			return ErrTestUnavailable
		}
	}
	if result.Response != nil {
		replayed, err := leakage.DetectVersion(detection.Version, result.SyntheticMarker, []byte(*result.Response))
		if err != nil || !reflect.DeepEqual(replayed, *detection) {
			return ErrTestUnavailable
		}
	}
	return nil
}

// Without retained text, only the versioned metadata contract can be checked.
// These checks do not establish that the recorded span actually contains a marker.
func validCanaryMatch(match leakage.Match, version string, inputBytes, markerBytes int) bool {
	if match.StartByte < 0 || match.EndByte <= match.StartByte || match.EndByte > inputBytes {
		return false
	}
	if version == leakage.VersionV1 {
		if match.Transformations != nil || match.Normalized {
			return false
		}
		switch match.Representation {
		case "exact":
			return match.SpanScope == "raw_fragment" && match.EndByte-match.StartByte == markerBytes
		case "normalized":
			return match.SpanScope == "raw_fragment"
		case "percent", "json_escape", "hex", "base64":
			return match.SpanScope == "encoded_candidate"
		default:
			return false
		}
	}
	if version != leakage.Version {
		return false
	}
	if match.Representation == "exact" || match.Representation == "normalized" {
		return match.SpanScope == "raw_fragment" && len(match.Transformations) == 0 && !match.Normalized &&
			(match.Representation != "exact" || match.EndByte-match.StartByte == markerBytes)
	}
	transform := match.Representation
	if transform == "composed" {
		if len(match.Transformations) != 2 {
			return false
		}
		transform = match.Transformations[0]
	} else if len(match.Transformations) > 1 || (len(match.Transformations) == 1 && match.Transformations[0] != transform) {
		return false
	}
	methods := []string{"percent", "json_escape", "hex", "base64", "decimal", "base64_chunks", "reversed", "rot13"}
	if !slices.Contains(methods, transform) {
		return false
	}
	for _, method := range match.Transformations {
		if !slices.Contains(methods, method) {
			return false
		}
	}
	if transform == "reversed" || transform == "rot13" {
		return match.SpanScope == "transformed_region" && match.StartByte == 0 && match.EndByte == inputBytes
	}
	return match.SpanScope == "encoded_candidate"
}
