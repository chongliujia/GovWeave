package gateway

import (
	"encoding/json"
	"errors"
	"slices"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"govweave/internal/sensitive"
)

const redactionVersion = "sensitive-redaction-v1"
const redactionMarker = "[REDACTED]"

// RedactionEvidence describes a completed transformation and recheck. It never
// contains values, source offsets, excerpts or hashes of the original text.
type RedactionEvidence struct {
	Version         string `json:"version"`
	Scope           string `json:"scope"`
	Replacements    int    `json:"replacements"`
	CheckDurationUS int64  `json:"check_duration_us"`
}

type redactionSpan struct{ start, end int }

// Redaction operates only on findings from the pinned detector. Credentials
// replace the full output because a private-key finding may cover only its
// header. Unknown or incomplete scans must never authorize partial release.
func redactOutput(text string, p OutputPolicySnapshot, detection sensitive.Result) (string, *RedactionEvidence, error) {
	started := time.Now()
	unavailable := errors.New("redaction_unavailable")
	if p.Mode != "redact" || p.RedactionVersion != redactionVersion || !sensitive.Supports(p.DetectorVersion) || detection.DetectorVersion != p.DetectorVersion || detection.State != "observed" || detection.Truncated ||
		detection.InputBytes != len(text) || len(text) > sensitive.MaxBytes || !utf8.ValidString(text) || strings.ContainsRune(text, utf8.RuneError) || len(detection.Findings) > sensitive.MaxFindings {
		return "", nil, unavailable
	}
	spans := []redactionSpan{}
	full := false
	for _, f := range detection.Findings {
		if f.StartByte < 0 || f.EndByte <= f.StartByte || f.EndByte > len(text) || !utf8.RuneStart(text[f.StartByte]) || f.EndByte < len(text) && !utf8.RuneStart(text[f.EndByte]) {
			return "", nil, unavailable
		}
		if !slices.Contains(p.Categories, f.Category) {
			continue
		}
		if publicEmailException(p, text, detection, f) {
			continue
		}
		if f.Category == "credential" {
			full = true
		}
		spans = append(spans, redactionSpan{f.StartByte, f.EndByte})
	}
	if len(spans) == 0 {
		return "", nil, unavailable
	}
	evidence := &RedactionEvidence{Version: redactionVersion, Scope: "matched_spans"}
	output := redactionMarker
	if full {
		evidence.Scope, evidence.Replacements = "full_output", 1
	} else {
		sort.Slice(spans, func(i, j int) bool {
			if spans[i].start != spans[j].start {
				return spans[i].start < spans[j].start
			}
			return spans[i].end > spans[j].end
		})
		merged := []redactionSpan{spans[0]}
		for _, s := range spans[1:] {
			last := &merged[len(merged)-1]
			if s.start <= last.end {
				if s.end > last.end {
					last.end = s.end
				}
				continue
			}
			merged = append(merged, s)
		}
		var b strings.Builder
		previous := 0
		for _, s := range merged {
			b.WriteString(text[previous:s.start])
			b.WriteString(redactionMarker)
			previous = s.end
		}
		b.WriteString(text[previous:])
		output = b.String()
		evidence.Replacements = len(merged)
	}
	if len(output) > sensitive.MaxBytes {
		return "", nil, unavailable
	}
	checked := sensitive.Scan([]byte(output), p.DetectorVersion)
	if checked.State == "unknown" {
		return "", nil, unavailable
	}
	for _, f := range checked.Findings {
		if slices.Contains(p.Categories, f.Category) && !publicEmailException(p, output, checked, f) {
			return "", nil, unavailable
		}
	}
	evidence.CheckDurationUS = time.Since(started).Microseconds()
	return output, evidence, nil
}

func applyOutputRedaction(text string, p OutputPolicySnapshot, detection sensitive.Result, assessment *OutputAssessment) (string, error) {
	redacted, evidence, err := redactOutput(text, p, detection)
	if err != nil {
		assessment.Result, assessment.State, assessment.Reason = "error", "unknown", "redaction_unavailable"
		assessment.Redaction = nil
		return "", err
	}
	assessment.Result, assessment.Redaction = "redacted", evidence
	return redacted, nil
}

// The input is the gateway-created canonical envelope, never a raw provider
// response. Only the checked text is replaced; provider extensions stay absent.
func replaceProtectedText(canonical []byte, text string) ([]byte, error) {
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(canonical, &envelope); err != nil {
		return nil, err
	}
	choices, err := json.Marshal([]any{map[string]any{"index": 0, "finish_reason": "stop", "message": map[string]string{"role": "assistant", "content": text}}})
	if err != nil {
		return nil, err
	}
	envelope["choices"] = choices
	return json.Marshal(envelope)
}
