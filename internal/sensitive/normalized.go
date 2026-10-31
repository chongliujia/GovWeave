package sensitive

import (
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

const Version2 = "sensitive-text-v2"

func SupportedVersion(version string) bool { return version == Version || version == Version2 }

// DetectVersion dispatches an immutable detector generation. Unknown versions
// fail closed; they never fall back to another generation.
func DetectVersion(input []byte, version string) Result {
	switch version {
	case Version:
		return Detect(input)
	case Version2:
		return detectNormalized(input)
	default:
		return Result{DetectorVersion: version, State: "unknown", Reason: "unsupported_version", InputBytes: len(input), Findings: []Finding{}}
	}
}

type sourceByte struct{ start, end int }
type textView struct {
	text  string
	spans []sourceByte
}

// Each output byte maps to a complete original rune (or bracket token). No
// normalization expands the input. Removed interior runes remain inside the
// returned original span, without storing text or hashes in findings.
func normalizeWidth(text string) textView {
	out := make([]byte, 0, len(text))
	spans := make([]sourceByte, 0, len(text))
	for pos, r := range text {
		size := utf8.RuneLen(r)
		switch r {
		case '\u200b', '\u200c', '\u200d', '\u2060', '\ufeff':
			continue
		case '\u3000':
			r = ' '
		default:
			if r >= '\uff01' && r <= '\uff5e' {
				r -= 0xfee0
			}
		}
		before := len(out)
		out = utf8.AppendRune(out, r)
		for i := before; i < len(out); i++ {
			spans = append(spans, sourceByte{pos, pos + size})
		}
	}
	return textView{string(out), spans}
}

// Only explicit bracketed email separators are rewritten, and only email
// findings from this view are admitted. Ordinary words and newlines are kept.
func normalizeEmail(view textView) textView {
	out := make([]byte, 0, len(view.text))
	spans := make([]sourceByte, 0, len(view.text))
	for i := 0; i < len(view.text); {
		n, replacement := 0, byte(0)
		if len(view.text)-i >= 4 && strings.EqualFold(view.text[i:i+4], "[at]") {
			n, replacement = 4, '@'
		}
		if len(view.text)-i >= 5 && strings.EqualFold(view.text[i:i+5], "[dot]") {
			n, replacement = 5, '.'
		}
		if n == 0 {
			out, spans = append(out, view.text[i]), append(spans, view.spans[i])
			i++
			continue
		}
		for len(out) > 0 && (out[len(out)-1] == ' ' || out[len(out)-1] == '\t') {
			out, spans = out[:len(out)-1], spans[:len(spans)-1]
		}
		out = append(out, replacement)
		spans = append(spans, sourceByte{view.spans[i].start, view.spans[i+n-1].end})
		i += n
		for i < len(view.text) && (view.text[i] == ' ' || view.text[i] == '\t') {
			i++
		}
	}
	return textView{string(out), spans}
}

func baseRule(rule string) string { return strings.TrimPrefix(rule, "normalized_") }

func detectNormalized(input []byte) (result Result) {
	started := time.Now()
	result = Detect(input)
	result.DetectorVersion = Version2
	defer func() { result.DurationUS = time.Since(started).Microseconds() }()
	if result.State == "unknown" {
		return result
	}
	text := string(input)
	// Common ASCII traffic avoids extra scans and offset allocations.
	if !strings.ContainsAny(text, "\u200b\u200c\u200d\u2060\ufeff\u3000") && !strings.ContainsFunc(text, func(r rune) bool { return r >= '\uff01' && r <= '\uff5e' }) && !strings.Contains(text, "[") {
		return result
	}
	view := normalizeWidth(text)
	findings := append([]Finding{}, result.Findings...)
	unknown := false
	collect := func(view textView, emailOnly bool) {
		observed := Detect([]byte(view.text))
		unknown = unknown || observed.State == "unknown"
		for _, f := range observed.Findings {
			if emailOnly && f.Category != "email" {
				continue
			}
			f.StartByte, f.EndByte = view.spans[f.StartByte].start, view.spans[f.EndByte-1].end
			f.RuleID = "normalized_" + f.RuleID
			findings = append(findings, f)
		}
	}
	if view.text != text {
		collect(view, false)
	}
	email := normalizeEmail(view)
	if email.text != view.text {
		collect(email, true)
	}
	// Merge overlapping observations of the same syntax rule. Preserve a raw
	// finding when it already covers the whole normalized finding, so one
	// entity does not exhaust the finding budget through duplicate views.
	sort.Slice(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		if baseRule(a.RuleID) != baseRule(b.RuleID) {
			return baseRule(a.RuleID) < baseRule(b.RuleID)
		}
		if a.StartByte != b.StartByte {
			return a.StartByte < b.StartByte
		}
		return a.EndByte > b.EndByte
	})
	merged := make([]Finding, 0, len(findings))
	for _, f := range findings {
		if len(merged) > 0 {
			last := &merged[len(merged)-1]
			if baseRule(last.RuleID) == baseRule(f.RuleID) && f.StartByte < last.EndByte {
				if f.EndByte > last.EndByte {
					last.EndByte = f.EndByte
					last.RuleID = "normalized_" + baseRule(last.RuleID)
				}
				if f.StartByte == last.StartByte && f.EndByte == last.EndByte && f.RuleID == baseRule(f.RuleID) {
					last.RuleID = f.RuleID
				}
				continue
			}
		}
		merged = append(merged, f)
	}
	sort.Slice(merged, func(i, j int) bool {
		a, b := merged[i], merged[j]
		if a.StartByte != b.StartByte {
			return a.StartByte < b.StartByte
		}
		if a.EndByte != b.EndByte {
			return a.EndByte < b.EndByte
		}
		return a.RuleID < b.RuleID
	})
	result.Findings = merged
	if len(merged) > MaxFindings {
		result.Findings = merged[:MaxFindings]
		unknown = true
	}
	if unknown {
		result.State, result.Reason, result.Truncated = "unknown", "finding_limit", true
		return result
	}
	result.State, result.Reason = "not_observed", "patterns_not_observed"
	if len(merged) > 0 {
		result.State, result.Reason = "observed", "patterns_observed"
	}
	return result
}
