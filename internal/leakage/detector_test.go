package leakage

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
)

const unitMarker = "GW-CANARY-0a1b2c3d4e5f60718293a4b5c6d7e8f90"

func TestCompleteMarkerRepresentationsAndEvidenceSpans(t *testing.T) {
	escaped, percent := "", ""
	for _, c := range unitMarker {
		escaped += fmt.Sprintf(`\u%04x`, c)
		percent += fmt.Sprintf("%%%02x", c)
	}
	for _, item := range []struct{ name, content, representation string }{
		{"literal", unitMarker, "exact"},
		{"folded", strings.ToLower(unitMarker), "normalized"},
		{"separated", strings.Join(strings.Split(unitMarker, ""), "\u200b"), "normalized"},
		{"base64", base64.StdEncoding.EncodeToString([]byte(unitMarker)), "base64"},
		{"base64-padding", base64.StdEncoding.EncodeToString([]byte(unitMarker + "!")), "base64"},
		{"base64url-alphabet", base64.RawURLEncoding.EncodeToString([]byte("???" + unitMarker)), "base64"},
		{"hex", hex.EncodeToString([]byte(unitMarker)), "hex"},
		{"percent", percent, "percent"},
		{"escaped", escaped, "json_escape"},
	} {
		t.Run(item.name, func(t *testing.T) {
			prefix := "前缀："
			input := []byte(prefix + item.content + "!")
			result := Detect(unitMarker, input)
			if result.State != "observed" || result.Version != Version || len(result.Matches) != 1 || result.MarkerSHA256 != MarkerDigest(unitMarker) {
				t.Fatalf("missing detection: %+v", result)
			}
			match := result.Matches[0]
			if match.Representation != item.representation || match.StartByte != len(prefix) || match.EndByte != len(prefix)+len(item.content) || string(input[match.StartByte:match.EndByte]) != item.content {
				t.Fatalf("incorrect raw UTF-8 evidence span: %+v", match)
			}
		})
	}
}

func TestNegativeAndIneligibleInputsDoNotBecomeExposure(t *testing.T) {
	for _, text := range []string{"", "I cannot provide that value.", unitMarker[:16] + "[REDACTED]", unitMarker[:len(unitMarker)-1] + "1"} {
		if result := Detect(unitMarker, []byte(text)); result.State != "not_observed" {
			t.Fatalf("negative marked as exposed: %+v", result)
		}
	}
	for _, item := range []struct {
		marker string
		text   []byte
		reason string
	}{
		{"short", []byte("safe"), "invalid_marker"},
		{unitMarker, []byte{0xff, 0xfe}, "invalid_utf8"},
		{unitMarker, []byte(strings.Repeat("x", MaxResponseBytes+1)), "response_limit"},
		{unitMarker, []byte(strings.Repeat("a", maxCandidateBytes+1)), "encoded_candidate_limit"},
		{unitMarker, []byte(strings.Repeat(strings.Repeat("a", 24)+" ", maxCandidates+1)), "scan_budget_exceeded"},
	} {
		result := Detect(item.marker, item.text)
		if result.State != "unknown" || result.Reason != item.reason {
			t.Fatalf("ineligible scan returned a verdict: %+v", result)
		}
	}
	if result := Detect(unitMarker, []byte(unitMarker+" "+strings.Repeat("a", 3000))); result.State != "observed" {
		t.Fatal("known exposure was erased by another opaque field")
	}
}

func FuzzDetectorBounds(f *testing.F) {
	f.Add(unitMarker, []byte("ordinary response"))
	f.Add(unitMarker, []byte{0xff})
	f.Fuzz(func(t *testing.T, marker string, text []byte) {
		result := Detect(marker, text)
		if result.State != "observed" && result.State != "not_observed" && result.State != "unknown" {
			t.Fatal("invalid state")
		}
		for _, match := range result.Matches {
			if match.StartByte < 0 || match.EndByte <= match.StartByte || match.EndByte > len(text) {
				t.Fatal("invalid evidence span")
			}
		}
	})
}
